//! Wire format v5.
//!
//! One fixed-size header, at most one key-agreement preamble, an optional
//! nickname, then AEAD ciphertext. Everything is little-endian (both mobile
//! targets are LE). Parsing borrows the input — no allocation until you `open`.
//!
//! ```text
//!  off  len  field
//!   0    1   magic 0x4D ('M')
//!   1    1   version
//!   2    1   flags        bit0 beacon, bit1 ack, bit2 FS preamble,
//!                         bit3 sender-key preamble, bit4 sender-key dist
//!   3    1   ttl          MUTABLE on relay -> excluded from AAD
//!   4    1   hops         MUTABLE on relay -> excluded from AAD
//!   5    1   nickname_len (<= 20)
//!   6    2   body_len     u16 LE, ciphertext+tag length
//!   8    8   epoch        sender's session epoch (see replay.rs)
//!  16    8   counter      sender's monotonic per-session message counter
//!  24   32   sender       Ed25519 identity key
//!  56   32   recipient    peer id, all-zero = broadcast
//!  88   16   msg_id       random; the ack correlator
//! 104   12   nonce
//! 116   36   FS preamble — PRESENT ONLY IF flags bit2:
//!                [32] ephemeral X25519 public key
//!                [ 4] recipient prekey generation, u32 LE
//! 116    8   SK preamble — PRESENT ONLY IF flags bit3:
//!                [ 4] sender chain id, u32 LE
//!                [ 4] message index within the chain, u32 LE
//!  ..    n   nickname (utf-8)
//!  ..    m   ciphertext || tag
//! ```
//!
//! Preambles are conditional rather than fixed header fields so a beacon does
//! not pay for machinery it cannot use, on a radio where every byte is scarce.
//! They sit *outside* the ciphertext because the recipient needs them to derive
//! the key, and *inside* the AAD so they cannot be swapped in flight.
//!
//! The two are **mutually exclusive** — one is directed, the other broadcast —
//! and a frame setting both is rejected structurally rather than resolved by
//! precedence. An ambiguous length prefix is how parsers grow bugs.
//!
//! `ttl`/`hops` are deliberately outside the AAD: a relay must be able to
//! decrement TTL without holding a key. **Everything else is inside it** —
//! header, whichever preamble is present, and the nickname — which is what
//! makes the anti-replay window trustworthy, stops an attacker re-pointing a
//! frame at a different prekey, and stops one rewriting the display name a
//! verified peer appears under.
//!
//! The nickname sits in the AAD rather than the ciphertext because a relay has
//! no key and must still be able to forward the frame byte-for-byte. It is
//! therefore authenticated but **not confidential**: anyone in radio range can
//! read it, they simply cannot change it.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{self, Identity, PeerId, NONCE_LEN, TAG_LEN};
use crate::prekey::PeerPrekey;
use crate::senderkey;
use crate::CoreError;

pub const MAGIC: u8 = 0x4D;
pub const VERSION: u8 = 5;
pub const HEADER_LEN: usize = 116;
pub const MAX_NICKNAME: usize = 20;

/// Length of the FS preamble when present: ephemeral pubkey + prekey generation.
pub const FS_PREAMBLE_LEN: usize = 32 + 4;
/// Length of the sender-key preamble when present: chain id + message index.
pub const SK_PREAMBLE_LEN: usize = senderkey::PREAMBLE_LEN;

/// Total on-air frame ceiling. A BLE 5 extended advertisement (`ADV_EXT_IND`)
/// carries up to 254 bytes; anything above that the platform layer must send
/// over a GATT write instead. We allow 512 so GATT-carried frames share one
/// format, and let the radio implementation decide how to ship it.
pub const MAX_FRAME: usize = 512;
/// Sized for the worst case — a forward-secret frame with a full nickname — so
/// a message accepted by `send` can never fail to fit at build time.
pub const MAX_BODY: usize = MAX_FRAME - HEADER_LEN - FS_PREAMBLE_LEN - MAX_NICKNAME - TAG_LEN;

pub const FLAG_BEACON: u8 = 0b0000_0001;
pub const FLAG_ACK: u8 = 0b0000_0010;
/// Set when the frame carries an FS preamble and is sealed with a
/// forward-secret key rather than the static-static fallback.
pub const FLAG_FS: u8 = 0b0000_0100;
/// Set when the frame carries a sender-key preamble — a broadcast sealed with a
/// ratcheted chain key rather than the static group key.
pub const FLAG_SK: u8 = 0b0000_1000;
/// Frame kind: this is a sender-key distribution, not user traffic.
pub const FLAG_SKDM: u8 = 0b0001_0000;

/// Offsets of the two fields a relay may rewrite. Named because three separate
/// places have to agree on them.
const OFF_TTL: usize = 3;
const OFF_HOPS: usize = 4;

/// The AAD spans the header, whichever preamble is present, **and the
/// nickname**. The nickname was outside it until v5, which meant anyone who
/// could hear a frame could rewrite the display name of a cryptographically
/// authenticated peer and have it accepted — see `the_nickname_is_authenticated`.
const MAX_AAD_LEN: usize = HEADER_LEN + FS_PREAMBLE_LEN + MAX_NICKNAME;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u8),
    LengthMismatch,
    BadNickname,
    /// A forward-secrecy preamble on a broadcast, or a sender-key preamble on a
    /// directed frame. Each names a key agreement that does not exist for that
    /// recipient, and accepting one would let the frame claim a guarantee the
    /// opening path does not provide.
    PreambleKindMismatch,
    /// Both preamble bits set. They imply different lengths and different key
    /// agreements; rather than pick one, refuse the frame.
    ConflictingPreambles,
}

/// What a frame is for. Derived from `flags`, so callers match on an enum
/// rather than remembering which bit means what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Discovery beacon: body is the sender's signed prekey bundle.
    Beacon,
    /// Delivery receipt: body is the 16-byte msg_id being acknowledged.
    Ack,
    /// Sender-key distribution: body is the sender's broadcast chain, handed to
    /// one peer over the forward-secret directed path. Never broadcast.
    SenderKey,
    /// Ordinary message.
    Message,
}

/// The forward-secrecy preamble, when present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsPreamble {
    pub ephemeral: [u8; 32],
    pub generation: u32,
}

/// The sender-key preamble, when present. Tells the receiver which chain and
/// which position to ratchet to; both are inside the AAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkPreamble {
    pub chain_id: u32,
    pub index: u32,
}

/// How to derive the sealing key for an outgoing frame.
pub enum Sealing<'a> {
    /// Beacons, and broadcasts from a node with no peers to distribute a chain
    /// to: the channel key every member holds. Not forward secret. The key is
    /// passed in rather than derived here so it is computed once per session
    /// instead of once per frame — and so a node cannot accidentally seal to a
    /// channel it did not join.
    Network { key: &'a [u8; 32] },
    /// Directed, but we have never seen a prekey for the recipient. Works, but
    /// is not forward secret — the receiver is told so.
    Static,
    /// Directed with forward secrecy. `ephemeral` must be freshly generated for
    /// this one frame and dropped immediately after.
    ForwardSecret {
        ephemeral: &'a StaticSecret,
        prekey: &'a PeerPrekey,
    },
    /// Broadcast with forward secrecy. `key` is one message key taken from our
    /// sender chain, which has already ratcheted past it.
    SenderKey {
        chain_id: u32,
        index: u32,
        key: &'a [u8; 32],
    },
}

/// How to derive the opening key for an inbound frame.
pub enum Opening<'a> {
    Network { key: &'a [u8; 32] },
    Static,
    ForwardSecret { prekey_secret: &'a StaticSecret },
    SenderKey { key: &'a [u8; 32] },
}

/// A parsed view over the caller's buffer. Zero-copy: `ciphertext` points into
/// the original slice; only `nickname` allocates (the peer table keeps it).
#[derive(Debug, Clone)]
pub struct ParsedFrame<'a> {
    pub sender: PeerId,
    pub recipient: PeerId,
    pub msg_id: [u8; 16],
    pub nonce: [u8; NONCE_LEN],
    pub epoch: u64,
    pub counter: u64,
    pub ttl: u8,
    pub hops: u8,
    pub kind: FrameKind,
    pub fs: Option<FsPreamble>,
    pub sk: Option<SkPreamble>,
    pub nickname: String,
    pub ciphertext: &'a [u8],
    /// Header (+ preamble) with the mutable fields zeroed — exactly what was
    /// fed to the AEAD. Inline rather than a `Vec` so parsing stays allocation
    /// free on the inbound hot path.
    aad_buf: [u8; MAX_AAD_LEN],
    aad_len: usize,
}

impl<'a> ParsedFrame<'a> {
    pub fn is_beacon(&self) -> bool {
        self.kind == FrameKind::Beacon
    }

    pub fn is_broadcast(&self) -> bool {
        self.recipient == crypto::BROADCAST_ID
    }

    /// True when the sender used a forward-secret path — the prekey exchange
    /// for directed frames, the sender-key ratchet for broadcasts. Surfaced to
    /// the UI so it can distinguish a guarantee it has from one it does not.
    pub fn is_forward_secret(&self) -> bool {
        self.fs.is_some() || self.sk.is_some()
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad_buf[..self.aad_len]
    }
}

pub fn parse(buf: &[u8]) -> Result<ParsedFrame<'_>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    if buf[0] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    if buf[1] != VERSION {
        return Err(FrameError::UnsupportedVersion(buf[1]));
    }

    let flags = buf[2];
    let nick_len = buf[5] as usize;
    let body_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;

    if nick_len > MAX_NICKNAME {
        return Err(FrameError::BadNickname);
    }

    // The preamble is length-bearing, so it must be resolved before any of the
    // offsets after the header can be trusted.
    let has_fs = flags & FLAG_FS != 0;
    let has_sk = flags & FLAG_SK != 0;
    if has_fs && has_sk {
        return Err(FrameError::ConflictingPreambles);
    }
    // Which preamble is present must agree with who the frame is addressed to.
    // Without this the flag and the key disagree: `unseal` picks the opening key
    // from the recipient, so a broadcast carrying FLAG_FS is opened with the
    // channel key while `is_forward_secret()` — which only looks at the
    // preambles — reports true. That is a group-key message wearing a padlock.
    // Rejecting the combination makes the two agree by construction rather than
    // by two call sites remembering to.
    let is_broadcast = buf[56..88] == crypto::BROADCAST_ID;
    if has_fs && is_broadcast {
        return Err(FrameError::PreambleKindMismatch);
    }
    if has_sk && !is_broadcast {
        return Err(FrameError::PreambleKindMismatch);
    }
    let preamble_len = match (has_fs, has_sk) {
        (true, _) => FS_PREAMBLE_LEN,
        (_, true) => SK_PREAMBLE_LEN,
        _ => 0,
    };
    if buf.len() < HEADER_LEN + preamble_len {
        return Err(FrameError::TooShort);
    }
    if HEADER_LEN + preamble_len + nick_len + body_len != buf.len() {
        return Err(FrameError::LengthMismatch);
    }

    let fs = has_fs.then(|| {
        let p = &buf[HEADER_LEN..HEADER_LEN + FS_PREAMBLE_LEN];
        let mut ephemeral = [0u8; 32];
        ephemeral.copy_from_slice(&p[..32]);
        FsPreamble {
            ephemeral,
            generation: u32::from_le_bytes(p[32..36].try_into().expect("4 bytes")),
        }
    });

    let sk = has_sk.then(|| {
        let p = &buf[HEADER_LEN..HEADER_LEN + SK_PREAMBLE_LEN];
        SkPreamble {
            chain_id: u32::from_le_bytes(p[0..4].try_into().expect("4 bytes")),
            index: u32::from_le_bytes(p[4..8].try_into().expect("4 bytes")),
        }
    });

    let epoch = u64::from_le_bytes(buf[8..16].try_into().expect("8 bytes"));
    let counter = u64::from_le_bytes(buf[16..24].try_into().expect("8 bytes"));

    let mut sender = [0u8; 32];
    sender.copy_from_slice(&buf[24..56]);
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&buf[56..88]);
    let mut msg_id = [0u8; 16];
    msg_id.copy_from_slice(&buf[88..104]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[104..116]);

    let nick_start = HEADER_LEN + preamble_len;
    let nickname = std::str::from_utf8(&buf[nick_start..nick_start + nick_len])
        .map_err(|_| FrameError::BadNickname)?
        .to_owned();

    let kind = if flags & FLAG_BEACON != 0 {
        FrameKind::Beacon
    } else if flags & FLAG_ACK != 0 {
        FrameKind::Ack
    } else if flags & FLAG_SKDM != 0 {
        FrameKind::SenderKey
    } else {
        FrameKind::Message
    };

    let (aad_buf, aad_len) = make_aad(&buf[..nick_start + nick_len]);

    Ok(ParsedFrame {
        sender,
        recipient,
        msg_id,
        nonce,
        epoch,
        counter,
        ttl: buf[OFF_TTL],
        hops: buf[OFF_HOPS],
        kind,
        fs,
        sk,
        nickname,
        ciphertext: &buf[nick_start + nick_len..],
        aad_buf,
        aad_len,
    })
}

/// Copy the header (plus preamble, if any) and zero the fields relays may
/// rewrite.
fn make_aad(prefix: &[u8]) -> ([u8; MAX_AAD_LEN], usize) {
    let mut aad = [0u8; MAX_AAD_LEN];
    let n = prefix.len().min(MAX_AAD_LEN);
    aad[..n].copy_from_slice(&prefix[..n]);
    aad[OFF_TTL] = 0;
    aad[OFF_HOPS] = 0;
    (aad, n)
}

/// Everything needed to emit a frame. Grouped into a struct because the
/// positional-argument version had grown to eight parameters, four of which
/// were `u64`/`u8` and trivially swappable at a call site.
pub struct Outgoing<'a> {
    pub recipient: PeerId,
    pub msg_id: [u8; 16],
    pub epoch: u64,
    pub counter: u64,
    pub ttl: u8,
    pub body: &'a [u8],
    pub nickname: &'a str,
    pub kind: FrameKind,
    pub sealing: Sealing<'a>,
}

/// Build a sealed frame.
pub fn build(identity: &Identity, out: &Outgoing<'_>) -> Result<Vec<u8>, CoreError> {
    if out.body.len() > MAX_BODY {
        return Err(CoreError::InvalidArgument("body exceeds MAX_BODY"));
    }

    // Truncate the nickname on a char boundary, not mid-codepoint.
    let nick = out.nickname.as_bytes();
    let nick = &nick[..nick.len().min(MAX_NICKNAME)];
    let nick = match std::str::from_utf8(nick) {
        Ok(_) => nick,
        Err(e) => &nick[..e.valid_up_to()],
    };

    let nonce = crypto::random_nonce()?;

    // Resolve the key and the preamble together — they are two halves of one
    // decision, and letting them diverge would produce a frame nobody can open.
    // The preamble is carried as bytes plus the flag that declares its length,
    // so the writer below cannot set one without the other.
    let mut preamble: [u8; FS_PREAMBLE_LEN] = [0u8; FS_PREAMBLE_LEN];
    let (key, preamble_flag, preamble_len) = match &out.sealing {
        Sealing::Network { key } => (**key, 0, 0),
        Sealing::Static => (identity.derive_static_key(&out.recipient)?, 0, 0),
        Sealing::ForwardSecret { ephemeral, prekey } => {
            let key = crypto::seal_key_fs(
                identity,
                ephemeral,
                &out.recipient,
                &prekey.public,
                prekey.generation,
            )?;
            preamble[..32].copy_from_slice(PublicKey::from(*ephemeral).as_bytes());
            preamble[32..36].copy_from_slice(&prekey.generation.to_le_bytes());
            (key, FLAG_FS, FS_PREAMBLE_LEN)
        }
        Sealing::SenderKey {
            chain_id,
            index,
            key,
        } => {
            preamble[0..4].copy_from_slice(&chain_id.to_le_bytes());
            preamble[4..8].copy_from_slice(&index.to_le_bytes());
            (**key, FLAG_SK, SK_PREAMBLE_LEN)
        }
    };

    let mut flags = match out.kind {
        FrameKind::Beacon => FLAG_BEACON,
        FrameKind::Ack => FLAG_ACK,
        FrameKind::SenderKey => FLAG_SKDM,
        FrameKind::Message => 0,
    };
    flags |= preamble_flag;

    let ct_len = out.body.len() + TAG_LEN;
    let mut buf = Vec::with_capacity(HEADER_LEN + preamble_len + nick.len() + ct_len);

    buf.push(MAGIC);
    buf.push(VERSION);
    buf.push(flags);
    buf.push(out.ttl);
    buf.push(0); // hops
    buf.push(nick.len() as u8);
    buf.extend_from_slice(&(ct_len as u16).to_le_bytes());
    buf.extend_from_slice(&out.epoch.to_le_bytes());
    buf.extend_from_slice(&out.counter.to_le_bytes());
    buf.extend_from_slice(&identity.public_id());
    buf.extend_from_slice(&out.recipient);
    buf.extend_from_slice(&out.msg_id);
    buf.extend_from_slice(&nonce);
    debug_assert_eq!(buf.len(), HEADER_LEN);

    buf.extend_from_slice(&preamble[..preamble_len]);

    // The nickname goes on *before* the AAD snapshot: it is authenticated data,
    // and appending it afterwards is exactly the bug v5 fixes.
    buf.extend_from_slice(nick);
    // AAD is derived from the bytes just written, with ttl/hops zeroed, so seal
    // and open compute byte-identical AAD.
    let (aad_buf, aad_len) = make_aad(&buf);
    buf.extend_from_slice(&crypto::seal_aead(
        &key,
        &nonce,
        &aad_buf[..aad_len],
        out.body,
    )?);
    Ok(buf)
}

pub fn open(
    identity: &Identity,
    f: &ParsedFrame<'_>,
    opening: Opening<'_>,
) -> Result<Vec<u8>, CoreError> {
    let key = match opening {
        Opening::Network { key } => *key,
        Opening::Static => identity.derive_static_key(&f.sender)?,
        Opening::ForwardSecret { prekey_secret } => {
            let fs = f.fs.as_ref().ok_or(CoreError::Crypto("no FS preamble"))?;
            crypto::open_key_fs(
                prekey_secret,
                &fs.ephemeral,
                &f.sender,
                &f.recipient,
                fs.generation,
            )?
        }
        // The caller derived this from the sender chain named in the preamble;
        // there is no key agreement left to do here.
        Opening::SenderKey { key } => *key,
    };
    crypto::open_aead(&key, &f.nonce, f.aad(), f.ciphertext)
}

/// Produce the relayed copy of a frame: TTL-1, hops+1, ciphertext untouched.
/// Cheap — one allocation and two byte writes, no crypto.
pub fn relay(buf: &[u8]) -> Result<Vec<u8>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    let mut out = buf.to_vec();
    out[OFF_TTL] = out[OFF_TTL].saturating_sub(1);
    out[OFF_HOPS] = out[OFF_HOPS].saturating_add(1);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default channel, so these tests exercise the same path a caller who
    /// supplies no secret gets. `'static` so the helpers below can hand out
    /// `Outgoing` values that outlive the call.
    fn open_key() -> &'static [u8; 32] {
        static K: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        K.get_or_init(|| crypto::network_key(crypto::OPEN_CHANNEL))
    }
    use crate::prekey::PrekeyRing;

    fn broadcast(body: &[u8]) -> Outgoing<'_> {
        Outgoing {
            recipient: crypto::BROADCAST_ID,
            msg_id: [5u8; 16],
            epoch: 42,
            counter: 7,
            ttl: 4,
            body,
            nickname: "",
            kind: FrameKind::Message,
            sealing: Sealing::Network { key: open_key() },
        }
    }

    fn directed<'a>(to: PeerId, body: &'a [u8], sealing: Sealing<'a>) -> Outgoing<'a> {
        Outgoing {
            recipient: to,
            msg_id: [6u8; 16],
            epoch: 42,
            counter: 8,
            ttl: 4,
            body,
            nickname: "",
            kind: FrameKind::Message,
            sealing,
        }
    }

    #[test]
    fn broadcast_roundtrip() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &broadcast(b"hi")).unwrap();
        let parsed = parse(&wire).unwrap();
        assert_eq!(parsed.sender, a.public_id());
        assert_eq!(parsed.epoch, 42);
        assert_eq!(parsed.counter, 7);
        assert!(!parsed.is_forward_secret());
        assert_eq!(
            open(&b, &parsed, Opening::Network { key: open_key() }).unwrap(),
            b"hi"
        );
    }

    #[test]
    fn static_directed_frame_only_opens_for_recipient() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let eve = Identity::from_seed([3u8; 32]);
        let wire = build(&a, &directed(b.public_id(), b"psst", Sealing::Static)).unwrap();
        let parsed = parse(&wire).unwrap();
        assert!(!parsed.is_forward_secret(), "static path must not claim FS");
        assert_eq!(open(&b, &parsed, Opening::Static).unwrap(), b"psst");
        assert!(open(&eve, &parsed, Opening::Static).is_err());
    }

    #[test]
    fn forward_secret_frame_roundtrips() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let ring = PrekeyRing::new(0).unwrap();
        let bundle = PeerPrekey {
            generation: ring.current().generation,
            public: ring.current().public,
            epoch: 1,
        };
        let ephemeral = crypto::random_secret().unwrap();

        let wire = build(
            &a,
            &directed(
                b.public_id(),
                b"forward secret",
                Sealing::ForwardSecret {
                    ephemeral: &ephemeral,
                    prekey: &bundle,
                },
            ),
        )
        .unwrap();

        let parsed = parse(&wire).unwrap();
        assert!(parsed.is_forward_secret());
        assert_eq!(parsed.fs.unwrap().generation, bundle.generation);
        assert_eq!(
            open(
                &b,
                &parsed,
                Opening::ForwardSecret {
                    prekey_secret: ring.current().secret()
                }
            )
            .unwrap(),
            b"forward secret"
        );
    }

    /// Once the prekey is gone the message is unrecoverable — including by the
    /// intended recipient, using its own long-term key. That is the guarantee.
    #[test]
    fn a_rotated_out_prekey_cannot_open_the_frame() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let mut ring = PrekeyRing::new(0).unwrap();
        let bundle = PeerPrekey {
            generation: ring.current().generation,
            public: ring.current().public,
            epoch: 1,
        };
        let ephemeral = crypto::random_secret().unwrap();
        let wire = build(
            &a,
            &directed(
                b.public_id(),
                b"burn after reading",
                Sealing::ForwardSecret {
                    ephemeral: &ephemeral,
                    prekey: &bundle,
                },
            ),
        )
        .unwrap();
        let parsed = parse(&wire).unwrap();

        // Rotate past the retention depth; the secret is zeroized on eviction.
        for i in 1..=(crate::prekey::RETAINED as u64 + 1) {
            ring.rotate(i).unwrap();
        }
        assert!(ring.get(bundle.generation).is_none());

        // The current prekey cannot substitute for the retired one.
        assert!(open(
            &b,
            &parsed,
            Opening::ForwardSecret {
                prekey_secret: ring.current().secret()
            }
        )
        .is_err());
        // Neither can the static fallback.
        assert!(open(&b, &parsed, Opening::Static).is_err());
    }

    #[test]
    fn the_fs_preamble_is_authenticated() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let ring = PrekeyRing::new(0).unwrap();
        let bundle = PeerPrekey {
            generation: ring.current().generation,
            public: ring.current().public,
            epoch: 1,
        };
        let ephemeral = crypto::random_secret().unwrap();
        let wire = build(
            &a,
            &directed(
                b.public_id(),
                b"x",
                Sealing::ForwardSecret {
                    ephemeral: &ephemeral,
                    prekey: &bundle,
                },
            ),
        )
        .unwrap();

        // Swapping the ephemeral key or re-pointing the generation must break
        // the AEAD, not silently derive a different key.
        for offset in [HEADER_LEN, HEADER_LEN + 31, HEADER_LEN + 32] {
            let mut tampered = wire.clone();
            tampered[offset] ^= 0xff;
            let p = parse(&tampered).unwrap();
            assert!(
                open(
                    &b,
                    &p,
                    Opening::ForwardSecret {
                        prekey_secret: ring.current().secret()
                    }
                )
                .is_err(),
                "tampering with preamble byte {offset} went undetected"
            );
        }
    }

    fn sender_key_broadcast<'a>(
        chain_id: u32,
        index: u32,
        key: &'a [u8; 32],
        body: &'a [u8],
    ) -> Outgoing<'a> {
        Outgoing {
            recipient: crypto::BROADCAST_ID,
            msg_id: [4u8; 16],
            epoch: 42,
            counter: 9,
            ttl: 4,
            body,
            nickname: "",
            kind: FrameKind::Message,
            sealing: Sealing::SenderKey {
                chain_id,
                index,
                key,
            },
        }
    }

    #[test]
    fn a_sender_key_broadcast_roundtrips() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let key = [0x5Au8; 32];

        let wire = build(
            &a,
            &sender_key_broadcast(0xDEADBEEF, 12, &key, b"to the group"),
        )
        .unwrap();
        let p = parse(&wire).unwrap();

        assert!(p.is_broadcast());
        assert!(
            p.is_forward_secret(),
            "a ratcheted broadcast is forward secret"
        );
        assert_eq!(
            p.sk.unwrap(),
            SkPreamble {
                chain_id: 0xDEADBEEF,
                index: 12
            }
        );
        assert!(p.fs.is_none(), "the FS preamble must not also be claimed");
        assert_eq!(
            open(&b, &p, Opening::SenderKey { key: &key }).unwrap(),
            b"to the group"
        );

        // The group key must not open it — that is the whole point.
        assert!(open(&b, &p, Opening::Network { key: open_key() }).is_err());
        // Nor may a different message key from the same chain.
        assert!(open(&b, &p, Opening::SenderKey { key: &[0x5Bu8; 32] }).is_err());
    }

    /// Re-pointing a frame at a different chain or index must break the AEAD
    /// rather than silently ask the receiver to ratchet somewhere else.
    #[test]
    fn the_sender_key_preamble_is_authenticated() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let key = [0x5Au8; 32];
        let wire = build(&a, &sender_key_broadcast(7, 3, &key, b"x")).unwrap();

        for offset in HEADER_LEN..HEADER_LEN + SK_PREAMBLE_LEN {
            let mut tampered = wire.clone();
            tampered[offset] ^= 0xff;
            let p = parse(&tampered).unwrap();
            assert!(
                open(&b, &p, Opening::SenderKey { key: &key }).is_err(),
                "tampering with preamble byte {offset} went undetected"
            );
        }
    }

    /// Both preamble bits set is not a frame with a precedence rule; it is a
    /// frame with two answers to "how long is the header", so it is refused.
    #[test]
    fn a_frame_claiming_both_preambles_is_refused() {
        let a = Identity::from_seed([1u8; 32]);
        let key = [1u8; 32];
        let mut wire = build(&a, &sender_key_broadcast(1, 0, &key, b"x")).unwrap();
        wire[2] |= FLAG_FS;
        assert_eq!(
            parse(&wire).unwrap_err(),
            FrameError::ConflictingPreambles,
            "an ambiguous length prefix must not be resolved by precedence"
        );
    }

    #[test]
    fn a_truncated_sender_key_preamble_is_rejected() {
        let a = Identity::from_seed([1u8; 32]);
        let wire = build(&a, &broadcast(b"x")).unwrap();
        let mut lying = wire[..HEADER_LEN + 4].to_vec();
        lying[2] |= FLAG_SK;
        assert_eq!(parse(&lying).unwrap_err(), FrameError::TooShort);
    }

    #[test]
    fn a_sender_key_distribution_is_a_distinct_kind() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let body = [3u8; crate::senderkey::DISTRIBUTION_LEN];
        let wire = build(
            &a,
            &Outgoing {
                recipient: b.public_id(),
                msg_id: [1u8; 16],
                epoch: 1,
                counter: 1,
                ttl: 4,
                body: &body,
                nickname: "",
                kind: FrameKind::SenderKey,
                sealing: Sealing::Static,
            },
        )
        .unwrap();
        let p = parse(&wire).unwrap();
        assert_eq!(p.kind, FrameKind::SenderKey);
        assert!(!p.is_broadcast(), "a chain key is never broadcast");
        assert_eq!(open(&b, &p, Opening::Static).unwrap(), body);
    }

    #[test]
    fn relaying_preserves_authenticity() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &broadcast(b"relayed")).unwrap();
        let hop2 = relay(&relay(&wire).unwrap()).unwrap();
        let p = parse(&hop2).unwrap();
        assert_eq!(p.ttl, 2);
        assert_eq!(p.hops, 2);
        // TTL/hops changed but the AEAD still verifies: they are outside the AAD.
        assert_eq!(
            open(&b, &p, Opening::Network { key: open_key() }).unwrap(),
            b"relayed"
        );
    }

    #[test]
    fn epoch_and_counter_are_authenticated() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &broadcast(b"x")).unwrap();
        for offset in [8usize, 16] {
            let mut tampered = wire.clone();
            tampered[offset] ^= 0xff;
            let p = parse(&tampered).unwrap();
            assert!(
                open(&b, &p, Opening::Network { key: open_key() }).is_err(),
                "flipping byte {offset} (epoch/counter) must fail AEAD"
            );
        }
    }

    #[test]
    fn header_tampering_is_caught() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &broadcast(b"x")).unwrap();
        // Every authenticated header byte, one at a time. Only ttl/hops may
        // survive tampering; everything else must break the AEAD.
        for offset in 0..HEADER_LEN {
            if offset == OFF_TTL || offset == OFF_HOPS {
                continue;
            }
            let mut tampered = wire.clone();
            tampered[offset] ^= 0xff;
            let broke = match parse(&tampered) {
                Err(_) => true, // structural rejection also counts
                Ok(p) => open(&b, &p, Opening::Network { key: open_key() }).is_err(),
            };
            assert!(broke, "tampering with header byte {offset} went undetected");
        }
    }

    #[test]
    fn beacon_carries_nickname_and_prekey_bundle() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let ring = PrekeyRing::new(0).unwrap();
        let bundle = ring.bundle(&a);
        let wire = build(
            &a,
            &Outgoing {
                recipient: crypto::BROADCAST_ID,
                msg_id: [1u8; 16],
                epoch: 1,
                counter: 0,
                ttl: 1,
                body: &bundle,
                nickname: "alice-with-a-very-long-name",
                kind: FrameKind::Beacon,
                sealing: Sealing::Network { key: open_key() },
            },
        )
        .unwrap();
        let p = parse(&wire).unwrap();
        assert!(p.is_beacon());
        assert!(p.nickname.len() <= MAX_NICKNAME);
        assert!(p.nickname.starts_with("alice"));

        let body = open(&b, &p, Opening::Network { key: open_key() }).unwrap();
        let peer_prekey = crate::prekey::parse_bundle(&a.public_id(), 1, &body).unwrap();
        assert_eq!(peer_prekey.public, ring.current().public);
    }

    #[test]
    fn multibyte_nickname_truncates_on_a_char_boundary() {
        let a = Identity::from_seed([1u8; 32]);
        let long = "é".repeat(21); // 42 bytes; a 20-byte cut lands mid-codepoint
        let wire = build(
            &a,
            &Outgoing {
                recipient: crypto::BROADCAST_ID,
                msg_id: [1u8; 16],
                epoch: 1,
                counter: 0,
                ttl: 1,
                body: b"",
                nickname: &long,
                kind: FrameKind::Beacon,
                sealing: Sealing::Network { key: open_key() },
            },
        )
        .unwrap();
        let p = parse(&wire).unwrap();
        assert_eq!(p.nickname, "é".repeat(10), "must not split a codepoint");
    }

    #[test]
    fn truncated_and_garbage_input_is_rejected_not_panicking() {
        assert_eq!(parse(&[]).unwrap_err(), FrameError::TooShort);
        assert_eq!(parse(&[0u8; 50]).unwrap_err(), FrameError::TooShort);
        assert_eq!(parse(&[0u8; 200]).unwrap_err(), FrameError::BadMagic);
        let mut bad = vec![0u8; 200];
        bad[0] = MAGIC;
        bad[1] = 99;
        assert_eq!(parse(&bad).unwrap_err(), FrameError::UnsupportedVersion(99));
    }

    /// A frame claiming FLAG_FS but too short to hold the preamble must be
    /// rejected structurally, before any offset arithmetic runs on it.
    #[test]
    fn a_truncated_fs_preamble_is_rejected() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        // Directed, because an FS preamble on a broadcast is now refused for a
        // different reason and would not exercise the length check.
        let wire = build(&a, &directed(b.public_id(), b"x", Sealing::Static)).unwrap();
        let mut lying = wire[..HEADER_LEN + 4].to_vec();
        lying[2] |= FLAG_FS;
        assert_eq!(parse(&lying).unwrap_err(), FrameError::TooShort);
    }

    /// The v5 fix. Until then the nickname sat outside the AAD, so anyone in
    /// radio range could rewrite the display name of a peer whose identity was
    /// cryptographically verified, and the AEAD would still pass.
    #[test]
    fn the_nickname_is_authenticated() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(
            &a,
            &Outgoing {
                recipient: crypto::BROADCAST_ID,
                msg_id: [1u8; 16],
                epoch: 1,
                counter: 0,
                ttl: 1,
                body: b"x",
                nickname: "alice",
                kind: FrameKind::Beacon,
                sealing: Sealing::Network { key: open_key() },
            },
        )
        .unwrap();
        assert_eq!(parse(&wire).unwrap().nickname, "alice");

        // Same length, so nick_len in the authenticated header is untouched.
        for offset in 0..5 {
            let mut tampered = wire.clone();
            tampered[HEADER_LEN + offset] ^= 0x20;
            let p = parse(&tampered).unwrap();
            assert!(
                open(&b, &p, Opening::Network { key: open_key() }).is_err(),
                "rewriting nickname byte {offset} went undetected"
            );
        }
    }

    /// A broadcast has no per-recipient exchange, so an FS preamble on one names
    /// a key agreement that cannot exist. Accepting it let the frame report
    /// `forwardSecret: true` while being opened with the channel key.
    #[test]
    fn a_forward_secret_preamble_on_a_broadcast_is_refused() {
        let a = Identity::from_seed([1u8; 32]);
        let wire = build(&a, &broadcast(b"x")).unwrap();
        let mut lying = wire[..HEADER_LEN].to_vec();
        lying[2] |= FLAG_FS;
        lying.extend_from_slice(&[0u8; FS_PREAMBLE_LEN]);
        lying.extend_from_slice(&wire[HEADER_LEN..]);
        assert_eq!(
            parse(&lying).unwrap_err(),
            FrameError::PreambleKindMismatch,
            "a group-key broadcast must not be able to claim forward secrecy"
        );
    }

    /// The mirror: a sender chain is a broadcast construct, so an SK preamble on
    /// a directed frame would be opened static-static while claiming FS.
    #[test]
    fn a_sender_key_preamble_on_a_directed_frame_is_refused() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &directed(b.public_id(), b"x", Sealing::Static)).unwrap();
        let mut lying = wire[..HEADER_LEN].to_vec();
        lying[2] |= FLAG_SK;
        lying.extend_from_slice(&[0u8; SK_PREAMBLE_LEN]);
        lying.extend_from_slice(&wire[HEADER_LEN..]);
        assert_eq!(parse(&lying).unwrap_err(), FrameError::PreambleKindMismatch);
    }

    #[test]
    fn older_wire_versions_are_rejected() {
        for old in [1u8, 2, 3, 4] {
            let mut v = vec![0u8; 200];
            v[0] = MAGIC;
            v[1] = old;
            assert_eq!(parse(&v).unwrap_err(), FrameError::UnsupportedVersion(old));
        }
    }

    /// The worst-case frame — forward secret, full nickname, max body — must
    /// still fit the ceiling. If MAX_BODY drifts, this catches it here rather
    /// than as a runtime build failure on a device.
    #[test]
    fn a_maximal_frame_fits_the_ceiling() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let ring = PrekeyRing::new(0).unwrap();
        let bundle = PeerPrekey {
            generation: ring.current().generation,
            public: ring.current().public,
            epoch: 1,
        };
        let ephemeral = crypto::random_secret().unwrap();
        let body = vec![0xAAu8; MAX_BODY];
        let wire = build(
            &a,
            &Outgoing {
                recipient: b.public_id(),
                msg_id: [1u8; 16],
                epoch: 1,
                counter: 1,
                ttl: 4,
                body: &body,
                nickname: "12345678901234567890",
                kind: FrameKind::Message,
                sealing: Sealing::ForwardSecret {
                    ephemeral: &ephemeral,
                    prekey: &bundle,
                },
            },
        )
        .unwrap();
        assert!(
            wire.len() <= MAX_FRAME,
            "maximal frame is {} bytes",
            wire.len()
        );
        assert_eq!(wire.len(), MAX_FRAME);
    }
}
