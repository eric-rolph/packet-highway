//! Wire format v3.
//!
//! One fixed-size header, an optional forward-secrecy preamble, an optional
//! nickname, then AEAD ciphertext. Everything is little-endian (both mobile
//! targets are LE). Parsing borrows the input — no allocation until you `open`.
//!
//! ```text
//!  off  len  field
//!   0    1   magic 0x4D ('M')
//!   1    1   version
//!   2    1   flags        bit0 = beacon, bit1 = ack, bit2 = forward secret
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
//!  ..    n   nickname (utf-8)
//!  ..    m   ciphertext || tag
//! ```
//!
//! The FS preamble is conditional rather than a fixed header field so beacons
//! and broadcasts — which can never be forward secret — do not pay 36 bytes
//! each on a radio where every byte is scarce. It sits *outside* the ciphertext
//! because the recipient needs it to derive the key, and *inside* the AAD so it
//! cannot be swapped in flight.
//!
//! `ttl`/`hops` are deliberately outside the AAD: a relay must be able to
//! decrement TTL without holding a key. **Everything else is inside it** —
//! including `epoch`, `counter` and the FS preamble — which is what makes the
//! anti-replay window trustworthy and stops an attacker re-pointing a frame at
//! a different prekey.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{self, Identity, PeerId, NONCE_LEN, TAG_LEN};
use crate::prekey::PeerPrekey;
use crate::CoreError;

pub const MAGIC: u8 = 0x4D;
pub const VERSION: u8 = 3;
pub const HEADER_LEN: usize = 116;
pub const MAX_NICKNAME: usize = 20;

/// Length of the FS preamble when present: ephemeral pubkey + prekey generation.
pub const FS_PREAMBLE_LEN: usize = 32 + 4;

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

/// Offsets of the two fields a relay may rewrite. Named because three separate
/// places have to agree on them.
const OFF_TTL: usize = 3;
const OFF_HOPS: usize = 4;

const MAX_AAD_LEN: usize = HEADER_LEN + FS_PREAMBLE_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u8),
    LengthMismatch,
    BadNickname,
}

/// What a frame is for. Derived from `flags`, so callers match on an enum
/// rather than remembering which bit means what.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Discovery beacon: body is the sender's signed prekey bundle.
    Beacon,
    /// Delivery receipt: body is the 16-byte msg_id being acknowledged.
    Ack,
    /// Ordinary message.
    Message,
}

/// The forward-secrecy preamble, when present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsPreamble {
    pub ephemeral: [u8; 32],
    pub generation: u32,
}

/// How to derive the sealing key for an outgoing frame.
pub enum Sealing<'a> {
    /// Broadcast and beacons: the group key every member holds.
    Network,
    /// Directed, but we have never seen a prekey for the recipient. Works, but
    /// is not forward secret — the receiver is told so.
    Static,
    /// Directed with forward secrecy. `ephemeral` must be freshly generated for
    /// this one frame and dropped immediately after.
    ForwardSecret {
        ephemeral: &'a StaticSecret,
        prekey: &'a PeerPrekey,
    },
}

/// How to derive the opening key for an inbound frame.
pub enum Opening<'a> {
    Network,
    Static,
    ForwardSecret { prekey_secret: &'a StaticSecret },
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

    /// True when the sender used the forward-secret path. Surfaced to the UI so
    /// it can distinguish a guarantee it has from one it does not.
    pub fn is_forward_secret(&self) -> bool {
        self.fs.is_some()
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
    let preamble_len = if has_fs { FS_PREAMBLE_LEN } else { 0 };
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
    } else {
        FrameKind::Message
    };

    let (aad_buf, aad_len) = make_aad(&buf[..HEADER_LEN + preamble_len]);

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
    let (key, preamble) = match &out.sealing {
        Sealing::Network => (crypto::network_key(), None),
        Sealing::Static => (identity.derive_static_key(&out.recipient)?, None),
        Sealing::ForwardSecret { ephemeral, prekey } => {
            let key = crypto::seal_key_fs(
                identity,
                ephemeral,
                &out.recipient,
                &prekey.public,
                prekey.generation,
            )?;
            let preamble = FsPreamble {
                ephemeral: PublicKey::from(*ephemeral).to_bytes(),
                generation: prekey.generation,
            };
            (key, Some(preamble))
        }
    };

    let mut flags = match out.kind {
        FrameKind::Beacon => FLAG_BEACON,
        FrameKind::Ack => FLAG_ACK,
        FrameKind::Message => 0,
    };
    if preamble.is_some() {
        flags |= FLAG_FS;
    }

    let ct_len = out.body.len() + TAG_LEN;
    let preamble_len = if preamble.is_some() {
        FS_PREAMBLE_LEN
    } else {
        0
    };
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

    if let Some(p) = &preamble {
        buf.extend_from_slice(&p.ephemeral);
        buf.extend_from_slice(&p.generation.to_le_bytes());
    }

    // AAD is derived from the bytes just written, with ttl/hops zeroed, so seal
    // and open compute byte-identical AAD.
    let (aad_buf, aad_len) = make_aad(&buf);
    buf.extend_from_slice(nick);
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
        Opening::Network => crypto::network_key(),
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
            sealing: Sealing::Network,
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
        assert_eq!(open(&b, &parsed, Opening::Network).unwrap(), b"hi");
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
        assert_eq!(open(&b, &p, Opening::Network).unwrap(), b"relayed");
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
                open(&b, &p, Opening::Network).is_err(),
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
                Ok(p) => open(&b, &p, Opening::Network).is_err(),
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
                sealing: Sealing::Network,
            },
        )
        .unwrap();
        let p = parse(&wire).unwrap();
        assert!(p.is_beacon());
        assert!(p.nickname.len() <= MAX_NICKNAME);
        assert!(p.nickname.starts_with("alice"));

        let body = open(&b, &p, Opening::Network).unwrap();
        let peer_prekey = crate::prekey::parse_bundle(&a.public_id(), &body).unwrap();
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
                sealing: Sealing::Network,
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
        let wire = build(&a, &broadcast(b"x")).unwrap();
        let mut lying = wire[..HEADER_LEN + 4].to_vec();
        lying[2] |= FLAG_FS;
        assert_eq!(parse(&lying).unwrap_err(), FrameError::TooShort);
    }

    #[test]
    fn older_wire_versions_are_rejected() {
        for old in [1u8, 2] {
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
