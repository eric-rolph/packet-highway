//! Wire format v2.
//!
//! One fixed-size header, then an optional nickname, then AEAD ciphertext.
//! Everything is little-endian (both mobile targets are LE). Parsing borrows
//! the input — no allocation until you `open`.
//!
//! ```text
//!  off  len  field
//!   0    1   magic 0x4D ('M')
//!   1    1   version
//!   2    1   flags        bit0 = beacon, bit1 = ack
//!   3    1   ttl          MUTABLE on relay -> excluded from AAD
//!   4    1   hops         MUTABLE on relay -> excluded from AAD
//!   5    1   nickname_len (<= 20)
//!   6    2   body_len     u16 LE, ciphertext+tag length
//!   8    8   epoch        sender's session epoch (see replay.rs)
//!  16    8   counter      sender's monotonic per-session message counter
//!  24   32   sender       X25519 public key
//!  56   32   recipient    peer id, all-zero = broadcast
//!  88   16   msg_id       random; the ack correlator
//! 104   12   nonce
//! 116    n   nickname (utf-8)
//! 116+n  m   ciphertext || tag
//! ```
//!
//! `ttl`/`hops` are deliberately outside the AAD: a relay must be able to
//! decrement TTL without holding a key. **Everything else is inside it**,
//! including `epoch` and `counter` — that is what makes the anti-replay window
//! in `replay.rs` trustworthy, because a forged counter cannot survive AEAD
//! verification.

use crate::crypto::{self, Identity, PeerId, NONCE_LEN, TAG_LEN};
use crate::CoreError;

pub const MAGIC: u8 = 0x4D;
pub const VERSION: u8 = 2;
pub const HEADER_LEN: usize = 116;
pub const MAX_NICKNAME: usize = 20;

/// Total on-air frame ceiling. A BLE 5 extended advertisement (`ADV_EXT_IND`)
/// carries up to 254 bytes; anything above that the platform layer must send
/// over a GATT write instead. We allow 512 so GATT-carried frames share one
/// format, and let the radio implementation decide how to ship it.
pub const MAX_FRAME: usize = 512;
pub const MAX_BODY: usize = MAX_FRAME - HEADER_LEN - MAX_NICKNAME - TAG_LEN;

pub const FLAG_BEACON: u8 = 0b0000_0001;
pub const FLAG_ACK: u8 = 0b0000_0010;

/// Offsets of the two fields a relay may rewrite. Named because three separate
/// places have to agree on them.
const OFF_TTL: usize = 3;
const OFF_HOPS: usize = 4;

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
    /// Discovery beacon: no body, carries the nickname.
    Beacon,
    /// Delivery receipt: body is the 16-byte msg_id being acknowledged.
    Ack,
    /// Ordinary message.
    Message,
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
    pub nickname: String,
    pub ciphertext: &'a [u8],
    /// Header with the mutable fields zeroed — exactly what was fed to the AEAD.
    pub aad: [u8; HEADER_LEN],
}

impl ParsedFrame<'_> {
    pub fn is_beacon(&self) -> bool {
        self.kind == FrameKind::Beacon
    }

    pub fn is_broadcast(&self) -> bool {
        self.recipient == crypto::BROADCAST_ID
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
    let ttl = buf[OFF_TTL];
    let hops = buf[OFF_HOPS];
    let nick_len = buf[5] as usize;
    let body_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;

    if nick_len > MAX_NICKNAME {
        return Err(FrameError::BadNickname);
    }
    if HEADER_LEN + nick_len + body_len != buf.len() {
        return Err(FrameError::LengthMismatch);
    }

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

    let nickname = std::str::from_utf8(&buf[HEADER_LEN..HEADER_LEN + nick_len])
        .map_err(|_| FrameError::BadNickname)?
        .to_owned();

    let kind = if flags & FLAG_BEACON != 0 {
        FrameKind::Beacon
    } else if flags & FLAG_ACK != 0 {
        FrameKind::Ack
    } else {
        FrameKind::Message
    };

    Ok(ParsedFrame {
        sender,
        recipient,
        msg_id,
        nonce,
        epoch,
        counter,
        ttl,
        hops,
        kind,
        nickname,
        ciphertext: &buf[HEADER_LEN + nick_len..],
        aad: make_aad(&buf[..HEADER_LEN]),
    })
}

/// Copy the header and zero the fields relays are allowed to rewrite.
fn make_aad(header: &[u8]) -> [u8; HEADER_LEN] {
    let mut aad = [0u8; HEADER_LEN];
    aad.copy_from_slice(header);
    aad[OFF_TTL] = 0;
    aad[OFF_HOPS] = 0;
    aad
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
}

/// Build a sealed frame. `recipient == BROADCAST_ID` selects the network key;
/// anything else selects the pairwise key.
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
    let key = select_key(identity, &out.recipient);

    let flags = match out.kind {
        FrameKind::Beacon => FLAG_BEACON,
        FrameKind::Ack => FLAG_ACK,
        FrameKind::Message => 0,
    };

    let ct_len = out.body.len() + TAG_LEN;
    let mut buf = Vec::with_capacity(HEADER_LEN + nick.len() + ct_len);
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

    // AAD is derived from the header just written, with ttl/hops zeroed, so
    // seal and open compute byte-identical AAD.
    let aad = make_aad(&buf[..HEADER_LEN]);
    buf.extend_from_slice(nick);
    buf.extend_from_slice(&crypto::seal_aead(&key, &nonce, &aad, out.body)?);
    Ok(buf)
}

pub fn open(identity: &Identity, f: &ParsedFrame<'_>) -> Result<Vec<u8>, CoreError> {
    let key = if f.is_broadcast() {
        crypto::network_key()
    } else {
        identity.derive_direct_key(&f.sender)
    };
    crypto::open_aead(&key, &f.nonce, &f.aad, f.ciphertext)
}

fn select_key(identity: &Identity, recipient: &PeerId) -> [u8; 32] {
    if *recipient == crypto::BROADCAST_ID {
        crypto::network_key()
    } else {
        identity.derive_direct_key(recipient)
    }
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

    fn msg<'a>(recipient: PeerId, body: &'a [u8]) -> Outgoing<'a> {
        Outgoing {
            recipient,
            msg_id: [5u8; 16],
            epoch: 42,
            counter: 7,
            ttl: 4,
            body,
            nickname: "",
            kind: FrameKind::Message,
        }
    }

    #[test]
    fn broadcast_roundtrip() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &msg(crypto::BROADCAST_ID, b"hi")).unwrap();
        let parsed = parse(&wire).unwrap();
        assert_eq!(parsed.sender, a.public_id());
        assert_eq!(parsed.epoch, 42);
        assert_eq!(parsed.counter, 7);
        assert_eq!(parsed.kind, FrameKind::Message);
        assert_eq!(open(&b, &parsed).unwrap(), b"hi");
    }

    #[test]
    fn directed_frame_only_opens_for_recipient() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let eve = Identity::from_seed([3u8; 32]);
        let wire = build(&a, &msg(b.public_id(), b"psst")).unwrap();
        let parsed = parse(&wire).unwrap();
        assert_eq!(open(&b, &parsed).unwrap(), b"psst");
        assert!(open(&eve, &parsed).is_err());
    }

    #[test]
    fn relaying_preserves_authenticity() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &msg(crypto::BROADCAST_ID, b"relayed")).unwrap();
        let hop2 = relay(&relay(&wire).unwrap()).unwrap();
        let p = parse(&hop2).unwrap();
        assert_eq!(p.ttl, 2);
        assert_eq!(p.hops, 2);
        // TTL/hops changed but the AEAD still verifies: they are outside the AAD.
        assert_eq!(open(&b, &p).unwrap(), b"relayed");
    }

    /// The security property the whole replay window rests on: epoch and
    /// counter are authenticated, so they cannot be rewritten in flight.
    #[test]
    fn epoch_and_counter_are_authenticated() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &msg(crypto::BROADCAST_ID, b"x")).unwrap();

        for offset in [8usize, 16] {
            let mut tampered = wire.clone();
            tampered[offset] ^= 0xff;
            let p = parse(&tampered).unwrap();
            assert!(
                open(&b, &p).is_err(),
                "flipping byte {offset} (epoch/counter) must fail AEAD"
            );
        }
    }

    #[test]
    fn header_tampering_is_caught() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = build(&a, &msg(crypto::BROADCAST_ID, b"x")).unwrap();
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
                Ok(p) => open(&b, &p).is_err(),
            };
            assert!(broke, "tampering with header byte {offset} went undetected");
        }
    }

    #[test]
    fn beacon_carries_nickname_and_verifies() {
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
                body: b"",
                nickname: "alice-with-a-very-long-name",
                kind: FrameKind::Beacon,
            },
        )
        .unwrap();
        let p = parse(&wire).unwrap();
        assert!(p.is_beacon());
        assert!(p.nickname.len() <= MAX_NICKNAME);
        assert!(p.nickname.starts_with("alice"));
        // A beacon is sealed like anything else, so it authenticates as a
        // member of the network even though it carries no body.
        assert_eq!(open(&b, &p).unwrap(), b"");
    }

    #[test]
    fn multibyte_nickname_truncates_on_a_char_boundary() {
        let a = Identity::from_seed([1u8; 32]);
        // 21 x 'é' = 42 bytes; the 20-byte cut lands mid-codepoint.
        let long = "é".repeat(21);
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
            },
        )
        .unwrap();
        let p = parse(&wire).unwrap();
        assert_eq!(p.nickname, "é".repeat(10), "must not split a codepoint");
    }

    #[test]
    fn ack_frames_roundtrip() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let acked = [0xABu8; 16];
        let wire = build(
            &a,
            &Outgoing {
                recipient: b.public_id(),
                msg_id: [9u8; 16],
                epoch: 1,
                counter: 1,
                ttl: 4,
                body: &acked,
                nickname: "",
                kind: FrameKind::Ack,
            },
        )
        .unwrap();
        let p = parse(&wire).unwrap();
        assert_eq!(p.kind, FrameKind::Ack);
        assert_eq!(open(&b, &p).unwrap(), acked);
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

    /// A v1 frame must be rejected cleanly, not misparsed. v1's header was 16
    /// bytes shorter, so every field after byte 8 would be read from the wrong
    /// offset if the version gate were missing.
    #[test]
    fn v1_frames_are_rejected() {
        let mut v1 = vec![0u8; 150];
        v1[0] = MAGIC;
        v1[1] = 1;
        assert_eq!(parse(&v1).unwrap_err(), FrameError::UnsupportedVersion(1));
    }
}
