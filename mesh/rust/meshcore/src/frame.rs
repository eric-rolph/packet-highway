//! Wire format.
//!
//! One fixed-size header, then an optional nickname, then AEAD ciphertext.
//! Everything is little-endian (both mobile targets are LE; we assert rather
//! than byte-swap). Parsing borrows the input — no allocation until you `open`.
//!
//! ```text
//!  off  len  field
//!   0    1   magic 0x4D ('M')
//!   1    1   version
//!   2    1   flags        bit0 = beacon
//!   3    1   ttl          MUTABLE on relay -> excluded from AAD
//!   4    1   hops         MUTABLE on relay -> excluded from AAD
//!   5    1   nickname_len (<= 20)
//!   6    2   body_len     u16 LE, ciphertext+tag length
//!   8   32   sender       X25519 public key
//!  40   32   recipient    peer id, all-zero = broadcast
//!  72   16   msg_id
//!  88   12   nonce
//! 100    n   nickname (utf-8, not authenticated for beacons -- see note)
//! 100+n  m   ciphertext || tag
//! ```
//!
//! `ttl`/`hops` are deliberately outside the AAD: a relay must be able to
//! decrement TTL without holding a key. Everything an attacker could use to
//! redirect or replay a message (sender, recipient, msg_id, nonce, lengths) is
//! inside the AAD.

use crate::crypto::{self, Identity, PeerId, NONCE_LEN, TAG_LEN};
use crate::CoreError;

pub const MAGIC: u8 = 0x4D;
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 100;
pub const MAX_NICKNAME: usize = 20;

/// Total on-air frame ceiling. A BLE 5 extended advertisement (`ADV_EXT_IND`)
/// carries up to 254 bytes; anything above that the platform layer must send
/// over a GATT write instead. We allow 512 so GATT-carried frames share one
/// format, and let the radio implementation decide how to ship it.
pub const MAX_FRAME: usize = 512;
pub const MAX_BODY: usize = MAX_FRAME - HEADER_LEN - MAX_NICKNAME - TAG_LEN;

pub const FLAG_BEACON: u8 = 0b0000_0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u8),
    LengthMismatch,
    BadNickname,
}

/// A parsed view over the caller's buffer. Zero-copy: `ciphertext` points into
/// the original slice; only `nickname` allocates (it is a `String` the peer
/// table keeps).
#[derive(Debug, Clone)]
pub struct ParsedFrame<'a> {
    pub sender: PeerId,
    pub recipient: PeerId,
    pub msg_id: [u8; 16],
    pub nonce: [u8; NONCE_LEN],
    pub ttl: u8,
    pub hops: u8,
    pub is_beacon: bool,
    pub nickname: String,
    pub ciphertext: &'a [u8],
    /// Header with the mutable fields zeroed — exactly what was fed to the AEAD.
    pub aad: [u8; HEADER_LEN],
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
    let ttl = buf[3];
    let hops = buf[4];
    let nick_len = buf[5] as usize;
    let body_len = u16::from_le_bytes([buf[6], buf[7]]) as usize;

    if nick_len > MAX_NICKNAME {
        return Err(FrameError::BadNickname);
    }
    if HEADER_LEN + nick_len + body_len != buf.len() {
        return Err(FrameError::LengthMismatch);
    }

    let mut sender = [0u8; 32];
    sender.copy_from_slice(&buf[8..40]);
    let mut recipient = [0u8; 32];
    recipient.copy_from_slice(&buf[40..72]);
    let mut msg_id = [0u8; 16];
    msg_id.copy_from_slice(&buf[72..88]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[88..100]);

    let nickname = std::str::from_utf8(&buf[HEADER_LEN..HEADER_LEN + nick_len])
        .map_err(|_| FrameError::BadNickname)?
        .to_owned();

    let ciphertext = &buf[HEADER_LEN + nick_len..];

    Ok(ParsedFrame {
        sender,
        recipient,
        msg_id,
        nonce,
        ttl,
        hops,
        is_beacon: flags & FLAG_BEACON != 0,
        nickname,
        ciphertext,
        aad: make_aad(&buf[..HEADER_LEN]),
    })
}

/// Copy the header and zero the fields relays are allowed to rewrite.
fn make_aad(header: &[u8]) -> [u8; HEADER_LEN] {
    let mut aad = [0u8; HEADER_LEN];
    aad.copy_from_slice(header);
    aad[3] = 0; // ttl
    aad[4] = 0; // hops
    aad
}

/// Build a signed-by-AEAD frame. `recipient == BROADCAST_ID` selects the
/// network key; anything else selects the pairwise key.
pub fn seal(
    identity: &Identity,
    recipient: &PeerId,
    msg_id: [u8; 16],
    ttl: u8,
    body: &[u8],
) -> Result<Vec<u8>, CoreError> {
    build(identity, recipient, msg_id, ttl, body, "", false)
}

/// A beacon is a frame with no body whose only job is to carry our public key
/// and nickname so neighbours can populate their peer table.
pub fn build_beacon(identity: &Identity, nickname: &str) -> Result<Vec<u8>, CoreError> {
    let msg_id = crypto::random_16()?;
    build(identity, &crypto::BROADCAST_ID, msg_id, 1, b"", nickname, true)
}

fn build(
    identity: &Identity,
    recipient: &PeerId,
    msg_id: [u8; 16],
    ttl: u8,
    body: &[u8],
    nickname: &str,
    beacon: bool,
) -> Result<Vec<u8>, CoreError> {
    if body.len() > MAX_BODY {
        return Err(CoreError::InvalidArgument("body exceeds MAX_BODY"));
    }
    let nick = nickname.as_bytes();
    let nick = &nick[..nick.len().min(MAX_NICKNAME)];
    // Guard against slicing a multi-byte char in half.
    let nick = match std::str::from_utf8(nick) {
        Ok(_) => nick,
        Err(e) => &nick[..e.valid_up_to()],
    };

    let nonce = crypto::random_nonce()?;
    let key = select_key(identity, recipient);

    // Header is written first with ttl/hops in place, then AAD is derived from
    // it with those bytes zeroed — so seal and open compute the identical AAD.
    let ct_len = body.len() + TAG_LEN;
    let mut out = Vec::with_capacity(HEADER_LEN + nick.len() + ct_len);
    out.push(MAGIC);
    out.push(VERSION);
    out.push(if beacon { FLAG_BEACON } else { 0 });
    out.push(ttl);
    out.push(0); // hops
    out.push(nick.len() as u8);
    out.extend_from_slice(&(ct_len as u16).to_le_bytes());
    out.extend_from_slice(&identity.public_id());
    out.extend_from_slice(recipient);
    out.extend_from_slice(&msg_id);
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), HEADER_LEN);

    let aad = make_aad(&out[..HEADER_LEN]);
    out.extend_from_slice(nick);
    out.extend_from_slice(&crypto::seal_aead(&key, &nonce, &aad, body)?);
    Ok(out)
}

pub fn open(identity: &Identity, f: &ParsedFrame<'_>) -> Result<Vec<u8>, CoreError> {
    let key = if f.recipient == crypto::BROADCAST_ID {
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
    out[3] = out[3].saturating_sub(1);
    out[4] = out[4].saturating_add(1);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_roundtrip() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = seal(&a, &crypto::BROADCAST_ID, [5u8; 16], 4, b"hi").unwrap();
        let parsed = parse(&wire).unwrap();
        assert_eq!(parsed.sender, a.public_id());
        assert_eq!(open(&b, &parsed).unwrap(), b"hi");
    }

    #[test]
    fn directed_frame_only_opens_for_recipient() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let eve = Identity::from_seed([3u8; 32]);
        let wire = seal(&a, &b.public_id(), [6u8; 16], 4, b"psst").unwrap();
        let parsed = parse(&wire).unwrap();
        assert_eq!(open(&b, &parsed).unwrap(), b"psst");
        assert!(open(&eve, &parsed).is_err());
    }

    #[test]
    fn relaying_preserves_authenticity() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let wire = seal(&a, &crypto::BROADCAST_ID, [7u8; 16], 4, b"relayed").unwrap();
        let hop1 = relay(&wire).unwrap();
        let hop2 = relay(&hop1).unwrap();
        let p = parse(&hop2).unwrap();
        assert_eq!(p.ttl, 2);
        assert_eq!(p.hops, 2);
        // TTL/hops changed but the AEAD still verifies: they are outside the AAD.
        assert_eq!(open(&b, &p).unwrap(), b"relayed");
    }

    #[test]
    fn header_tampering_is_caught() {
        let a = Identity::from_seed([1u8; 32]);
        let b = Identity::from_seed([2u8; 32]);
        let mut wire = seal(&a, &crypto::BROADCAST_ID, [8u8; 16], 4, b"x").unwrap();
        wire[72] ^= 0xff; // flip a msg_id byte, which IS in the AAD
        let p = parse(&wire).unwrap();
        assert!(open(&b, &p).is_err());
    }

    #[test]
    fn beacon_carries_nickname() {
        let a = Identity::from_seed([1u8; 32]);
        let wire = build_beacon(&a, "alice-with-a-very-long-name").unwrap();
        let p = parse(&wire).unwrap();
        assert!(p.is_beacon);
        assert!(p.nickname.len() <= MAX_NICKNAME);
        assert!(p.nickname.starts_with("alice"));
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
}
