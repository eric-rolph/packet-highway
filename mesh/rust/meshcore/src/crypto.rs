//! Identity, key agreement and AEAD.
//!
//! ## Threat model (be honest about it)
//!
//! Directed messages use **static-static X25519** ECDH: `DH(my_static,
//! their_static)` → HKDF → ChaCha20-Poly1305. That authenticates the sender
//! implicitly and needs zero round trips — which matters a lot when your
//! transport is a connectionless BLE advertisement and a "handshake" may never
//! complete. The cost is **no forward secrecy**: compromising a long-term key
//! retroactively decrypts everything.
//!
//! Broadcast messages use a **network key** derived from a channel secret, so
//! every participant can read them. This is a group key, not a group ratchet.
//!
//! Before shipping to real users, replace this module with a Noise XX handshake
//! plus a Double Ratchet per peer, keeping the same function signatures — the
//! rest of the crate only depends on `derive_direct_key` / `seal` / `open`.
//! The API surface here is deliberately shaped to make that swap local.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CoreError;

/// A peer is addressed by its 32-byte X25519 public key. Copy + Hash so it can
/// be a `HashMap` key without allocation.
pub type PeerId = [u8; 32];

/// Reserved all-zero id meaning "everyone". Not a valid curve point, so it can
/// never collide with a real peer.
pub const BROADCAST_ID: PeerId = [0u8; 32];

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Domain separator baked into every derived key. Change it and old builds can
/// no longer talk to new ones — which is the point during protocol migrations.
const KDF_DOMAIN: &[u8] = b"meshcore/v1/x25519-chacha20poly1305";
/// Placeholder channel secret for the public mesh. In production this is the
/// per-channel secret the user joined with, not a constant.
const CHANNEL_SECRET: &[u8] = b"meshcore/v1/public-channel";

/// Long-term identity. `Clone` is cheap (two 32-byte arrays) and needed because
/// the worker thread owns a copy.
#[derive(Clone)]
pub struct Identity {
    secret: StaticSecret,
    public: PublicKey,
}

impl Identity {
    pub fn generate() -> Result<Self, CoreError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| CoreError::Crypto("getrandom failed"))?;
        Ok(Self::from_seed(seed))
    }

    /// Deterministic identity from a stored seed. The seed is what you persist
    /// in the Keychain / Android Keystore — never the clamped secret itself.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_id(&self) -> PeerId {
        *self.public.as_bytes()
    }

    /// Static-static ECDH → HKDF-ish extract. See the module note on FS.
    pub fn derive_direct_key(&self, peer: &PeerId) -> [u8; 32] {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer));
        let mut h = Sha256::new();
        h.update(KDF_DOMAIN);
        h.update(b"\x01direct");
        h.update(shared.as_bytes());
        // Bind both identities in a canonical (sorted) order so both sides
        // derive the same key regardless of who is sending.
        let (lo, hi) = {
            let me = self.public_id();
            if me <= *peer {
                (me, *peer)
            } else {
                (*peer, me)
            }
        };
        h.update(lo);
        h.update(hi);
        h.finalize().into()
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the secret.
        write!(f, "Identity({})", hex16(&self.public_id()))
    }
}

/// Group key for broadcast traffic.
pub fn network_key() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KDF_DOMAIN);
    h.update(b"\x02broadcast");
    h.update(CHANNEL_SECRET);
    h.finalize().into()
}

/// AEAD seal. Returns `ciphertext || tag`.
pub fn seal_aead(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, CoreError> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| CoreError::Crypto("seal"))
}

/// AEAD open. Input is `ciphertext || tag`.
pub fn open_aead(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, CoreError> {
    if ct.len() < TAG_LEN {
        return Err(CoreError::Crypto("ciphertext shorter than tag"));
    }
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CoreError::Crypto("open: auth failed"))
}

pub fn random_16() -> Result<[u8; 16], CoreError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| CoreError::Crypto("getrandom failed"))?;
    Ok(b)
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN], CoreError> {
    let mut b = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut b).map_err(|_| CoreError::Crypto("getrandom failed"))?;
    Ok(b)
}

/// Short hex for logs. Never format a full key into a log line.
pub fn hex16(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_key_is_symmetric() {
        let a = Identity::from_seed([3u8; 32]);
        let b = Identity::from_seed([4u8; 32]);
        assert_eq!(
            a.derive_direct_key(&b.public_id()),
            b.derive_direct_key(&a.public_id())
        );
    }

    #[test]
    fn aead_rejects_tampering() {
        let k = network_key();
        let n = [7u8; NONCE_LEN];
        let mut ct = seal_aead(&k, &n, b"aad", b"secret").unwrap();
        assert_eq!(open_aead(&k, &n, b"aad", &ct).unwrap(), b"secret");
        ct[0] ^= 0xff;
        assert!(open_aead(&k, &n, b"aad", &ct).is_err());
        // Wrong AAD must also fail — this is what protects the frame header.
        let ct2 = seal_aead(&k, &n, b"aad", b"secret").unwrap();
        assert!(open_aead(&k, &n, b"other", &ct2).is_err());
    }
}
