//! Identity, key agreement and AEAD.
//!
//! ## Identity is Ed25519, DH is X25519
//!
//! A node's identity is an **Ed25519** keypair, and its `PeerId` is the 32-byte
//! Ed25519 public key. Diffie-Hellman uses the birationally-equivalent X25519
//! form of the same key, derived on demand:
//!
//! * secret: `SigningKey::to_scalar_bytes()` → `StaticSecret`
//! * public: `VerifyingKey::to_montgomery()` → `x25519::PublicKey`
//!
//! One keypair, two uses. The reason to carry Ed25519 rather than raw X25519 is
//! that **a node has to sign its prekeys** (see below), and X25519 keys cannot
//! sign. This is the same construction Signal uses for exactly the same reason.
//!
//! ## Forward secrecy
//!
//! Directed messages are forward secret via an X3DH-shaped exchange that costs
//! **zero round trips** — which is the only kind that works when the transport
//! is a connectionless advertisement and a handshake may never complete.
//!
//! Every node publishes a rotating **signed prekey** in its beacon. To send:
//!
//! ```text
//! DH1 = DH(ephemeral_sender, prekey_recipient)   <- provides forward secrecy
//! DH2 = DH(static_sender,    prekey_recipient)   <- authenticates the sender
//! key = KDF(DH1 ‖ DH2 ‖ sender ‖ recipient ‖ generation)
//! ```
//!
//! The sender then drops the ephemeral secret. Once the recipient also rotates
//! that prekey out of its ring, the message is unrecoverable **even if both
//! long-term keys are later compromised**. That is the property the previous
//! static-static construction did not have.
//!
//! The prekey is signed by the Ed25519 identity, so another mesh member cannot
//! publish a prekey on someone else's behalf and intercept their mail — which
//! they otherwise could, since beacons are only authenticated by the shared
//! network key.
//!
//! ## Broadcasts: a sender-key ratchet
//!
//! A broadcast has no single recipient, so there is no pairwise exchange to be
//! forward secret about. Instead each node runs one **sender chain**: a random
//! 32-byte chain key, ratcheted once per broadcast.
//!
//! ```text
//! mk_i     = KDF(ck_i, "sk-message")   <- seals broadcast i
//! ck_{i+1} = KDF(ck_i, "sk-chain")     <- replaces ck_i, which is then erased
//! ```
//!
//! The ratchet is one-way, so possessing `ck_n` says nothing about `ck_{n-1}`.
//! What makes that *worth* anything is how the chain reaches the group: the
//! chain key is handed to each peer in a **directed, forward-secret** frame over
//! the prekey path above — never in a beacon. An attacker who records the whole
//! session and later seizes the device gets neither the retired prekeys that
//! would open the distribution frames nor the spent chain keys that would open
//! the broadcasts.
//!
//! That is the property the group key never had: [`network_key`] is derived from
//! a constant, so one stolen channel secret decrypted every broadcast ever
//! recorded. See `senderkey.rs` for the ratchet and its limits.
//!
//! ## What is still not forward secret
//!
//! * **Broadcasts sent before any sender key has been distributed** — a node
//!   with no peers yet still falls back to [`network_key`], with the flag clear.
//! * **Directed messages to a peer whose prekey we have never seen.** Rather
//!   than refuse to send, the frame falls back to static-static and sets no
//!   `FLAG_FS`; the receiver reports `forward_secret: false` on the event so the
//!   UI can say so rather than implying a guarantee it does not have.
//! * **Post-compromise security.** There is no ratchet, so an attacker who
//!   steals the prekey ring reads traffic until the next rotation. Bounded by
//!   `prekey::ROTATE_INTERVAL_MS`, not zero.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::CoreError;

/// A peer is addressed by its 32-byte **Ed25519** public key. Copy + Hash so it
/// can be a `HashMap` key without allocation.
pub type PeerId = [u8; 32];

/// Reserved all-zero id meaning "everyone".
///
/// It *does* decompress to a valid Edwards point (a small-order one), so this
/// is not self-enforcing — every code path compares against it explicitly
/// before choosing a key, and [`dh`] refuses it outright.
pub const BROADCAST_ID: PeerId = [0u8; 32];

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;

/// Domain separator baked into every derived key. Change it and old builds can
/// no longer talk to new ones — which is the point during protocol migrations.
const KDF_DOMAIN: &[u8] = b"meshcore/v4/ed25519-x25519-chacha20poly1305";
/// The channel every node falls into when the caller supplies nothing.
///
/// This is a *published* value, not a secret — it names the open mesh anyone can
/// join, in the way an unencrypted SSID does. It is deliberately not called a
/// secret any more: treating a constant compiled into every copy of the binary
/// as a secret was the misleading part of the old design, not the constant.
///
/// A caller that wants a mesh only its members can read passes its own bytes as
/// [`crate::Config::channel_secret`].
pub const OPEN_CHANNEL: &[u8] = b"meshcore/v4/open-channel";
/// Signed alongside a prekey so a signature can never be replayed as anything
/// other than a prekey announcement.
const PREKEY_DOMAIN: &[u8] = b"meshcore/v4/prekey";

/// Long-term identity. `Clone` is cheap and needed because the worker thread
/// owns a copy.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Result<Self, CoreError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|_| CoreError::Crypto("getrandom failed"))?;
        Ok(Self::from_seed(seed))
    }

    /// Deterministic identity from a stored seed. The seed is what you persist
    /// in the Keychain / Android Keystore — never the expanded scalar.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_id(&self) -> PeerId {
        self.signing.verifying_key().to_bytes()
    }

    /// The X25519 form of our secret, for Diffie-Hellman.
    pub fn x25519_secret(&self) -> StaticSecret {
        StaticSecret::from(self.signing.to_scalar_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(msg).to_bytes()
    }

    /// Static-static ECDH — the **non**-forward-secret fallback, used only when
    /// we have never seen a prekey for the recipient.
    pub fn derive_static_key(&self, peer: &PeerId) -> Result<[u8; 32], CoreError> {
        let peer_x = peer_x25519(peer)?;
        let shared = dh(&self.x25519_secret(), &peer_x)?;
        let mut h = Sha256::new();
        h.update(KDF_DOMAIN);
        h.update(b"\x01static");
        h.update(shared);
        // Bind both identities in a canonical (sorted) order so both sides
        // derive the same key regardless of who is sending.
        let me = self.public_id();
        let (lo, hi) = if me <= *peer {
            (me, *peer)
        } else {
            (*peer, me)
        };
        h.update(lo);
        h.update(hi);
        Ok(h.finalize().into())
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never log the secret.
        write!(f, "Identity({})", hex16(&self.public_id()))
    }
}

/// Convert a peer's Ed25519 id into its X25519 public key.
///
/// Rejects anything that is not a valid compressed Edwards point. Note that
/// this is *not* sufficient on its own — see [`dh`].
pub fn peer_x25519(peer: &PeerId) -> Result<PublicKey, CoreError> {
    let vk = VerifyingKey::from_bytes(peer).map_err(|_| CoreError::Crypto("bad peer id"))?;
    Ok(PublicKey::from(vk.to_montgomery().to_bytes()))
}

/// Every Diffie-Hellman in this crate goes through here.
///
/// Decoding a peer id successfully is **not** enough to make it safe to DH
/// with. Small-order points — `[0u8; 32]` and `y = 1` among them — decompress
/// perfectly well and then drive the shared secret to all zeros, so an attacker
/// who can choose a peer id could fix the key for everyone who talks to them.
/// `was_contributory` is the check that catches it, and routing all DH through
/// one function is what stops a future call site from forgetting it.
fn dh(secret: &StaticSecret, public: &PublicKey) -> Result<[u8; 32], CoreError> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(CoreError::Crypto(
            "non-contributory DH: small-order public key",
        ));
    }
    Ok(*shared.as_bytes())
}

// ---------------------------------------------------------------------------
// Prekey signing
// ---------------------------------------------------------------------------

fn prekey_message(generation: u32, prekey_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(PREKEY_DOMAIN.len() + 4 + 32);
    m.extend_from_slice(PREKEY_DOMAIN);
    m.extend_from_slice(&generation.to_le_bytes());
    m.extend_from_slice(prekey_pub);
    m
}

pub fn sign_prekey(
    identity: &Identity,
    generation: u32,
    prekey_pub: &[u8; 32],
) -> [u8; SIGNATURE_LEN] {
    identity.sign(&prekey_message(generation, prekey_pub))
}

/// Verify that `peer` really published this prekey.
///
/// Without this, any member of the mesh could beacon a prekey under someone
/// else's id and receive their directed mail — beacons are only authenticated
/// by the shared network key, which every member holds.
pub fn verify_prekey(
    peer: &PeerId,
    generation: u32,
    prekey_pub: &[u8; 32],
    signature: &[u8; SIGNATURE_LEN],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(peer) else {
        return false;
    };
    vk.verify(
        &prekey_message(generation, prekey_pub),
        &Signature::from_bytes(signature),
    )
    .is_ok()
}

// ---------------------------------------------------------------------------
// Key agreement
// ---------------------------------------------------------------------------

/// Combine the two DH outputs with the transcript context. Both sides call this
/// with identical inputs; if they ever disagree, decryption fails closed.
fn fs_key(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    sender: &PeerId,
    recipient: &PeerId,
    generation: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KDF_DOMAIN);
    h.update(b"\x03forward-secret");
    h.update(dh1);
    h.update(dh2);
    h.update(sender);
    h.update(recipient);
    h.update(generation.to_le_bytes());
    h.finalize().into()
}

/// Sender side. `ephemeral` is used once and must be dropped immediately after
/// — that drop is what makes the message forward secret.
pub fn seal_key_fs(
    identity: &Identity,
    ephemeral: &StaticSecret,
    recipient: &PeerId,
    recipient_prekey: &[u8; 32],
    generation: u32,
) -> Result<[u8; 32], CoreError> {
    let prekey = PublicKey::from(*recipient_prekey);
    let dh1 = dh(ephemeral, &prekey)?;
    let dh2 = dh(&identity.x25519_secret(), &prekey)?;
    Ok(fs_key(
        &dh1,
        &dh2,
        &identity.public_id(),
        recipient,
        generation,
    ))
}

/// Recipient side, using the prekey secret the sender addressed.
pub fn open_key_fs(
    prekey_secret: &StaticSecret,
    ephemeral_pub: &[u8; 32],
    sender: &PeerId,
    recipient: &PeerId,
    generation: u32,
) -> Result<[u8; 32], CoreError> {
    let dh1 = dh(prekey_secret, &PublicKey::from(*ephemeral_pub))?;
    let dh2 = dh(prekey_secret, &peer_x25519(sender)?)?;
    Ok(fs_key(&dh1, &dh2, sender, recipient, generation))
}

/// Group key for the channel, derived from whatever secret the caller joined
/// with.
///
/// Two roles, both of them bootstrap-shaped:
///
/// * **Beacons.** A peer that holds nothing yet has to be able to read one, or
///   it can never obtain a prekey and never receive a sender chain.
/// * **Broadcasts from a node with no peers**, which has nobody to hand a chain
///   to. Everything else uses [`sender_chain_step`].
///
/// It is **not** forward secret and never can be: whoever learns the channel
/// secret reads every beacon ever recorded under it, and the pre-chain
/// broadcasts too. What changed is the blast radius — the secret is now the
/// caller's, so learning one channel's key says nothing about another's, and
/// compiling the binary no longer grants membership.
///
/// Callers should derive this **once** and keep it; it is a SHA-256 per call.
pub fn network_key(channel_secret: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KDF_DOMAIN);
    h.update(b"\x02broadcast");
    // Length-prefixed so two different secrets cannot collide by concatenation
    // with the domain tag — belt and braces, since the tag is fixed-length, but
    // this is the kind of thing that stops being true when someone adds a field.
    h.update((channel_secret.len() as u64).to_le_bytes());
    h.update(channel_secret);
    h.finalize().into()
}

/// One click of a sender chain: `(message_key, next_chain_key)`.
///
/// Two independent derivations from the same input, under different domain
/// tags. That separation is what makes it safe to hand the message key to the
/// AEAD while keeping the chain alive: recovering `ck_i` from `mk_i` would mean
/// inverting SHA-256, so a leaked message key compromises exactly one broadcast.
///
/// The caller **must** overwrite `ck_i` with the returned chain key and erase
/// the old one. The ratchet is not the security property on its own — the
/// erasure is; see `senderkey.rs`.
pub fn sender_chain_step(chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut mk = Sha256::new();
    mk.update(KDF_DOMAIN);
    mk.update(b"\x04sk-message");
    mk.update(chain);

    let mut next = Sha256::new();
    next.update(KDF_DOMAIN);
    next.update(b"\x05sk-chain");
    next.update(chain);

    (mk.finalize().into(), next.finalize().into())
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

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

pub fn random_32() -> Result<[u8; 32], CoreError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|_| CoreError::Crypto("getrandom failed"))?;
    Ok(b)
}

pub fn random_u32() -> Result<u32, CoreError> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|_| CoreError::Crypto("getrandom failed"))?;
    Ok(u32::from_le_bytes(b))
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN], CoreError> {
    let mut b = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut b).map_err(|_| CoreError::Crypto("getrandom failed"))?;
    Ok(b)
}

pub fn random_secret() -> Result<StaticSecret, CoreError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|_| CoreError::Crypto("getrandom failed"))?;
    Ok(StaticSecret::from(b))
}

/// Short hex for logs. Never format a full key into a log line.
pub fn hex16(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_key_is_symmetric() {
        let a = Identity::from_seed([3u8; 32]);
        let b = Identity::from_seed([4u8; 32]);
        assert_eq!(
            a.derive_static_key(&b.public_id()).unwrap(),
            b.derive_static_key(&a.public_id()).unwrap()
        );
    }

    /// The birational map has to agree in both directions or every DH silently
    /// produces two different keys and nothing decrypts.
    #[test]
    fn ed25519_and_x25519_forms_agree() {
        let id = Identity::from_seed([5u8; 32]);
        let from_secret = PublicKey::from(&id.x25519_secret());
        let from_public = peer_x25519(&id.public_id()).unwrap();
        assert_eq!(from_secret.as_bytes(), from_public.as_bytes());
    }

    #[test]
    fn a_malformed_peer_id_is_rejected_at_decode() {
        // y = 2 and y = 7 have no corresponding x on the curve.
        for y in [2u8, 7] {
            let mut id = [0u8; 32];
            id[0] = y;
            assert!(peer_x25519(&id).is_err(), "y={y} should not decompress");
        }
    }

    /// Regression: decoding is not enough. These ids decompress perfectly well
    /// and then force the shared secret to all zeros, which would let anyone
    /// who picks such an id read — and forge — traffic addressed to them.
    #[test]
    fn small_order_peer_ids_are_rejected_at_dh_not_merely_at_decode() {
        let id = Identity::from_seed([1u8; 32]);

        let identity_point = {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        };
        for hostile in [BROADCAST_ID, identity_point] {
            assert!(
                peer_x25519(&hostile).is_ok(),
                "precondition: this id decodes, which is why the DH check matters"
            );
            assert!(
                id.derive_static_key(&hostile).is_err(),
                "small-order id {} must be refused",
                hex16(&hostile)
            );
        }

        // The same guard applies on the forward-secret path.
        let ephemeral = random_secret().unwrap();
        assert!(seal_key_fs(&id, &ephemeral, &id.public_id(), &[0u8; 32], 0).is_err());
        assert!(open_key_fs(&ephemeral, &[0u8; 32], &id.public_id(), &id.public_id(), 0).is_err());
    }

    #[test]
    fn forward_secret_key_agreement_matches_on_both_sides() {
        let sender = Identity::from_seed([1u8; 32]);
        let recipient = Identity::from_seed([2u8; 32]);
        let prekey_secret = random_secret().unwrap();
        let prekey_pub = PublicKey::from(&prekey_secret).to_bytes();
        let ephemeral = random_secret().unwrap();
        let ephemeral_pub = PublicKey::from(&ephemeral).to_bytes();

        let k_send =
            seal_key_fs(&sender, &ephemeral, &recipient.public_id(), &prekey_pub, 7).unwrap();
        let k_recv = open_key_fs(
            &prekey_secret,
            &ephemeral_pub,
            &sender.public_id(),
            &recipient.public_id(),
            7,
        )
        .unwrap();
        assert_eq!(k_send, k_recv);
    }

    /// The generation is in the KDF transcript, so a frame cannot be silently
    /// re-pointed at a different prekey.
    #[test]
    fn a_different_generation_yields_a_different_key() {
        let sender = Identity::from_seed([1u8; 32]);
        let recipient = Identity::from_seed([2u8; 32]);
        let prekey_secret = random_secret().unwrap();
        let prekey_pub = PublicKey::from(&prekey_secret).to_bytes();
        let ephemeral = random_secret().unwrap();

        let k7 = seal_key_fs(&sender, &ephemeral, &recipient.public_id(), &prekey_pub, 7).unwrap();
        let k8 = seal_key_fs(&sender, &ephemeral, &recipient.public_id(), &prekey_pub, 8).unwrap();
        assert_ne!(k7, k8);
    }

    /// The property that makes it forward secret: the long-term keys alone are
    /// not enough. Only the (ephemeral, prekey) pair opens the message, and both
    /// are erased on rotation.
    #[test]
    fn long_term_keys_alone_cannot_derive_the_message_key() {
        let sender = Identity::from_seed([1u8; 32]);
        let recipient = Identity::from_seed([2u8; 32]);
        let prekey_secret = random_secret().unwrap();
        let prekey_pub = PublicKey::from(&prekey_secret).to_bytes();
        let ephemeral = random_secret().unwrap();

        let real =
            seal_key_fs(&sender, &ephemeral, &recipient.public_id(), &prekey_pub, 1).unwrap();

        // An attacker holding BOTH static secrets, but neither the ephemeral
        // nor the prekey secret, can only compute the static-static key.
        let compromised = sender.derive_static_key(&recipient.public_id()).unwrap();
        assert_ne!(real, compromised);

        // Even knowing the ephemeral *public* key does not help.
        let eph_pub = PublicKey::from(&ephemeral).to_bytes();
        let guess = dh(&sender.x25519_secret(), &PublicKey::from(eph_pub)).unwrap();
        assert_ne!(real, guess);
    }

    #[test]
    fn a_prekey_signature_binds_it_to_one_identity() {
        let alice = Identity::from_seed([1u8; 32]);
        let mallory = Identity::from_seed([2u8; 32]);
        let prekey = [9u8; 32];

        let sig = sign_prekey(&alice, 3, &prekey);
        assert!(verify_prekey(&alice.public_id(), 3, &prekey, &sig));

        // Mallory cannot publish a prekey as Alice.
        let forged = sign_prekey(&mallory, 3, &prekey);
        assert!(!verify_prekey(&alice.public_id(), 3, &prekey, &forged));

        // Nor can Alice's signature be lifted onto a different prekey...
        assert!(!verify_prekey(&alice.public_id(), 3, &[8u8; 32], &sig));
        // ...or a different generation.
        assert!(!verify_prekey(&alice.public_id(), 4, &prekey, &sig));
    }

    /// The two outputs must be independent of each other and of the input, or
    /// handing the message key to the AEAD would leak the chain.
    #[test]
    fn a_chain_step_produces_two_unrelated_keys() {
        let ck = [7u8; 32];
        let (mk, next) = sender_chain_step(&ck);
        assert_ne!(mk, next);
        assert_ne!(mk, ck);
        assert_ne!(next, ck);
        // Deterministic: both sides of a broadcast must land on the same key.
        assert_eq!(sender_chain_step(&ck), (mk, next));
    }

    /// Walking the chain must never revisit a message key — every broadcast
    /// gets its own, and a repeat would be nonce-reuse-shaped.
    #[test]
    fn a_chain_never_repeats_a_message_key() {
        let mut ck = [3u8; 32];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let (mk, next) = sender_chain_step(&ck);
            assert!(seen.insert(mk), "message key repeated within one chain");
            ck = next;
        }
    }

    #[test]
    fn aead_rejects_tampering() {
        let k = network_key(OPEN_CHANNEL);
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
