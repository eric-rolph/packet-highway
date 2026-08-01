//! Rotating signed prekeys — the thing that makes directed messages forward
//! secret without a round trip.
//!
//! Each node keeps a small ring: one **current** prekey, published in every
//! beacon, plus a few **retired** ones kept only long enough for messages that
//! were already in flight when rotation happened.
//!
//! ```text
//!   gen 7  current   <- advertised, everyone sends to this
//!   gen 6  retired   \
//!   gen 5  retired    > still decryptable; in-flight grace
//!   gen 4  retired   /
//!   gen 3  dropped   <- secret zeroized: these messages are now unrecoverable
//! ```
//!
//! **Dropping is the feature.** Forward secrecy is not delivered by the key
//! agreement alone — it is delivered by the secret ceasing to exist. `x25519`'s
//! `StaticSecret` zeroizes on drop, so evicting the back of the ring is what
//! actually makes old traffic unrecoverable.
//!
//! ## Choosing the interval and depth
//!
//! The window during which a stolen ring exposes traffic is
//! `ROTATE_INTERVAL_MS * (RETAINED + 1)` — with the values below, four minutes.
//! Shrinking either tightens that but risks dropping a prekey while a slow
//! multi-hop message is still crossing the mesh, and the sender would have to
//! fall back and retry. The outbox deadline is 120s, so retention has to exceed
//! it or a retried message could arrive addressed to a prekey that no longer
//! exists; `RETAINED * ROTATE_INTERVAL_MS = 180s` leaves a margin over that.
//! The `retention_outlives_the_outbox_deadline` test pins the relationship so
//! nobody tunes one constant without the other.

use std::collections::VecDeque;

use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{self, Identity, PeerId, SIGNATURE_LEN};
use crate::CoreError;

/// How often the current prekey is replaced.
pub const ROTATE_INTERVAL_MS: u64 = 60_000;
/// How many superseded prekeys stay decryptable.
pub const RETAINED: usize = 3;

/// Serialised length of a bundle: generation ‖ public ‖ signature.
pub const BUNDLE_LEN: usize = 4 + 32 + SIGNATURE_LEN;

/// One prekey. The secret is zeroized when this is dropped.
pub struct PrekeyPair {
    pub generation: u32,
    pub public: [u8; 32],
    secret: StaticSecret,
}

impl PrekeyPair {
    fn generate(generation: u32) -> Result<Self, CoreError> {
        let secret = crypto::random_secret()?;
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self {
            generation,
            public,
            secret,
        })
    }

    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

impl std::fmt::Debug for PrekeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PrekeyPair(gen {}, {})",
            self.generation,
            crypto::hex16(&self.public)
        )
    }
}

/// A peer's advertised prekey, after its signature has been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerPrekey {
    pub generation: u32,
    pub public: [u8; 32],
}

/// Our own ring of prekeys.
#[derive(Debug)]
pub struct PrekeyRing {
    current: PrekeyPair,
    retired: VecDeque<PrekeyPair>,
    rotated_at_ms: u64,
    next_generation: u32,
}

impl PrekeyRing {
    pub fn new(now_ms: u64) -> Result<Self, CoreError> {
        Ok(Self {
            current: PrekeyPair::generate(0)?,
            retired: VecDeque::with_capacity(RETAINED),
            rotated_at_ms: now_ms,
            next_generation: 1,
        })
    }

    pub fn current(&self) -> &PrekeyPair {
        &self.current
    }

    /// Look up a prekey by the generation a sender addressed. `None` means it
    /// has been rotated out — the message is undecryptable, by design.
    pub fn get(&self, generation: u32) -> Option<&PrekeyPair> {
        if self.current.generation == generation {
            return Some(&self.current);
        }
        self.retired.iter().find(|p| p.generation == generation)
    }

    /// Rotate if the interval has elapsed. Returns whether it did, so the caller
    /// knows to re-publish its beacon.
    pub fn rotate_if_due(&mut self, now_ms: u64) -> Result<bool, CoreError> {
        if now_ms.saturating_sub(self.rotated_at_ms) < ROTATE_INTERVAL_MS {
            return Ok(false);
        }
        self.rotate(now_ms)?;
        Ok(true)
    }

    pub fn rotate(&mut self, now_ms: u64) -> Result<(), CoreError> {
        let fresh = PrekeyPair::generate(self.next_generation)?;
        self.next_generation = self.next_generation.wrapping_add(1);
        let superseded = std::mem::replace(&mut self.current, fresh);
        self.retired.push_front(superseded);
        // The eviction here is the forward-secrecy event: the popped pair's
        // StaticSecret is zeroized on drop and that traffic becomes
        // unrecoverable to anyone, including us.
        while self.retired.len() > RETAINED {
            self.retired.pop_back();
        }
        self.rotated_at_ms = now_ms;
        Ok(())
    }

    /// Serialise the current prekey plus its signature, for the beacon body.
    pub fn bundle(&self, identity: &Identity) -> Vec<u8> {
        let sig = crypto::sign_prekey(identity, self.current.generation, &self.current.public);
        let mut out = Vec::with_capacity(BUNDLE_LEN);
        out.extend_from_slice(&self.current.generation.to_le_bytes());
        out.extend_from_slice(&self.current.public);
        out.extend_from_slice(&sig);
        out
    }

    #[cfg(test)]
    pub(crate) fn retired_generations(&self) -> Vec<u32> {
        self.retired.iter().map(|p| p.generation).collect()
    }
}

/// Parse and **verify** a peer's advertised bundle.
///
/// Returns `None` for anything malformed or incorrectly signed. Verification is
/// not optional: beacons are sealed with the shared network key, so without a
/// signature any member could advertise a prekey under another member's id and
/// receive their directed mail.
pub fn parse_bundle(peer: &PeerId, body: &[u8]) -> Option<PeerPrekey> {
    if body.len() != BUNDLE_LEN {
        return None;
    }
    let generation = u32::from_le_bytes(body[0..4].try_into().ok()?);
    let mut public = [0u8; 32];
    public.copy_from_slice(&body[4..36]);
    let mut signature = [0u8; SIGNATURE_LEN];
    signature.copy_from_slice(&body[36..BUNDLE_LEN]);

    crypto::verify_prekey(peer, generation, &public, &signature)
        .then_some(PeerPrekey { generation, public })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_current_prekey_is_always_retrievable() {
        let ring = PrekeyRing::new(0).unwrap();
        let gen = ring.current().generation;
        assert!(ring.get(gen).is_some());
        assert!(ring.get(gen + 1).is_none());
    }

    #[test]
    fn rotation_keeps_recent_generations_decryptable() {
        let mut ring = PrekeyRing::new(0).unwrap();
        let gen0 = ring.current().generation;
        ring.rotate(1).unwrap();
        assert_ne!(ring.current().generation, gen0);
        assert!(
            ring.get(gen0).is_some(),
            "a just-rotated prekey must still open in-flight mail"
        );
    }

    #[test]
    fn rotating_past_the_retention_depth_destroys_the_old_secret() {
        let mut ring = PrekeyRing::new(0).unwrap();
        let gen0 = ring.current().generation;
        for i in 1..=(RETAINED as u64 + 1) {
            ring.rotate(i).unwrap();
        }
        assert!(
            ring.get(gen0).is_none(),
            "generation {gen0} must be unrecoverable after {} rotations",
            RETAINED + 1
        );
        assert_eq!(ring.retired_generations().len(), RETAINED);
    }

    #[test]
    fn rotation_respects_the_interval() {
        let mut ring = PrekeyRing::new(1_000).unwrap();
        assert!(!ring.rotate_if_due(1_000 + ROTATE_INTERVAL_MS - 1).unwrap());
        assert!(ring.rotate_if_due(1_000 + ROTATE_INTERVAL_MS).unwrap());
        // The clock restarts from the rotation, not from construction.
        assert!(!ring.rotate_if_due(1_000 + ROTATE_INTERVAL_MS + 1).unwrap());
    }

    /// A retried message can be up to the outbox deadline old when it lands. If
    /// retention were shorter, the recipient would have dropped the prekey and
    /// the retry could never succeed.
    #[test]
    fn retention_outlives_the_outbox_deadline() {
        let retention_ms = ROTATE_INTERVAL_MS * RETAINED as u64;
        assert!(
            retention_ms > crate::outbox::DEADLINE_MS,
            "prekey retention {retention_ms}ms must exceed the outbox deadline {}ms",
            crate::outbox::DEADLINE_MS
        );
    }

    #[test]
    fn a_bundle_round_trips_through_verification() {
        let id = Identity::from_seed([1u8; 32]);
        let ring = PrekeyRing::new(0).unwrap();
        let body = ring.bundle(&id);
        assert_eq!(body.len(), BUNDLE_LEN);

        let parsed = parse_bundle(&id.public_id(), &body).expect("own bundle must verify");
        assert_eq!(parsed.generation, ring.current().generation);
        assert_eq!(parsed.public, ring.current().public);
    }

    #[test]
    fn a_bundle_attributed_to_the_wrong_peer_is_refused() {
        let alice = Identity::from_seed([1u8; 32]);
        let bob = Identity::from_seed([2u8; 32]);
        let ring = PrekeyRing::new(0).unwrap();
        let body = ring.bundle(&alice);
        // The exact impersonation the signature exists to stop.
        assert!(parse_bundle(&bob.public_id(), &body).is_none());
    }

    #[test]
    fn a_tampered_bundle_is_refused() {
        let id = Identity::from_seed([1u8; 32]);
        let ring = PrekeyRing::new(0).unwrap();
        let good = ring.bundle(&id);

        for offset in [0usize, 10, 40, BUNDLE_LEN - 1] {
            let mut bad = good.clone();
            bad[offset] ^= 0xff;
            assert!(
                parse_bundle(&id.public_id(), &bad).is_none(),
                "flipping byte {offset} of a bundle went undetected"
            );
        }
        // Wrong length, including empty and truncated.
        assert!(parse_bundle(&id.public_id(), &[]).is_none());
        assert!(parse_bundle(&id.public_id(), &good[..BUNDLE_LEN - 1]).is_none());
    }
}
