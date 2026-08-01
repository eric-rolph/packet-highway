//! Relay-side store-and-forward: carrying someone else's mail.
//!
//! `outbox.rs` makes a node retry its *own* undelivered messages. This module
//! does the other half — the part that makes a mesh delay-tolerant rather than
//! merely multi-hop.
//!
//! Today a directed frame for a peer who is out of range gets re-flooded once
//! and then forgotten. If nobody in range can reach the recipient at that
//! instant, the message is gone, even though a node that saw it may well meet
//! the recipient thirty seconds later. Holding the frame and re-flooding it on
//! discovery turns "everyone had to be connected at once" into "the message
//! travels with whoever is going that way".
//!
//! ## What is held, and what is not
//!
//! Only **directed frames for a peer we cannot currently see**. Three exclusions,
//! each for its own reason:
//!
//! * **Broadcasts** are already repeated by every node that hears them; caching
//!   one would be a second, slower flood of traffic that already went everywhere.
//! * **Frames addressed to us** are ours to handle, not to carry.
//! * **Frames for a peer already in our table** were just flooded to a peer who
//!   is right there. Caching those fills the buffer with mail that has already
//!   arrived, crowding out the frames that actually need carrying.
//!
//! The relay cannot read any of it — this is ciphertext it has no key for, held
//! only because it knows the 32-byte recipient id from the header.
//!
//! ## Why each frame is forwarded once
//!
//! [`take_for_peer`](RelayCache::take_for_peer) **removes** what it returns. In a
//! crowded room every relay that saw a frame is holding a copy, so a peer walking
//! back into range would otherwise draw one flood per relay per discovery. The
//! recipient's msg_id dedup would swallow the duplicates, but the air time is
//! already spent by then. One shot per relay, then the entry is gone.
//!
//! ## Bounds
//!
//! Two of them, and both matter. [`CAPACITY`] stops a hostile flooder from
//! turning every relay into its memory; [`TTL_MS`] stops a relay delivering a
//! message the *sender* has already given up on. That second one is a coherence
//! property, not a housekeeping detail: `outbox::DEADLINE_MS` is when the sender
//! tells its user the message expired, and a relay handing it over after that
//! would contradict a receipt the user already saw. A `const` assertion below
//! makes tuning them apart a build failure rather than a field report.

use std::collections::VecDeque;

use crate::crypto::PeerId;

/// Frames held for absent peers. Each is at most `frame::MAX_FRAME` bytes, so
/// this bounds the cache at roughly 64 KB.
pub const CAPACITY: usize = 128;

/// How long a carried frame stays worth delivering.
///
/// Tuned independently of `outbox::DEADLINE_MS` — a deployment may well want
/// relays to give up sooner than senders do — but it must never exceed it, for
/// the coherence reason in the module note. The bound is a **compile-time**
/// assertion below rather than a test: deriving one from the other would make
/// the check tautological, and a unit test would only catch it after a build.
pub const TTL_MS: u64 = 120_000;

const _: () = assert!(
    TTL_MS <= crate::outbox::DEADLINE_MS,
    "a relay must give up before the sender reports the message expired"
);

struct Cached {
    recipient: PeerId,
    msg_id: [u8; 16],
    wire: Vec<u8>,
    cached_at_ms: u64,
}

/// Frames this node is carrying on behalf of peers it cannot currently see.
#[derive(Default)]
pub struct RelayCache {
    entries: VecDeque<Cached>,
}

impl std::fmt::Debug for RelayCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format the frames; they are other people's ciphertext.
        write!(f, "RelayCache({} carried)", self.entries.len())
    }
}

impl RelayCache {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, msg_id: &[u8; 16]) -> bool {
        self.entries.iter().any(|e| e.msg_id == *msg_id)
    }

    /// Hold a frame for an absent peer. Returns false if it was already held —
    /// the same frame reaches us from several neighbours in a flood, and storing
    /// each arrival would let one message evict the rest of the cache.
    pub fn store(
        &mut self,
        recipient: PeerId,
        msg_id: [u8; 16],
        wire: Vec<u8>,
        now_ms: u64,
    ) -> bool {
        if self.contains(&msg_id) {
            return false;
        }
        if self.entries.len() >= CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Cached {
            recipient,
            msg_id,
            wire,
            cached_at_ms: now_ms,
        });
        true
    }

    /// Take everything held for `peer`, removing it. See the module note on why
    /// this is destructive.
    pub fn take_for_peer(&mut self, peer: &PeerId) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut kept = VecDeque::with_capacity(self.entries.len());
        for entry in std::mem::take(&mut self.entries) {
            if entry.recipient == *peer {
                out.push(entry.wire);
            } else {
                kept.push_back(entry);
            }
        }
        self.entries = kept;
        out
    }

    /// Drop frames older than [`TTL_MS`]. Returns how many were dropped.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|e| now_ms.saturating_sub(e.cached_at_ms) < TTL_MS);
        before - self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: PeerId = [1u8; 32];
    const BOB: PeerId = [2u8; 32];

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn a_carried_frame_comes_back_when_its_recipient_appears() {
        let mut c = RelayCache::default();
        assert!(c.store(ALICE, id(1), vec![0xAA], 0));
        assert!(c.store(BOB, id(2), vec![0xBB], 0));
        assert_eq!(c.len(), 2);

        assert_eq!(c.take_for_peer(&ALICE), vec![vec![0xAA]]);
        assert_eq!(c.len(), 1, "only Alice's mail leaves");
        assert_eq!(c.take_for_peer(&BOB), vec![vec![0xBB]]);
        assert!(c.is_empty());
    }

    /// In a crowded room every relay holds a copy. Handing the same frame over
    /// on every future discovery would spend air the recipient's dedup then
    /// throws away.
    #[test]
    fn taking_is_destructive() {
        let mut c = RelayCache::default();
        c.store(ALICE, id(1), vec![1], 0);
        assert_eq!(c.take_for_peer(&ALICE).len(), 1);
        assert!(
            c.take_for_peer(&ALICE).is_empty(),
            "a carried frame is forwarded once"
        );
    }

    /// The same frame arrives from several neighbours during a flood. Storing
    /// each copy would let one message evict everything else we are carrying.
    #[test]
    fn the_same_frame_is_only_held_once() {
        let mut c = RelayCache::default();
        assert!(c.store(ALICE, id(1), vec![1], 0));
        assert!(!c.store(ALICE, id(1), vec![1], 5));
        assert!(
            !c.store(BOB, id(1), vec![9], 9),
            "keyed on msg_id, not peer"
        );
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn the_cache_is_bounded_and_evicts_oldest_first() {
        let mut c = RelayCache::default();
        for n in 0..CAPACITY {
            let mut m = [0u8; 16];
            m[..8].copy_from_slice(&(n as u64).to_le_bytes());
            c.store(ALICE, m, vec![n as u8], n as u64);
        }
        assert_eq!(c.len(), CAPACITY);

        let mut newest = [0xFFu8; 16];
        newest[0] = 0xAB;
        c.store(ALICE, newest, vec![0], 9_999);
        assert_eq!(c.len(), CAPACITY, "a flooder cannot grow us without limit");

        let mut oldest = [0u8; 16];
        oldest[..8].copy_from_slice(&0u64.to_le_bytes());
        assert!(!c.contains(&oldest), "oldest goes first");
        assert!(c.contains(&newest));
    }

    #[test]
    fn stale_frames_are_dropped() {
        let mut c = RelayCache::default();
        c.store(ALICE, id(1), vec![1], 0);
        c.store(ALICE, id(2), vec![2], TTL_MS);

        assert_eq!(c.expire(TTL_MS - 1), 0, "nothing is stale yet");
        assert_eq!(c.expire(TTL_MS), 1, "the first one is now too old");
        assert_eq!(c.len(), 1);
        assert!(c.contains(&id(2)));
    }
}
