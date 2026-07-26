//! Store-and-forward for directed messages.
//!
//! A flood-routed mesh gives you no delivery signal: you put a frame on the air
//! and hope. This module adds the missing half — the recipient acks, and until
//! that ack arrives the sender keeps the frame and retries.
//!
//! ## What is and is not retried
//!
//! Only **directed** messages. A broadcast has no single recipient to ack it,
//! so retrying one would just be duplicate traffic; broadcasts are reported
//! delivered as soon as they are on the air.
//!
//! ## Backoff
//!
//! Exponential from 1s, capped, with a hard deadline. The cap matters more than
//! the growth rate here: BLE advertisement windows are short and a peer that is
//! going to come back usually does so within a minute, so an uncapped backoff
//! would sit idle exactly when the peer reappears. The peer-discovery hook
//! below is the real accelerator — a retry fires immediately when the recipient
//! shows up, rather than waiting out the timer.

use std::collections::HashMap;

use crate::crypto::PeerId;

/// First retry delay. Doubles each attempt.
pub const BASE_BACKOFF_MS: u64 = 1_000;
/// Never wait longer than this between attempts.
pub const MAX_BACKOFF_MS: u64 = 15_000;
/// Give up after this long and report the message expired.
pub const DEADLINE_MS: u64 = 120_000;
/// Bound on queued messages. Oldest is dropped when full, so a peer that never
/// comes back cannot grow the queue without limit.
pub const CAPACITY: usize = 256;

#[derive(Debug, Clone)]
pub struct Pending {
    pub msg_id: [u8; 16],
    pub recipient: PeerId,
    /// The sealed frame, kept verbatim so a retry is a memcpy, not a re-seal.
    /// Re-sealing would burn a fresh counter per attempt and make the
    /// recipient's replay window see a gap for every retry.
    pub wire: Vec<u8>,
    pub attempts: u32,
    pub queued_at_ms: u64,
    pub next_attempt_ms: u64,
}

impl Pending {
    fn backoff(attempts: u32) -> u64 {
        BASE_BACKOFF_MS
            .saturating_mul(1u64 << attempts.min(8))
            .min(MAX_BACKOFF_MS)
    }
}

/// What the worker should do with a pending entry on this tick.
#[derive(Debug, PartialEq, Eq)]
pub enum Due {
    Retry(Vec<u8>),
    Expired,
}

/// A due entry, carrying the recipient so the caller does not have to re-parse
/// the frame (or look the entry back up after it has been removed).
#[derive(Debug, PartialEq, Eq)]
pub struct DueItem {
    pub msg_id: [u8; 16],
    pub recipient: PeerId,
    pub due: Due,
}

#[derive(Debug, Default)]
pub struct Outbox {
    pending: HashMap<[u8; 16], Pending>,
    /// Insertion order, for evicting the oldest at capacity.
    order: Vec<[u8; 16]>,
}

impl Outbox {
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn contains(&self, msg_id: &[u8; 16]) -> bool {
        self.pending.contains_key(msg_id)
    }

    /// Queue a directed frame. Returns the msg_id evicted to make room, if any.
    pub fn push(
        &mut self,
        msg_id: [u8; 16],
        recipient: PeerId,
        wire: Vec<u8>,
        now_ms: u64,
    ) -> Option<[u8; 16]> {
        // Re-queuing an id already present would leave a stale duplicate in
        // `order` and make `len()` disagree with the map. Random 16-byte ids
        // make this vanishingly unlikely, but "vanishingly unlikely" is not a
        // reason to leave a data structure that can go inconsistent.
        self.remove(&msg_id);

        let evicted = if self.pending.len() >= CAPACITY {
            let oldest = self.order.first().copied();
            if let Some(id) = oldest {
                self.remove(&id);
            }
            oldest
        } else {
            None
        };

        self.pending.insert(
            msg_id,
            Pending {
                msg_id,
                recipient,
                wire,
                attempts: 0,
                queued_at_ms: now_ms,
                next_attempt_ms: now_ms + Pending::backoff(0),
            },
        );
        self.order.push(msg_id);
        evicted
    }

    /// An ack arrived. Returns true if it matched something we were retrying —
    /// false for a duplicate or unsolicited ack, which is not an error.
    pub fn ack(&mut self, msg_id: &[u8; 16]) -> bool {
        self.remove(msg_id)
    }

    /// Everything due at `now_ms`: frames to retransmit, and messages that hit
    /// their deadline. Expired entries are removed as part of this call.
    pub fn take_due(&mut self, now_ms: u64) -> Vec<DueItem> {
        let mut out = Vec::new();
        let mut expired = Vec::new();

        for p in self.pending.values_mut() {
            if now_ms.saturating_sub(p.queued_at_ms) >= DEADLINE_MS {
                expired.push(p.msg_id);
                out.push(DueItem {
                    msg_id: p.msg_id,
                    recipient: p.recipient,
                    due: Due::Expired,
                });
            } else if now_ms >= p.next_attempt_ms {
                p.attempts += 1;
                p.next_attempt_ms = now_ms + Pending::backoff(p.attempts);
                out.push(DueItem {
                    msg_id: p.msg_id,
                    recipient: p.recipient,
                    due: Due::Retry(p.wire.clone()),
                });
            }
        }

        for id in expired {
            self.remove(&id);
        }
        out
    }

    /// A peer just appeared. Make everything queued for them due immediately —
    /// this is what turns "eventually retried" into "delivered the moment they
    /// walk into range", which is the whole point of a mesh messenger.
    pub fn wake_for_peer(&mut self, peer: &PeerId, now_ms: u64) -> usize {
        let mut woken = 0;
        for p in self.pending.values_mut() {
            if p.recipient == *peer && p.next_attempt_ms > now_ms {
                p.next_attempt_ms = now_ms;
                woken += 1;
            }
        }
        woken
    }

    fn remove(&mut self, msg_id: &[u8; 16]) -> bool {
        if self.pending.remove(msg_id).is_some() {
            self.order.retain(|id| id != msg_id);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: PeerId = [7u8; 32];

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn a_queued_message_retries_on_backoff_then_expires() {
        let mut o = Outbox::default();
        o.push(id(1), PEER, vec![0xAA], 0);

        // Nothing due before the first backoff elapses.
        assert!(o.take_due(BASE_BACKOFF_MS - 1).is_empty());

        let due = o.take_due(BASE_BACKOFF_MS);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].due, Due::Retry(vec![0xAA]));
        assert_eq!(due[0].recipient, PEER);

        // Second attempt waits twice as long.
        assert!(o.take_due(BASE_BACKOFF_MS + 1).is_empty());

        let due = o.take_due(DEADLINE_MS);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].due, Due::Expired);
        assert!(o.is_empty(), "an expired message must be dropped");
    }

    #[test]
    fn backoff_grows_then_caps() {
        assert_eq!(Pending::backoff(0), BASE_BACKOFF_MS);
        assert_eq!(Pending::backoff(1), 2 * BASE_BACKOFF_MS);
        assert_eq!(Pending::backoff(2), 4 * BASE_BACKOFF_MS);
        assert_eq!(
            Pending::backoff(60),
            MAX_BACKOFF_MS,
            "must not overflow the shift"
        );
    }

    #[test]
    fn an_ack_removes_the_pending_message() {
        let mut o = Outbox::default();
        o.push(id(1), PEER, vec![1], 0);
        assert!(o.ack(&id(1)));
        assert!(o.is_empty());
        // A duplicate ack is normal on a lossy radio, not an error.
        assert!(!o.ack(&id(1)));
    }

    #[test]
    fn peer_discovery_makes_queued_messages_due_immediately() {
        let mut o = Outbox::default();
        o.push(id(1), PEER, vec![1], 0);
        o.push(id(2), [8u8; 32], vec![2], 0);

        assert!(o.take_due(10).is_empty(), "backoff has not elapsed");
        assert_eq!(o.wake_for_peer(&PEER, 10), 1, "only PEER's message wakes");

        let due = o.take_due(10);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].msg_id, id(1));
    }

    /// Distinct ids for more than 256 entries — a single repeated byte would
    /// collide once `n` exceeds `u8::MAX`.
    fn nth_id(n: usize) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(n as u64).to_le_bytes());
        id
    }

    #[test]
    fn the_queue_is_bounded_and_evicts_oldest_first() {
        let mut o = Outbox::default();
        for n in 0..CAPACITY {
            o.push(nth_id(n), PEER, vec![], 0);
        }
        assert_eq!(o.len(), CAPACITY);

        let evicted = o.push(nth_id(9999), PEER, vec![], 0);
        assert_eq!(evicted, Some(nth_id(0)), "oldest goes first");
        assert_eq!(o.len(), CAPACITY);
        assert!(o.contains(&nth_id(9999)));
        assert!(!o.contains(&nth_id(0)));
    }

    #[test]
    fn requeuing_an_existing_id_does_not_corrupt_the_order_list() {
        let mut o = Outbox::default();
        o.push(id(1), PEER, vec![1], 0);
        o.push(id(1), PEER, vec![2], 0);
        assert_eq!(o.len(), 1, "len must track the map, not the order list");

        // One ack must fully clear it — a duplicated order entry would leave
        // a phantom behind.
        assert!(o.ack(&id(1)));
        assert!(o.is_empty());
        assert!(o.take_due(u64::MAX / 2).is_empty());
    }

    #[test]
    fn retry_reuses_the_original_frame_bytes() {
        // Re-sealing on retry would consume a fresh counter each time and punch
        // holes in the recipient's replay window.
        let mut o = Outbox::default();
        o.push(id(1), PEER, vec![1, 2, 3], 0);
        let first = o.take_due(BASE_BACKOFF_MS);
        let second = o.take_due(BASE_BACKOFF_MS * 10);
        assert_eq!(first[0].due, Due::Retry(vec![1, 2, 3]));
        assert_eq!(second[0].due, Due::Retry(vec![1, 2, 3]));
    }
}
