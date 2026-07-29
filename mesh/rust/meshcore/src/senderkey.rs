//! Sender keys — forward secrecy for broadcasts.
//!
//! A directed message can be forward secret because there are two parties and
//! therefore a Diffie-Hellman to do (see `prekey.rs`). A broadcast has no single
//! recipient, so the previous design fell back to a group key derived from a
//! constant: one stolen channel secret decrypted every broadcast ever recorded.
//!
//! This module replaces that with the sender-keys construction. Each node runs
//! **one outbound chain**, ratcheted once per broadcast:
//!
//! ```text
//!   ck0 ──step──▶ ck1 ──step──▶ ck2 ──step──▶ ck3   (erased as it advances)
//!    │             │             │             │
//!    ▼             ▼             ▼             ▼
//!   mk0           mk1           mk2           mk3    (one broadcast each)
//! ```
//!
//! ## The distribution is the whole design
//!
//! Ratcheting alone buys nothing if the chain key travels in the clear — or,
//! just as bad, sealed under the same static group key. Recording the beacon
//! that carried it would hand an attacker the chain, and the ratchet with it.
//!
//! So the chain key is **never broadcast**. It is delivered peer-to-peer in a
//! directed [`crate::frame::FrameKind::SenderKey`] frame, sealed with the
//! forward-secret prekey path. To read a recorded broadcast an attacker needs
//! the distribution frame, and to read *that* they need a prekey secret that was
//! zeroized minutes later. That is the chain of erasures the guarantee rests on.
//!
//! A consequence worth stating plainly: a peer learns a chain from wherever it
//! joined, so **broadcasts sent before a peer arrived are unreadable to them**.
//! That is correct group-messaging behaviour, not a bug — no retroactive access.
//!
//! ## Reordering, and the DoS this design avoids
//!
//! BLE reorders and drops. If a broadcast arrives at index 9 while we are at
//! index 6, we ratchet forward and keep the skipped message keys so 7 and 8 can
//! still be opened when they turn up. That cache is the one place forward
//! secrecy is deliberately weakened; it is bounded by [`SKIPPED_CAP`] and each
//! key is removed the moment it is used.
//!
//! Crucially, ratcheting is **not** committed until the AEAD verifies. Anyone
//! can put a frame on the air claiming `index = 9`; if that advanced our state
//! immediately, an attacker could skip us past the real sender's messages and
//! destroy the keys for them. [`InboundChain::derive`] computes against a copy
//! and returns a [`Derived`] the caller commits only after decryption succeeds.

use std::collections::{BTreeMap, HashMap, VecDeque};

use zeroize::Zeroize;

use crate::crypto::{self, PeerId};
use crate::CoreError;

/// Wire preamble on a sender-key broadcast: `chain_id` ‖ `index`, both u32 LE.
pub const PREAMBLE_LEN: usize = 8;

/// Body of a distribution frame: `chain_id` ‖ `index` ‖ chain key.
pub const DISTRIBUTION_LEN: usize = 4 + 4 + 32;

/// How far ahead of our position a single frame may claim to be. Bounds the
/// work an unauthenticated frame can make us do, and the size of one skip.
pub const MAX_SKIP: u32 = 64;

/// Ceiling on retained skipped message keys, per chain. Every entry is a key
/// still able to open a message, so this is a forward-secrecy budget as much as
/// a memory one.
pub const SKIPPED_CAP: usize = 128;

/// Chains retained per peer. A peer that restarts announces a fresh `chain_id`;
/// keeping one previous chain lets its last few in-flight broadcasts land, and
/// evicting beyond that erases the old chain key.
pub const CHAINS_PER_PEER: usize = 2;

// ---------------------------------------------------------------------------
// Outbound
// ---------------------------------------------------------------------------

/// Our own broadcast chain. One per session.
pub struct SenderChain {
    chain_id: u32,
    index: u32,
    key: [u8; 32],
}

impl SenderChain {
    pub fn new() -> Result<Self, CoreError> {
        Ok(Self {
            chain_id: crypto::random_u32()?,
            index: 0,
            key: crypto::random_32()?,
        })
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Take the next message key and advance, erasing the key that produced it.
    ///
    /// Returns `None` once the chain is exhausted — 4 billion broadcasts from
    /// one session, so in practice never, but wrapping would reuse keys.
    pub fn next_message_key(&mut self) -> Option<([u8; 32], u32)> {
        let index = self.index;
        let next_index = index.checked_add(1)?;
        let (mk, next) = crypto::sender_chain_step(&self.key);
        self.key.zeroize();
        self.key = next;
        self.index = next_index;
        Some((mk, index))
    }

    /// Serialise the chain *as it stands now* for a distribution frame.
    ///
    /// Deliberately the current key, not the original: a peer we meet at index
    /// 40 can read from 40 onward and nothing before it.
    pub fn distribution(&self) -> [u8; DISTRIBUTION_LEN] {
        let mut out = [0u8; DISTRIBUTION_LEN];
        out[0..4].copy_from_slice(&self.chain_id.to_le_bytes());
        out[4..8].copy_from_slice(&self.index.to_le_bytes());
        out[8..DISTRIBUTION_LEN].copy_from_slice(&self.key);
        out
    }
}

impl Drop for SenderChain {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for SenderChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never format the key.
        write!(
            f,
            "SenderChain(id {:08x}, index {})",
            self.chain_id, self.index
        )
    }
}

// ---------------------------------------------------------------------------
// Inbound
// ---------------------------------------------------------------------------

/// A peer's chain, as received in a distribution frame.
#[derive(Clone)]
pub struct Distribution {
    pub chain_id: u32,
    pub index: u32,
    key: [u8; 32],
}

impl Drop for Distribution {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl std::fmt::Debug for Distribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Distribution(id {:08x}, index {})",
            self.chain_id, self.index
        )
    }
}

/// Parse a distribution body. Length is the only validity check available here
/// — authenticity comes from the frame it arrived in, which was sealed to us.
pub fn parse_distribution(body: &[u8]) -> Option<Distribution> {
    if body.len() != DISTRIBUTION_LEN {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[8..DISTRIBUTION_LEN]);
    Some(Distribution {
        chain_id: u32::from_le_bytes(body[0..4].try_into().ok()?),
        index: u32::from_le_bytes(body[4..8].try_into().ok()?),
        key,
    })
}

/// A message key plus the state change that produced it, held back until the
/// AEAD says the frame was genuine. See the module note on the DoS this closes.
pub struct Derived {
    pub key: [u8; 32],
    /// Index the chain moves to. `None` when the key came from the skip cache,
    /// in which case the chain does not move at all.
    advance_to: Option<(u32, [u8; 32])>,
    newly_skipped: Vec<(u32, [u8; 32])>,
    consumed_from_cache: Option<u32>,
}

impl Drop for Derived {
    fn drop(&mut self) {
        self.key.zeroize();
        if let Some((_, chain)) = self.advance_to.as_mut() {
            chain.zeroize();
        }
        for (_, k) in self.newly_skipped.iter_mut() {
            k.zeroize();
        }
    }
}

/// One peer's chain state, receiving side.
pub struct InboundChain {
    index: u32,
    key: [u8; 32],
    /// Message keys for indices we jumped over, awaiting the late frames.
    skipped: BTreeMap<u32, [u8; 32]>,
}

impl Drop for InboundChain {
    fn drop(&mut self) {
        self.key.zeroize();
        for (_, k) in self.skipped.iter_mut() {
            k.zeroize();
        }
    }
}

impl std::fmt::Debug for InboundChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "InboundChain(index {}, {} skipped)",
            self.index,
            self.skipped.len()
        )
    }
}

impl InboundChain {
    fn from_distribution(d: &Distribution) -> Self {
        Self {
            index: d.index,
            key: d.key,
            skipped: BTreeMap::new(),
        }
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    #[cfg(test)]
    pub(crate) fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Compute the message key for `index` **without mutating anything**.
    ///
    /// `None` means we cannot open it: the index is behind us and its key has
    /// already been spent, or it is further ahead than [`MAX_SKIP`].
    pub fn derive(&self, index: u32) -> Option<Derived> {
        if index < self.index {
            // Behind us — only openable if we kept the key when we skipped it.
            let key = *self.skipped.get(&index)?;
            return Some(Derived {
                key,
                advance_to: None,
                newly_skipped: Vec::new(),
                consumed_from_cache: Some(index),
            });
        }

        let skip = index - self.index;
        if skip > MAX_SKIP {
            return None;
        }
        let next_index = index.checked_add(1)?;

        let mut chain = self.key;
        let mut newly_skipped = Vec::with_capacity(skip as usize);
        for i in self.index..index {
            let (mk, next) = crypto::sender_chain_step(&chain);
            newly_skipped.push((i, mk));
            chain.zeroize();
            chain = next;
        }
        let (key, next) = crypto::sender_chain_step(&chain);
        chain.zeroize();

        Some(Derived {
            key,
            advance_to: Some((next_index, next)),
            newly_skipped,
            consumed_from_cache: None,
        })
    }

    /// Apply a [`Derived`] once its frame has been authenticated. Erases the
    /// superseded chain key and the message key that was just spent.
    pub fn commit(&mut self, mut d: Derived) {
        if let Some(index) = d.consumed_from_cache.take() {
            if let Some(mut k) = self.skipped.remove(&index) {
                k.zeroize();
            }
        }
        for (i, k) in std::mem::take(&mut d.newly_skipped) {
            self.skipped.insert(i, k);
        }
        if let Some((next_index, next)) = d.advance_to.take() {
            self.key.zeroize();
            self.key = next;
            self.index = next_index;
        }
        // Oldest first: the further behind an index is, the less likely the
        // frame is still in flight, and the longer its key has been retained.
        while self.skipped.len() > SKIPPED_CAP {
            let Some(oldest) = self.skipped.keys().next().copied() else {
                break;
            };
            if let Some(mut k) = self.skipped.remove(&oldest) {
                k.zeroize();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Every peer chain we hold, newest first per peer.
#[derive(Debug, Default)]
pub struct ChainStore {
    peers: HashMap<PeerId, VecDeque<(u32, InboundChain)>>,
}

impl ChainStore {
    /// Install a distribution.
    ///
    /// A distribution for a chain we already hold is only accepted when it
    /// moves *forward*. A replayed older one would otherwise hand us back chain
    /// keys we had ratcheted past and erased — undoing the forward secrecy the
    /// ratchet exists to provide.
    pub fn install(&mut self, peer: PeerId, d: &Distribution) -> bool {
        let chains = self.peers.entry(peer).or_default();
        if let Some((_, existing)) = chains.iter_mut().find(|(id, _)| *id == d.chain_id) {
            if d.index <= existing.index {
                return false;
            }
            *existing = InboundChain::from_distribution(d);
            return true;
        }
        chains.push_front((d.chain_id, InboundChain::from_distribution(d)));
        // Eviction erases the dropped chain key; a peer that keeps restarting
        // cannot make us hold its history open.
        while chains.len() > CHAINS_PER_PEER {
            chains.pop_back();
        }
        true
    }

    pub fn get_mut(&mut self, peer: &PeerId, chain_id: u32) -> Option<&mut InboundChain> {
        self.peers
            .get_mut(peer)?
            .iter_mut()
            .find(|(id, _)| *id == chain_id)
            .map(|(_, chain)| chain)
    }

    #[cfg(test)]
    pub(crate) fn chain_ids(&self, peer: &PeerId) -> Vec<u32> {
        self.peers
            .get(peer)
            .map(|c| c.iter().map(|(id, _)| *id).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: PeerId = [9u8; 32];

    /// Drive a chain through `n` broadcasts and hand back what the receiver
    /// would see: (index, message key) pairs.
    fn broadcast_n(chain: &mut SenderChain, n: usize) -> Vec<(u32, [u8; 32])> {
        (0..n)
            .map(|_| {
                let (mk, i) = chain.next_message_key().unwrap();
                (i, mk)
            })
            .collect()
    }

    fn receiver(chain: &SenderChain) -> InboundChain {
        InboundChain::from_distribution(&parse_distribution(&chain.distribution()).unwrap())
    }

    #[test]
    fn a_distribution_round_trips() {
        let chain = SenderChain::new().unwrap();
        let d = parse_distribution(&chain.distribution()).unwrap();
        assert_eq!(d.chain_id, chain.chain_id());
        assert_eq!(d.index, 0);

        assert!(parse_distribution(&[]).is_none());
        assert!(parse_distribution(&[0u8; DISTRIBUTION_LEN - 1]).is_none());
        assert!(parse_distribution(&[0u8; DISTRIBUTION_LEN + 1]).is_none());
    }

    #[test]
    fn sender_and_receiver_agree_in_order() {
        let mut sender = SenderChain::new().unwrap();
        let mut rx = receiver(&sender);
        for (index, expected) in broadcast_n(&mut sender, 8) {
            let d = rx.derive(index).expect("in-order index must derive");
            assert_eq!(d.key, expected);
            rx.commit(d);
        }
        assert_eq!(rx.index(), 8);
        assert_eq!(rx.skipped_len(), 0, "in-order traffic caches nothing");
    }

    /// The reordering case BLE actually produces: a later frame arrives first,
    /// then the gap fills in.
    #[test]
    fn a_skipped_frame_can_still_be_opened_when_it_arrives() {
        let mut sender = SenderChain::new().unwrap();
        // Snapshot the chain before it advances — a peer that joins later would
        // legitimately start further along, which is a different test.
        let mut rx = receiver(&sender);
        let sent = broadcast_n(&mut sender, 5);

        // Index 4 lands first.
        let (i4, mk4) = sent[4];
        let d = rx.derive(i4).unwrap();
        assert_eq!(d.key, mk4);
        rx.commit(d);
        assert_eq!(rx.skipped_len(), 4, "0..=3 held for the stragglers");

        // Then the stragglers, out of order among themselves.
        for &(i, mk) in [&sent[1], &sent[3], &sent[0], &sent[2]] {
            let d = rx.derive(i).unwrap();
            assert_eq!(d.key, mk);
            rx.commit(d);
        }
        assert_eq!(rx.skipped_len(), 0, "each key is erased once it is used");
    }

    /// Spending a key must destroy it — otherwise the cache is a permanent
    /// archive of openable messages.
    #[test]
    fn a_used_skipped_key_cannot_be_used_twice() {
        let mut sender = SenderChain::new().unwrap();
        let mut rx = receiver(&sender);
        let sent = broadcast_n(&mut sender, 3);

        let d = rx.derive(sent[2].0).unwrap();
        rx.commit(d);
        let d = rx.derive(sent[0].0).unwrap();
        rx.commit(d);
        assert!(
            rx.derive(sent[0].0).is_none(),
            "a spent message key must be gone"
        );
    }

    #[test]
    fn an_index_beyond_max_skip_is_refused() {
        let sender = SenderChain::new().unwrap();
        let rx = receiver(&sender);
        assert!(rx.derive(MAX_SKIP).is_some(), "the boundary itself is fine");
        assert!(rx.derive(MAX_SKIP + 1).is_none());
        assert!(rx.derive(u32::MAX).is_none());
    }

    /// The reason `derive` and `commit` are separate. A forged frame — anyone
    /// can put one on the air — must not be able to ratchet us past the real
    /// sender's messages and destroy their keys.
    #[test]
    fn deriving_without_committing_leaves_the_chain_untouched() {
        let mut sender = SenderChain::new().unwrap();
        let mut rx = receiver(&sender);
        let sent = broadcast_n(&mut sender, 3);

        // An attacker claims index 60. We compute a key; the AEAD then fails,
        // so we never commit.
        let forged = rx.derive(60).unwrap();
        drop(forged);
        assert_eq!(rx.index(), 0, "an unverified frame must not move the chain");
        assert_eq!(rx.skipped_len(), 0);

        // The genuine messages still open.
        for (index, expected) in sent {
            let d = rx.derive(index).unwrap();
            assert_eq!(d.key, expected);
            rx.commit(d);
        }
    }

    #[test]
    fn the_skip_cache_is_bounded() {
        let mut sender = SenderChain::new().unwrap();
        let mut rx = receiver(&sender);
        // Jump MAX_SKIP at a time until well past the cap.
        let mut index = 0u32;
        while rx.skipped_len() < SKIPPED_CAP {
            index += MAX_SKIP;
            let d = rx.derive(index).unwrap();
            rx.commit(d);
        }
        index += MAX_SKIP;
        let d = rx.derive(index).unwrap();
        rx.commit(d);
        assert!(
            rx.skipped_len() <= SKIPPED_CAP,
            "skip cache grew to {}",
            rx.skipped_len()
        );
        let _ = &mut sender;
    }

    /// Rewinding would restore chain keys we had erased. A replayed old
    /// distribution must not be able to do that.
    #[test]
    fn a_distribution_cannot_rewind_a_chain() {
        let mut sender = SenderChain::new().unwrap();
        let early = parse_distribution(&sender.distribution()).unwrap();
        broadcast_n(&mut sender, 5);
        let later = parse_distribution(&sender.distribution()).unwrap();

        let mut store = ChainStore::default();
        assert!(store.install(PEER, &later));
        assert_eq!(store.get_mut(&PEER, later.chain_id).unwrap().index(), 5);

        assert!(!store.install(PEER, &early), "a replayed older SKDM");
        assert_eq!(
            store.get_mut(&PEER, later.chain_id).unwrap().index(),
            5,
            "chain must not have been rewound"
        );
    }

    #[test]
    fn a_restarting_peer_does_not_accumulate_chains() {
        let mut store = ChainStore::default();
        let mut ids = Vec::new();
        for _ in 0..CHAINS_PER_PEER + 3 {
            let chain = SenderChain::new().unwrap();
            let d = parse_distribution(&chain.distribution()).unwrap();
            ids.push(d.chain_id);
            store.install(PEER, &d);
        }
        let held = store.chain_ids(&PEER);
        assert_eq!(held.len(), CHAINS_PER_PEER);
        // Newest first, oldest evicted.
        assert_eq!(held[0], *ids.last().unwrap());
        assert!(store.get_mut(&PEER, ids[0]).is_none());
    }

    #[test]
    fn an_unknown_chain_is_not_openable() {
        let mut store = ChainStore::default();
        assert!(store.get_mut(&PEER, 1234).is_none());
        let chain = SenderChain::new().unwrap();
        let d = parse_distribution(&chain.distribution()).unwrap();
        store.install(PEER, &d);
        assert!(store.get_mut(&PEER, d.chain_id.wrapping_add(1)).is_none());
        assert!(store.get_mut(&[8u8; 32], d.chain_id).is_none());
    }
}
