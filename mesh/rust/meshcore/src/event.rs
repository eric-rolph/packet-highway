//! Events pushed from Rust up to JS, and their binary wire format.
//!
//! ## Why binary and not JSON
//!
//! Every event crosses three boundaries: Rust → C → C++/JSI → JS. JSON costs a
//! serialize in Rust, a `String` copy in C++, and a `JSON.parse` on the JS
//! thread — for a BLE payload that is already bytes. Instead each event
//! serialises into **one contiguous `Vec<u8>`**, that `Vec`'s allocation is
//! *moved* (not copied) into a JSI `ArrayBuffer`, and JS reads it with a
//! `DataView`. Cost across the whole path: one allocation, zero copies of the
//! message body. See `js/src/events.ts` for the mirror decoder.
//!
//! The layout is versioned by `MeshCore::ABI_VERSION`; the native installer
//! refuses to bind a library whose version does not match the JS package.

use crate::crypto::PeerId;

pub const EVENT_HEADER_LEN: usize = 16;

// Keep these in lockstep with `js/src/events.ts` and `MeshEventKind` in the
// generated C header.
pub const KIND_PEER_DISCOVERED: u8 = 1;
pub const KIND_PEER_LOST: u8 = 2;
pub const KIND_MESSAGE_RECEIVED: u8 = 3;
pub const KIND_MESSAGE_DELIVERED: u8 = 4;
pub const KIND_TRANSPORT_STATE: u8 = 5;
pub const KIND_ERROR: u8 = 6;

#[derive(Debug, Clone)]
pub struct Event {
    pub seq: u32,
    pub ts_ms: u64,
    pub kind: EventKind,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    PeerDiscovered { peer: PeerId, nickname: String, rssi: i8, hops: u8 },
    PeerLost { peer: PeerId },
    MessageReceived { sender: PeerId, msg_id: [u8; 16], ttl: u8, hops: u8, rssi: i8, body: Vec<u8> },
    MessageDelivered { msg_id: [u8; 16], direct: bool },
    TransportState { running: bool },
    Error { message: String },
}

impl Event {
    fn new(seq: u32, kind: EventKind) -> Self {
        Self { seq, ts_ms: crate::now_ms(), kind }
    }

    pub fn peer_discovered(seq: u32, peer: PeerId, nickname: &str, rssi: i8, hops: u8) -> Self {
        Self::new(seq, EventKind::PeerDiscovered { peer, nickname: nickname.to_owned(), rssi, hops })
    }

    pub fn peer_lost(seq: u32, peer: PeerId) -> Self {
        Self::new(seq, EventKind::PeerLost { peer })
    }

    pub fn message_received(
        seq: u32,
        sender: PeerId,
        msg_id: [u8; 16],
        ttl: u8,
        hops: u8,
        rssi: i8,
        body: Vec<u8>,
    ) -> Self {
        Self::new(seq, EventKind::MessageReceived { sender, msg_id, ttl, hops, rssi, body })
    }

    pub fn message_delivered(seq: u32, msg_id: [u8; 16], direct: bool) -> Self {
        Self::new(seq, EventKind::MessageDelivered { msg_id, direct })
    }

    pub fn transport_state(seq: u32, running: bool) -> Self {
        Self::new(seq, EventKind::TransportState { running })
    }

    pub fn error(seq: u32, message: &str) -> Self {
        Self::new(seq, EventKind::Error { message: message.to_owned() })
    }

    pub fn kind_tag(&self) -> u8 {
        match self.kind {
            EventKind::PeerDiscovered { .. } => KIND_PEER_DISCOVERED,
            EventKind::PeerLost { .. } => KIND_PEER_LOST,
            EventKind::MessageReceived { .. } => KIND_MESSAGE_RECEIVED,
            EventKind::MessageDelivered { .. } => KIND_MESSAGE_DELIVERED,
            EventKind::TransportState { .. } => KIND_TRANSPORT_STATE,
            EventKind::Error { .. } => KIND_ERROR,
        }
    }

    /// Serialise into exactly one heap allocation, sized up front. The returned
    /// `Vec` is what gets handed to the FFI layer, which transfers ownership of
    /// its buffer to JS without copying.
    pub fn to_wire(&self) -> Vec<u8> {
        let body_hint = match &self.kind {
            EventKind::PeerDiscovered { nickname, .. } => 32 + 2 + 4 + nickname.len(),
            EventKind::PeerLost { .. } => 32,
            EventKind::MessageReceived { body, .. } => 32 + 16 + 4 + 4 + body.len(),
            EventKind::MessageDelivered { .. } => 16 + 4,
            EventKind::TransportState { .. } => 4,
            EventKind::Error { message } => 4 + message.len(),
        };
        let mut w = Vec::with_capacity(EVENT_HEADER_LEN + body_hint);

        w.push(crate::ABI_VERSION as u8);
        w.push(self.kind_tag());
        w.extend_from_slice(&0u16.to_le_bytes()); // flags, reserved
        w.extend_from_slice(&self.seq.to_le_bytes());
        w.extend_from_slice(&self.ts_ms.to_le_bytes());
        debug_assert_eq!(w.len(), EVENT_HEADER_LEN);

        match &self.kind {
            EventKind::PeerDiscovered { peer, nickname, rssi, hops } => {
                w.extend_from_slice(peer);
                w.push(*rssi as u8);
                w.push(*hops);
                put_bytes(&mut w, nickname.as_bytes());
            }
            EventKind::PeerLost { peer } => w.extend_from_slice(peer),
            EventKind::MessageReceived { sender, msg_id, ttl, hops, rssi, body } => {
                w.extend_from_slice(sender);
                w.extend_from_slice(msg_id);
                w.push(*ttl);
                w.push(*hops);
                w.push(*rssi as u8);
                w.push(0); // pad to keep the following u32 4-byte aligned
                put_bytes(&mut w, body);
            }
            EventKind::MessageDelivered { msg_id, direct } => {
                w.extend_from_slice(msg_id);
                w.push(*direct as u8);
                w.extend_from_slice(&[0u8; 3]);
            }
            EventKind::TransportState { running } => {
                w.push(*running as u8);
                w.extend_from_slice(&[0u8; 3]);
            }
            EventKind::Error { message } => put_bytes(&mut w, message.as_bytes()),
        }
        w
    }
}

#[inline]
fn put_bytes(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(&(b.len() as u32).to_le_bytes());
    w.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_received_layout_is_stable() {
        let ev = Event::message_received(42, [9u8; 32], [1u8; 16], 5, 2, -60, b"body".to_vec());
        let w = ev.to_wire();

        assert_eq!(w[0], crate::ABI_VERSION as u8);
        assert_eq!(w[1], KIND_MESSAGE_RECEIVED);
        assert_eq!(u32::from_le_bytes(w[4..8].try_into().unwrap()), 42);
        assert_eq!(&w[16..48], &[9u8; 32]);
        assert_eq!(&w[48..64], &[1u8; 16]);
        assert_eq!(w[64], 5); // ttl
        assert_eq!(w[65], 2); // hops
        assert_eq!(w[66] as i8, -60); // rssi
        assert_eq!(u32::from_le_bytes(w[68..72].try_into().unwrap()), 4);
        assert_eq!(&w[72..76], b"body");
        assert_eq!(w.len(), 76);
    }

    #[test]
    fn to_wire_does_not_reallocate() {
        // If this ever fires, the capacity hints above drifted from the writer
        // and every event costs an extra memcpy on the hot path.
        for ev in [
            Event::peer_discovered(1, [0u8; 32], "bob", -40, 1),
            Event::peer_lost(2, [0u8; 32]),
            Event::message_received(3, [0u8; 32], [0u8; 16], 4, 0, -50, vec![0; 200]),
            Event::message_delivered(4, [0u8; 16], true),
            Event::transport_state(5, true),
            Event::error(6, "boom"),
        ] {
            let w = ev.to_wire();
            assert!(
                w.capacity() >= w.len(),
                "capacity hint too small for {:?}",
                ev.kind_tag()
            );
        }
    }
}
