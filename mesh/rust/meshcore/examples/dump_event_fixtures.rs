//! Emits the canonical binary encoding of every event kind as JSON-ish hex, so
//! the TypeScript decoder can be tested against the *real* Rust encoder instead
//! of against someone's reading of the spec comment.
//!
//! Run:  cargo run -p meshcore --example dump_event_fixtures
//! Used by: js/test/decode.test.mjs

use meshcore::event::{Event, KIND_MESSAGE_RECEIVED};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let peer = [0xAAu8; 32];
    let msg_id = [0xBBu8; 16];

    let fixtures: Vec<(&str, Event)> = vec![
        ("peerDiscovered", Event::peer_discovered(1, peer, "ada-löve", -42, 3)),
        ("peerLost", Event::peer_lost(2, peer)),
        (
            "messageReceived",
            Event::message_received(3, peer, msg_id, 6, 2, -71, b"hello mesh".to_vec()),
        ),
        ("messageDelivered", Event::message_delivered(4, msg_id, true)),
        ("transportState", Event::transport_state(5, true)),
        ("error", Event::error(6, "radio failure: scan denied")),
    ];

    println!("[");
    let n = fixtures.len();
    for (i, (name, ev)) in fixtures.iter().enumerate() {
        let wire = ev.to_wire();
        println!(
            r#"  {{"name":"{}","kind":{},"seq":{},"ts":{},"hex":"{}"}}{}"#,
            name,
            ev.kind_tag(),
            ev.seq,
            ev.ts_ms,
            hex(&wire),
            if i + 1 == n { "" } else { "," }
        );
    }
    println!("]");

    // Sanity: the layout test in event.rs pins these offsets; if this assert
    // ever fires the fixtures are meaningless.
    let probe = Event::message_received(0, peer, msg_id, 1, 1, -1, b"x".to_vec());
    assert_eq!(probe.kind_tag(), KIND_MESSAGE_RECEIVED);
}
