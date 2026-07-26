//! # meshcore
//!
//! Pure-Rust mesh messaging core. **This crate contains no FFI and no platform
//! code** — it is a `rlib` that can be unit-tested and fuzzed on the host.
//! All platform capability (the BLE radio) is injected as a trait object, and
//! all output leaves via an [`EventSink`]. The `meshcore-ffi` crate is the only
//! place `extern "C"` / `#[no_mangle]` appears.
//!
//! ## Why the radio is a trait and not Rust code
//!
//! Rust cannot drive the BLE radio on either mobile platform. iOS exposes only
//! CoreBluetooth (Objective-C, requires an app-owned run loop and Info.plist
//! entitlements); Android exposes only `BluetoothLeScanner`/`BluetoothLeAdvertiser`
//! through the Java framework, and background scanning is bound to a Java
//! foreground `Service`. Crates like `btleplug` do not target either platform.
//!
//! So the split is:
//!
//! * **Rust owns**: framing, dedup, anti-replay, TTL/flood routing,
//!   store-and-forward, session key agreement, AEAD, retransmit timers,
//!   peer table.
//! * **Platform owns**: turning the radio on, emitting an advertisement blob
//!   Rust handed it, and pushing received advertisement blobs back down.
//!
//! Rust stays the brain; the platform is a dumb pipe. That is also the split
//! that keeps 95% of the logic host-testable.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod crypto;
pub mod event;
pub mod frame;
pub mod outbox;
pub mod replay;

pub use crypto::{Identity, PeerId};
pub use event::{Event, EventKind};
pub use frame::{FrameError, FrameKind, ParsedFrame};
pub use outbox::Outbox;
pub use replay::{ReplayVerdict, ReplayWindow};

/// Bumped whenever the C ABI or the binary event layout changes. The native
/// layer asserts this at install time so a stale `.so` can never silently
/// mis-decode events.
pub const ABI_VERSION: u32 = 2;

/// Max hops a flooded frame may take before it is dropped.
const DEFAULT_TTL: u8 = 6;
/// How many recently-seen message ids we remember for loop suppression.
const DEDUP_CAPACITY: usize = 4096;
/// Cadence of the housekeeping tick (retransmit, peer expiry).
const TICK: Duration = Duration::from_millis(250);
/// A peer we have not heard from in this long is considered gone.
const PEER_TTL: Duration = Duration::from_secs(30);
/// How often to re-emit our discovery beacon.
const BEACON_INTERVAL_MS: u64 = 2_000;
/// Cap on the inbox, drained synchronously by JS via `receive_message`.
const INBOX_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// Injected platform capability
// ---------------------------------------------------------------------------

/// The BLE radio, implemented by the native layer (CoreBluetooth / Android BLE).
///
/// Implementations are called from the core's worker thread, never from the JS
/// thread, and must not block for long — enqueue and return.
pub trait PlatformRadio: Send + Sync {
    /// Begin advertising `payload` (already framed + encrypted by the core).
    /// The slice is **borrowed** — copy it if you need it past the call.
    fn start_advertising(&self, payload: &[u8]) -> Result<(), CoreError>;
    fn stop_advertising(&self) -> Result<(), CoreError>;
    fn start_scanning(&self) -> Result<(), CoreError>;
    fn stop_scanning(&self) -> Result<(), CoreError>;
    /// Best-effort directed send over a GATT connection, when one exists.
    /// Returning `Err` makes the core fall back to flooding.
    fn send_direct(&self, peer: &PeerId, payload: &[u8]) -> Result<(), CoreError>;
}

/// Where the core pushes asynchronous events. Implemented by the FFI layer,
/// which forwards to C / JNI. Called from the worker thread.
pub trait EventSink: Send + Sync {
    fn emit(&self, event: Event);
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    NotRunning,
    InvalidArgument(&'static str),
    Crypto(&'static str),
    UnknownPeer,
    Radio(String),
    Frame(FrameError),
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoreError::NotRunning => write!(f, "core is not broadcasting"),
            CoreError::InvalidArgument(w) => write!(f, "invalid argument: {w}"),
            CoreError::Crypto(w) => write!(f, "crypto failure: {w}"),
            CoreError::UnknownPeer => write!(f, "unknown peer"),
            CoreError::Radio(w) => write!(f, "radio failure: {w}"),
            CoreError::Frame(e) => write!(f, "frame error: {e:?}"),
        }
    }
}

impl From<FrameError> for CoreError {
    fn from(e: FrameError) -> Self {
        CoreError::Frame(e)
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Config {
    /// Human-visible name broadcast in the beacon. Truncated to 20 bytes.
    pub nickname: String,
    /// 32-byte seed for the long-term identity key. `None` = generate.
    pub identity_seed: Option<[u8; 32]>,
    pub ttl: u8,
    /// Session epoch, stamped into every frame for anti-replay. Defaults to the
    /// wall clock at construction; pass a persisted boot counter if you have
    /// one (see `replay.rs` for why that is better).
    pub epoch: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nickname: String::from("anon"),
            identity_seed: None,
            ttl: DEFAULT_TTL,
            epoch: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Peer table
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: PeerId,
    pub nickname: String,
    pub rssi: i8,
    pub last_seen_ms: u64,
    pub hops: u8,
}

// ---------------------------------------------------------------------------
// Commands into the worker thread
// ---------------------------------------------------------------------------

enum Command {
    Start,
    Stop,
    /// Owned copy of an inbound advertisement. The FFI layer only ever borrows
    /// the platform's buffer; this is where the one unavoidable copy happens.
    Ingest {
        rssi: i8,
        bytes: Vec<u8>,
    },
    Send {
        to: Option<PeerId>,
        body: Vec<u8>,
        msg_id: [u8; 16],
    },
    Shutdown,
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

/// Owning handle to the mesh. The FFI layer keeps exactly one and hands out a
/// raw pointer to it.
pub struct MeshCore {
    tx: mpsc::Sender<Command>,
    running: Arc<AtomicBool>,
    seq: Arc<AtomicU32>,
    identity: Identity,
    peers: Arc<Mutex<HashMap<PeerId, Peer>>>,
    /// Synchronous drain queue for the JSI pull path (`receive_message`).
    inbox: Arc<Mutex<VecDeque<Event>>>,
    /// Depth of the retransmit queue, readable without touching the worker.
    outbox_len: Arc<AtomicU64>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl MeshCore {
    pub fn new(
        config: Config,
        radio: Arc<dyn PlatformRadio>,
        sink: Arc<dyn EventSink>,
    ) -> Result<Self, CoreError> {
        let identity = match config.identity_seed {
            Some(seed) => Identity::from_seed(seed),
            None => Identity::generate()?,
        };
        let epoch = config.epoch.unwrap_or_else(now_ms);

        let (tx, rx) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(false));
        let seq = Arc::new(AtomicU32::new(0));
        let peers: Arc<Mutex<HashMap<PeerId, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
        let inbox = Arc::new(Mutex::new(VecDeque::new()));
        let outbox_len = Arc::new(AtomicU64::new(0));

        let mut worker_state = Worker {
            config: config.clone(),
            identity: identity.clone(),
            epoch,
            counter: 0,
            radio,
            sink,
            running: running.clone(),
            seq: seq.clone(),
            peers: peers.clone(),
            inbox: inbox.clone(),
            outbox: Outbox::default(),
            outbox_len: outbox_len.clone(),
            replay: HashMap::new(),
            seen: VecDeque::with_capacity(DEDUP_CAPACITY),
            seen_set: HashMap::new(),
            last_beacon_ms: 0,
        };

        // A single OS thread, not a tokio runtime. The workload is timer-driven
        // and IO-free from Rust's point of view (the radio is someone else's
        // event loop), so an async runtime would only add binary size.
        let worker = std::thread::Builder::new()
            .name("meshcore".into())
            .stack_size(512 * 1024)
            .spawn(move || worker_state.run(rx))
            .map_err(|e| CoreError::Radio(e.to_string()))?;

        Ok(Self {
            tx,
            running,
            seq,
            identity,
            peers,
            inbox,
            outbox_len,
            worker: Some(worker),
        })
    }

    pub fn public_key(&self) -> PeerId {
        self.identity.public_id()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Number of directed messages awaiting an ack.
    pub fn outbox_len(&self) -> u64 {
        self.outbox_len.load(Ordering::Relaxed)
    }

    pub fn start_broadcasting(&self) -> Result<(), CoreError> {
        self.tx
            .send(Command::Start)
            .map_err(|_| CoreError::NotRunning)
    }

    pub fn stop_broadcasting(&self) -> Result<(), CoreError> {
        self.tx
            .send(Command::Stop)
            .map_err(|_| CoreError::NotRunning)
    }

    /// Queue a message. Returns the 16-byte message id immediately; delivery is
    /// reported later as a `MessageDelivered` (or `MessageExpired`) event.
    /// `to == None` broadcasts.
    pub fn send_message(&self, to: Option<PeerId>, body: &[u8]) -> Result<[u8; 16], CoreError> {
        if body.is_empty() {
            return Err(CoreError::InvalidArgument("empty body"));
        }
        if body.len() > frame::MAX_BODY {
            return Err(CoreError::InvalidArgument("body exceeds MAX_BODY"));
        }
        let msg_id = crypto::random_16()?;
        self.tx
            .send(Command::Send {
                to,
                body: body.to_vec(),
                msg_id,
            })
            .map_err(|_| CoreError::NotRunning)?;
        Ok(msg_id)
    }

    /// Feed a raw advertisement / GATT write captured by the platform radio.
    ///
    /// `bytes` is **borrowed** for the duration of this call only. This is the
    /// single hottest inbound path, so the copy into the worker queue is the
    /// only allocation.
    pub fn ingest(&self, rssi: i8, bytes: &[u8]) -> Result<(), CoreError> {
        if bytes.is_empty() || bytes.len() > frame::MAX_FRAME {
            return Err(CoreError::InvalidArgument("advertisement length"));
        }
        self.tx
            .send(Command::Ingest {
                rssi,
                bytes: bytes.to_vec(),
            })
            .map_err(|_| CoreError::NotRunning)
    }

    /// Synchronously pop one pending event, if any.
    ///
    /// The push path ([`EventSink`]) is the primary one; this exists so a JSI
    /// caller on the JS thread can drain without a thread hop — useful when JS
    /// wakes up from background and wants whatever accumulated.
    pub fn receive_message(&self) -> Option<Event> {
        self.inbox.lock().ok()?.pop_front()
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.peers
            .lock()
            .map(|p| p.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }
}

impl Drop for MeshCore {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Shutdown);
        if let Some(w) = self.worker.take() {
            // Join, don't detach: the platform radio trait object is owned by
            // the worker and may hold a JNI global ref / ObjC strong ref that
            // must be released before the caller unloads us.
            let _ = w.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

struct Worker {
    config: Config,
    identity: Identity,
    epoch: u64,
    counter: u64,
    radio: Arc<dyn PlatformRadio>,
    sink: Arc<dyn EventSink>,
    running: Arc<AtomicBool>,
    seq: Arc<AtomicU32>,
    peers: Arc<Mutex<HashMap<PeerId, Peer>>>,
    inbox: Arc<Mutex<VecDeque<Event>>>,
    outbox: Outbox,
    outbox_len: Arc<AtomicU64>,
    replay: HashMap<PeerId, ReplayWindow>,
    seen: VecDeque<[u8; 16]>,
    seen_set: HashMap<[u8; 16], u64>,
    last_beacon_ms: u64,
}

impl Worker {
    fn run(&mut self, rx: mpsc::Receiver<Command>) {
        loop {
            match rx.recv_timeout(TICK) {
                Ok(Command::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(cmd) => self.handle(cmd),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            self.tick();
        }
        let _ = self.radio.stop_advertising();
        let _ = self.radio.stop_scanning();
        self.running.store(false, Ordering::Release);
    }

    fn handle(&mut self, cmd: Command) {
        let result = match cmd {
            Command::Start => self.do_start(),
            Command::Stop => self.do_stop(),
            Command::Ingest { rssi, bytes } => self.do_ingest(rssi, &bytes),
            Command::Send { to, body, msg_id } => self.do_send(to, &body, msg_id),
            Command::Shutdown => Ok(()),
        };
        if let Err(e) = result {
            self.emit(Event::error(self.tick_seq(), &e.to_string()));
        }
    }

    /// Consume the next per-session counter. Every sealed frame gets a distinct
    /// one, which is what the recipient's replay window keys off.
    fn next_counter(&mut self) -> u64 {
        let c = self.counter;
        self.counter += 1;
        c
    }

    fn do_start(&mut self) -> Result<(), CoreError> {
        self.radio.start_scanning()?;
        self.running.store(true, Ordering::Release);
        self.send_beacon()?;
        self.emit(Event::transport_state(self.tick_seq(), true));
        Ok(())
    }

    fn do_stop(&mut self) -> Result<(), CoreError> {
        self.radio.stop_advertising()?;
        self.radio.stop_scanning()?;
        self.running.store(false, Ordering::Release);
        self.emit(Event::transport_state(self.tick_seq(), false));
        Ok(())
    }

    fn send_beacon(&mut self) -> Result<(), CoreError> {
        let counter = self.next_counter();
        let nickname = self.config.nickname.clone();
        let wire = frame::build(
            &self.identity,
            &frame::Outgoing {
                recipient: crypto::BROADCAST_ID,
                msg_id: crypto::random_16()?,
                epoch: self.epoch,
                counter,
                ttl: 1, // a beacon describes us; it is never relayed
                body: b"",
                nickname: &nickname,
                kind: FrameKind::Beacon,
            },
        )?;
        self.radio.start_advertising(&wire)?;
        self.last_beacon_ms = now_ms();
        Ok(())
    }

    fn do_send(
        &mut self,
        to: Option<PeerId>,
        body: &[u8],
        msg_id: [u8; 16],
    ) -> Result<(), CoreError> {
        if !self.running.load(Ordering::Acquire) {
            return Err(CoreError::NotRunning);
        }
        let recipient = to.unwrap_or(crypto::BROADCAST_ID);
        let counter = self.next_counter();
        let wire = frame::build(
            &self.identity,
            &frame::Outgoing {
                recipient,
                msg_id,
                epoch: self.epoch,
                counter,
                ttl: self.config.ttl,
                body,
                nickname: "",
                kind: FrameKind::Message,
            },
        )?;

        // Mark our own id as seen so a neighbour's re-flood does not loop back.
        self.remember(msg_id);
        self.transmit(&recipient, &wire);

        match to {
            Some(peer) => {
                // Directed: hold it until the recipient acks. This is the
                // store-and-forward half — see outbox.rs.
                if let Some(dropped) = self.outbox.push(msg_id, peer, wire, now_ms()) {
                    self.emit(Event::message_expired(
                        self.tick_seq(),
                        dropped,
                        "outbox full",
                    ));
                }
                self.sync_outbox_len();
            }
            None => {
                // Broadcast has no single recipient to ack, so "on the air" is
                // the only delivery signal that exists.
                self.emit(Event::message_delivered(self.tick_seq(), msg_id, false));
            }
        }
        Ok(())
    }

    /// Put a frame on the air, preferring a GATT connection when we have one.
    /// Returns true if it went out directly rather than by flooding.
    fn transmit(&self, recipient: &PeerId, wire: &[u8]) -> bool {
        if *recipient != crypto::BROADCAST_ID && self.radio.send_direct(recipient, wire).is_ok() {
            return true;
        }
        let _ = self.radio.start_advertising(wire);
        false
    }

    fn do_ingest(&mut self, rssi: i8, bytes: &[u8]) -> Result<(), CoreError> {
        let parsed = frame::parse(bytes)?;

        // 1. Loop suppression before any crypto work — cheapest rejection first.
        if self.remember(parsed.msg_id) {
            return Ok(());
        }

        // Never process our own re-flood as if it were someone else's frame.
        if parsed.sender == self.identity.public_id() {
            return Ok(());
        }

        let for_us = parsed.recipient == self.identity.public_id() || parsed.is_broadcast();

        // 2. Only frames we can authenticate get to touch any state. A directed
        //    frame for someone else is relayed unopened at step 4.
        if for_us {
            match frame::open(&self.identity, &parsed) {
                Ok(plaintext) => self.accept(&parsed, plaintext, rssi)?,
                Err(e) => {
                    // The air is full of other people's traffic; only surface
                    // failures on frames that were addressed to us specifically.
                    if !parsed.is_broadcast() {
                        self.emit(Event::error(self.tick_seq(), &e.to_string()));
                    }
                }
            }
        }

        // 3. Relay: decrement TTL and re-flood. Done for frames not addressed
        //    to us (we are a relay) and for broadcasts (we are a repeater).
        //    Note this happens without a key — that is the point of a mesh.
        if parsed.ttl > 1 && parsed.recipient != self.identity.public_id() {
            let relayed = frame::relay(bytes)?;
            let _ = self.radio.start_advertising(&relayed);
        }
        Ok(())
    }

    /// Handle a frame whose AEAD has verified.
    ///
    /// The replay check lives here, *after* verification, deliberately: checking
    /// before would let an attacker spray forged counters and lock out the real
    /// sender, converting a replay defence into a denial of service.
    fn accept(
        &mut self,
        parsed: &ParsedFrame<'_>,
        plaintext: Vec<u8>,
        rssi: i8,
    ) -> Result<(), CoreError> {
        let verdict = match self.replay.get_mut(&parsed.sender) {
            Some(w) => w.admit(parsed.epoch, parsed.counter),
            None => {
                self.replay.insert(
                    parsed.sender,
                    ReplayWindow::new(parsed.epoch, parsed.counter),
                );
                ReplayVerdict::Fresh
            }
        };
        if verdict != ReplayVerdict::Fresh {
            // Silent drop: a replay is an attack or a stale relay, and neither
            // is worth waking the UI for.
            return Ok(());
        }

        // Verified and fresh, so this peer is real and reachable.
        self.touch_peer(parsed.sender, parsed.nickname.clone(), rssi, parsed.hops);

        match parsed.kind {
            FrameKind::Beacon => {}
            FrameKind::Ack => {
                if plaintext.len() == 16 {
                    let mut acked = [0u8; 16];
                    acked.copy_from_slice(&plaintext);
                    if self.outbox.ack(&acked) {
                        self.sync_outbox_len();
                        self.emit(Event::message_delivered(self.tick_seq(), acked, true));
                    }
                }
            }
            FrameKind::Message => {
                let ev = Event::message_received(
                    self.tick_seq(),
                    parsed.sender,
                    parsed.msg_id,
                    parsed.ttl,
                    parsed.hops,
                    rssi,
                    plaintext,
                );
                self.push_inbox(ev.clone());
                self.emit(ev);

                // Only directed messages are acked — a broadcast would draw an
                // ack from every listener at once.
                if !parsed.is_broadcast() {
                    self.send_ack(&parsed.sender, parsed.msg_id)?;
                }
            }
        }
        Ok(())
    }

    fn send_ack(&mut self, to: &PeerId, acked: [u8; 16]) -> Result<(), CoreError> {
        let counter = self.next_counter();
        let wire = frame::build(
            &self.identity,
            &frame::Outgoing {
                recipient: *to,
                msg_id: crypto::random_16()?,
                epoch: self.epoch,
                counter,
                ttl: self.config.ttl,
                body: &acked,
                nickname: "",
                kind: FrameKind::Ack,
            },
        )?;
        self.transmit(to, &wire);
        Ok(())
    }

    fn tick(&mut self) {
        let now = now_ms();

        // Expire stale peers.
        let mut gone = Vec::new();
        if let Ok(mut peers) = self.peers.lock() {
            peers.retain(|id, p| {
                let alive = now.saturating_sub(p.last_seen_ms) < PEER_TTL.as_millis() as u64;
                if !alive {
                    gone.push(*id);
                }
                alive
            });
        }
        for id in gone {
            self.emit(Event::peer_lost(self.tick_seq(), id));
        }

        if !self.running.load(Ordering::Acquire) {
            return;
        }

        // Retransmit and expire.
        for item in self.outbox.take_due(now) {
            match item.due {
                outbox::Due::Retry(wire) => {
                    self.transmit(&item.recipient, &wire);
                }
                outbox::Due::Expired => {
                    self.emit(Event::message_expired(
                        self.tick_seq(),
                        item.msg_id,
                        "no ack",
                    ));
                }
            }
        }
        self.sync_outbox_len();

        // Re-beacon so peers that arrive mid-session still find us.
        if now.saturating_sub(self.last_beacon_ms) >= BEACON_INTERVAL_MS {
            if let Err(e) = self.send_beacon() {
                self.emit(Event::error(self.tick_seq(), &e.to_string()));
            }
        }
    }

    fn sync_outbox_len(&self) {
        self.outbox_len
            .store(self.outbox.len() as u64, Ordering::Relaxed);
    }

    /// Returns `true` if we had already seen this id.
    fn remember(&mut self, id: [u8; 16]) -> bool {
        if self.seen_set.contains_key(&id) {
            return true;
        }
        if self.seen.len() == DEDUP_CAPACITY {
            if let Some(old) = self.seen.pop_front() {
                self.seen_set.remove(&old);
            }
        }
        self.seen.push_back(id);
        self.seen_set.insert(id, now_ms());
        false
    }

    fn touch_peer(&mut self, id: PeerId, nickname: String, rssi: i8, hops: u8) {
        let mut is_new = false;
        if let Ok(mut peers) = self.peers.lock() {
            let entry = peers.entry(id).or_insert_with(|| {
                is_new = true;
                Peer {
                    id,
                    nickname: nickname.clone(),
                    rssi,
                    last_seen_ms: 0,
                    hops,
                }
            });
            entry.rssi = rssi;
            entry.hops = hops;
            entry.last_seen_ms = now_ms();
            if !nickname.is_empty() {
                entry.nickname = nickname.clone();
            }
        }
        if is_new {
            self.emit(Event::peer_discovered(
                self.tick_seq(),
                id,
                &nickname,
                rssi,
                hops,
            ));
            // Anything queued for this peer becomes due right now. This is what
            // makes "walks back into range" feel instant instead of waiting out
            // an exponential backoff.
            if self.outbox.wake_for_peer(&id, now_ms()) > 0 {
                self.flush_woken(&id);
            }
        }
    }

    fn flush_woken(&mut self, peer: &PeerId) {
        let now = now_ms();
        for item in self.outbox.take_due(now) {
            if item.recipient != *peer {
                continue; // another peer's entry that happened to also be due
            }
            if let outbox::Due::Retry(wire) = item.due {
                self.transmit(peer, &wire);
            }
        }
    }

    fn push_inbox(&self, ev: Event) {
        if let Ok(mut inbox) = self.inbox.lock() {
            // Bounded: if JS never drains, drop oldest rather than grow forever.
            if inbox.len() >= INBOX_CAPACITY {
                inbox.pop_front();
            }
            inbox.push_back(ev);
        }
    }

    fn emit(&self, ev: Event) {
        self.sink.emit(ev);
    }

    fn tick_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests — these run on the host with `cargo test`, no device needed.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct NullRadio {
        sent: Mutex<Vec<Vec<u8>>>,
        direct_ok: AtomicBool,
    }

    impl NullRadio {
        fn drain(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.sent.lock().unwrap())
        }
    }

    impl PlatformRadio for NullRadio {
        fn start_advertising(&self, p: &[u8]) -> Result<(), CoreError> {
            self.sent.lock().unwrap().push(p.to_vec());
            Ok(())
        }
        fn stop_advertising(&self) -> Result<(), CoreError> {
            Ok(())
        }
        fn start_scanning(&self) -> Result<(), CoreError> {
            Ok(())
        }
        fn stop_scanning(&self) -> Result<(), CoreError> {
            Ok(())
        }
        fn send_direct(&self, _: &PeerId, p: &[u8]) -> Result<(), CoreError> {
            if self.direct_ok.load(Ordering::Relaxed) {
                self.sent.lock().unwrap().push(p.to_vec());
                Ok(())
            } else {
                Err(CoreError::UnknownPeer)
            }
        }
    }

    #[derive(Default)]
    struct CollectSink {
        events: Mutex<Vec<Event>>,
    }

    impl CollectSink {
        fn kinds(&self) -> Vec<u8> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|e| e.kind_tag())
                .collect()
        }
        fn bodies(&self) -> Vec<Vec<u8>> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter_map(|e| match &e.kind {
                    EventKind::MessageReceived { body, .. } => Some(body.clone()),
                    _ => None,
                })
                .collect()
        }
        fn count(&self, tag: u8) -> usize {
            self.kinds().iter().filter(|k| **k == tag).count()
        }
    }

    impl EventSink for CollectSink {
        fn emit(&self, e: Event) {
            self.events.lock().unwrap().push(e);
        }
    }

    struct Node {
        core: MeshCore,
        radio: Arc<NullRadio>,
        sink: Arc<CollectSink>,
    }

    fn node(nickname: &str, seed: u8) -> Node {
        let radio = Arc::new(NullRadio::default());
        let sink = Arc::new(CollectSink::default());
        let core = MeshCore::new(
            Config {
                nickname: nickname.into(),
                identity_seed: Some([seed; 32]),
                ttl: 4,
                epoch: Some(1),
            },
            radio.clone(),
            sink.clone(),
        )
        .unwrap();
        Node { core, radio, sink }
    }

    fn settle() {
        std::thread::sleep(Duration::from_millis(200));
    }

    /// Hand everything `from` put on the air to `to`, as a radio would.
    fn deliver(from: &Node, to: &Node) {
        for wire in from.radio.drain() {
            to.core.ingest(-55, &wire).unwrap();
        }
        settle();
    }

    #[test]
    fn roundtrip_broadcast_between_two_cores() {
        let a = node("alice", 1);
        let b = node("bob", 2);
        a.core.start_broadcasting().unwrap();
        b.core.start_broadcasting().unwrap();
        settle();

        a.core.send_message(None, b"hello mesh").unwrap();
        settle();
        deliver(&a, &b);

        assert_eq!(b.sink.bodies(), vec![b"hello mesh".to_vec()]);
        assert!(
            b.sink.count(event::KIND_PEER_DISCOVERED) >= 1,
            "B should discover A"
        );
    }

    #[test]
    fn duplicate_frames_are_suppressed() {
        let a = node("alice", 1);
        a.core.start_broadcasting().unwrap();
        settle();

        let sender = Identity::from_seed([9u8; 32]);
        let wire = frame::build(
            &sender,
            &frame::Outgoing {
                recipient: crypto::BROADCAST_ID,
                msg_id: [7u8; 16],
                epoch: 1,
                counter: 0,
                ttl: 4,
                body: b"dup",
                nickname: "",
                kind: FrameKind::Message,
            },
        )
        .unwrap();

        for _ in 0..5 {
            a.core.ingest(-40, &wire).unwrap();
        }
        settle();
        assert_eq!(a.sink.count(event::KIND_MESSAGE_RECEIVED), 1);
    }

    /// The dedup LRU catches identical frames; this catches the same *content*
    /// re-sealed under a fresh msg_id, which dedup cannot see.
    #[test]
    fn a_replayed_counter_is_rejected_even_with_a_fresh_msg_id() {
        let a = node("alice", 1);
        a.core.start_broadcasting().unwrap();
        settle();

        let sender = Identity::from_seed([9u8; 32]);
        let build = |msg_id: [u8; 16], counter: u64| {
            frame::build(
                &sender,
                &frame::Outgoing {
                    recipient: crypto::BROADCAST_ID,
                    msg_id,
                    epoch: 5,
                    counter,
                    ttl: 4,
                    body: b"transfer $100",
                    nickname: "",
                    kind: FrameKind::Message,
                },
            )
            .unwrap()
        };

        a.core.ingest(-40, &build([1u8; 16], 0)).unwrap();
        a.core.ingest(-40, &build([2u8; 16], 1)).unwrap();
        settle();
        assert_eq!(a.sink.count(event::KIND_MESSAGE_RECEIVED), 2);

        // Same counters, different msg_ids: the dedup cache sees nothing wrong,
        // the replay window does.
        a.core.ingest(-40, &build([3u8; 16], 0)).unwrap();
        a.core.ingest(-40, &build([4u8; 16], 1)).unwrap();
        settle();
        assert_eq!(
            a.sink.count(event::KIND_MESSAGE_RECEIVED),
            2,
            "replayed counters must not be delivered"
        );
    }

    #[test]
    fn a_directed_message_is_acked_and_leaves_the_outbox() {
        let a = node("alice", 1);
        let b = node("bob", 2);
        a.core.start_broadcasting().unwrap();
        b.core.start_broadcasting().unwrap();
        settle();

        // Let them see each other first.
        deliver(&a, &b);
        deliver(&b, &a);

        let msg_id = a
            .core
            .send_message(Some(b.core.public_key()), b"private")
            .unwrap();
        settle();
        assert_eq!(a.core.outbox_len(), 1, "directed message waits for an ack");

        deliver(&a, &b);
        assert_eq!(b.sink.bodies(), vec![b"private".to_vec()]);

        // B's ack travels back.
        deliver(&b, &a);
        assert_eq!(a.core.outbox_len(), 0, "ack must clear the outbox");

        let delivered_direct = a.sink.events.lock().unwrap().iter().any(|e| {
            matches!(&e.kind, EventKind::MessageDelivered { msg_id: m, direct: true }
                              if *m == msg_id)
        });
        assert!(delivered_direct, "an acked message reports direct delivery");
    }

    #[test]
    fn a_broadcast_is_reported_delivered_without_an_ack() {
        let a = node("alice", 1);
        a.core.start_broadcasting().unwrap();
        settle();
        a.core.send_message(None, b"to everyone").unwrap();
        settle();

        assert_eq!(a.core.outbox_len(), 0, "broadcasts are not retried");
        assert_eq!(a.sink.count(event::KIND_MESSAGE_DELIVERED), 1);
    }

    #[test]
    fn an_unacked_message_is_retried() {
        let a = node("alice", 1);
        let b = node("bob", 2);
        a.core.start_broadcasting().unwrap();
        settle();

        a.core
            .send_message(Some(b.core.public_key()), b"are you there")
            .unwrap();
        settle();
        a.radio.drain(); // discard the first transmission

        // Wait past the first backoff and confirm the frame goes out again.
        std::thread::sleep(Duration::from_millis(outbox::BASE_BACKOFF_MS + 400));
        let retried: Vec<_> = a
            .radio
            .drain()
            .into_iter()
            .filter(|w| {
                frame::parse(w)
                    .map(|p| p.kind == FrameKind::Message)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !retried.is_empty(),
            "an unacked directed message must be retried"
        );
        assert_eq!(a.core.outbox_len(), 1);
    }

    /// Retries must reuse the original bytes. Re-sealing would burn a counter
    /// per attempt and punch holes in the recipient's replay window.
    #[test]
    fn retries_reuse_the_original_frame() {
        let a = node("alice", 1);
        let b = node("bob", 2);
        a.core.start_broadcasting().unwrap();
        settle();

        a.core
            .send_message(Some(b.core.public_key()), b"same bytes")
            .unwrap();
        settle();
        let first: Vec<_> = a
            .radio
            .drain()
            .into_iter()
            .filter(|w| {
                frame::parse(w)
                    .map(|p| p.kind == FrameKind::Message)
                    .unwrap_or(false)
            })
            .collect();

        std::thread::sleep(Duration::from_millis(outbox::BASE_BACKOFF_MS + 400));
        let second: Vec<_> = a
            .radio
            .drain()
            .into_iter()
            .filter(|w| {
                frame::parse(w)
                    .map(|p| p.kind == FrameKind::Message)
                    .unwrap_or(false)
            })
            .collect();

        assert_eq!(
            first.first(),
            second.first(),
            "retry must be byte-identical"
        );
    }

    #[test]
    fn a_relay_carries_a_frame_it_cannot_read() {
        let a = node("alice", 1);
        let relay = node("relay", 2);
        let c = node("carol", 3);
        a.core.start_broadcasting().unwrap();
        relay.core.start_broadcasting().unwrap();
        c.core.start_broadcasting().unwrap();
        settle();

        // A sends to C, who is not in range. Only the relay hears it.
        a.core
            .send_message(Some(c.core.public_key()), b"two hops")
            .unwrap();
        settle();
        deliver(&a, &relay);

        // The relay cannot decrypt it...
        assert!(
            relay.sink.bodies().is_empty(),
            "relay must not read the payload"
        );
        // ...but it re-floods it, and C can.
        deliver(&relay, &c);
        assert_eq!(c.sink.bodies(), vec![b"two hops".to_vec()]);
    }

    #[test]
    fn our_own_reflooded_frame_is_ignored() {
        let a = node("alice", 1);
        a.core.start_broadcasting().unwrap();
        settle();
        a.core.send_message(None, b"echo").unwrap();
        settle();

        // Feed A's own traffic straight back, as a neighbour's relay would.
        for wire in a.radio.drain() {
            a.core.ingest(-30, &wire).unwrap();
        }
        settle();
        assert_eq!(a.sink.count(event::KIND_MESSAGE_RECEIVED), 0);
    }

    #[test]
    fn a_peer_walking_into_range_flushes_the_queue_immediately() {
        let a = node("alice", 1);
        let b = node("bob", 2);
        a.core.start_broadcasting().unwrap();
        settle();

        // B is not visible yet, so this queues.
        a.core
            .send_message(Some(b.core.public_key()), b"waiting for you")
            .unwrap();
        settle();
        assert_eq!(a.core.outbox_len(), 1);
        a.radio.drain();

        // B appears. Its beacon should trigger an immediate flush, well inside
        // the exponential backoff.
        b.core.start_broadcasting().unwrap();
        settle();
        deliver(&b, &a);

        let resent: Vec<_> = a
            .radio
            .drain()
            .into_iter()
            .filter(|w| {
                frame::parse(w)
                    .map(|p| p.kind == FrameKind::Message)
                    .unwrap_or(false)
            })
            .collect();
        assert!(
            !resent.is_empty(),
            "discovering the recipient must flush the queue"
        );
    }
}
