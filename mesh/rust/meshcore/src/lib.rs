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
//! * **Rust owns**: framing, dedup, TTL/flood routing, store-and-forward queue,
//!   session key agreement, AEAD, retransmit timers, peer table.
//! * **Platform owns**: turning the radio on, emitting an advertisement blob
//!   Rust handed it, and pushing received advertisement blobs back down.
//!
//! Rust stays the brain; the platform is a dumb pipe. That is also the split
//! that keeps 95% of the logic host-testable.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod crypto;
pub mod event;
pub mod frame;

pub use crypto::{Identity, PeerId};
pub use event::{Event, EventKind};
pub use frame::{FrameError, ParsedFrame};

/// Bumped whenever the C ABI or the binary event layout changes. The native
/// layer asserts this at install time so a stale `.so` can never silently
/// mis-decode events.
pub const ABI_VERSION: u32 = 1;

/// Max hops a flooded frame may take before it is dropped.
const DEFAULT_TTL: u8 = 6;
/// How many recently-seen message ids we remember for loop suppression.
const DEDUP_CAPACITY: usize = 4096;
/// Cadence of the housekeeping tick (retransmit, dedup GC, peer expiry).
const TICK: Duration = Duration::from_millis(250);
/// A peer we have not heard from in this long is considered gone.
const PEER_TTL: Duration = Duration::from_secs(30);

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
    /// Human-visible name broadcast in the advertisement. Truncated to 20 bytes
    /// to fit a BLE legacy ADV_IND PDU alongside the service UUID + pubkey hint.
    pub nickname: String,
    /// 32-byte seed for the long-term identity key. `None` = generate.
    pub identity_seed: Option<[u8; 32]>,
    pub ttl: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self { nickname: String::from("anon"), identity_seed: None, ttl: DEFAULT_TTL }
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
    Ingest { rssi: i8, bytes: Vec<u8> },
    Send { to: Option<PeerId>, body: Vec<u8>, msg_id: [u8; 16] },
    Shutdown,
}

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

/// Owning handle to the mesh. Cheap to clone (`Arc` inside); the FFI layer
/// keeps exactly one and hands out a raw pointer to it.
pub struct MeshCore {
    tx: mpsc::Sender<Command>,
    running: Arc<AtomicBool>,
    seq: Arc<AtomicU32>,
    identity: Identity,
    peers: Arc<Mutex<HashMap<PeerId, Peer>>>,
    /// Synchronous drain queue for the JSI pull path (`receive_message`).
    inbox: Arc<Mutex<VecDeque<Event>>>,
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

        let (tx, rx) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(false));
        let seq = Arc::new(AtomicU32::new(0));
        let peers: Arc<Mutex<HashMap<PeerId, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
        let inbox = Arc::new(Mutex::new(VecDeque::new()));

        let mut worker_state = Worker {
            config: config.clone(),
            identity: identity.clone(),
            radio,
            sink,
            running: running.clone(),
            seq: seq.clone(),
            peers: peers.clone(),
            inbox: inbox.clone(),
            seen: VecDeque::with_capacity(DEDUP_CAPACITY),
            seen_set: HashMap::new(),
        };

        // A single OS thread, not a tokio runtime. The workload is timer-driven
        // and IO-free from Rust's point of view (the radio is someone else's
        // event loop), so an async runtime would only add binary size.
        let worker = std::thread::Builder::new()
            .name("meshcore".into())
            .stack_size(512 * 1024)
            .spawn(move || worker_state.run(rx))
            .map_err(|e| CoreError::Radio(e.to_string()))?;

        Ok(Self { tx, running, seq, identity, peers, inbox, worker: Some(worker) })
    }

    pub fn public_key(&self) -> PeerId {
        self.identity.public_id()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub fn start_broadcasting(&self) -> Result<(), CoreError> {
        self.tx.send(Command::Start).map_err(|_| CoreError::NotRunning)
    }

    pub fn stop_broadcasting(&self) -> Result<(), CoreError> {
        self.tx.send(Command::Stop).map_err(|_| CoreError::NotRunning)
    }

    /// Queue a message. Returns the 16-byte message id immediately; delivery is
    /// reported later as a `MessageDelivered` event. `to == None` broadcasts.
    pub fn send_message(&self, to: Option<PeerId>, body: &[u8]) -> Result<[u8; 16], CoreError> {
        if body.is_empty() {
            return Err(CoreError::InvalidArgument("empty body"));
        }
        if body.len() > frame::MAX_BODY {
            return Err(CoreError::InvalidArgument("body exceeds MAX_BODY"));
        }
        let msg_id = crypto::random_16()?;
        self.tx
            .send(Command::Send { to, body: body.to_vec(), msg_id })
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
            .send(Command::Ingest { rssi, bytes: bytes.to_vec() })
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
        self.peers.lock().map(|p| p.values().cloned().collect()).unwrap_or_default()
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
    radio: Arc<dyn PlatformRadio>,
    sink: Arc<dyn EventSink>,
    running: Arc<AtomicBool>,
    seq: Arc<AtomicU32>,
    peers: Arc<Mutex<HashMap<PeerId, Peer>>>,
    inbox: Arc<Mutex<VecDeque<Event>>>,
    seen: VecDeque<[u8; 16]>,
    seen_set: HashMap<[u8; 16], u64>,
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

    fn do_start(&mut self) -> Result<(), CoreError> {
        let beacon = frame::build_beacon(&self.identity, &self.config.nickname)?;
        self.radio.start_advertising(&beacon)?;
        self.radio.start_scanning()?;
        self.running.store(true, Ordering::Release);
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
        let wire = frame::seal(&self.identity, &recipient, msg_id, self.config.ttl, body)?;

        // Mark our own id as seen so a neighbour's re-flood does not loop back.
        self.remember(msg_id);

        let delivered = match to {
            Some(peer) => self.radio.send_direct(&peer, &wire).is_ok(),
            None => false,
        };
        if !delivered {
            self.radio.start_advertising(&wire)?; // flood
        }
        self.emit(Event::message_delivered(self.tick_seq(), msg_id, delivered));
        Ok(())
    }

    fn do_ingest(&mut self, rssi: i8, bytes: &[u8]) -> Result<(), CoreError> {
        let parsed = frame::parse(bytes)?;

        // 1. Loop suppression before any crypto work — cheapest rejection first.
        if self.remember(parsed.msg_id) {
            return Ok(());
        }

        // 2. Peer table refresh happens for every valid frame, beacon or not.
        self.touch_peer(parsed.sender, parsed.nickname.clone(), rssi, parsed.hops);

        if parsed.is_beacon {
            return Ok(());
        }

        // 3. Only try to decrypt frames addressed to us or broadcast.
        let for_us =
            parsed.recipient == self.identity.public_id() || parsed.recipient == crypto::BROADCAST_ID;

        if for_us {
            match frame::open(&self.identity, &parsed) {
                Ok(plaintext) => {
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
                }
                Err(e) => self.emit(Event::error(self.tick_seq(), &e.to_string())),
            }
        }

        // 4. Relay: decrement TTL and re-flood regardless of whether it was for
        //    us (broadcast) or not (we are a relay). This is what makes a mesh.
        if parsed.ttl > 1 && parsed.recipient != self.identity.public_id() {
            let relayed = frame::relay(bytes)?;
            let _ = self.radio.start_advertising(&relayed);
        }
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
                Peer { id, nickname: nickname.clone(), rssi, last_seen_ms: 0, hops }
            });
            entry.rssi = rssi;
            entry.hops = hops;
            entry.last_seen_ms = now_ms();
            if !nickname.is_empty() {
                entry.nickname = nickname.clone();
            }
        }
        if is_new {
            self.emit(Event::peer_discovered(self.tick_seq(), id, &nickname, rssi, hops));
        }
    }

    fn push_inbox(&self, ev: Event) {
        if let Ok(mut inbox) = self.inbox.lock() {
            // Bounded: if JS never drains, drop oldest rather than grow forever.
            if inbox.len() >= 256 {
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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
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
        fn send_direct(&self, _: &PeerId, _: &[u8]) -> Result<(), CoreError> {
            Err(CoreError::UnknownPeer)
        }
    }

    #[derive(Default)]
    struct CollectSink {
        events: Mutex<Vec<Event>>,
    }
    impl EventSink for CollectSink {
        fn emit(&self, e: Event) {
            self.events.lock().unwrap().push(e);
        }
    }

    #[test]
    fn roundtrip_broadcast_between_two_cores() {
        let radio_a = Arc::new(NullRadio::default());
        let sink_a = Arc::new(CollectSink::default());
        let a = MeshCore::new(
            Config { nickname: "alice".into(), identity_seed: Some([1u8; 32]), ttl: 4 },
            radio_a.clone(),
            sink_a.clone(),
        )
        .unwrap();

        let radio_b = Arc::new(NullRadio::default());
        let sink_b = Arc::new(CollectSink::default());
        let b = MeshCore::new(
            Config { nickname: "bob".into(), identity_seed: Some([2u8; 32]), ttl: 4 },
            radio_b.clone(),
            sink_b.clone(),
        )
        .unwrap();

        a.start_broadcasting().unwrap();
        b.start_broadcasting().unwrap();
        std::thread::sleep(Duration::from_millis(200));

        a.send_message(None, b"hello mesh").unwrap();
        std::thread::sleep(Duration::from_millis(200));

        // Hand every byte A put on the air to B, as the radio would.
        let on_air: Vec<Vec<u8>> = radio_a.sent.lock().unwrap().clone();
        for wire in on_air {
            b.ingest(-55, &wire).unwrap();
        }
        std::thread::sleep(Duration::from_millis(300));

        let events = sink_b.events.lock().unwrap();
        let got: Vec<_> = events
            .iter()
            .filter_map(|e| match &e.kind {
                EventKind::MessageReceived { body, .. } => Some(body.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(got, vec![b"hello mesh".to_vec()], "B should decrypt A's broadcast");

        assert!(
            events.iter().any(|e| matches!(&e.kind, EventKind::PeerDiscovered { .. })),
            "B should have discovered A"
        );
    }

    #[test]
    fn duplicate_frames_are_suppressed() {
        let radio = Arc::new(NullRadio::default());
        let sink = Arc::new(CollectSink::default());
        let a = MeshCore::new(Config::default(), radio.clone(), sink.clone()).unwrap();
        a.start_broadcasting().unwrap();
        std::thread::sleep(Duration::from_millis(100));

        let sender = Identity::from_seed([9u8; 32]);
        let wire = frame::seal(&sender, &crypto::BROADCAST_ID, [7u8; 16], 4, b"dup").unwrap();
        for _ in 0..5 {
            a.ingest(-40, &wire).unwrap();
        }
        std::thread::sleep(Duration::from_millis(300));

        let n = sink
            .events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(&e.kind, EventKind::MessageReceived { .. }))
            .count();
        assert_eq!(n, 1, "five copies of one frame must surface exactly once");
    }
}
