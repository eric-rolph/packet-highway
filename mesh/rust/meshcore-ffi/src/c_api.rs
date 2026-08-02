//! The C ABI. `cbindgen` turns this file into `meshcore.h`, which the iOS
//! Objective-C++ layer and the shared JSI C++ layer both `#include`.
//!
//! Rules enforced here, and nowhere else in the codebase:
//!
//! 1. Every exported fn is `extern "C"` and wrapped in `catch_unwind`. Rust
//!    unwinding into ObjC/C++ frames is undefined behaviour; a panic becomes
//!    `MESH_STATUS_PANIC` instead.
//! 2. Every exported fn null-checks every pointer before dereferencing.
//! 3. No Rust type crosses the boundary except `#[repr(C)]` structs and
//!    primitives. No `String`, no `Vec`, no enum with payload.
//! 4. Errors are `MeshStatus` codes plus a thread-local message retrievable
//!    with `mesh_last_error` — never a returned pointer that could leak.

use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::{Arc, RwLock};

use meshcore::{Config, CoreError, Event, EventSink, MeshCore, PeerId, PlatformRadio};

use crate::buffer::{borrow, MeshBuffer};

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshStatus {
    Ok = 0,
    NullHandle = 1,
    InvalidArgument = 2,
    Crypto = 3,
    NotRunning = 4,
    UnknownPeer = 5,
    Radio = 6,
    Frame = 7,
    /// A Rust panic was caught at the boundary. The library is still usable but
    /// this always indicates a bug — report it.
    Panic = 255,
}

impl From<CoreError> for MeshStatus {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::NotRunning => MeshStatus::NotRunning,
            CoreError::InvalidArgument(_) => MeshStatus::InvalidArgument,
            CoreError::Crypto(_) => MeshStatus::Crypto,
            CoreError::UnknownPeer => MeshStatus::UnknownPeer,
            CoreError::Radio(_) => MeshStatus::Radio,
            CoreError::Frame(_) => MeshStatus::Frame,
        }
    }
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

pub(crate) fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
}

pub(crate) fn last_error_string() -> String {
    LAST_ERROR.with(|e| e.borrow().clone())
}

fn fail(e: CoreError) -> MeshStatus {
    set_last_error(e.to_string());
    e.into()
}

/// Run `f`, converting a panic into `Panic` rather than unwinding into C.
///
/// In the release profile `panic = "abort"` means this never actually catches —
/// it exists for the debug/test profile and for the day someone flips the
/// profile back. Keeping it costs nothing in release (the landing pad is
/// eliminated) and keeps the invariant honest.
///
/// `AssertUnwindSafe` is used deliberately: `MeshHandle` is not `UnwindSafe`
/// because it owns a `JoinHandle`, but nothing here observes core state *after*
/// a panic — we return a status code and the next call re-reads state through
/// the same locks. The core's own `Mutex`es are handled with
/// `unwrap_or_else(into_inner)` so a poisoned lock degrades rather than
/// cascades.
fn guard<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            set_last_error("panic caught at FFI boundary");
            fallback
        }
    }
}

// ---------------------------------------------------------------------------
// Opaque handle
// ---------------------------------------------------------------------------

/// Opaque to C. Created by `mesh_core_new`, destroyed by `mesh_core_free`.
pub struct MeshHandle {
    core: MeshCore,
    sink: Arc<SwappableSink>,
}

impl MeshHandle {
    pub(crate) fn new_internal(
        config: Config,
        radio: Arc<dyn PlatformRadio>,
    ) -> Result<Box<MeshHandle>, CoreError> {
        let sink = Arc::new(SwappableSink::default());
        let core = MeshCore::new(config, radio, sink.clone() as Arc<dyn EventSink>)?;
        Ok(Box::new(MeshHandle { core, sink }))
    }

    pub(crate) fn core(&self) -> &MeshCore {
        &self.core
    }

    pub(crate) fn set_sink(&self, f: MeshEventSink, ctx: *mut c_void) {
        self.sink.set(f, ctx);
    }
}

/// Turn a raw handle into a reference, or return `NullHandle`.
macro_rules! handle {
    ($h:expr) => {
        match unsafe { $h.as_ref() } {
            Some(h) => h,
            None => {
                set_last_error("null MeshHandle");
                return MeshStatus::NullHandle;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Event sink
// ---------------------------------------------------------------------------

/// Callback invoked from the mesh worker thread with a freshly allocated event
/// buffer. **The callee takes ownership of `payload` and must release it with
/// `mesh_buffer_free`** (or hand it to something that will, like the JSI
/// `MutableBuffer` adapter).
///
/// It is invoked on Rust's worker thread, *not* the JS thread. The C++ layer is
/// responsible for hopping onto the JS thread via `CallInvoker::invokeAsync`
/// before touching a `jsi::Runtime`.
pub type MeshEventSink =
    Option<unsafe extern "C" fn(ctx: *mut c_void, kind: u32, payload: MeshBuffer)>;

/// Holds the currently-registered sink. Swappable because React Native creates
/// the native module (and therefore the core) before the JSI runtime exists;
/// the sink is installed later, from `installJSI`.
#[derive(Default)]
struct SwappableSink {
    inner: RwLock<Option<SinkTarget>>,
}

#[derive(Clone, Copy)]
struct SinkTarget {
    f: unsafe extern "C" fn(*mut c_void, u32, MeshBuffer),
    /// Stored as `usize` so `SinkTarget` stays auto-`Send`/`Sync`. The pointer
    /// is only ever handed straight back to `f`, never dereferenced by Rust.
    ctx: usize,
}

impl SwappableSink {
    fn set(&self, f: MeshEventSink, ctx: *mut c_void) {
        let mut w = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *w = f.map(|f| SinkTarget {
            f,
            ctx: ctx as usize,
        });
    }
}

impl EventSink for SwappableSink {
    fn emit(&self, event: Event) {
        // The read guard is deliberately held **across** the callback. That
        // makes `mesh_core_set_event_sink(handle, NULL, NULL)` a true barrier:
        // once it returns (it needs the write lock), no callback can still be
        // in flight, so the C++ HostObject can unregister in its destructor and
        // then safely die.
        //
        // The cost of that guarantee: a sink implementation must never call
        // `mesh_core_set_event_sink` from inside the callback. The C++ layer
        // does not — it copies the buffer pointer and posts to the JS thread.
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let Some(target) = guard.as_ref() else {
            // No sink yet (JSI not installed, or app tearing down). Messages
            // are still queued in the core's inbox, so nothing is lost that JS
            // can't pull with `receiveMessage()` once it comes up.
            return;
        };
        let wire = event.to_wire();
        let kind = event.kind_tag() as u32;
        // Ownership of `wire`'s allocation transfers to the callee here.
        unsafe { (target.f)(target.ctx as *mut c_void, kind, MeshBuffer::from_vec(wire)) };
    }
}

// ---------------------------------------------------------------------------
// Platform radio vtable (implemented by iOS Objective-C++)
// ---------------------------------------------------------------------------

/// Function table the native layer fills in so Rust can drive the radio.
///
/// `ctx` is opaque to Rust and is passed back verbatim to every callback — on
/// iOS it is an `__bridge`'d `MeshRadio *`. Every fn may be null, in which case
/// the corresponding operation returns `MESH_STATUS_RADIO`.
///
/// Callbacks are invoked from the mesh worker thread. Implementations must be
/// thread-safe and must not block (dispatch to your own queue and return).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MeshPlatformRadio {
    pub ctx: *mut c_void,
    pub start_advertising:
        Option<unsafe extern "C" fn(ctx: *mut c_void, payload: *const u8, len: usize) -> i32>,
    pub stop_advertising: Option<unsafe extern "C" fn(ctx: *mut c_void) -> i32>,
    pub start_scanning: Option<unsafe extern "C" fn(ctx: *mut c_void) -> i32>,
    pub stop_scanning: Option<unsafe extern "C" fn(ctx: *mut c_void) -> i32>,
    pub send_direct: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            peer: *const u8, // always 32 bytes
            payload: *const u8,
            len: usize,
        ) -> i32,
    >,
    /// Optional destructor for `ctx`, called exactly once when the core is
    /// freed. On iOS this is where you `CFRelease` the bridged retain.
    pub destroy: Option<unsafe extern "C" fn(ctx: *mut c_void)>,
}

struct CRadio(MeshPlatformRadio);

// SAFETY: `ctx` is never dereferenced by Rust — it is only passed back to the
// C callbacks. The native side's contract (documented on MeshPlatformRadio) is
// that those callbacks are safe to invoke from any thread.
unsafe impl Send for CRadio {}
unsafe impl Sync for CRadio {}

impl CRadio {
    fn check(rc: i32, what: &'static str) -> Result<(), CoreError> {
        if rc == 0 {
            Ok(())
        } else {
            Err(CoreError::Radio(format!("{what} returned {rc}")))
        }
    }
}

impl PlatformRadio for CRadio {
    fn start_advertising(&self, payload: &[u8]) -> Result<(), CoreError> {
        let f = self
            .0
            .start_advertising
            .ok_or(CoreError::Radio("no start_advertising".into()))?;
        Self::check(
            unsafe { f(self.0.ctx, payload.as_ptr(), payload.len()) },
            "start_advertising",
        )
    }
    fn stop_advertising(&self) -> Result<(), CoreError> {
        let f = self
            .0
            .stop_advertising
            .ok_or(CoreError::Radio("no stop_advertising".into()))?;
        Self::check(unsafe { f(self.0.ctx) }, "stop_advertising")
    }
    fn start_scanning(&self) -> Result<(), CoreError> {
        let f = self
            .0
            .start_scanning
            .ok_or(CoreError::Radio("no start_scanning".into()))?;
        Self::check(unsafe { f(self.0.ctx) }, "start_scanning")
    }
    fn stop_scanning(&self) -> Result<(), CoreError> {
        let f = self
            .0
            .stop_scanning
            .ok_or(CoreError::Radio("no stop_scanning".into()))?;
        Self::check(unsafe { f(self.0.ctx) }, "stop_scanning")
    }
    fn send_direct(&self, peer: &PeerId, payload: &[u8]) -> Result<(), CoreError> {
        let f = self.0.send_direct.ok_or(CoreError::UnknownPeer)?;
        Self::check(
            unsafe { f(self.0.ctx, peer.as_ptr(), payload.as_ptr(), payload.len()) },
            "send_direct",
        )
    }
}

impl Drop for CRadio {
    fn drop(&mut self) {
        if let Some(d) = self.0.destroy {
            unsafe { d(self.0.ctx) };
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// All pointers are **borrowed for the duration of `mesh_core_new` only**;
/// Rust copies what it needs before returning.
#[repr(C)]
pub struct MeshConfig {
    pub nickname: *const u8,
    pub nickname_len: usize,
    /// Exactly 32 bytes, or null to generate a fresh identity.
    pub identity_seed: *const u8,
    /// Secret defining which mesh to join. Null falls back to the published
    /// open channel — a mesh anyone can read, which is the right default for a
    /// demo and the wrong one for anything private.
    pub channel_secret: *const u8,
    pub channel_secret_len: usize,
    pub ttl: u8,
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// ABI/event-layout version. The JS package refuses to install if this does not
/// match its own constant — that check is what stops a cached `.so` from a
/// previous build silently mis-decoding events.
#[no_mangle]
pub extern "C" fn mesh_abi_version() -> u32 {
    meshcore::ABI_VERSION
}

/// Create a core. On success `*out` receives an owning pointer that must be
/// released with `mesh_core_free`.
///
/// **This call consumes `radio` unconditionally.** Whether it succeeds or
/// fails, `radio.destroy(radio.ctx)` will have been invoked exactly once by the
/// time it returns, so the caller must never invoke it themselves. The rule is
/// blunt on purpose: the previous contract ("Rust never took the vtable on
/// failure") was true only for the two argument-validation returns, and a
/// caller balancing its own retain on a `CoreError` path released the radio a
/// second time.
///
/// # Safety
/// `config` must be valid; `radio.ctx` must outlive the core (or be managed by
/// `radio.destroy`); `out` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mesh_core_new(
    config: *const MeshConfig,
    radio: MeshPlatformRadio,
    out: *mut *mut MeshHandle,
) -> MeshStatus {
    guard(MeshStatus::Panic, || {
        // Take ownership before anything that can return early. Every exit path
        // below now drops this exactly once, which is what makes the
        // unconditional contract above true rather than aspirational.
        let radio = Arc::new(CRadio(radio));

        if out.is_null() {
            set_last_error("null out pointer");
            return MeshStatus::InvalidArgument;
        }
        *out = std::ptr::null_mut();

        let cfg = match config.as_ref() {
            Some(c) => c,
            None => {
                set_last_error("null config");
                return MeshStatus::InvalidArgument;
            }
        };

        let nickname = match borrow(cfg.nickname, cfg.nickname_len) {
            Some(b) => String::from_utf8_lossy(b).into_owned(),
            None => String::from("anon"),
        };
        let identity_seed = borrow(cfg.identity_seed, 32).map(|s| {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(s);
            seed
        });

        // Borrowed for this call only; `Config` takes an owned copy.
        let channel_secret = borrow(cfg.channel_secret, cfg.channel_secret_len)
            .map(|b| b.to_vec())
            .unwrap_or_else(|| meshcore::crypto::OPEN_CHANNEL.to_vec());

        let core_cfg = Config {
            nickname,
            identity_seed,
            channel_secret,
            ttl: if cfg.ttl == 0 { 6 } else { cfg.ttl },
            // None => wall clock at construction. Pass a persisted boot counter
            // via MeshConfig once identity storage lands; see replay.rs.
            epoch: None,
            // Everything else takes the core's default. Struct-update syntax on
            // purpose: a new tuning field in Config should not break the C ABI,
            // which only carries what MeshConfig actually exposes.
            ..Default::default()
        };

        match MeshHandle::new_internal(core_cfg, radio) {
            Ok(handle) => {
                *out = Box::into_raw(handle);
                MeshStatus::Ok
            }
            Err(e) => fail(e),
        }
    })
}

/// Destroy a core. Blocks until the worker thread has joined and the radio
/// `destroy` callback has run, so it is safe to tear down the native radio
/// object immediately after this returns.
///
/// # Safety
/// `handle` must come from `mesh_core_new` and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn mesh_core_free(handle: *mut MeshHandle) {
    if handle.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(Box::from_raw(handle))));
}

/// Register (or clear, with `sink == NULL`) the async event callback.
///
/// # Safety
/// `handle` must be live. `ctx` must remain valid until the sink is replaced or
/// the core is freed.
#[no_mangle]
pub unsafe extern "C" fn mesh_core_set_event_sink(
    handle: *mut MeshHandle,
    sink: MeshEventSink,
    ctx: *mut c_void,
) -> MeshStatus {
    let h = handle!(handle);
    guard(MeshStatus::Panic, || {
        h.set_sink(sink, ctx);
        MeshStatus::Ok
    })
}

/// Write our 32-byte public key into `out32`.
///
/// # Safety
/// `out32` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mesh_core_public_key(
    handle: *mut MeshHandle,
    out32: *mut u8,
) -> MeshStatus {
    let h = handle!(handle);
    if out32.is_null() {
        set_last_error("null out32");
        return MeshStatus::InvalidArgument;
    }
    guard(MeshStatus::Panic, || {
        std::ptr::copy_nonoverlapping(h.core.public_key().as_ptr(), out32, 32);
        MeshStatus::Ok
    })
}

/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn mesh_start_broadcasting(handle: *mut MeshHandle) -> MeshStatus {
    let h = handle!(handle);
    guard(MeshStatus::Panic, || match h.core.start_broadcasting() {
        Ok(()) => MeshStatus::Ok,
        Err(e) => fail(e),
    })
}

/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn mesh_stop_broadcasting(handle: *mut MeshHandle) -> MeshStatus {
    let h = handle!(handle);
    guard(MeshStatus::Panic, || match h.core.stop_broadcasting() {
        Ok(()) => MeshStatus::Ok,
        Err(e) => fail(e),
    })
}

/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn mesh_is_running(handle: *mut MeshHandle) -> bool {
    match handle.as_ref() {
        Some(h) => h.core.is_running(),
        None => false,
    }
}

/// Number of directed messages queued awaiting an ack.
///
/// Cheap: a relaxed atomic load, no lock and no round trip to the worker
/// thread, so a UI can poll it per frame if it wants a "3 pending" badge.
///
/// # Safety
/// `handle` must be live.
#[no_mangle]
pub unsafe extern "C" fn mesh_outbox_len(handle: *mut MeshHandle) -> u64 {
    match handle.as_ref() {
        Some(h) => h.core.outbox_len(),
        None => 0,
    }
}

/// Queue a message. `peer` is 32 bytes, or null to broadcast. `out_msg_id`
/// receives the 16-byte id synchronously so JS can render an optimistic row
/// before the radio has done anything.
///
/// `body` is borrowed and copied internally — the caller may free it on return.
///
/// # Safety
/// All non-null pointers must be valid for their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn mesh_send_message(
    handle: *mut MeshHandle,
    peer: *const u8,
    body: *const u8,
    body_len: usize,
    out_msg_id: *mut u8,
) -> MeshStatus {
    let h = handle!(handle);
    guard(MeshStatus::Panic, || {
        let body = match borrow(body, body_len) {
            Some(b) => b,
            None => {
                set_last_error("null or empty body");
                return MeshStatus::InvalidArgument;
            }
        };
        let to = borrow(peer, 32).map(|s| {
            let mut id = [0u8; 32];
            id.copy_from_slice(s);
            id
        });
        match h.core.send_message(to, body) {
            Ok(msg_id) => {
                if !out_msg_id.is_null() {
                    std::ptr::copy_nonoverlapping(msg_id.as_ptr(), out_msg_id, 16);
                }
                MeshStatus::Ok
            }
            Err(e) => fail(e),
        }
    })
}

/// Feed a raw advertisement / GATT payload captured by the platform radio.
///
/// The hottest inbound call in the system: it borrows the platform's buffer and
/// never retains it, so callers can reuse a single scratch buffer per scan
/// callback and avoid one allocation per advertisement.
///
/// # Safety
/// `data` must be valid for `len` bytes for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn mesh_ingest(
    handle: *mut MeshHandle,
    rssi: i8,
    data: *const u8,
    len: usize,
) -> MeshStatus {
    let h = handle!(handle);
    guard(MeshStatus::Panic, || {
        let bytes = match borrow(data, len) {
            Some(b) => b,
            None => {
                set_last_error("null advertisement");
                return MeshStatus::InvalidArgument;
            }
        };
        match h.core.ingest(rssi, bytes) {
            Ok(()) => MeshStatus::Ok,
            Err(e) => fail(e),
        }
    })
}

/// Synchronously pop one queued event, encoded with the same binary layout as
/// the push path. `out->ptr` is null when the queue is empty.
///
/// # Safety
/// `out` must be writable. The caller owns `*out` and must `mesh_buffer_free`
/// it when `ptr` is non-null.
#[no_mangle]
pub unsafe extern "C" fn mesh_receive_message(
    handle: *mut MeshHandle,
    out: *mut MeshBuffer,
) -> MeshStatus {
    let h = handle!(handle);
    if out.is_null() {
        set_last_error("null out buffer");
        return MeshStatus::InvalidArgument;
    }
    guard(MeshStatus::Panic, || {
        *out = match h.core.receive_message() {
            Some(ev) => MeshBuffer::from_vec(ev.to_wire()),
            None => MeshBuffer::empty(),
        };
        MeshStatus::Ok
    })
}

/// Snapshot the peer table into one buffer.
///
/// Layout (LE): `u32 count`, then per peer:
/// `[32] id | i8 rssi | u8 hops | u16 pad | u64 last_seen_ms | u32 nick_len | nick`
///
/// # Safety
/// `out` must be writable; the caller frees it with `mesh_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn mesh_peers(handle: *mut MeshHandle, out: *mut MeshBuffer) -> MeshStatus {
    let h = handle!(handle);
    if out.is_null() {
        set_last_error("null out buffer");
        return MeshStatus::InvalidArgument;
    }
    guard(MeshStatus::Panic, || {
        let peers = h.core.peers();
        let mut w = Vec::with_capacity(4 + peers.len() * 64);
        w.extend_from_slice(&(peers.len() as u32).to_le_bytes());
        for p in &peers {
            w.extend_from_slice(&p.id);
            w.push(p.rssi as u8);
            w.push(p.hops);
            w.extend_from_slice(&[0u8; 2]);
            w.extend_from_slice(&p.last_seen_ms.to_le_bytes());
            let n = p.nickname.as_bytes();
            w.extend_from_slice(&(n.len() as u32).to_le_bytes());
            w.extend_from_slice(n);
        }
        *out = MeshBuffer::from_vec(w);
        MeshStatus::Ok
    })
}

/// Fetch the last error message for **this thread** as UTF-8.
///
/// # Safety
/// `out` must be writable; the caller frees it with `mesh_buffer_free`.
#[no_mangle]
pub unsafe extern "C" fn mesh_last_error(out: *mut MeshBuffer) -> MeshStatus {
    if out.is_null() {
        return MeshStatus::InvalidArgument;
    }
    let msg = LAST_ERROR.with(|e| e.borrow().clone());
    *out = MeshBuffer::from_vec(msg.into_bytes());
    MeshStatus::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ADV_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SINK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SINK_BYTES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn adv(_ctx: *mut c_void, _p: *const u8, _l: usize) -> i32 {
        ADV_CALLS.fetch_add(1, Ordering::SeqCst);
        0
    }
    unsafe extern "C" fn ok0(_ctx: *mut c_void) -> i32 {
        0
    }
    unsafe extern "C" fn sink(_ctx: *mut c_void, _kind: u32, payload: MeshBuffer) {
        SINK_CALLS.fetch_add(1, Ordering::SeqCst);
        SINK_BYTES.fetch_add(payload.len, Ordering::SeqCst);
        // Exactly what every native caller must do.
        unsafe { crate::buffer::mesh_buffer_free(payload) };
    }

    fn vtable() -> MeshPlatformRadio {
        MeshPlatformRadio {
            ctx: std::ptr::null_mut(),
            start_advertising: Some(adv),
            stop_advertising: Some(ok0),
            start_scanning: Some(ok0),
            stop_scanning: Some(ok0),
            send_direct: None,
            destroy: None,
        }
    }

    #[test]
    fn full_c_abi_lifecycle() {
        let nick = b"tester";
        let cfg = MeshConfig {
            nickname: nick.as_ptr(),
            nickname_len: nick.len(),
            identity_seed: [7u8; 32].as_ptr(),
            // Null exercises the open-channel default, which is what a caller
            // that ignores the new field gets.
            channel_secret: std::ptr::null(),
            channel_secret_len: 0,
            ttl: 4,
        };
        let mut handle: *mut MeshHandle = std::ptr::null_mut();
        unsafe {
            assert_eq!(mesh_core_new(&cfg, vtable(), &mut handle), MeshStatus::Ok);
            assert!(!handle.is_null());

            assert_eq!(
                mesh_core_set_event_sink(handle, Some(sink), std::ptr::null_mut()),
                MeshStatus::Ok
            );

            let mut pk = [0u8; 32];
            assert_eq!(
                mesh_core_public_key(handle, pk.as_mut_ptr()),
                MeshStatus::Ok
            );
            assert_ne!(pk, [0u8; 32]);

            assert_eq!(mesh_start_broadcasting(handle), MeshStatus::Ok);
            std::thread::sleep(std::time::Duration::from_millis(150));
            assert!(mesh_is_running(handle));

            let body = b"hello";
            let mut msg_id = [0u8; 16];
            assert_eq!(
                mesh_send_message(
                    handle,
                    std::ptr::null(),
                    body.as_ptr(),
                    body.len(),
                    msg_id.as_mut_ptr()
                ),
                MeshStatus::Ok
            );
            std::thread::sleep(std::time::Duration::from_millis(200));

            assert!(ADV_CALLS.load(Ordering::SeqCst) >= 2, "beacon + message");
            assert!(
                SINK_CALLS.load(Ordering::SeqCst) >= 2,
                "transport state + delivered"
            );
            assert!(SINK_BYTES.load(Ordering::SeqCst) > 0);

            let mut peers = MeshBuffer::empty();
            assert_eq!(mesh_peers(handle, &mut peers), MeshStatus::Ok);
            assert_eq!(
                u32::from_le_bytes(peers.into_vec()[..4].try_into().unwrap()),
                0
            );

            assert_eq!(mesh_stop_broadcasting(handle), MeshStatus::Ok);
            std::thread::sleep(std::time::Duration::from_millis(150));
            mesh_core_free(handle);
        }
    }

    #[test]
    fn every_entry_point_survives_null() {
        unsafe {
            let mut out = MeshBuffer::empty();
            assert_eq!(
                mesh_start_broadcasting(std::ptr::null_mut()),
                MeshStatus::NullHandle
            );
            assert_eq!(
                mesh_stop_broadcasting(std::ptr::null_mut()),
                MeshStatus::NullHandle
            );
            assert_eq!(
                mesh_core_public_key(std::ptr::null_mut(), std::ptr::null_mut()),
                MeshStatus::NullHandle
            );
            assert_eq!(
                mesh_ingest(std::ptr::null_mut(), 0, std::ptr::null(), 0),
                MeshStatus::NullHandle
            );
            assert_eq!(
                mesh_receive_message(std::ptr::null_mut(), &mut out),
                MeshStatus::NullHandle
            );
            assert!(!mesh_is_running(std::ptr::null_mut()));
            assert_eq!(
                mesh_core_new(std::ptr::null(), vtable(), std::ptr::null_mut()),
                MeshStatus::InvalidArgument
            );
            mesh_core_free(std::ptr::null_mut()); // must not crash
        }
    }

    #[test]
    fn ingest_is_immune_to_garbage() {
        let cfg = MeshConfig {
            nickname: std::ptr::null(),
            nickname_len: 0,
            identity_seed: std::ptr::null(),
            channel_secret: std::ptr::null(),
            channel_secret_len: 0,
            ttl: 0,
        };
        let mut handle: *mut MeshHandle = std::ptr::null_mut();
        unsafe {
            assert_eq!(mesh_core_new(&cfg, vtable(), &mut handle), MeshStatus::Ok);
            let junk = [0xABu8; 300];
            // Fuzz-lite: every prefix length of a garbage buffer must return a
            // status code, never panic or read out of bounds.
            for n in 1..junk.len() {
                let st = mesh_ingest(handle, -70, junk.as_ptr(), n);
                assert_ne!(st, MeshStatus::Panic, "panicked on {n}-byte garbage");
            }
            mesh_core_free(handle);
        }
    }
}
