# meshcore — Rust ↔ React Native bridge architecture

A serverless P2P mesh messenger: Rust owns protocol, crypto and routing; React
Native owns the UI; the layer between them is designed so a decrypted payload
crosses from Rust's allocator into a JS `Uint8Array` **without a single copy**.

---

## 0. One correction to the brief, up front

> "the core networking, cryptography, and BLE broadcast logic will be written in Rust"

Networking, crypto and routing: yes. **BLE broadcast: not possible.** Rust
cannot drive the radio on either platform:

| | Radio API | Why Rust can't own it |
|---|---|---|
| iOS | CoreBluetooth | Objective-C only; needs an `NSObject` delegate on an app run loop, plus Info.plist entitlements |
| Android | `BluetoothLe{Scanner,Advertiser}` | Java framework only; background scanning must be owned by a Java foreground `Service` |

`btleplug` and friends do not target mobile. So the radio is **injected** into
the core as a trait object and the control flow is inverted:

```
Rust  --calls-->  PlatformRadio::start_advertising(&[u8])   ->  CoreBluetooth / BluetoothLeAdvertiser
Rust  <--fed---   MeshCore::ingest(rssi, &[u8])             <-  scan callbacks
```

Rust stays the brain, the platform is a dumb pipe, and ~95% of the logic stays
host-testable (`cargo test` runs the two-node mesh handshake with no device).

Two more platform constraints the design has to absorb:

- **iOS ignores manufacturer data in advertisements.** `CBPeripheralManager`
  accepts only `CBAdvertisementDataLocalNameKey` and
  `…ServiceUUIDsKey`. So the frame cannot ride in the advertisement — the
  advertisement is a discovery beacon and frames move over a GATT
  characteristic. Android *can* put ~26 bytes in a legacy advertisement
  (~250 with BLE 5 extended), so `MeshRadio.kt` uses the advertisement for
  short frames and reports failure for long ones rather than truncating a
  frame into an undecryptable one.
- **Android scan permissions changed twice.** API 31+ wants
  `BLUETOOTH_SCAN`/`ADVERTISE`/`CONNECT` (with `neverForLocation`, or every
  user sees a location prompt for a chat app); API ≤30 gates scanning on
  `ACCESS_FINE_LOCATION`. Both are declared in the library manifest.

---

## 1. Binding generator: why neither uniffi nor cxx

This was the explicit question, so here is the reasoning rather than just the
answer.

**uniffi — rejected for this project.** It is excellent at what it does:
describe an API once, generate idiomatic Kotlin and Swift. But:

- It generates **Kotlin and Swift**, not C++. JSI *is* C++. A uniffi binding
  therefore lands one layer too high — you would still hand-write a Turbo
  Module to get from Kotlin/Swift down to JSI, which is most of the work
  you were trying to avoid.
- Byte arrays cross as `ByteArray`/`Data`, i.e. **copied into the managed
  heap**. For a `Vec<u8>` of decrypted plaintext that is a copy into Kotlin,
  then a copy into JSI. Two copies on the hottest path.
- The generated `RustBuffer` lifetime is uniffi's, so you cannot hand its
  allocation to a `jsi::MutableBuffer` and let Hermes' GC free it.

uniffi *would* be the right call if the consumers were native Swift/Kotlin apps
rather than a JS runtime, or if the payloads were small structs rather than
byte slabs.

**cxx — rejected, narrowly.** `cxx` generates a safe Rust↔C++ seam, which is
the right *shape*. But its owning types (`rust::Vec<u8>`, `rust::Slice`) still
need manual plumbing to satisfy `jsi::MutableBuffer`'s `data()`/`size()`
contract and its destructor timing, so the interesting part — the ownership
handoff — stays hand-written. What's left for `cxx` to generate is a dozen
function signatures. That is not worth a build-time codegen step and a second
dependency in every compile unit.

**Chosen: hand-written `extern "C"` + cbindgen-generated header.**

```
meshcore (pure Rust, no FFI)
    ↑ trait objects
meshcore-ffi  ──cbindgen──>  meshcore.h
    ↑ C ABI                       ↓ #include
    │                    shared/cpp (JSI HostObject)   ← ONE copy, both platforms
    │                         ↓                ↓
    │                    iOS .mm          Android OnLoad.cpp
    └── android.rs (JNI, for the Kotlin radio only)
```

- The C ABI is ~14 functions and 4 structs. Small enough to hand-write, review,
  and keep panic-safe.
- cbindgen generates the header from the Rust source, so the C declarations
  **cannot drift** from the Rust definitions — that's the failure mode people
  actually hit, and it's the part worth automating.
- The JSI layer is a single C++ file compiled verbatim by both the CocoaPod and
  the Android CMake build. Not "the same design" on two platforms — the same
  source.
- JNI appears only in `android.rs`, and only because the Kotlin radio has to be
  reachable from Rust's worker thread. The `jni` crate handles thread
  attachment and reference frames correctly; doing that from C++ would be more
  code, not less. **It compiles on the host too**, so `cargo test` catches JNI
  signature drift instead of an NDK build twenty minutes later.

---

## 2. Layout

```
mesh/
├── rust/                              cargo workspace
│   ├── Cargo.toml                     profile: opt-level=z, fat LTO, panic=abort
│   ├── meshcore/                      ── PURE RUST, host-testable, zero FFI
│   │   ├── src/lib.rs                 MeshCore, worker thread, PlatformRadio/EventSink traits
│   │   ├── src/crypto.rs              X25519 + ChaCha20-Poly1305, Identity
│   │   ├── src/frame.rs               wire format, seal/open/relay
│   │   ├── src/event.rs               events + the binary layout JS decodes
│   │   └── examples/dump_event_fixtures.rs   feeds the JS contract test
│   └── meshcore-ffi/                  ── THE ONLY CRATE WITH #[no_mangle]
│       ├── src/buffer.rs              MeshBuffer: the one ownership primitive
│       ├── src/c_api.rs               extern "C" surface  → iOS + shared C++
│       ├── src/android.rs             JNI surface         → Kotlin
│       ├── build.rs + cbindgen.toml   generates include/meshcore.h
│       └── crate-type = [staticlib, cdylib, rlib]
│
├── shared/cpp/                        ── COMPILED BY BOTH PLATFORMS
│   ├── MeshRustBuffer.h               jsi::MutableBuffer adapter — the zero-copy seam
│   ├── MeshCoreHostObject.h/.cpp      global.__MeshCore
│
├── ios/
│   ├── MeshCore.podspec               vendors MeshCore.xcframework + shared/cpp
│   ├── Frameworks/                    (generated) xcframework + meshcore.h
│   └── MeshCore/
│       ├── MeshCoreModule.h/.mm       Turbo Module: lifetime + JSI install
│       └── MeshRadio.h/.mm            CoreBluetooth behind the C vtable
│
├── android/
│   ├── build.gradle                   cargo-ndk wired in as a task dependency
│   ├── CMakeLists.txt                 builds libmeshcore_jsi.so
│   ├── src/main/AndroidManifest.xml   BLE permissions for API 24…34
│   ├── src/main/cpp/OnLoad.cpp        JSI install via fbjni + CallInvokerHolder
│   ├── src/main/jniLibs/<abi>/        (generated) libmeshcore_ffi.so
│   └── src/main/java/com/meshcore/
│       ├── MeshCoreNative.kt          external fun declarations
│       ├── MeshRadio.kt               BLE scanner/advertiser, direct ByteBuffer ingest
│       ├── MeshCoreModule.kt          Turbo Module: lifetime + JSI install
│       └── MeshCorePackage.kt         autolinking
│
├── js/
│   ├── src/NativeMeshCore.ts          Turbo Module spec (cold path only)
│   ├── src/events.ts                  binary decoder, mirrors event.rs
│   ├── src/index.ts                   public API
│   └── test/decode.test.mjs           decodes bytes from the REAL Rust encoder
│
└── scripts/{build-ios.sh,build-android.sh}
```

---

## 3. Memory management across the boundary

### The rule

**Whoever allocated it, frees it — and there is exactly one free function.**

| Direction | Representation | Lifetime | Freed by |
|---|---|---|---|
| Rust → native | `MeshBuffer { ptr, len, cap }` by value | until freed | **native**, via `mesh_buffer_free`, exactly once |
| native → Rust | `const uint8_t*, size_t` | the callee's stack frame | **native**, after the call returns |
| JS → Rust | borrowed `jsi::ArrayBuffer` storage | the synchronous call | nobody — it's the JS heap |
| Rust → JS | `MeshBuffer` adopted by `jsi::MutableBuffer` | until Hermes GCs the ArrayBuffer | **Hermes**, via `~MeshRustBuffer` |

`cap` travels with `ptr`/`len` because Rust's deallocator needs the exact
layout the allocation was made with. That is also why native code must never
call `free()` on `MeshBuffer.ptr`: it came from Rust's allocator, not libc's.
Doing so is heap corruption, not a leak.

### Path A — Rust → JS, zero copy (the important one)

```rust
// meshcore-ffi/src/buffer.rs — O(1), no memcpy
pub fn from_vec(v: Vec<u8>) -> MeshBuffer {
    let mut v = ManuallyDrop::new(v);
    MeshBuffer { ptr: v.as_mut_ptr(), len: v.len(), cap: v.capacity() }
}
```

```cpp
// shared/cpp/MeshRustBuffer.h — the allocation's new owner
class MeshRustBuffer : public jsi::MutableBuffer {
  ~MeshRustBuffer() override { mesh_buffer_free(buf_); }   // the single free
  uint8_t* data() override { return buf_.ptr; }            // no copy
};
jsi::ArrayBuffer(rt, std::make_shared<MeshRustBuffer>(buf));
```

```ts
// js/src/events.ts — a view, not a copy
const body = new Uint8Array(buffer, o, bodyLen);
```

The bytes Rust wrote the decrypted plaintext into are the bytes JS reads.
Hermes' GC finalizing the ArrayBuffer is what returns them to Rust — there is
no manual free on the JS side and no way to forget one.

Two honest caveats, both documented at the call site:

1. **Release is GC-timed.** A burst of large payloads pins Rust memory until
   the next Hermes GC. `copyToArrayBuffer()` is provided as the
   free-immediately-pay-one-memcpy alternative; measure before choosing.
2. **Don't `structuredClone`/transfer the ArrayBuffer in JS.** Detaching it
   while `MeshRustBuffer` still owns the storage is a use-after-free.

### Path B — native → Rust, borrow only

`mesh_ingest(handle, rssi, data, len)` reconstructs a `&[u8]` for the duration
of the call and copies once into the worker queue. Callers reuse one scratch
buffer per scan callback:

- **iOS**: a 512-byte `uint8_t _scratch[]` member on `MeshRadio`.
- **Android**: `ByteBuffer.allocateDirect(512)` in a `ThreadLocal`, passed to
  `nativeIngestDirect`. Direct buffers live outside the Java heap and cannot
  move, so Rust reads them in place — no JNI pinning, no critical section, and
  **zero Java-heap allocation per advertisement** in a crowded room.
  `nativeIngest(byte[])` is also provided and uses
  `GetPrimitiveArrayCritical` (held for one `memcpy`, never across a callback
  or a lock).

### Panic and null discipline

Every `extern "C"` function: `catch_unwind` → `MESH_STATUS_PANIC`, and a null
check on every pointer before dereference. Unwinding across an FFI boundary is
UB, so the release profile also sets `panic = "abort"` — the guard is belt and
braces for the debug profile.

`borrow()` returns `Option<&[u8]>` and rejects null rather than producing a
zero-length slice from a null pointer, which is UB even though it reads nothing.

Covered by tests: `every_entry_point_survives_null` calls each entry point with
nulls, and `ingest_is_immune_to_garbage` feeds every prefix length of a
300-byte garbage buffer and asserts a status code comes back — never a panic.

---

## 4. Threading

```
 JS thread            Rust worker            CoreBluetooth / BLE binder thread
 ─────────            ───────────            ─────────────────────────────────
 __MeshCore.send() ──> mpsc queue
                       seal + AEAD
                       radio.start_advertising() ──────────> on the air
                                                             scan callback
                       mpsc queue         <───────────────── mesh_ingest(&[u8])
                       parse, dedup, open
                       EventSink::emit()
                          │
                          │ MeshBuffer (moved)
                          ▼
                       C trampoline  ── CallInvoker::invokeAsync ──┐
                                                                   ▼
 listener(kind, ArrayBuffer)  <──────────────────────────── JS thread
```

Load-bearing details:

- **Every JSI method is called on the JS thread and is synchronous.** Rust's
  entry points only push onto an mpsc queue, so nothing here can stall a frame
  on radio IO.
- **Events originate on Rust's worker thread.** The C++ trampoline takes
  ownership of the buffer *first* (RAII, so every exit path frees it), then
  hops to the JS thread via `CallInvoker::invokeAsync` before touching a
  `jsi::Runtime`. Touching a Runtime off the JS thread is the classic
  nondeterministic Hermes crash.
- **Teardown is ordered, and the ordering is enforced by a lock.**
  `SwappableSink::emit` holds its read guard *across* the callback, which makes
  `mesh_core_set_event_sink(handle, NULL, NULL)` a true barrier: once it
  returns, no callback can still be in flight. So:

  ```
  1. host->invalidate()   // unregisters the sink; blocks until in-flight events finish
  2. mesh_core_free()     // joins the worker thread, fires radio destroy
  ```

  Reversing those two frees the runtime out from under an in-flight event. The
  price of the guarantee: a sink implementation must never call
  `mesh_core_set_event_sink` from inside the callback. The C++ layer doesn't.
- **The host object holds a `weak_ptr` to itself** across the thread hop, so an
  event in flight during an RN reload is dropped instead of writing into freed
  memory. Drops are counted and surfaced as `mesh.droppedEvents`, so
  backpressure is observable rather than silent.
- **iOS `ctx` lifetime**: `+vtableForRadio:` takes a `CFBridgingRetain` (+1) on
  the radio, balanced by the `destroy` callback Rust invokes exactly once from
  `mesh_core_free`, after the worker has joined. If `mesh_core_new` *fails*,
  Rust never took the vtable, so the module balances the retain itself.
- **Android radio lifetime**: `AndroidRadio` holds a JNI `GlobalRef`, released
  when the core is dropped.

---

## 5. Why JSI for the hot path and a Turbo Module for the rest

| | Turbo Module | JSI HostObject |
|---|---|---|
| call cost | codegen'd C++ shim, marshals each arg | direct C++ call |
| bytes | copied through the marshaller | `ArrayBuffer` borrowed in place |
| shape | Promise or blocking sync | synchronous |
| used for | `initializeCore`, `installJSI`, permissions | `send`, `receive`, `peers`, events |

A Turbo Module is already far better than the old bridge, but every argument
still round-trips through a generated marshaller. For a payload arriving at BLE
advertisement rates that is the difference between a copy per message and none.

`send()` returns the 16-byte message id **synchronously**, so the UI can render
an optimistic row on the same tick and reconcile on `messageDelivered`.

### Event fan-out happens in JS

One native→JS callback is registered for the whole app; `mesh.on(type, fn)`
fans out in JS. N registered callbacks crossing the boundary would be N times
the boundary cost for the same work.

---

## 6. Wire formats

Both are little-endian (both mobile targets are LE) and versioned by
`meshcore::ABI_VERSION`, which JS asserts at install time — that check is what
stops a cached `.so` from an older build from silently mis-decoding every event
into plausible-looking garbage.

**Frame** (100-byte header + optional nickname + AEAD ciphertext):

```
0   magic 'M' │ 1  version │ 2  flags │ 3  ttl* │ 4  hops* │ 5  nick_len
6   body_len u16 │ 8  sender[32] │ 40 recipient[32] │ 72 msg_id[16] │ 88 nonce[12]
100 nickname │ … ciphertext‖tag
```

`ttl`/`hops` (marked `*`) are **outside the AAD** — a relay must be able to
decrement TTL without holding a key. Everything usable to redirect or replay a
message (sender, recipient, msg_id, nonce, lengths) is inside it.
`relaying_preserves_authenticity` and `header_tampering_is_caught` pin both
halves of that.

**Event**: 16-byte header (`version, kind, flags, seq, ts_ms`) then a
kind-specific body, serialised into exactly one heap allocation whose capacity
is computed up front — `to_wire_does_not_reallocate` guards the hint, because a
reallocation is a silent extra memcpy on the hot path.

---

## 7. Build

```bash
# Rust core, host tests (no device needed — includes a two-node mesh handshake)
cargo test --manifest-path mesh/rust/Cargo.toml

# The Rust↔TS wire-format contract, using bytes from the real Rust encoder
cd mesh/js && node --test test/decode.test.mjs

# iOS: 3 slices -> MeshCore.xcframework + meshcore.h
PROFILE=release bash mesh/scripts/build-ios.sh
cd ios && pod install

# Android: 4 ABIs -> jniLibs/. Also runs automatically from Gradle.
cargo install cargo-ndk
ANDROID_NDK_HOME=$ANDROID_HOME/ndk/26.1.10909125 bash mesh/scripts/build-android.sh
```

Two build choices worth stating:

- **iOS gets a `staticlib`, not a dylib.** A dynamic framework adds a `dlopen`
  at launch and a second binary to code-sign; a static archive gets LTO'd into
  the app binary and disappears from the launch path.
- **XCFramework, not a fat `.a`.** Since Xcode 12, arm64-device and
  arm64-simulator are distinct platforms that `lipo` refuses to combine.
  XCFramework is the only container that holds both, and it's what makes Apple
  Silicon simulators work without the `EXCLUDED_ARCHS` hack.
- `-Wl,--no-undefined` on the Android link turns "missing `mesh_*` symbol" from
  a runtime `dlopen` crash on a user's phone into a link error on your machine.

---

## 8. Test coverage today

29 tests, all runnable on a laptop with no device:

- **18 Rust** (`cargo test`) — AEAD tamper rejection, symmetric key agreement,
  frame roundtrip/relay/tamper, garbage-input fuzz-lite, dedup suppression,
  a **two-node mesh handshake** (A broadcasts, bytes are handed to B, B
  discovers A and decrypts), full C-ABI lifecycle with a mock radio + sink,
  null-safety on every entry point, `MeshBuffer` non-copying roundtrip.
- **11 JS** (`node --test`) — the decoder against bytes emitted by the *actual*
  Rust encoder, including signed RSSI, non-ASCII nicknames, the zero-copy view
  assertion (`body.buffer === source`), ABI-mismatch and truncation failures.

That last suite matters more than its size suggests: `event.rs` and `events.ts`
have no compiler between them, so a hand-written decoder drifting from the
encoder is the single most likely way this project breaks. The test regenerates
fixtures from Rust on every run.

---

## 9. What is scaffolding, and what to do next

Honest inventory of what is *not* production-ready:

1. **Crypto has no forward secrecy.** Directed messages use static-static
   X25519 → HKDF → ChaCha20-Poly1305: zero round trips, which matters when the
   transport is a connectionless advertisement and a handshake may never
   complete — but compromising a long-term key retroactively decrypts
   everything. Broadcast uses a group key derived from a constant channel
   secret. Replace with Noise XX + a Double Ratchet per peer; `crypto.rs` is
   shaped so that swap stays local to the module.
2. **No replay window.** Dedup is a 4096-entry LRU of message ids, which stops
   flood loops but not a determined replay after eviction. Add a per-sender
   monotonic counter inside the AAD.
3. **GATT is stubbed on Android.** `MeshRadio.sendDirect` returns `false`, so
   Rust floods. Correct behaviour, but directed sends never get the fast path
   until the `peerId → BluetoothGatt` map is wired up.
4. **iOS background operation** needs `UIBackgroundModes` = `bluetooth-central`
   + `bluetooth-peripheral`, and the service UUID moves to the overflow area
   where only other iOS devices can see it. **Android background** needs a
   foreground service, or the scanner is throttled to ~1 result per 5 minutes
   with the screen off.
5. **Identity is not persisted.** The 32-byte seed should go in the Keychain
   (iOS) / Keystore-wrapped (Android) and be passed to `initializeCore`.
6. **No store-and-forward.** The core drops frames for offline peers rather
   than queueing them.
