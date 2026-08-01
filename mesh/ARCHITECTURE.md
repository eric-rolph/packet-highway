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
│   │   ├── src/crypto.rs              Ed25519 identity, X25519 DH, ChaCha20-Poly1305
│   │   ├── src/prekey.rs              rotating signed prekeys (directed FS)
│   │   ├── src/senderkey.rs           ratcheting sender keys (broadcast FS)
│   │   ├── src/frame.rs               wire format v4, build/open/relay
│   │   ├── src/replay.rs              per-sender sliding anti-replay window
│   │   ├── src/relaycache.rs          carrying mail for peers out of range
│   │   ├── src/outbox.rs              store-and-forward: acks, backoff, expiry
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

## 5a. Forward secrecy

### The transport dictates the design

Noise XX is the obvious answer and the wrong one here. It needs 1.5 round trips,
and the transport is a connectionless BLE advertisement over a mesh where a peer
may be in range for eight seconds and a handshake may simply never complete.
A protocol you cannot finish provides no secrecy at all.

So directed messages use an **X3DH-shaped exchange with zero round trips**:

```
DH1 = DH(ephemeral_sender, prekey_recipient)   <- provides forward secrecy
DH2 = DH(static_sender,    prekey_recipient)   <- authenticates the sender
key = KDF(DH1 ‖ DH2 ‖ sender ‖ recipient ‖ generation)
```

The sender drops the ephemeral secret immediately. Once the recipient rotates
that prekey out of its ring, the message is unrecoverable **even if both
long-term keys are later compromised** — the property static-static ECDH never
had.

### Identity moved to Ed25519

`PeerId` is now a 32-byte **Ed25519** public key; DH uses the birationally
equivalent X25519 form of the same key (`to_scalar_bytes` / `to_montgomery`).
One keypair, two uses.

The reason is not aesthetic: **a node has to sign its prekeys**, and X25519 keys
cannot sign. Beacons are sealed with the group network key, which every member
holds — so without a signature any member could beacon a prekey under someone
else's id and collect their directed mail. `a_forged_prekey_bundle_is_not_installed`
is the test for exactly that attack.

### Rotation is what actually delivers it

Key agreement alone is not forward secrecy; **the secret ceasing to exist** is.
`x25519`'s `StaticSecret` zeroizes on drop, so evicting the back of the prekey
ring is the security event:

```
gen 7  current   <- advertised in every beacon
gen 6  retired   \
gen 5  retired    > in-flight grace
gen 4  retired   /
gen 3  dropped   <- zeroized; this traffic is now unrecoverable
```

Exposure window for a stolen ring is `ROTATE_INTERVAL_MS × (RETAINED + 1)` =
4 minutes. Retention must also *exceed* the 120s outbox deadline, or a retried
message could arrive addressed to a prekey that no longer exists — and
`retention_outlives_the_outbox_deadline` pins that relationship so nobody tunes
one constant without the other.

### Broadcasts: a sender-key ratchet (`senderkey.rs`)

A directed message can be forward secret because there are two parties and
therefore a DH to do. A broadcast has no single recipient, so it used to fall
back to `network_key()` — derived from a **constant**. One stolen channel secret
decrypted every broadcast ever recorded under it.

Each node now runs one outbound chain, ratcheted once per broadcast:

```
mk_i     = KDF(ck_i, "sk-message")   <- seals broadcast i, then discarded
ck_{i+1} = KDF(ck_i, "sk-chain")     <- replaces ck_i, which is zeroized
```

Two independent derivations from the same input, so handing `mk_i` to the AEAD
tells an attacker nothing about `ck_i`. The ratchet is one-way: holding `ck_n`
says nothing about `ck_{n-1}`.

**The distribution is the whole design.** Ratcheting buys nothing if the chain
key travels sealed under the same static group key — recording that one frame
would hand over the chain and everything downstream of it. So the chain key is
*never broadcast*. It goes peer-to-peer in a directed `FrameKind::SenderKey`
frame over the prekey path above. To read a recorded broadcast an attacker needs
the distribution frame; to read that they need a prekey secret that was zeroized
minutes later. That chain of erasures is where the guarantee comes from, and
`a_chain_key_is_never_broadcast` is the test that keeps it true.

Three consequences worth stating plainly:

- **No retroactive access.** A peer receives the chain as it stands, so
  broadcasts sent before it arrived are unreadable to it. That is correct group
  behaviour, not a gap.
- **Beacons stay group-sealed.** They carry the prekey bundle a peer needs in
  order to *receive* a chain, so sealing them to a chain would be a bootstrap
  that requires itself.
- **A node with no peers still falls back** to the group key, with the flag
  clear — same honesty rule as the directed path.

**Ratcheting is not recovery.** The ratchet shuts the past and nothing else:
`ck_{i+1}` follows from `ck_i`, so an attacker who takes a chain key reads every
broadcast that sender makes from then on — for the whole session, if the chain
lives that long. Recovery needs entropy the attacker never saw, so the chain is
**thrown away and regenerated** every `senderkey::ROTATE_INTERVAL_MS` and the
fresh one is redistributed over the prekey path immediately. Replacement, not a
step: a step would leave the new key derivable from the old.

That interval is deliberately equal to `prekey::ROTATE_INTERVAL_MS` — the two
jointly set the post-compromise window, so whichever is longer is the real bound
and letting them drift would make one decorative
(`chain_rotation_matches_prekey_rotation`). The cost is a burst of one directed
frame per known peer per rotation, which is why `Config::chain_rotate_ms` exists:
a deployment with many peers per node can trade window for traffic.

The ordering inside `rotate_sender_chain` matters. `chain_shared_with` is cleared
and refilled within one call, because while it is empty `seal` would fall back to
the group key — a rotation that downgraded every broadcast in the gap would be
worse than not rotating. The worker is single-threaded, so nothing can be sealed
in between, and `the_sender_chain_rotates_and_peers_keep_reading` asserts both
that the chain id changes and that no message is lost or downgraded across it.

**Reordering, and a DoS the split-phase design closes.** BLE reorders, so a
frame at index 9 arriving while we sit at index 6 must ratchet forward and keep
the skipped message keys. That cache is the one place forward secrecy is
deliberately weakened; it is bounded by `SKIPPED_CAP` and each key is erased the
moment it is spent.

Crucially the ratchet is **not committed until the AEAD verifies**. Anyone can
put a frame on the air claiming `index = 9`; if that advanced our state
immediately an attacker could skip us past the real sender's messages and
destroy their keys — a replay defence turned into a denial of service, the same
mistake `replay.rs` avoids by ordering. `InboundChain::derive` computes against a
copy and returns a value the caller commits only after decryption succeeds
(`deriving_without_committing_leaves_the_chain_untouched`).

### Honest about the fallback

Sending to a peer whose beacon we have never seen has no prekey to use. Rather
than refuse, the frame falls back to static-static, `FLAG_FS` stays clear, and
the receiver reports `forwardSecret: false` so the UI can say so instead of
implying a guarantee it does not have. The flag is authenticated (it is in the
AAD), so an attacker cannot downgrade a frame by flipping it. The same applies
to a broadcast sent before any chain has been distributed.

### A bug this work surfaced

Writing the "invalid peer id" test turned up a real vulnerability in the DH
path. `VerifyingKey::from_bytes` accepts small-order points — `[0u8; 32]` and
`y = 1` decompress perfectly well — and DH against them drives the shared secret
to **all zeros**. Anyone choosing such an id could have fixed the key for
everyone who talked to them. Every DH in the crate now routes through one
`dh()` helper that checks `was_contributory()`; centralising it is what stops a
future call site from forgetting the check.

---

## 5b. Delivery, replay and store-and-forward

Three properties a flood mesh does not give you for free, added in the core so
both platforms get them identically.

### Anti-replay (`replay.rs`)

The msg_id dedup cache is a 4096-entry LRU. It stops flood loops, but it is
bounded — capture a frame, replay it after 4096 other messages, and it is
delivered twice. In a busy room that is seconds.

So every frame carries an authenticated `(epoch, counter)` pair and each sender
gets a 64-bit sliding window, the same shape as IPsec's (RFC 4303 §3.4.3):
in-order traffic always passes, reordering within 64 frames is tolerated, exact
replays are `Duplicate`, and anything older is `TooOld`.

Two details carry the weight:

- **The window is consulted *after* the AEAD verifies, never before.** Checking
  first would let an attacker spray forged high counters and lock out the real
  sender — a replay defence turned into a denial of service.
- **`epoch` handles restarts.** A restarted node resets its counter to zero,
  which is indistinguishable from a replay; a higher epoch resets the window,
  and a *lower* one is refused, so re-injecting a whole captured session fails.
  Epoch defaults to the wall clock at construction, which is monotonic across
  restarts **unless the clock rolls back**. That is the known weakness; the fix
  is a persisted boot counter, one `u64` in the same Keychain/Keystore blob as
  the identity seed. `Config::epoch` already accepts it.

### Delivery receipts and retransmit (`outbox.rs`)

Directed messages are held until the recipient acks, then retried with capped
exponential backoff (1s → 15s) until a 120s deadline, after which the UI gets a
`messageExpired` event instead of a message stuck on "sending" forever.
Broadcasts are not retried — there is no single recipient to ack one — and are
reported delivered as soon as they are on the air.

Retries reuse the **original frame bytes** rather than re-sealing. Re-sealing
would burn a fresh counter per attempt and punch holes in the recipient's replay
window; there is a test pinning that (`retries_reuse_the_original_frame`).

The queue is bounded at 256 with oldest-first eviction, so a peer that never
returns cannot grow it without limit.

**Sender-key distributions ride the same queue.** They are directed, they are
acked, and losing one costs the peer *every* broadcast we make until the next
redistribution — which is the exact failure this module exists to prevent. What
they must not do is surface as receipts: there is no user-visible message for a
`messageDelivered` to attach to, and a `messageExpired` for a frame the user
never sent would be a lie. So entries carry a `Traffic` tag; retry, backoff, wake
and eviction are identical for both kinds, only the reporting differs, and
`outbox_len` reports `user_len()` so protocol housekeeping never ticks up the
UI's pending badge.

Queuing a fresh distribution first drops any still-pending one for that peer:
the old frame describes chain state we have moved past, so retrying it spends air
re-announcing a position we no longer broadcast from.

`a_dropped_sender_key_distribution_is_retried` is the regression test, and it was
checked against the unfixed code — removing the `push` makes it fail, which is
the only way to know a test of this shape is testing anything.

### Carrying someone else's mail (`relaycache.rs`)

The outbox covers a node's *own* undelivered messages. The other half — what
makes a mesh delay-tolerant rather than merely multi-hop — is carrying frames for
peers nobody can currently reach. Previously a directed frame for an absent
recipient was re-flooded once and forgotten, so if no node in range could reach
them at that instant the message was simply gone, even though a node that heard
it might meet the recipient a minute later.

Relays now hold such frames and hand them over on discovery. The relay cannot
read any of it — this is ciphertext it has no key for, held only because the
32-byte recipient id is in the clear in the header.

Three things are deliberately *not* carried: broadcasts (already repeated by
every node that hears them), frames addressed to us (ours to handle), and frames
for a peer already in our table (just flooded to someone who is right there —
caching those crowds out the mail that actually needs carrying). The last
predicate is pinned from both sides, by `a_frame_for_a_visible_peer_is_not_carried`
and `a_frame_for_an_unseen_peer_is_carried`; the first version of that test
passed with the guard removed, which is why both exist.

Hand-off is destructive. In a crowded room every relay that saw a frame holds a
copy, so a peer walking back into range would otherwise draw one flood per relay.
The recipient's dedup would swallow the duplicates, but the air time is already
spent by then.

Two bounds, and the second is a correctness property rather than housekeeping:
`CAPACITY` stops a hostile flooder from turning every relay into its memory, and
`TTL_MS` stops a relay delivering a message the *sender* has already reported
expired to its user. The two constants are tuned independently — a deployment may
want relays to give up sooner — but a `const` assertion makes tuning them the
wrong way round a build failure, which was verified by doing it.

`MeshCore::carried_len()` exposes how much mail a node is holding for the mesh.
Not yet plumbed through the C ABI.

### Walking back into range

The backoff timer is the fallback, not the mechanism. When a peer is
*discovered*, everything queued for them is made due immediately and flushed —
which is what makes a mesh messenger feel like a mesh messenger rather than a
retry loop. `a_peer_walking_into_range_flushes_the_queue_immediately` covers it.

---

## 6. Wire formats

Both are little-endian (both mobile targets are LE). The **event** layout is
versioned by `meshcore::ABI_VERSION`, which JS asserts at install time — that
check is what stops a cached `.so` from an older build from silently mis-decoding
every event into plausible-looking garbage. The **frame** carries its own
independent `VERSION` byte, because the two evolve for different reasons: adding
sender keys changed what goes on the air without moving a single event field, so
the frame went to v4 and the ABI stayed at 3.

**Frame v4** (116-byte header + at most one preamble + nickname + ciphertext):

```
0   magic 'M' │ 1  version │ 2  flags* │ 3  ttl† │ 4  hops† │ 5  nick_len
6   body_len u16 │ 8  epoch u64 │ 16 counter u64
24  sender[32] (Ed25519) │ 56 recipient[32] │ 88 msg_id[16] │ 104 nonce[12]
116 [only if FLAG_FS] ephemeral_pubkey[32] ‖ prekey_generation u32
116 [only if FLAG_SK] chain_id u32 ‖ message_index u32
 ..  nickname │ … ciphertext‖tag
```

`ttl`/`hops` (†) are the only fields outside the AAD — a relay must decrement
TTL without holding a key. Everything else is authenticated, including `epoch`,
`counter`, the flags (*) and whichever preamble is present, so an attacker can
neither replay, downgrade off a forward-secret path, re-point a frame at a
different prekey, nor steer a receiver to a different point in a sender chain.

Preambles are **conditional** rather than fixed header fields: a beacon should
not pay 36 bytes for machinery it cannot use, on a radio where a legacy
advertisement holds 31 bytes total. They are also **mutually exclusive** — one is
directed, the other broadcast — and a frame setting both bits is rejected
structurally rather than resolved by precedence, because an ambiguous length
prefix is how parsers grow bugs (`a_frame_claiming_both_preambles_is_refused`).

`header_tampering_is_caught` flips every authenticated header byte one at a time;
`the_fs_preamble_is_authenticated` and `the_sender_key_preamble_is_authenticated`
do the same for each preamble.

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

121 tests, all runnable on a laptop with no device, all enforced by CI
(`.github/workflows/meshcore.yml`).

- **101 Rust core + 6 FFI** (`cargo test`):
  - *crypto* — AEAD tamper and wrong-AAD rejection, Ed25519↔X25519 agreement in
    both directions, malformed peer ids refused at decode, **small-order peer
    ids refused at DH** (the vulnerability §5a describes), FS key agreement
    matching on both sides, generation bound into the transcript, long-term keys
    alone insufficient to derive a message key, prekey signatures bound to one
    identity, a chain step's two outputs unrelated to each other and to their
    input, no message key repeating within 256 steps of a chain.
  - *senderkey* — distribution round-trip and length rejection, sender and
    receiver agreeing in order, a skipped frame still opening when it arrives,
    a spent skip-cache key unusable twice, an index beyond `MAX_SKIP` refused,
    **deriving without committing leaving the chain untouched** (the forged-index
    DoS), the skip cache bounded, a replayed older distribution unable to rewind
    a chain, a restarting peer not accumulating chains, unknown chains unopenable,
    a chain due only after its interval (and never after a backwards clock jump),
    a rotated chain unreachable from the old one, chain rotation tied to prekey
    rotation.
  - *prekey* — retention keeps in-flight mail decryptable, rotating past the
    depth destroys the secret, rotation respects its interval, retention
    outlives the outbox deadline, bundles round-trip, bundles attributed to the
    wrong peer or tampered at any of four offsets are refused.
  - *frame* — broadcast/directed/FS/sender-key roundtrips, relay preserves
    authenticity, **every** authenticated header byte flipped one at a time, both
    preambles authenticated byte by byte, a rotated-out prekey cannot open the
    frame, a truncated preamble of either kind rejected structurally, a frame
    claiming both preambles refused, a distribution frame is a distinct kind and
    never broadcast, multibyte nickname truncation, v1–v3 frames rejected rather
    than misparsed, a maximal frame fits the ceiling exactly.
  - *replay* — in-order, exact replay, reordering inside the window,
    beyond-window rejection, a >64 jump that would be a shift overflow, restart
    resets, whole-session replay refused, `u64::MAX` saturation.
  - *outbox* — backoff growth and cap, ack removal, peer-discovery wake, bounded
    eviction, retry byte-identity, re-queue consistency, internal traffic
    retrying while staying out of the user count, acks reporting which kind they
    cleared, expiry carrying the kind so receipts can be suppressed, a newer
    distribution dropping the superseded one.
  - *core* — two-node handshake, dedup, replay rejected with a fresh msg_id,
    directed ack clears the outbox, unacked retry, a relay carrying a frame it
    cannot read, own re-flood ignored, queue flush on peer discovery,
    **FS negotiated once the prekey is known**, **fallback admits it is not FS**,
    **a forged prekey bundle is never installed**, **broadcasts become forward
    secret once a peer holds the chain**, a broadcast before any distribution
    admits it is not, **a chain key is never broadcast**, a peer without the
    chain cannot read a ratcheted broadcast, reordered ratcheted broadcasts all
    decode, **the sender chain rotates without losing a message or downgrading**,
    **a dropped sender-key distribution is retried**, those retries stay
    invisible to the user, and **a relay carries a frame to a peer that only
    arrives later**.
  - *relaycache* — carried frames returned on discovery, hand-off destructive so
    each relay forwards once, the same frame held only once however many
    neighbours flood it, bounded with oldest-first eviction, stale frames
    dropped.
  - *FFI* — full C-ABI lifecycle with a mock radio and sink, null-safety on every
    entry point, garbage-ingest fuzz over every prefix length, `MeshBuffer`
    non-copying roundtrip.
- **14 JS** (`node --test`) — the decoder against bytes emitted by the *actual*
  Rust encoder: signed RSSI, non-ASCII nicknames, the zero-copy view assertion
  (`body.buffer === source`), the forward-secrecy flag decoded rather than
  assumed (two fixtures of the same kind differing only in that bit),
  ABI-mismatch and truncation failures, and a check that every event kind Rust
  emits has a decoder branch.

That last suite matters more than its size suggests: `event.rs` and `events.ts`
have no compiler between them, so a hand-written decoder drifting from the
encoder is the single most likely way this project breaks. The test regenerates
fixtures from Rust on every run.

### CI

`.github/workflows/meshcore.yml`, scoped to `mesh/**`:

| job | what it catches |
|---|---|
| `rust` | `cargo fmt --check`, `clippy -D warnings`, `cargo test`, header presence |
| `cross` | `cargo check` for aarch64-android, armv7-android, aarch64-ios |
| `js` | strict `tsc` on the decoder + the wire-format contract test |
| `shell` | `shellcheck` on both build scripts |

The `cross` job is the cheap one worth calling out: `cargo check` does not link,
so the mobile targets validate on a plain Ubuntu runner in seconds — no NDK, no
Xcode, no macOS minutes. It catches target-gated breakage (JNI signatures, libc
differences) long before a device build would.

`-D warnings` is passed to clippy after `--` rather than set as a global
`RUSTFLAGS`, because cargo applies `RUSTFLAGS` to dependency crates too and one
warning in a transitive dependency would then fail the build.

One thing to expect: the `rust` job uses `dtolnay/rust-toolchain@stable`, so **a
clean local clippy does not mean a clean CI clippy** if your toolchain is older.
That is not hypothetical — the sender-key work passed clippy 0.1.94 locally and
failed on 0.1.97 in CI over a style lint that had been broadened in between.
`rustup update` before pushing, or expect one red run. Pinning CI to a fixed
toolchain would make the two agree, at the cost of never seeing new lints.

## 9. What is scaffolding, and what to do next

Honest inventory of what is *not* production-ready:

1. **Post-compromise security is bounded, not achieved.** Both key schedules now
   recover on a timer — a stolen prekey ring reads directed traffic for at most
   four minutes, a stolen sender chain reads broadcasts for at most one rotation
   interval. But recovery by *replacement on a clock* is weaker than recovery by
   *DH per message*: there is still no Double Ratchet, so an attacker with
   continuing access simply re-steals each new key and never loses the thread.
   Closing that means a real ratchet on the directed path; `crypto.rs` is shaped
   so the key-derivation swap stays local.
2. **The skip cache trades a little forward secrecy for deliverability.**
   Up to `SKIPPED_CAP` message keys per chain are retained so out-of-order
   broadcasts still open. Each is erased when spent, but until then it is a live
   key. Shrinking the cap tightens the window and drops more reordered traffic;
   there is no setting that gives both.
3. **The channel secret is a constant.** `CHANNEL_SECRET` in `crypto.rs` is a
   placeholder for the per-channel secret a user actually joins with. Until it
   is real, "the network key" means "anyone with this build". Sender keys shrink
   the blast radius — the group key now only opens beacons and the broadcasts of
   a node that has no peers yet — but membership is still unauthenticated, so
   anyone with the build joins the mesh and receives chains like anyone else.
4. **Epoch depends on the wall clock.** See §5b: a device whose clock rolls
   backwards has its frames refused by peers until it restarts. The fix is a
   persisted boot counter; `Config::epoch` already accepts one.
5. **Identity is not persisted.** The 32-byte seed should live in the Keychain
   (iOS) / Keystore-wrapped (Android) and be passed to `initializeCore`. Pair it
   with the boot counter from (4) — same blob, same write. Until then every
   launch is a new identity and no peer can recognise you twice.
6. **GATT is stubbed on Android.** `MeshRadio.sendDirect` returns `false`, so
   Rust floods. Correct behaviour, but directed sends never get the fast path
   until the `peerId → BluetoothGatt` map is wired up.
7. **A queued message keeps its original sealing.** The outbox stores sealed
   bytes on purpose (re-sealing would burn replay counters), so a message queued
   before the recipient's beacon arrived stays non-FS through its retries. Only
   messages sent *after* the prekey is known get the upgrade.
8. **A peer that is unreachable for the whole outbox deadline still loses the
   chain.** Distributions are now retried like any directed frame (§5b), so a
   dropped one recovers in about a second instead of a rotation interval. But
   after 120s of failure the entry expires silently, and that peer reads nothing
   from us until the next prekey rotation queues a fresh one. Bounded at
   `ROTATE_INTERVAL_MS`, not eliminated.
9. **iOS background operation** needs `UIBackgroundModes` = `bluetooth-central`
   + `bluetooth-peripheral`, and the service UUID moves to the overflow area
   where only other iOS devices can see it. **Android background** needs a
   foreground service, or the scanner is throttled to ~1 result per 5 minutes
   with the screen off.
10. **Carried mail is bounded and best-effort.** Relays now hold frames for
   absent peers (§5b), but a relay that fills its 128-frame buffer, restarts, or
   never meets the recipient still drops them, and nothing tells the sender that
   happened. It raises the odds of delivery; it does not make delivery reliable.
11. **The native layers are unverified by CI.** The Objective-C++ and
    Kotlin/CMake code compiles only under Xcode and the Android NDK, neither of
    which is on the CI runner. `cargo check` covers the mobile *Rust* targets;
    the platform layers need a macOS runner and an SDK image to gate properly.

None of this is a reason to hold the current work — each item is independent and
the tests pin the behaviour that exists today.
