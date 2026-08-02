// MeshCoreHostObject.cpp — see the header for the threading contract.

#include "MeshCoreHostObject.h"

#include "MeshRustBuffer.h"

namespace meshcore {

namespace {

/// Read a Rust-allocated UTF-8 buffer into a std::string and free it.
std::string takeString(MeshBuffer buf) {
  std::string s;
  if (buf.ptr != nullptr && buf.len > 0) {
    s.assign(reinterpret_cast<const char*>(buf.ptr), buf.len);
  }
  mesh_buffer_free(buf);
  return s;
}

std::string lastError() {
  MeshBuffer buf{nullptr, 0, 0};
  mesh_last_error(&buf);
  return takeString(buf);
}

/// Boilerplate-free host function definition.
jsi::Value fn(jsi::Runtime& rt,
              const char* name,
              unsigned argc,
              jsi::HostFunctionType body) {
  return jsi::Function::createFromHostFunction(
      rt, jsi::PropNameID::forAscii(rt, name), argc, std::move(body));
}

}  // namespace

MeshCoreHostObject::MeshCoreHostObject(
    MeshHandle* handle,
    std::shared_ptr<react::CallInvoker> callInvoker,
    jsi::Runtime* runtime)
    : handle_(handle),
      callInvoker_(std::move(callInvoker)),
      runtime_(runtime) {}

MeshCoreHostObject::~MeshCoreHostObject() {
  invalidate();
  // Safe here and only here: the runtime owns this object, so its destructor
  // runs on the JS thread, which is the only thread allowed to destroy a
  // jsi::Function. See the note in invalidate().
  std::lock_guard<std::mutex> lock(listenerMutex_);
  listener_.reset();
}

void MeshCoreHostObject::registerEventSink() {
  // `this` is stable for as long as the sink is registered: invalidate()
  // unregisters, and Rust holds its sink lock across the callback, so once
  // mesh_core_set_event_sink(NULL) returns no trampoline can be in flight.
  mesh_core_set_event_sink(handle_, &MeshCoreHostObject::eventTrampoline, this);
}

void MeshCoreHostObject::invalidate() {
  bool expected = true;
  if (!valid_.compare_exchange_strong(expected, false)) {
    return;  // already invalidated
  }
  // Order matters: unregister first (this blocks until any in-flight event
  // callback has returned), then forget the handle.
  if (handle_ != nullptr) {
    mesh_core_set_event_sink(handle_, nullptr, nullptr);
  }
  // MUST null the handle, not merely flip valid_. Both platform modules call
  // invalidate() and then immediately free the core, but the JS runtime still
  // owns this object through `global.__MeshCore` and can keep calling in — a UI
  // polling `pendingCount` on a timer is the obvious case, and c_api.rs invites
  // exactly that. Every host function below would then dereference freed
  // memory. The Rust side already null-checks every entry point (the `handle!`
  // macro returns MESH_STATUS_NULL_HANDLE, and the accessors return 0/false),
  // so this one store turns a use-after-free into a defined no-op.
  handle_ = nullptr;

  // `listener_` is deliberately NOT reset here. It holds a jsi::Function, and
  // ~jsi::Function mutates the runtime's managed-value list — which is only
  // legal on the JS thread. invalidate() is called from the platform module's
  // thread (RN's method queue on iOS, the UI thread on Android), so dropping it
  // here would race Hermes' internal free list and corrupt the heap. The
  // destructor does it instead: this object is owned by the runtime, so
  // ~MeshCoreHostObject runs on the JS thread by construction.
}

// ---------------------------------------------------------------------------
// Event delivery: Rust worker thread -> JS thread
// ---------------------------------------------------------------------------

void MeshCoreHostObject::eventTrampoline(void* ctx,
                                         uint32_t kind,
                                         MeshBuffer payload) {
  static_cast<MeshCoreHostObject*>(ctx)->onEvent(kind, payload);
}

void MeshCoreHostObject::onEvent(uint32_t kind, MeshBuffer payload) {
  // FIRST thing, before any early return: take ownership of the Rust
  // allocation in an RAII type. Every path out of this function now frees it
  // exactly once, including exceptions and the "we're shutting down" path.
  auto owned = std::make_shared<MeshRustBuffer>(payload);

  if (!valid_.load(std::memory_order_acquire) || callInvoker_ == nullptr) {
    dropped_.fetch_add(1, std::memory_order_relaxed);
    return;  // `owned` frees the buffer here
  }

  // A weak_ptr, not `this`: the host object can be destroyed between posting
  // and running if the runtime tears down. If the lock() fails we drop the
  // event instead of writing into freed memory.
  std::weak_ptr<MeshCoreHostObject> weak = weak_from_this();

  callInvoker_->invokeAsync([weak, kind, owned]() {
    auto self = weak.lock();
    if (!self || !self->valid_.load(std::memory_order_acquire)) {
      return;
    }
    std::shared_ptr<jsi::Function> listener;
    {
      std::lock_guard<std::mutex> lock(self->listenerMutex_);
      listener = self->listener_;
    }
    if (!listener) {
      self->dropped_.fetch_add(1, std::memory_order_relaxed);
      return;
    }

    jsi::Runtime& rt = *self->runtime_;
    try {
      // The ArrayBuffer shares `owned`'s storage — still zero-copy. JS holding
      // onto the buffer keeps the Rust allocation alive, which is exactly the
      // semantics you want.
      auto arrayBuffer = jsi::ArrayBuffer(rt, owned);
      listener->call(rt, jsi::Value(static_cast<int>(kind)),
                     jsi::Value(rt, arrayBuffer));
    } catch (const jsi::JSError& e) {
      // A throwing JS listener must not take down the native thread.
      self->dropped_.fetch_add(1, std::memory_order_relaxed);
    }
  });
}

// ---------------------------------------------------------------------------
// Property surface
// ---------------------------------------------------------------------------

jsi::Value MeshCoreHostObject::throwLastError(jsi::Runtime& rt,
                                              const char* what) {
  throw jsi::JSError(rt, std::string(what) + ": " + lastError());
}

std::vector<jsi::PropNameID> MeshCoreHostObject::getPropertyNames(
    jsi::Runtime& rt) {
  std::vector<std::string> names{
      "abiVersion", "publicKey",   "start", "stop",  "isRunning",
      "send",       "receive",     "peers", "setEventListener",
      "droppedEvents", "outboxLen"};
  std::vector<jsi::PropNameID> out;
  out.reserve(names.size());
  for (auto& n : names) {
    out.push_back(jsi::PropNameID::forUtf8(rt, n));
  }
  return out;
}

jsi::Value MeshCoreHostObject::get(jsi::Runtime& rt,
                                   const jsi::PropNameID& propName) {
  const std::string name = propName.utf8(rt);

  if (name == "abiVersion") {
    return jsi::Value(static_cast<int>(mesh_abi_version()));
  }

  if (name == "droppedEvents") {
    return jsi::Value(
        static_cast<double>(dropped_.load(std::memory_order_relaxed)));
  }

  if (name == "outboxLen") {
    return jsi::Value(static_cast<double>(mesh_outbox_len(handle_)));
  }

  if (name == "publicKey") {
    return fn(rt, "publicKey", 0,
              [this](jsi::Runtime& rt, const jsi::Value&, const jsi::Value*,
                     size_t) -> jsi::Value {
                // 32 bytes: cheaper to let JS own a fresh ArrayBuffer than to
                // round-trip an allocation through Rust.
                auto ctor = rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
                auto ab = ctor.callAsConstructor(rt, 32).getObject(rt).getArrayBuffer(rt);
                if (mesh_core_public_key(handle_, ab.data(rt)) != MESH_STATUS_OK) {
                  return throwLastError(rt, "publicKey");
                }
                return jsi::Value(rt, ab);
              });
  }

  if (name == "start") {
    return fn(rt, "start", 0,
              [this](jsi::Runtime& rt, const jsi::Value&, const jsi::Value*,
                     size_t) -> jsi::Value {
                if (mesh_start_broadcasting(handle_) != MESH_STATUS_OK) {
                  return throwLastError(rt, "start");
                }
                return jsi::Value::undefined();
              });
  }

  if (name == "stop") {
    return fn(rt, "stop", 0,
              [this](jsi::Runtime& rt, const jsi::Value&, const jsi::Value*,
                     size_t) -> jsi::Value {
                if (mesh_stop_broadcasting(handle_) != MESH_STATUS_OK) {
                  return throwLastError(rt, "stop");
                }
                return jsi::Value::undefined();
              });
  }

  if (name == "isRunning") {
    return fn(rt, "isRunning", 0,
              [this](jsi::Runtime&, const jsi::Value&, const jsi::Value*,
                     size_t) -> jsi::Value {
                return jsi::Value(mesh_is_running(handle_));
              });
  }

  // send(peerId: ArrayBuffer | null, body: ArrayBuffer) -> ArrayBuffer(16)
  //
  // Fully synchronous and zero-copy on the way in: Rust reads straight out of
  // the JS heap and copies once into its worker queue. No Promise, no bridge
  // serialization, no base64 — this is the whole reason for using JSI here.
  if (name == "send") {
    return fn(rt, "send", 2,
              [this](jsi::Runtime& rt, const jsi::Value&,
                     const jsi::Value* args, size_t count) -> jsi::Value {
                if (count < 2) {
                  throw jsi::JSError(rt, "send(peerId, body) requires 2 args");
                }
                BorrowedBytes peer = borrowBytes(rt, args[0]);
                BorrowedBytes body = borrowBytes(rt, args[1]);
                if (body.ptr == nullptr || body.len == 0) {
                  throw jsi::JSError(rt, "send: body must be a non-empty ArrayBuffer");
                }
                if (peer.ptr != nullptr && peer.len != 32) {
                  throw jsi::JSError(rt, "send: peerId must be exactly 32 bytes");
                }

                auto ctor = rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
                auto out = ctor.callAsConstructor(rt, 16).getObject(rt).getArrayBuffer(rt);

                if (mesh_send_message(handle_, peer.ptr, body.ptr, body.len,
                                      out.data(rt)) != MESH_STATUS_OK) {
                  return throwLastError(rt, "send");
                }
                return jsi::Value(rt, out);
              });
  }

  // receive() -> ArrayBuffer | null. Synchronous drain of anything queued while
  // no listener was attached (e.g. the app was backgrounded).
  if (name == "receive") {
    return fn(rt, "receive", 0,
              [this](jsi::Runtime& rt, const jsi::Value&, const jsi::Value*,
                     size_t) -> jsi::Value {
                MeshBuffer buf{nullptr, 0, 0};
                if (mesh_receive_message(handle_, &buf) != MESH_STATUS_OK) {
                  return throwLastError(rt, "receive");
                }
                return adoptAsArrayBuffer(rt, buf);
              });
  }

  if (name == "peers") {
    return fn(rt, "peers", 0,
              [this](jsi::Runtime& rt, const jsi::Value&, const jsi::Value*,
                     size_t) -> jsi::Value {
                MeshBuffer buf{nullptr, 0, 0};
                if (mesh_peers(handle_, &buf) != MESH_STATUS_OK) {
                  return throwLastError(rt, "peers");
                }
                return adoptAsArrayBuffer(rt, buf);
              });
  }

  // setEventListener(fn | null)
  if (name == "setEventListener") {
    return fn(rt, "setEventListener", 1,
              [this](jsi::Runtime& rt, const jsi::Value&,
                     const jsi::Value* args, size_t count) -> jsi::Value {
                std::lock_guard<std::mutex> lock(listenerMutex_);
                if (count == 0 || args[0].isNull() || args[0].isUndefined()) {
                  listener_.reset();
                  return jsi::Value::undefined();
                }
                listener_ = std::make_shared<jsi::Function>(
                    args[0].asObject(rt).asFunction(rt));
                return jsi::Value::undefined();
              });
  }

  return jsi::Value::undefined();
}

// ---------------------------------------------------------------------------

std::shared_ptr<MeshCoreHostObject> MeshCoreHostObject::install(
    jsi::Runtime& rt,
    MeshHandle* handle,
    std::shared_ptr<react::CallInvoker> callInvoker) {
  auto host = std::make_shared<MeshCoreHostObject>(handle, std::move(callInvoker), &rt);
  host->registerEventSink();
  rt.global().setProperty(
      rt, "__MeshCore",
      jsi::Object::createFromHostObject(rt, host));
  return host;
}

}  // namespace meshcore
