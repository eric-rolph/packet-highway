// MeshCoreHostObject.h
//
// The single JSI binding, shared verbatim by iOS and Android. Installed as
// `global.__MeshCore`. Everything on the hot path (send / receive / events)
// goes through this object; the Turbo Module beside it only handles cold,
// promise-shaped calls (permissions, install, teardown).
//
// Threading:
//   * Every method here is called ON the JS thread, synchronously. Rust's
//     entry points are non-blocking (they push onto an mpsc queue), so this is
//     safe — nothing here can stall a frame on radio IO.
//   * Events arrive FROM the Rust worker thread via a C function pointer. They
//     are hopped onto the JS thread with CallInvoker before any jsi:: type is
//     touched. Touching a Runtime off the JS thread is the #1 way to get
//     nondeterministic Hermes crashes.

#pragma once

#include <ReactCommon/CallInvoker.h>
#include <jsi/jsi.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>

extern "C" {
#include "meshcore.h"
}

namespace meshcore {

namespace jsi = facebook::jsi;
namespace react = facebook::react;

class MeshCoreHostObject : public jsi::HostObject,
                           public std::enable_shared_from_this<MeshCoreHostObject> {
 public:
  /// `handle` is owned by the platform module, not by this object — the module
  /// outlives the JSI runtime on a reload. This object only borrows it, and
  /// unregisters itself from Rust before it dies.
  MeshCoreHostObject(MeshHandle* handle,
                     std::shared_ptr<react::CallInvoker> callInvoker,
                     jsi::Runtime* runtime);

  ~MeshCoreHostObject() override;

  /// Must be called once, after construction, because it needs shared_from_this.
  void registerEventSink();

  /// Idempotent. Call from the platform module before the runtime goes away
  /// (RN reload, app teardown) so no event can land in a dead Runtime.
  void invalidate();

  jsi::Value get(jsi::Runtime& rt, const jsi::PropNameID& name) override;
  std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;

  /// Install `global.__MeshCore`. Returns the host object so the caller can
  /// keep it alive and invalidate it later.
  static std::shared_ptr<MeshCoreHostObject> install(
      jsi::Runtime& rt,
      MeshHandle* handle,
      std::shared_ptr<react::CallInvoker> callInvoker);

 private:
  /// C trampoline registered with `mesh_core_set_event_sink`. Runs on Rust's
  /// worker thread.
  static void eventTrampoline(void* ctx, uint32_t kind, MeshBuffer payload);
  void onEvent(uint32_t kind, MeshBuffer payload);

  jsi::Value throwLastError(jsi::Runtime& rt, const char* what);

  MeshHandle* handle_;
  std::shared_ptr<react::CallInvoker> callInvoker_;
  jsi::Runtime* runtime_;

  /// Guards `listener_`, which is written from the JS thread (setEventListener)
  /// and read from the JS thread (event delivery). The mutex exists for the
  /// teardown race, where invalidate() may run from a different thread.
  std::mutex listenerMutex_;
  std::shared_ptr<jsi::Function> listener_;

  /// Flipped by invalidate(). Checked both before scheduling and again on the
  /// JS thread, because the runtime can die between the two.
  std::atomic<bool> valid_{true};

  /// Dropped-event counter, surfaced as `__MeshCore.droppedEvents` so a
  /// backpressure problem is observable instead of silent.
  std::atomic<uint64_t> dropped_{0};
};

}  // namespace meshcore
