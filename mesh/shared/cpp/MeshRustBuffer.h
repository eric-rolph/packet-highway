// MeshRustBuffer.h
//
// The zero-copy seam between Rust's allocator and JavaScript's heap.
//
// `jsi::MutableBuffer` lets you hand JS an ArrayBuffer whose storage you own.
// We wrap a `MeshBuffer` (ptr/len/cap from Rust) in one of these, construct
// `jsi::ArrayBuffer` from it, and JS gets a view over *the exact bytes Rust
// wrote the decrypted payload into*. No memcpy, no base64, no JSON.
//
// Ownership: the ArrayBuffer holds a shared_ptr to this object. When Hermes
// garbage-collects the ArrayBuffer, the shared_ptr drops, ~MeshRustBuffer runs,
// and `mesh_buffer_free` returns the allocation to Rust. That is the whole
// lifetime contract — there is no manual free on the JS side and no way to
// forget one.
//
// Two caveats worth knowing before you rely on this:
//
//  1. Release is GC-timed, not deterministic. A burst of large payloads keeps
//     Rust memory alive until the next Hermes GC. For sustained high-rate
//     traffic prefer `copyToArrayBuffer` below, which frees immediately and
//     pays one memcpy — measure before choosing.
//  2. Do not `structuredClone`/transfer the ArrayBuffer in JS. Detaching it
//     while this object still owns the storage is how you get a use-after-free.

#pragma once

#include <jsi/jsi.h>

#include <cstring>
#include <memory>

extern "C" {
#include "meshcore.h"
}

namespace meshcore {

namespace jsi = facebook::jsi;

/// RAII owner of one Rust allocation, exposed to JSI as ArrayBuffer storage.
class MeshRustBuffer : public jsi::MutableBuffer {
 public:
  explicit MeshRustBuffer(MeshBuffer buf) noexcept : buf_(buf) {}

  ~MeshRustBuffer() override {
    // The single free for this allocation. Zero the struct so a double
    // destruction (which would be a bug elsewhere) is a no-op, not a crash.
    mesh_buffer_free(buf_);
    buf_ = MeshBuffer{nullptr, 0, 0};
  }

  // Non-copyable, non-movable: two owners would mean two frees.
  MeshRustBuffer(const MeshRustBuffer&) = delete;
  MeshRustBuffer& operator=(const MeshRustBuffer&) = delete;
  MeshRustBuffer(MeshRustBuffer&&) = delete;
  MeshRustBuffer& operator=(MeshRustBuffer&&) = delete;

  size_t size() const override { return buf_.len; }
  uint8_t* data() override { return buf_.ptr; }

 private:
  MeshBuffer buf_;
};

/// Wrap a Rust buffer as a JS ArrayBuffer without copying. Takes ownership of
/// `buf` unconditionally — even on the empty path, so callers cannot leak by
/// forgetting the null case.
inline jsi::Value adoptAsArrayBuffer(jsi::Runtime& rt, MeshBuffer buf) {
  if (buf.ptr == nullptr || buf.len == 0) {
    mesh_buffer_free(buf);
    return jsi::Value::null();
  }
  return jsi::Value(
      rt, jsi::ArrayBuffer(rt, std::make_shared<MeshRustBuffer>(buf)));
}

/// Copying alternative: one memcpy, but the Rust allocation is returned before
/// this function comes back. Use for small, very high-rate events where GC
/// pressure matters more than the copy.
inline jsi::Value copyToArrayBuffer(jsi::Runtime& rt, MeshBuffer buf) {
  if (buf.ptr == nullptr || buf.len == 0) {
    mesh_buffer_free(buf);
    return jsi::Value::null();
  }
  auto arrayBufferCtor = rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
  auto obj = arrayBufferCtor.callAsConstructor(rt, static_cast<int>(buf.len))
                 .getObject(rt);
  auto ab = obj.getArrayBuffer(rt);
  std::memcpy(ab.data(rt), buf.ptr, buf.len);
  mesh_buffer_free(buf);
  return jsi::Value(rt, ab);
}

/// Borrow a JS ArrayBuffer's storage for the duration of a synchronous call
/// into Rust. Nothing is copied and nothing is retained past the call — this
/// mirrors the `const uint8_t*, size_t` half of the ownership table.
struct BorrowedBytes {
  const uint8_t* ptr = nullptr;
  size_t len = 0;
};

inline BorrowedBytes borrowBytes(jsi::Runtime& rt, const jsi::Value& v) {
  if (v.isNull() || v.isUndefined() || !v.isObject()) {
    return {};
  }
  auto obj = v.getObject(rt);
  if (obj.isArrayBuffer(rt)) {
    auto ab = obj.getArrayBuffer(rt);
    return {ab.data(rt), ab.size(rt)};
  }
  // Accept a TypedArray/DataView by unwrapping its .buffer, honouring
  // byteOffset so a subarray view does not silently read from index 0.
  if (obj.hasProperty(rt, "buffer")) {
    auto inner = obj.getProperty(rt, "buffer");
    if (inner.isObject() && inner.getObject(rt).isArrayBuffer(rt)) {
      auto ab = inner.getObject(rt).getArrayBuffer(rt);
      size_t offset = 0;
      size_t length = ab.size(rt);
      if (obj.hasProperty(rt, "byteOffset")) {
        offset = static_cast<size_t>(obj.getProperty(rt, "byteOffset").asNumber());
      }
      if (obj.hasProperty(rt, "byteLength")) {
        length = static_cast<size_t>(obj.getProperty(rt, "byteLength").asNumber());
      }
      if (offset > ab.size(rt) || offset + length > ab.size(rt)) {
        return {};
      }
      return {ab.data(rt) + offset, length};
    }
  }
  return {};
}

}  // namespace meshcore
