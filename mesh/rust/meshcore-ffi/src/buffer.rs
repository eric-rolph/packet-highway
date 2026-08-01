//! The single ownership primitive that crosses the FFI boundary.
//!
//! # The rule
//!
//! **Whoever allocated it, frees it.** There is exactly one allocator on each
//! side and one free function to match:
//!
//! | Direction | Type | Lifetime | Freed by |
//! |---|---|---|---|
//! | Rust → native | [`MeshBuffer`] (by value) | until `mesh_buffer_free` | **caller** (native), exactly once |
//! | native → Rust | `const uint8_t*, size_t` | the callee's stack frame only | **caller** (native), after return |
//!
//! Rust never frees a pointer it did not allocate, and native code never frees
//! a `MeshBuffer.ptr` with `free()` — the buffer came from Rust's allocator,
//! which on both platforms is a different arena than libc's `malloc`. Calling
//! `free()` on it is heap corruption, not a leak.
//!
//! # Zero copy
//!
//! [`MeshBuffer::from_vec`] does not copy. It disassembles a `Vec<u8>` into
//! `(ptr, len, cap)` and forgets it; `mesh_buffer_free` reassembles the exact
//! same triple. The pointer JS eventually sees in an `ArrayBuffer` is the very
//! allocation Rust wrote the plaintext into.

use std::mem::ManuallyDrop;

/// An owned byte region allocated by Rust and handed to the native layer.
///
/// `cap` is carried alongside `len` because Rust's deallocator needs the exact
/// layout the allocation was made with — this is why native code cannot invent
/// a `MeshBuffer` and pass it to `mesh_buffer_free`.
#[repr(C)]
#[derive(Debug)]
pub struct MeshBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl MeshBuffer {
    /// Transfer ownership of `v`'s allocation to the caller. O(1), no copy.
    pub fn from_vec(v: Vec<u8>) -> Self {
        let mut v = ManuallyDrop::new(v);
        MeshBuffer {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        }
    }

    pub fn empty() -> Self {
        MeshBuffer {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// # Safety
    /// `self` must have come from [`MeshBuffer::from_vec`] and must not have
    /// been freed already.
    pub unsafe fn into_vec(self) -> Vec<u8> {
        if self.ptr.is_null() {
            return Vec::new();
        }
        Vec::from_raw_parts(self.ptr, self.len, self.cap)
    }
}

/// Release a buffer produced by any `mesh_*` function.
///
/// Idempotent only against a *zeroed* struct — calling it twice with the same
/// non-null pointer is a double free. Native wrappers must null the struct
/// after freeing, which is why every wrapper below owns its buffer in an RAII
/// type rather than a bare struct.
///
/// # Safety
/// `buf` must be a value returned by this library and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn mesh_buffer_free(buf: MeshBuffer) {
    drop(buf.into_vec());
}

/// Borrow a native-owned region for the duration of a call.
///
/// # Safety
/// `ptr` must be valid for `len` bytes and stay valid until the caller returns.
pub(crate) unsafe fn borrow<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        // A zero-length slice from a null pointer is UB even though it reads
        // nothing, so an empty payload is represented as `None`, not `&[]`.
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_the_same_allocation() {
        let v = vec![1u8, 2, 3, 4];
        let addr = v.as_ptr();
        let buf = MeshBuffer::from_vec(v);
        assert_eq!(buf.ptr as *const u8, addr, "from_vec must not copy");
        assert_eq!(buf.len, 4);
        let back = unsafe { buf.into_vec() };
        assert_eq!(back, vec![1, 2, 3, 4]);
    }

    #[test]
    fn empty_buffer_frees_cleanly() {
        unsafe { mesh_buffer_free(MeshBuffer::empty()) };
    }

    #[test]
    fn borrow_rejects_null() {
        assert!(unsafe { borrow(std::ptr::null(), 0) }.is_none());
    }
}
