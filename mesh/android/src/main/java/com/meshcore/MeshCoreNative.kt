package com.meshcore

import java.nio.ByteBuffer

/**
 * Raw JNI surface. One-to-one with the `#[no_mangle] extern "system"` functions
 * in `meshcore-ffi/src/android.rs` — if you change a signature here, change it
 * there, and the host-side `cargo test` will not catch it. That is the one
 * place in this project where a rename can produce an `UnsatisfiedLinkError`
 * instead of a compile error, so keep the two files adjacent in review.
 *
 * Nothing outside this file may hold the `Long` handle. It is a raw pointer;
 * using it after [nativeDestroy] is a use-after-free with no safety net.
 */
internal object MeshCoreNative {

    init {
        // libmeshcore_jsi.so has a DT_NEEDED on libmeshcore_ffi.so, so loading
        // the JSI library pulls the Rust core in with it. Loading in the other
        // order also works; loading only the core would leave JSI uninstalled.
        System.loadLibrary("meshcore_ffi")
        System.loadLibrary("meshcore_jsi")
    }

    external fun nativeAbiVersion(): Int

    /** Returns the core pointer, or 0 on failure (see [nativeLastError]). */
    external fun nativeCreate(
        nickname: String,
        identitySeed: ByteArray?,
        ttl: Int,
        radio: MeshRadio,
    ): Long

    /** Joins the Rust worker thread and releases the global ref to `radio`. */
    external fun nativeDestroy(handle: Long)

    external fun nativeStart(handle: Long): Int
    external fun nativeStop(handle: Long): Int
    external fun nativeIsRunning(handle: Long): Boolean
    external fun nativePublicKey(handle: Long): ByteArray

    /** Returns the 16-byte message id, or null on failure. */
    external fun nativeSend(handle: Long, peer: ByteArray?, body: ByteArray): ByteArray?

    /**
     * Inbound frame from a `byte[]`. Rust pins the array in a JNI critical
     * section for the length of one copy.
     */
    external fun nativeIngest(handle: Long, rssi: Int, data: ByteArray, len: Int): Int

    /**
     * Inbound frame from a **direct** [ByteBuffer] — the zero-copy path.
     * Allocate the buffer once per scanning thread and reuse it; Rust reads
     * straight out of it with no pinning and no allocation.
     */
    external fun nativeIngestDirect(handle: Long, buffer: ByteBuffer, len: Int, rssi: Int): Int

    /** Thread-local: call it on the same thread that saw the failing call. */
    external fun nativeLastError(): String
}
