package com.meshcore

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import androidx.core.content.ContextCompat
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.turbomodule.core.CallInvokerHolderImpl

/**
 * Turbo Module: owns the Rust core's lifetime and installs the JSI binding.
 *
 * Everything on the hot path lives on `global.__MeshCore`, not here. A
 * `@ReactMethod` still marshals every argument through the codegen'd bridge —
 * fine for `initializeCore()`, wrong for a per-message `send()`.
 *
 * Teardown order is the load-bearing part of this file:
 *
 *   1. `nativeInvalidateJSI()`  — unregisters the event sink. Rust holds its
 *      sink lock across callbacks, so once this returns no event can be in
 *      flight and the C++ host object is safe to drop.
 *   2. `nativeDestroy(handle)`  — joins the Rust worker thread and releases the
 *      JNI global ref to [MeshRadio].
 *
 * Reversing those two frees the runtime out from under an in-flight event.
 */
class MeshCoreModule(private val reactContext: ReactApplicationContext) :
    ReactContextBaseJavaModule(reactContext) {

    private var handle: Long = 0L
    private var radio: MeshRadio? = null

    override fun getName() = NAME

    // -----------------------------------------------------------------------
    // JNI declared in OnLoad.cpp
    // -----------------------------------------------------------------------
    private external fun nativeInstallJSI(
        runtimePtr: Long,
        callInvokerHolder: Any,
        coreHandle: Long,
    ): Boolean

    private external fun nativeInvalidateJSI()

    // -----------------------------------------------------------------------
    // Cold API
    // -----------------------------------------------------------------------

    /**
     * Create the Rust core. Idempotent. Returns the native ABI version so JS
     * can assert it against its own constant before installing.
     */
    @ReactMethod(isBlockingSynchronousMethod = true)
    fun initializeCore(
        nickname: String,
        identitySeedBase64: String?,
        channelSecretBase64: String?,
    ): Int {
        if (handle != 0L) return MeshCoreNative.nativeAbiVersion()

        val seed = identitySeedBase64
            ?.takeIf { it.isNotEmpty() }
            ?.let { runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull() }
            ?.takeIf { it.size == 32 }   // wrong length: mint a new identity instead of truncating

        // Null means the published open channel — the default is resolved in
        // Rust so all three surfaces agree on what "no secret" means.
        val channel = channelSecretBase64
            ?.takeIf { it.isNotEmpty() }
            ?.let { runCatching { Base64.decode(it, Base64.NO_WRAP) }.getOrNull() }
            ?.takeIf { it.isNotEmpty() }

        val r = MeshRadio(reactContext)
        val h = MeshCoreNative.nativeCreate(nickname, seed, channel, DEFAULT_TTL, r)
        if (h == 0L) {
            throw IllegalStateException("mesh_core_new failed: ${MeshCoreNative.nativeLastError()}")
        }
        r.coreHandle = h
        radio = r
        handle = h
        return MeshCoreNative.nativeAbiVersion()
    }

    /**
     * Install `global.__MeshCore`. Must be called on the JS thread, after
     * [initializeCore].
     */
    @ReactMethod(isBlockingSynchronousMethod = true)
    fun installJSI(): Boolean {
        check(handle != 0L) { "call initializeCore() before installJSI()" }
        val runtimePtr = reactContext.javaScriptContextHolder?.get() ?: return false
        val holder = reactContext.catalystInstance
            ?.jsCallInvokerHolder as? CallInvokerHolderImpl ?: return false
        return nativeInstallJSI(runtimePtr, holder, handle)
    }

    /**
     * The permissions BLE actually needs, which changed twice. Reported to JS
     * so the UI can request them; the radio itself never prompts.
     */
    @ReactMethod(isBlockingSynchronousMethod = true)
    fun missingPermissions(): String {
        val needed = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // API 31+: no location requirement if you declare neverForLocation.
            listOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_ADVERTISE,
                Manifest.permission.BLUETOOTH_CONNECT,
            )
        } else {
            // API 24-30: scanning is gated on *location*, which surprises
            // everyone the first time.
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        return needed.filter {
            ContextCompat.checkSelfPermission(reactContext, it) != PackageManager.PERMISSION_GRANTED
        }.joinToString(",")
    }

    @ReactMethod(isBlockingSynchronousMethod = true)
    fun isBluetoothReady(): Boolean = radio?.isBluetoothReady() ?: false

    override fun invalidate() {
        nativeInvalidateJSI()          // 1. barrier
        val h = handle
        handle = 0L
        radio?.coreHandle = 0L
        if (h != 0L) {
            MeshCoreNative.nativeDestroy(h)  // 2. join worker, release radio ref
        }
        radio = null
        super.invalidate()
    }

    companion object {
        const val NAME = "MeshCore"
        private const val DEFAULT_TTL = 6
    }
}
