package com.meshcore

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.nio.ByteBuffer
import java.util.UUID

/**
 * The Android half of `meshcore::PlatformRadio`. Rust calls these five methods
 * from its worker thread via JNI (see `android.rs`); each one must be
 * thread-safe and must return promptly.
 *
 * Method names and signatures are matched **by string** in `AndroidRadio` on
 * the Rust side — `startAdvertising([B)Z` and friends. Renaming a method here
 * without renaming it there produces a runtime NoSuchMethodError, not a
 * compile error.
 */
@SuppressLint("MissingPermission") // checked in MeshCoreModule before start()
class MeshRadio(private val context: Context) {

    companion object {
        private const val TAG = "MeshRadio"
        val SERVICE_UUID: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")

        /** Legacy ADV_IND leaves ~26 bytes for manufacturer data after the UUID. */
        private const val LEGACY_MANUFACTURER_BUDGET = 26

        /** Bluetooth SIG member id. Use your own; 0xFFFF is the test/dev value. */
        private const val MANUFACTURER_ID = 0xFFFF
    }

    /** Set by [MeshCoreModule] immediately after the core is created. */
    @Volatile
    var coreHandle: Long = 0L

    private val adapter: BluetoothAdapter? =
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)?.adapter

    /**
     * One reusable direct buffer per scan callback thread.
     *
     * Android delivers scan results on a single binder-dispatch thread, but
     * `ThreadLocal` costs nothing and removes the assumption. Reusing it means
     * a crowded room (hundreds of advertisements/second) allocates zero bytes
     * on the Java heap per packet — no GC pressure on the BLE path at all.
     */
    private val scratch = ThreadLocal.withInitial { ByteBuffer.allocateDirect(512) }

    private var advertiser = adapter?.bluetoothLeAdvertiser
    private var scanner = adapter?.bluetoothLeScanner

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
            Log.w(TAG, "advertise failed: $errorCode")
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val handle = coreHandle
            if (handle == 0L) return
            val payload = result.scanRecord
                ?.getManufacturerSpecificData(MANUFACTURER_ID)
                ?: return

            val buf = scratch.get()!!
            buf.clear()
            if (payload.size > buf.capacity()) return
            buf.put(payload)

            // Zero-copy handoff: Rust reads this direct buffer's memory
            // in place, copies once into its worker queue, and returns.
            MeshCoreNative.nativeIngestDirect(handle, buf, payload.size, result.rssi)
        }

        override fun onBatchScanResults(results: MutableList<ScanResult>) {
            results.forEach { onScanResult(ScanSettings.CALLBACK_TYPE_ALL_MATCHES, it) }
        }

        override fun onScanFailed(errorCode: Int) {
            Log.w(TAG, "scan failed: $errorCode")
        }
    }

    // -----------------------------------------------------------------------
    // Called from Rust's worker thread
    // -----------------------------------------------------------------------

    /**
     * Unlike iOS, Android *does* let us put bytes in the advertisement, so
     * short frames go on the air directly. Anything longer needs BLE 5
     * extended advertising (`isLeExtendedAdvertisingSupported`) or a GATT
     * write; we report failure so Rust can decide, rather than silently
     * truncating a frame into an undecryptable one.
     */
    fun startAdvertising(payload: ByteArray): Boolean {
        val adv = advertiser ?: return false
        if (payload.size > LEGACY_MANUFACTURER_BUDGET && !supportsExtendedAdvertising()) {
            Log.w(TAG, "frame ${payload.size}B exceeds legacy budget; needs GATT")
            return false
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(0)
            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false) // the name eats the budget we need
            .addServiceUuid(ParcelUuid(SERVICE_UUID))
            .addManufacturerData(MANUFACTURER_ID, payload)
            .build()

        return try {
            // Restarting is how we replace the payload; there is no
            // "update advertisement" API on the legacy advertiser.
            adv.stopAdvertising(advertiseCallback)
            adv.startAdvertising(settings, data, advertiseCallback)
            true
        } catch (e: Exception) {
            Log.e(TAG, "startAdvertising", e)
            false
        }
    }

    fun stopAdvertising(): Boolean = try {
        advertiser?.stopAdvertising(advertiseCallback)
        true
    } catch (e: Exception) {
        Log.e(TAG, "stopAdvertising", e); false
    }

    fun startScanning(): Boolean {
        val sc = scanner ?: return false
        val filters = listOf(
            ScanFilter.Builder().setServiceUuid(ParcelUuid(SERVICE_UUID)).build()
        )
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            // Every advertisement, not one per device: re-broadcasts and RSSI
            // changes are the mesh's routing signal.
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .setReportDelay(0)
            .build()
        return try {
            sc.startScan(filters, settings, scanCallback); true
        } catch (e: Exception) {
            Log.e(TAG, "startScanning", e); false
        }
    }

    fun stopScanning(): Boolean = try {
        scanner?.stopScan(scanCallback); true
    } catch (e: Exception) {
        Log.e(TAG, "stopScanning", e); false
    }

    /**
     * Directed send over an existing GATT connection. Returning false is not an
     * error — Rust falls back to flooding the frame.
     */
    fun sendDirect(peer: ByteArray, payload: ByteArray): Boolean {
        // A full implementation keeps a peerId -> BluetoothGatt map populated
        // by the connection callbacks and writes the frame characteristic.
        // Until GATT is wired up, flooding is the correct behaviour.
        return false
    }

    private fun supportsExtendedAdvertising(): Boolean =
        adapter?.isLeExtendedAdvertisingSupported == true

    fun isBluetoothReady(): Boolean = adapter?.isEnabled == true
}
