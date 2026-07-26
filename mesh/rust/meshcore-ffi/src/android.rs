//! Android JNI surface.
//!
//! ## Why the radio vtable is implemented in Rust here, but in Objective-C++ on iOS
//!
//! On iOS the radio *has* to live in ObjC — CoreBluetooth needs an
//! `NSObject`-conforming delegate — so the natural place for the vtable is the
//! `.mm` file, and Rust just calls C function pointers.
//!
//! On Android the radio lives in Kotlin, and reaching Kotlin means JNI. Doing
//! that from C++ would mean hand-writing `AttachCurrentThread`, method-id
//! caching and local-reference frames. The `jni` crate already does all three
//! correctly, so [`AndroidRadio`] implements `PlatformRadio` directly and the
//! C++ layer on Android is left doing nothing but JSI.
//!
//! Both paths converge on the same `meshcore::PlatformRadio` trait, so the core
//! is identical on the two platforms.
//!
//! ## JNI reference hygiene
//!
//! * `radio` is a **global ref**, released exactly once when `AndroidRadio` is
//!   dropped (which happens when `mesh_core_free`/`nativeDestroy` joins the
//!   worker thread).
//! * Every upcall creates local refs (the `jbyteArray` we pass down). They are
//!   freed when the `AttachGuard` scope ends. The worker thread is a Rust
//!   thread, so without an explicit frame those locals would accumulate on the
//!   attached thread's local table until detach — the per-call attach guard is
//!   what bounds that.

use std::sync::Arc;

use jni::objects::{
    GlobalRef, JByteArray, JByteBuffer, JClass, JObject, JString, JValue, ReleaseMode,
};
use jni::sys::{jboolean, jint, jlong, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};

use meshcore::{Config, CoreError, PeerId, PlatformRadio};

use crate::c_api::{set_last_error, MeshHandle, MeshStatus};

// ---------------------------------------------------------------------------
// Radio bridge: Rust -> Kotlin
// ---------------------------------------------------------------------------

/// Mirrors the Kotlin interface `com.meshcore.MeshRadio`.
struct AndroidRadio {
    vm: JavaVM,
    radio: GlobalRef,
}

impl AndroidRadio {
    fn call_bool(&self, method: &str, sig: &str, args: &[JValue]) -> Result<(), CoreError> {
        // Attaching an already-attached thread is a cheap no-op; the guard
        // bounds the local-reference table for this call.
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| CoreError::Radio(format!("attach: {e}")))?;

        let ok = env
            .call_method(&self.radio, method, sig, args)
            .and_then(|v| v.z())
            .map_err(|e| {
                // A pending Java exception poisons every later JNI call on this
                // thread, so clear it before returning.
                let _ = env.exception_clear();
                CoreError::Radio(format!("{method}: {e}"))
            })?;

        if ok {
            Ok(())
        } else {
            Err(CoreError::Radio(format!("{method} returned false")))
        }
    }
}

impl PlatformRadio for AndroidRadio {
    fn start_advertising(&self, payload: &[u8]) -> Result<(), CoreError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| CoreError::Radio(format!("attach: {e}")))?;
        let arr = env
            .byte_array_from_slice(payload)
            .map_err(|e| CoreError::Radio(format!("byte_array_from_slice: {e}")))?;
        let obj: &JObject = arr.as_ref();
        let ok = env
            .call_method(&self.radio, "startAdvertising", "([B)Z", &[JValue::Object(obj)])
            .and_then(|v| v.z())
            .map_err(|e| {
                let _ = env.exception_clear();
                CoreError::Radio(format!("startAdvertising: {e}"))
            })?;
        if ok {
            Ok(())
        } else {
            Err(CoreError::Radio("startAdvertising returned false".into()))
        }
    }

    fn stop_advertising(&self) -> Result<(), CoreError> {
        self.call_bool("stopAdvertising", "()Z", &[])
    }

    fn start_scanning(&self) -> Result<(), CoreError> {
        self.call_bool("startScanning", "()Z", &[])
    }

    fn stop_scanning(&self) -> Result<(), CoreError> {
        self.call_bool("stopScanning", "()Z", &[])
    }

    fn send_direct(&self, peer: &PeerId, payload: &[u8]) -> Result<(), CoreError> {
        let mut env = self
            .vm
            .attach_current_thread()
            .map_err(|e| CoreError::Radio(format!("attach: {e}")))?;
        let peer_arr = env
            .byte_array_from_slice(peer)
            .map_err(|e| CoreError::Radio(format!("peer array: {e}")))?;
        let data_arr = env
            .byte_array_from_slice(payload)
            .map_err(|e| CoreError::Radio(format!("data array: {e}")))?;
        let p: &JObject = peer_arr.as_ref();
        let d: &JObject = data_arr.as_ref();
        let ok = env
            .call_method(
                &self.radio,
                "sendDirect",
                "([B[B)Z",
                &[JValue::Object(p), JValue::Object(d)],
            )
            .and_then(|v| v.z())
            .map_err(|e| {
                let _ = env.exception_clear();
                CoreError::Radio(format!("sendDirect: {e}"))
            })?;
        if ok {
            Ok(())
        } else {
            Err(CoreError::UnknownPeer)
        }
    }
}

// ---------------------------------------------------------------------------
// Handle marshalling
// ---------------------------------------------------------------------------

/// Kotlin holds the core as a `Long`. This is the only place that cast lives.
fn as_handle<'a>(handle: jlong) -> Option<&'a MeshHandle> {
    if handle == 0 {
        None
    } else {
        unsafe { (handle as *mut MeshHandle).as_ref() }
    }
}

// ---------------------------------------------------------------------------
// Exports — com.meshcore.MeshCoreNative
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    meshcore::ABI_VERSION as jint
}

/// Returns the core pointer as a `jlong`, or 0 on failure (see `nativeLastError`).
#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeCreate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    nickname: JString<'local>,
    seed: JByteArray<'local>,
    ttl: jint,
    radio: JObject<'local>,
) -> jlong {
    let vm = match env.get_java_vm() {
        Ok(vm) => vm,
        Err(e) => {
            set_last_error(format!("get_java_vm: {e}"));
            return 0;
        }
    };
    let radio_ref = match env.new_global_ref(&radio) {
        Ok(r) => r,
        Err(e) => {
            set_last_error(format!("new_global_ref: {e}"));
            return 0;
        }
    };

    let nickname: String = match env.get_string(&nickname) {
        Ok(s) => s.into(),
        Err(_) => String::from("anon"),
    };

    let identity_seed = if seed.is_null() {
        None
    } else {
        match env.convert_byte_array(&seed) {
            Ok(v) if v.len() == 32 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&v);
                Some(s)
            }
            _ => None,
        }
    };

    let cfg = Config {
        nickname,
        identity_seed,
        ttl: if ttl <= 0 || ttl > 255 { 6 } else { ttl as u8 },
    };

    let radio = Arc::new(AndroidRadio { vm, radio: radio_ref });
    match MeshHandle::new_internal(cfg, radio) {
        Ok(handle) => Box::into_raw(handle) as jlong,
        Err(e) => {
            set_last_error(e.to_string());
            0
        }
    }
}

/// Joins the worker thread and releases the global ref to the Kotlin radio.
/// Kotlin must null its `handle` field immediately after calling this.
#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    unsafe { drop(Box::from_raw(handle as *mut MeshHandle)) };
}

#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeStart(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match as_handle(handle) {
        Some(h) => match h.core().start_broadcasting() {
            Ok(()) => MeshStatus::Ok as jint,
            Err(e) => {
                set_last_error(e.to_string());
                MeshStatus::from(e) as jint
            }
        },
        None => MeshStatus::NullHandle as jint,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match as_handle(handle) {
        Some(h) => match h.core().stop_broadcasting() {
            Ok(()) => MeshStatus::Ok as jint,
            Err(e) => {
                set_last_error(e.to_string());
                MeshStatus::from(e) as jint
            }
        },
        None => MeshStatus::NullHandle as jint,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeIsRunning(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    match as_handle(handle) {
        Some(h) if h.core().is_running() => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativePublicKey<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> JByteArray<'local> {
    match as_handle(handle) {
        Some(h) => env.byte_array_from_slice(&h.core().public_key()).unwrap_or_default(),
        None => JByteArray::default(),
    }
}

/// Returns the 16-byte message id, or null on failure.
#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeSend<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    peer: JByteArray<'local>,
    body: JByteArray<'local>,
) -> JByteArray<'local> {
    let Some(h) = as_handle(handle) else {
        set_last_error("null handle");
        return JByteArray::default();
    };

    let to = if peer.is_null() {
        None
    } else {
        match env.convert_byte_array(&peer) {
            Ok(v) if v.len() == 32 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(&v);
                Some(id)
            }
            _ => {
                set_last_error("peer id must be 32 bytes");
                return JByteArray::default();
            }
        }
    };

    // `convert_byte_array` copies. That is acceptable on the *outbound* path,
    // which is user-typed-message rate; the inbound path below avoids it.
    let Ok(body) = env.convert_byte_array(&body) else {
        set_last_error("bad body array");
        return JByteArray::default();
    };

    match h.core().send_message(to, &body) {
        Ok(msg_id) => env.byte_array_from_slice(&msg_id).unwrap_or_default(),
        Err(e) => {
            set_last_error(e.to_string());
            JByteArray::default()
        }
    }
}

/// Inbound advertisement via a `byte[]`.
///
/// Uses a JNI *critical* section so the JVM hands back the array's real storage
/// instead of a copy whenever the GC allows it. The section is held for the
/// length of one `memcpy` into the worker queue — never across a callback, an
/// allocation, or a lock, all of which can deadlock a critical region.
#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeIngest(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    rssi: jint,
    data: JByteArray,
    len: jint,
) -> jint {
    let Some(h) = as_handle(handle) else {
        return MeshStatus::NullHandle as jint;
    };
    if data.is_null() || len <= 0 {
        return MeshStatus::InvalidArgument as jint;
    }

    let elements = match unsafe { env.get_array_elements_critical(&data, ReleaseMode::NoCopyBack) }
    {
        Ok(e) => e,
        Err(_) => return MeshStatus::InvalidArgument as jint,
    };
    let available = elements.len().min(len as usize);
    // SAFETY: `elements` is valid for `elements.len()` jbytes; jbyte is i8 and
    // has the same layout as u8.
    let slice = unsafe { std::slice::from_raw_parts(elements.as_ptr() as *const u8, available) };

    match h.core().ingest(rssi as i8, slice) {
        Ok(()) => MeshStatus::Ok as jint,
        Err(e) => {
            set_last_error(e.to_string());
            MeshStatus::from(e) as jint
        }
    }
}

/// Inbound advertisement via a **direct** `ByteBuffer` — the genuinely
/// zero-copy path.
///
/// Allocate one `ByteBuffer.allocateDirect(512)` per scan callback thread in
/// Kotlin, copy the scan record into it once, and call this. No JNI array
/// pinning, no critical section, no per-advertisement allocation on either side
/// of the boundary.
#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeIngestDirect(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buffer: JByteBuffer,
    len: jint,
    rssi: jint,
) -> jint {
    let Some(h) = as_handle(handle) else {
        return MeshStatus::NullHandle as jint;
    };
    if len <= 0 {
        return MeshStatus::InvalidArgument as jint;
    }

    let (Ok(ptr), Ok(cap)) =
        (env.get_direct_buffer_address(&buffer), env.get_direct_buffer_capacity(&buffer))
    else {
        set_last_error("not a direct ByteBuffer");
        return MeshStatus::InvalidArgument as jint;
    };
    if ptr.is_null() {
        return MeshStatus::InvalidArgument as jint;
    }

    let n = cap.min(len as usize);
    // SAFETY: a direct ByteBuffer's storage is valid for its capacity and is
    // pinned outside the Java heap, so it cannot move under us.
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, n) };

    match h.core().ingest(rssi as i8, slice) {
        Ok(()) => MeshStatus::Ok as jint,
        Err(e) => {
            set_last_error(e.to_string());
            MeshStatus::from(e) as jint
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_meshcore_MeshCoreNative_nativeLastError<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> JString<'local> {
    // Note the thread-local: this must be called on the same thread that saw
    // the failing call, which is how Kotlin uses it (immediately after a
    // non-zero status on the same JNI thread).
    env.new_string(crate::c_api::last_error_string()).unwrap_or_default()
}
