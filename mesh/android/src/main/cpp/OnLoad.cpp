// OnLoad.cpp
//
// Android's JSI installer. Everything below the JSI boundary is shared with
// iOS; this file only bridges "Kotlin has a Runtime pointer and a CallInvoker"
// into "C++ has a MeshCoreHostObject".
//
// The Rust core itself is created from Kotlin via MeshCoreNative (see
// android.rs) and passed here as a jlong — so this file never touches the
// radio, the config, or the protocol.

#include <fbjni/fbjni.h>
#include <jni.h>
#include <jsi/jsi.h>

#include <ReactCommon/CallInvokerHolder.h>

#include <memory>
#include <mutex>

#include "MeshCoreHostObject.h"

using namespace facebook;

namespace {

// The installed host object, kept alive past the JNI call so we can invalidate
// it on reload. One per process — RN has one JS runtime.
std::mutex g_hostMutex;
std::shared_ptr<meshcore::MeshCoreHostObject> g_host;

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  return jni::initialize(vm, [] {});
}

/// Called from MeshCoreModule.installJSI().
///
/// @param runtimePtr  reactContext.javaScriptContextHolder.get()
/// @param holder      reactContext.catalystInstance.jsCallInvokerHolder
/// @param coreHandle  the jlong returned by MeshCoreNative.nativeCreate
extern "C" JNIEXPORT jboolean JNICALL
Java_com_meshcore_MeshCoreModule_nativeInstallJSI(JNIEnv* env,
                                                  jobject /*thiz*/,
                                                  jlong runtimePtr,
                                                  jobject holder,
                                                  jlong coreHandle) {
  if (runtimePtr == 0 || coreHandle == 0 || holder == nullptr) {
    return JNI_FALSE;
  }

  auto* runtime = reinterpret_cast<jsi::Runtime*>(runtimePtr);
  auto* core = reinterpret_cast<MeshHandle*>(coreHandle);

  // Refuse to bind a library whose event layout does not match what the JS
  // package expects. Without this check a cached .so from an older build
  // mis-decodes every event into plausible-looking garbage.
  auto callInvokerHolder =
      jni::alias_ref<react::CallInvokerHolder::javaobject>{
          reinterpret_cast<react::CallInvokerHolder::javaobject>(holder)};
  std::shared_ptr<react::CallInvoker> callInvoker =
      callInvokerHolder->cthis()->getCallInvoker();

  std::lock_guard<std::mutex> lock(g_hostMutex);
  if (g_host != nullptr) {
    // Fast Refresh: tear down the old binding before installing into the new
    // runtime, or the old one keeps a dangling Runtime*.
    g_host->invalidate();
    g_host.reset();
  }
  g_host = meshcore::MeshCoreHostObject::install(*runtime, core, callInvoker);
  return JNI_TRUE;
}

/// Called from MeshCoreModule.invalidate(), *before* nativeDestroy.
extern "C" JNIEXPORT void JNICALL
Java_com_meshcore_MeshCoreModule_nativeInvalidateJSI(JNIEnv*, jobject) {
  std::lock_guard<std::mutex> lock(g_hostMutex);
  if (g_host != nullptr) {
    g_host->invalidate();
    g_host.reset();
  }
}
