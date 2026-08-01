// MeshCoreModule.mm
//
// Lifecycle owner for the Rust core + JSI installer.
//
// Ordering rules this file exists to enforce:
//
//   initialize()  ->  mesh_core_new         (radio vtable retained by Rust)
//   installJSI()  ->  MeshCoreHostObject    (sink registered, global installed)
//   invalidate()  ->  host->invalidate()    (sink unregistered, barrier)
//                 ->  mesh_core_free        (worker joined, radio released)
//
// Getting that order wrong is the difference between a clean RN reload and a
// crash in Hermes' GC three seconds later.

#import "MeshCoreModule.h"
#import "MeshRadio.h"

#import <React/RCTBridge+Private.h>
#import <React/RCTUtils.h>
#import <ReactCommon/CallInvoker.h>
#import <ReactCommon/RCTTurboModule.h>
#import <jsi/jsi.h>

#import "MeshCoreHostObject.h"

extern "C" {
#include "meshcore.h"
}

using namespace facebook;

/// RN 0.74+ exposes this protocol for modules that install raw JSI bindings.
/// Guarded so the same source compiles against older RN.
#if __has_include(<ReactCommon/RCTTurboModuleWithJSIBindings.h>)
#import <ReactCommon/RCTTurboModuleWithJSIBindings.h>
#define MESH_HAS_JSI_BINDINGS_PROTOCOL 1
@interface MeshCoreModule () <RCTTurboModuleWithJSIBindings>
@end
#endif

@implementation MeshCoreModule {
  MeshHandle *_core;
  MeshRadio *_radio;
  std::shared_ptr<meshcore::MeshCoreHostObject> _host;
}

RCT_EXPORT_MODULE(MeshCore)

@synthesize bridge = _bridge;

/// The JSI install has to happen on the JS thread, and the module has to exist
/// before it. Both are true if we are constructed on the main queue.
+ (BOOL)requiresMainQueueSetup {
  return YES;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Create the Rust core.
///
/// `identitySeedBase64` is the 32-byte seed you persisted in the Keychain, or
/// nil to mint a new identity. Returns the ABI version so JS can assert it
/// matches the version the JS package was built against.
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(initializeCore
                                       : (NSString *)nickname
                                       : (NSString *_Nullable)identitySeedBase64) {
  if (_core != NULL) {
    return @(mesh_abi_version());  // already initialised; idempotent
  }

  _radio = [[MeshRadio alloc] init];

  NSData *nick = [nickname dataUsingEncoding:NSUTF8StringEncoding];
  NSData *seed = identitySeedBase64.length > 0
                     ? [[NSData alloc] initWithBase64EncodedString:identitySeedBase64 options:0]
                     : nil;
  if (seed != nil && seed.length != 32) {
    seed = nil;  // wrong length is a caller bug; generating is safer than truncating
  }

  MeshConfig cfg;
  cfg.nickname = (const uint8_t *)nick.bytes;
  cfg.nickname_len = nick.length;
  cfg.identity_seed = seed != nil ? (const uint8_t *)seed.bytes : NULL;
  cfg.ttl = 6;

  // `nick`/`seed` are only borrowed for this call — Rust copies before it
  // returns, so ARC releasing them right after is fine.
  MeshPlatformRadio vtable = [MeshRadio vtableForRadio:_radio];

  MeshHandle *handle = NULL;
  MeshStatus st = mesh_core_new(&cfg, vtable, &handle);
  if (st != MESH_STATUS_OK || handle == NULL) {
    // Rust never took the vtable, so the CFBridgingRetain in +vtableForRadio:
    // is ours to balance.
    if (vtable.destroy != NULL) {
      vtable.destroy(vtable.ctx);
    }
    _radio = nil;
    @throw [NSException exceptionWithName:@"MeshCoreInitFailed"
                                   reason:[NSString stringWithFormat:@"mesh_core_new: %d", (int)st]
                                 userInfo:nil];
  }

  _core = handle;
  _radio.coreHandle = handle;
  return @(mesh_abi_version());
}

/// Old-architecture / manual install path. On the New Architecture,
/// -installJSIBindingsWithRuntime:callInvoker: below is called for us and this
/// is never needed.
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(installJSI) {
  RCTCxxBridge *cxxBridge = (RCTCxxBridge *)self.bridge;
  if (cxxBridge == nil || cxxBridge.runtime == nullptr) {
    return @NO;
  }
  auto &runtime = *(jsi::Runtime *)cxxBridge.runtime;
  [self installIntoRuntime:runtime callInvoker:cxxBridge.jsCallInvoker];
  return @YES;
}

#ifdef MESH_HAS_JSI_BINDINGS_PROTOCOL
- (void)installJSIBindingsWithRuntime:(jsi::Runtime &)runtime
                          callInvoker:(const std::shared_ptr<react::CallInvoker> &)callInvoker {
  [self installIntoRuntime:runtime callInvoker:callInvoker];
}
#endif

- (void)installIntoRuntime:(jsi::Runtime &)runtime
               callInvoker:(std::shared_ptr<react::CallInvoker>)callInvoker {
  if (_core == NULL) {
    // JS called installJSI() before initializeCore(). Surface it loudly rather
    // than installing a HostObject with a null handle.
    throw jsi::JSError(runtime, "MeshCore: call initializeCore() before installJSI()");
  }
  if (_host != nullptr) {
    _host->invalidate();  // re-install after a reload
    _host.reset();
  }
  _host = meshcore::MeshCoreHostObject::install(runtime, _core, std::move(callInvoker));
}

/// Called by RN on bridge teardown and on every Fast Refresh reload.
- (void)invalidate {
  // Barrier first: after this returns, Rust cannot call into C++ any more.
  if (_host != nullptr) {
    _host->invalidate();
    _host.reset();
  }
  // Then the core. This joins the worker thread and fires the radio's
  // `destroy` callback, releasing the CFBridgingRetain on _radio.
  if (_core != NULL) {
    _radio.coreHandle = NULL;
    mesh_core_free(_core);
    _core = NULL;
  }
  _radio = nil;
}

- (void)dealloc {
  [self invalidate];
}

@end
