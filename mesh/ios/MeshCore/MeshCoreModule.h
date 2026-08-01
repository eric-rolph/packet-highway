// MeshCoreModule.h
//
// The Turbo Module. Deliberately thin: it owns the Rust core's lifetime and
// installs the JSI HostObject. Every hot-path call goes through
// `global.__MeshCore` (see MeshCoreHostObject), not through this module —
// a Turbo Module call still crosses a codegen'd C++ shim per argument, which is
// fine for `initialize()` and wrong for a per-message send.

#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

@interface MeshCoreModule : NSObject <RCTBridgeModule>
@end
