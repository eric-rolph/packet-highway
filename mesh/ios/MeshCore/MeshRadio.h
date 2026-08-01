// MeshRadio.h
//
// CoreBluetooth implementation of the `MeshPlatformRadio` vtable.
//
// ## The iOS constraint you have to design around
//
// iOS does **not** let you put arbitrary bytes in a BLE advertisement.
// `CBPeripheralManager startAdvertising:` accepts exactly two keys —
// `CBAdvertisementDataLocalNameKey` and `CBAdvertisementDataServiceUUIDsKey`.
// `CBAdvertisementDataManufacturerDataKey` is silently ignored. In the
// background you lose the local name too, and your service UUID moves into the
// "overflow area" that only other iOS devices can see.
//
// So the frame cannot ride in the advertisement. The split this class
// implements:
//
//   * **Advertisement** = discovery beacon only. Service UUID + a truncated
//     local name. Enough for a peer to find us.
//   * **Frame transport** = a GATT characteristic. We publish the current
//     outbound frame on a notifying characteristic; subscribed centrals get it
//     pushed. Directed sends write to the peer's characteristic.
//
// Android is less restrictive (you can put ~26 bytes of manufacturer data in a
// legacy advertisement, or ~250 with BLE 5 extended advertising), but we use
// the same GATT path there for symmetry — see MeshRadio.kt.

#import <CoreBluetooth/CoreBluetooth.h>
#import <Foundation/Foundation.h>

extern "C" {
#include "meshcore.h"
}

NS_ASSUME_NONNULL_BEGIN

@interface MeshRadio : NSObject <CBPeripheralManagerDelegate, CBCentralManagerDelegate, CBPeripheralDelegate>

/// The core handle, set by MeshCoreModule right after `mesh_core_new` returns.
/// Weak in the ownership sense: the module owns it, the radio only calls into it.
@property(nonatomic, assign) MeshHandle *coreHandle;

/// Build the C vtable pointing at `radio`.
///
/// `ctx` takes a **+1 retain** on the radio via `CFBridgingRetain`, balanced by
/// the `destroy` callback that Rust invokes exactly once when the core is
/// freed. That is what keeps the radio alive for as long as Rust can call it,
/// without leaking it if the module is deallocated first.
+ (MeshPlatformRadio)vtableForRadio:(MeshRadio *)radio;

@end

NS_ASSUME_NONNULL_END
