// MeshRadio.mm — CoreBluetooth radio behind the Rust vtable.

#import "MeshRadio.h"

#import <os/log.h>

static NSString *const kMeshServiceUUID = @"6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
static NSString *const kMeshFrameCharUUID = @"6E400002-B5A3-F393-E0A9-E50E24DCCA9E";

/// Advertisements arrive on CoreBluetooth's queue at up to a few hundred per
/// second in a crowded room. We reuse one scratch buffer per radio rather than
/// allocating an NSData copy per packet — `mesh_ingest` only borrows it.
static const NSUInteger kScratchCapacity = 512;

@interface MeshRadio () {
  uint8_t _scratch[kScratchCapacity];
}
@property(nonatomic, strong) CBPeripheralManager *peripheral;
@property(nonatomic, strong) CBCentralManager *central;
@property(nonatomic, strong) CBMutableCharacteristic *frameChar;
@property(nonatomic, strong) dispatch_queue_t bleQueue;
@property(nonatomic, strong) NSData *pendingFrame;
@property(nonatomic, strong) NSMutableDictionary<NSString *, CBPeripheral *> *connected;
@property(nonatomic, assign) BOOL serviceAdded;
@end

@implementation MeshRadio

- (instancetype)init {
  if ((self = [super init])) {
    // One serial queue for all CoreBluetooth work. Rust's worker thread calls
    // into us from *its* thread, so every entry point below hops here and
    // returns immediately — the radio never blocks the mesh worker.
    _bleQueue = dispatch_queue_create("com.meshcore.ble", DISPATCH_QUEUE_SERIAL);
    _connected = [NSMutableDictionary dictionary];
    _peripheral = [[CBPeripheralManager alloc] initWithDelegate:self queue:_bleQueue options:nil];
    _central = [[CBCentralManager alloc] initWithDelegate:self queue:_bleQueue options:nil];
  }
  return self;
}

// ---------------------------------------------------------------------------
// Rust -> ObjC (the vtable)
// ---------------------------------------------------------------------------

static int mesh_ios_start_advertising(void *ctx, const uint8_t *payload, size_t len) {
  MeshRadio *radio = (__bridge MeshRadio *)ctx;
  // Copy here, and only here: the pointer Rust handed us is valid only for the
  // duration of this call, and we are about to hand the work to another queue.
  NSData *frame = [NSData dataWithBytes:payload length:len];
  [radio publishFrame:frame];
  return 0;
}

static int mesh_ios_stop_advertising(void *ctx) {
  MeshRadio *radio = (__bridge MeshRadio *)ctx;
  dispatch_async(radio.bleQueue, ^{
    [radio.peripheral stopAdvertising];
  });
  return 0;
}

static int mesh_ios_start_scanning(void *ctx) {
  MeshRadio *radio = (__bridge MeshRadio *)ctx;
  dispatch_async(radio.bleQueue, ^{
    if (radio.central.state != CBManagerStatePoweredOn) {
      return;  // resumes from centralManagerDidUpdateState:
    }
    [radio.central scanForPeripheralsWithServices:@[ [CBUUID UUIDWithString:kMeshServiceUUID] ]
                                          options:@{
                                            // We want every advertisement, not
                                            // one per device: RSSI and rebroadcast
                                            // timing are signal for the mesh.
                                            CBCentralManagerScanOptionAllowDuplicatesKey : @YES
                                          }];
  });
  return 0;
}

static int mesh_ios_stop_scanning(void *ctx) {
  MeshRadio *radio = (__bridge MeshRadio *)ctx;
  dispatch_async(radio.bleQueue, ^{
    [radio.central stopScan];
  });
  return 0;
}

static int mesh_ios_send_direct(void *ctx,
                                const uint8_t *peer,
                                const uint8_t *payload,
                                size_t len) {
  MeshRadio *radio = (__bridge MeshRadio *)ctx;
  NSString *key = [MeshRadio hexKey:peer length:32];
  NSData *frame = [NSData dataWithBytes:payload length:len];
  __block int rc = 0;
  dispatch_sync(radio.bleQueue, ^{
    CBPeripheral *target = radio.connected[key];
    if (target == nil) {
      rc = -1;  // Rust falls back to flooding
      return;
    }
    for (CBService *svc in target.services) {
      for (CBCharacteristic *ch in svc.characteristics) {
        if ([ch.UUID isEqual:[CBUUID UUIDWithString:kMeshFrameCharUUID]]) {
          [target writeValue:frame forCharacteristic:ch type:CBCharacteristicWriteWithoutResponse];
          return;
        }
      }
    }
    rc = -1;
  });
  return rc;
}

/// Balances the CFBridgingRetain in +vtableForRadio:. Called by Rust exactly
/// once, from `mesh_core_free`, after the worker thread has joined — so no
/// callback can be in flight when the radio is released.
static void mesh_ios_destroy(void *ctx) {
  CFBridgingRelease(ctx);
}

+ (MeshPlatformRadio)vtableForRadio:(MeshRadio *)radio {
  MeshPlatformRadio vt;
  vt.ctx = (void *)CFBridgingRetain(radio);
  vt.start_advertising = mesh_ios_start_advertising;
  vt.stop_advertising = mesh_ios_stop_advertising;
  vt.start_scanning = mesh_ios_start_scanning;
  vt.stop_scanning = mesh_ios_stop_scanning;
  vt.send_direct = mesh_ios_send_direct;
  vt.destroy = mesh_ios_destroy;
  return vt;
}

// ---------------------------------------------------------------------------
// Publishing a frame
// ---------------------------------------------------------------------------

- (void)publishFrame:(NSData *)frame {
  dispatch_async(self.bleQueue, ^{
    self.pendingFrame = frame;

    if (self.peripheral.state != CBManagerStatePoweredOn) {
      return;  // retried from peripheralManagerDidUpdateState:
    }
    [self ensureServiceAdded];

    // Push to anyone subscribed. Returns NO when the transmit queue is full;
    // CoreBluetooth then calls -peripheralManagerIsReadyToUpdateSubscribers:.
    if (self.frameChar != nil) {
      [self.peripheral updateValue:frame
                 forCharacteristic:self.frameChar
              onSubscribedCentrals:nil];
    }

    // Keep the discovery beacon up. Note what is NOT here: the frame itself.
    // iOS ignores manufacturer data, so the advertisement is discovery-only.
    if (!self.peripheral.isAdvertising) {
      [self.peripheral startAdvertising:@{
        CBAdvertisementDataServiceUUIDsKey : @[ [CBUUID UUIDWithString:kMeshServiceUUID] ]
      }];
    }
  });
}

- (void)ensureServiceAdded {
  if (self.serviceAdded) {
    return;
  }
  self.frameChar = [[CBMutableCharacteristic alloc]
      initWithType:[CBUUID UUIDWithString:kMeshFrameCharUUID]
        properties:CBCharacteristicPropertyNotify | CBCharacteristicPropertyWriteWithoutResponse |
                   CBCharacteristicPropertyRead
             value:nil
       permissions:CBAttributePermissionsReadable | CBAttributePermissionsWriteable];

  CBMutableService *svc =
      [[CBMutableService alloc] initWithType:[CBUUID UUIDWithString:kMeshServiceUUID] primary:YES];
  svc.characteristics = @[ self.frameChar ];
  [self.peripheral addService:svc];
  self.serviceAdded = YES;
}

// ---------------------------------------------------------------------------
// ObjC -> Rust (inbound)
// ---------------------------------------------------------------------------

/// The one inbound funnel. Copies into the per-radio scratch buffer and lends
/// it to Rust; nothing is allocated per advertisement.
- (void)ingest:(NSData *)data rssi:(int8_t)rssi {
  if (self.coreHandle == NULL || data.length == 0) {
    return;
  }
  NSUInteger n = MIN(data.length, kScratchCapacity);
  [data getBytes:_scratch length:n];
  MeshStatus st = mesh_ingest(self.coreHandle, rssi, _scratch, n);
  if (st != MESH_STATUS_OK && st != MESH_STATUS_FRAME) {
    // MESH_STATUS_FRAME just means "not one of ours" — the air is full of
    // other people's advertisements and that is not worth logging.
    os_log_error(OS_LOG_DEFAULT, "meshcore ingest failed: %d", (int)st);
  }
}

#pragma mark - CBCentralManagerDelegate

- (void)centralManagerDidUpdateState:(CBCentralManager *)central {
  if (central.state == CBManagerStatePoweredOn) {
    mesh_ios_start_scanning((__bridge void *)self);
  }
}

- (void)centralManager:(CBCentralManager *)central
    didDiscoverPeripheral:(CBPeripheral *)peripheral
        advertisementData:(NSDictionary<NSString *, id> *)advertisementData
                     RSSI:(NSNumber *)RSSI {
  // The advertisement carries no frame (see the header). Discovering a peer
  // means connecting to read its characteristic.
  peripheral.delegate = self;
  if (peripheral.state == CBPeripheralStateDisconnected) {
    [central connectPeripheral:peripheral options:nil];
  }
}

- (void)centralManager:(CBCentralManager *)central
    didConnectPeripheral:(CBPeripheral *)peripheral {
  [peripheral discoverServices:@[ [CBUUID UUIDWithString:kMeshServiceUUID] ]];
}

- (void)centralManager:(CBCentralManager *)central
    didDisconnectPeripheral:(CBPeripheral *)peripheral
                      error:(NSError *)error {
  [self.connected removeObjectsForKeys:[self.connected allKeysForObject:peripheral]];
}

#pragma mark - CBPeripheralDelegate

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(NSError *)error {
  for (CBService *svc in peripheral.services) {
    [peripheral discoverCharacteristics:@[ [CBUUID UUIDWithString:kMeshFrameCharUUID ] ]
                             forService:svc];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral
    didDiscoverCharacteristicsForService:(CBService *)service
                                   error:(NSError *)error {
  for (CBCharacteristic *ch in service.characteristics) {
    // Subscribe: from here on frames are pushed to us without polling.
    [peripheral setNotifyValue:YES forCharacteristic:ch];
  }
}

- (void)peripheral:(CBPeripheral *)peripheral
    didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic
                              error:(NSError *)error {
  if (error != nil || characteristic.value == nil) {
    return;
  }
  // RSSI is read separately and asynchronously; -80 is a conservative default
  // until readRSSI: comes back.
  [self ingest:characteristic.value rssi:-80];

  // The frame's sender key is what identifies the peer, so the connection map
  // is keyed off it once we have seen a valid frame.
  [peripheral readRSSI];
}

- (void)peripheral:(CBPeripheral *)peripheral
    didReadRSSI:(NSNumber *)RSSI
          error:(NSError *)error {
  // Nothing to do; kept so RSSI reads do not log "unhandled delegate callback".
}

#pragma mark - CBPeripheralManagerDelegate

- (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral {
  if (peripheral.state == CBManagerStatePoweredOn && self.pendingFrame != nil) {
    [self publishFrame:self.pendingFrame];
  }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral
    didReceiveWriteRequests:(NSArray<CBATTRequest *> *)requests {
  for (CBATTRequest *req in requests) {
    [self ingest:req.value rssi:-60];
  }
  [peripheral respondToRequest:requests.firstObject withResult:CBATTErrorSuccess];
}

- (void)peripheralManagerIsReadyToUpdateSubscribers:(CBPeripheralManager *)peripheral {
  if (self.pendingFrame != nil && self.frameChar != nil) {
    [peripheral updateValue:self.pendingFrame
          forCharacteristic:self.frameChar
       onSubscribedCentrals:nil];
  }
}

#pragma mark - Helpers

+ (NSString *)hexKey:(const uint8_t *)bytes length:(size_t)len {
  NSMutableString *s = [NSMutableString stringWithCapacity:len * 2];
  for (size_t i = 0; i < len; i++) {
    [s appendFormat:@"%02x", bytes[i]];
  }
  return s;
}

@end
