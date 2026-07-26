# meshcore

Rust core + React Native bridge for a serverless P2P mesh messenger.

**[→ ARCHITECTURE.md](./ARCHITECTURE.md)** — the design: binding-generator
choice, memory ownership across the FFI, threading, wire formats, and an honest
list of what is still scaffolding.

## Quick start

```bash
# Rust core + FFI, host tests (no device)
cargo test --manifest-path rust/Cargo.toml

# Rust encoder ↔ TypeScript decoder contract
cd js && node --test test/decode.test.mjs

# Native artifacts
PROFILE=release bash scripts/build-ios.sh        # -> ios/Frameworks/MeshCore.xcframework
bash scripts/build-android.sh                    # -> android/src/main/jniLibs/<abi>/
```

## Usage

```ts
import { mesh, peerIdToHex } from 'react-native-meshcore';

mesh.initialize({ nickname: 'ada' });

mesh.on('peerDiscovered', (e) => console.log('saw', e.nickname, e.rssi));
mesh.on('messageReceived', (e) =>
  console.log(peerIdToHex(e.sender), new TextDecoder().decode(e.body)),
);

// Directed messages are held until acked, retried with backoff, and reported
// as messageDelivered{direct:true} or messageExpired.
mesh.on('messageDelivered', (e) => console.log('delivered', e.direct));
mesh.on('messageExpired', (e) => console.log('gave up:', e.reason));

mesh.start();
mesh.send(null, new TextEncoder().encode('hello mesh')); // broadcast
mesh.send(peerId, new TextEncoder().encode('just you')); // directed + acked
console.log(mesh.pendingCount, 'awaiting ack');
```

## Shape

```
js/       thin API + binary event decoder
  ↕ JSI (zero-copy ArrayBuffer)         hot path: send / receive / events
  ↕ Turbo Module                        cold path: init / install / permissions
shared/cpp/   one JSI HostObject, compiled by BOTH platforms
  ↕ C ABI (cbindgen-generated header)
rust/meshcore-ffi/   the only crate with #[no_mangle]
rust/meshcore/       pure Rust: framing, X25519+ChaCha20Poly1305, flood routing,
                     anti-replay window, store-and-forward outbox
  ↕ PlatformRadio trait (injected)
ios/MeshRadio.mm     CoreBluetooth
android/MeshRadio.kt BluetoothLe{Scanner,Advertiser}
```

The radio is injected rather than owned by Rust because neither platform
exposes BLE to anything but Objective-C / Java — see ARCHITECTURE.md §0.
