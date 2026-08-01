/**
 * Turbo Module spec — consumed by React Native's codegen.
 *
 * Note what is *not* here: `send`, `receive`, and the event stream. Those live
 * on the JSI HostObject (`global.__MeshCore`).
 *
 * The split is deliberate:
 *
 *   Turbo Module          JSI HostObject
 *   ------------          --------------
 *   codegen'd C++ shim    direct C++ call
 *   marshals each arg     borrows the ArrayBuffer in place
 *   Promise or blocking   synchronous, no scheduler hop
 *   great for setup       required for per-message traffic
 *
 * A Turbo Module is already far better than the old bridge, but every argument
 * still round-trips through a generated marshaller. For a `Uint8Array` payload
 * arriving at BLE advertisement rates that is the difference between a copy per
 * message and none.
 */
import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  /**
   * Create the Rust core. Idempotent. Returns the native ABI version, which
   * must equal `MESH_ABI_VERSION` in `events.ts`.
   *
   * @param nickname            broadcast in the discovery beacon, truncated to 20 bytes
   * @param identitySeedBase64  32 bytes from the Keychain/Keystore, or null to mint one
   * @param channelSecretBase64 which mesh to join, or null for the published
   *                            open channel that anyone can read
   */
  initializeCore(
    nickname: string,
    identitySeedBase64: string | null,
    channelSecretBase64: string | null,
  ): number;

  /** Install `global.__MeshCore`. Call after `initializeCore`. */
  installJSI(): boolean;

  /** Android only: comma-separated permissions still to request. '' on iOS. */
  missingPermissions(): string;

  isBluetoothReady(): boolean;
}

export default TurboModuleRegistry.getEnforcing<Spec>('MeshCore');
