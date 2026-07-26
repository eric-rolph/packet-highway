/**
 * Public API.
 *
 * ```ts
 * import { mesh } from 'react-native-meshcore';
 *
 * await mesh.initialize({ nickname: 'ada' });
 * const off = mesh.on('messageReceived', (e) => {
 *   console.log(peerIdToHex(e.sender), new TextDecoder().decode(e.body));
 * });
 * mesh.start();
 * mesh.send(null, new TextEncoder().encode('hello mesh'));  // broadcast
 * ```
 */
import NativeMeshCore from './NativeMeshCore';
import {
  MESH_ABI_VERSION,
  decodeEvent,
  decodePeers,
  type MeshEvent,
  type PeerInfo,
} from './events';

export * from './events';

/** The JSI HostObject installed by the native module. */
interface MeshCoreJSI {
  readonly abiVersion: number;
  readonly droppedEvents: number;
  publicKey(): ArrayBuffer;
  start(): void;
  stop(): void;
  isRunning(): boolean;
  /** @returns the 16-byte message id */
  send(peerId: ArrayBuffer | Uint8Array | null, body: ArrayBuffer | Uint8Array): ArrayBuffer;
  receive(): ArrayBuffer | null;
  peers(): ArrayBuffer;
  setEventListener(fn: ((kind: number, payload: ArrayBuffer) => void) | null): void;
}

declare global {
  // eslint-disable-next-line no-var
  var __MeshCore: MeshCoreJSI | undefined;
}

type Handler<E extends MeshEvent = MeshEvent> = (event: E) => void;
type EventType = MeshEvent['type'];

export interface InitOptions {
  nickname: string;
  /** 32 bytes, base64. Persist it in the Keychain / Android Keystore. */
  identitySeedBase64?: string | null;
}

class Mesh {
  #jsi: MeshCoreJSI | null = null;
  #handlers = new Map<EventType, Set<Handler<never>>>();

  get initialized(): boolean {
    return this.#jsi !== null;
  }

  /**
   * Create the Rust core and install the JSI binding. Idempotent.
   *
   * Throws if the native ABI version differs from this package's — that
   * mismatch means a stale `.so`/`.a` and would otherwise surface as corrupt
   * events much later and much less obviously.
   */
  initialize(options: InitOptions): void {
    if (this.#jsi) return;

    const nativeAbi = NativeMeshCore.initializeCore(
      options.nickname,
      options.identitySeedBase64 ?? null,
    );
    if (nativeAbi !== MESH_ABI_VERSION) {
      throw new Error(
        `meshcore ABI mismatch: native=${nativeAbi} js=${MESH_ABI_VERSION}. ` +
          'Rebuild the native library (yarn build:ios / build:android).',
      );
    }

    if (!NativeMeshCore.installJSI()) {
      throw new Error('meshcore: JSI install failed (remote debugging enabled?)');
    }
    const jsi = globalThis.__MeshCore;
    if (!jsi) {
      throw new Error('meshcore: __MeshCore missing after install');
    }
    this.#jsi = jsi;

    // One native->JS callback for the whole app. Fan-out happens here in JS,
    // which is cheaper than N registered callbacks crossing the boundary.
    jsi.setEventListener((_kind, payload) => {
      let event: MeshEvent;
      try {
        event = decodeEvent(payload);
      } catch (err) {
        // A decode failure is a native/JS contract break. Surface it rather
        // than dropping it silently.
        console.error('[meshcore] event decode failed', err);
        return;
      }
      const set = this.#handlers.get(event.type);
      if (!set) return;
      for (const h of set) {
        try {
          (h as Handler)(event);
        } catch (err) {
          // One bad subscriber must not stop the others.
          console.error(`[meshcore] handler for ${event.type} threw`, err);
        }
      }
    });

    // Drain anything the core queued before JSI was up (backgrounded app,
    // slow startup). Events queued with no sink still land in Rust's inbox.
    this.drain();
  }

  /** Subscribe. Returns an unsubscribe function. */
  on<T extends EventType>(
    type: T,
    handler: Handler<Extract<MeshEvent, { type: T }>>,
  ): () => void {
    let set = this.#handlers.get(type);
    if (!set) {
      set = new Set();
      this.#handlers.set(type, set);
    }
    set.add(handler as Handler<never>);
    return () => {
      set!.delete(handler as Handler<never>);
    };
  }

  start(): void {
    this.#require().start();
  }

  stop(): void {
    this.#require().stop();
  }

  get running(): boolean {
    return this.#jsi?.isRunning() ?? false;
  }

  /**
   * Send a message. Synchronous and zero-copy: Rust reads `body` straight out
   * of the JS heap. Returns the 16-byte message id so the UI can render an
   * optimistic row immediately and reconcile on `messageDelivered`.
   *
   * @param peerId 32 bytes, or null to broadcast to the whole mesh
   */
  send(peerId: Uint8Array | null, body: Uint8Array): Uint8Array {
    const id = this.#require().send(peerId, body);
    return new Uint8Array(id);
  }

  publicKey(): Uint8Array {
    return new Uint8Array(this.#require().publicKey());
  }

  peers(): PeerInfo[] {
    return decodePeers(this.#require().peers());
  }

  /**
   * Pull queued events synchronously. Called automatically on initialize; call
   * it again on app foreground, when events may have accumulated while the JS
   * thread was suspended.
   */
  drain(): number {
    const jsi = this.#jsi;
    if (!jsi) return 0;
    let n = 0;
    for (;;) {
      const payload = jsi.receive();
      if (!payload) break;
      try {
        const event = decodeEvent(payload);
        const set = this.#handlers.get(event.type);
        if (set) for (const h of set) (h as Handler)(event);
        n++;
      } catch (err) {
        console.error('[meshcore] drain decode failed', err);
        break;
      }
    }
    return n;
  }

  /** Events dropped because no listener was attached or JS threw. */
  get droppedEvents(): number {
    return this.#jsi?.droppedEvents ?? 0;
  }

  /** Android: permissions still needing a runtime request. Empty on iOS. */
  missingPermissions(): string[] {
    const s = NativeMeshCore.missingPermissions();
    return s ? s.split(',') : [];
  }

  #require(): MeshCoreJSI {
    if (!this.#jsi) throw new Error('meshcore: call initialize() first');
    return this.#jsi;
  }
}

export const mesh = new Mesh();
export default mesh;
