/**
 * Binary event decoder. Mirrors `meshcore/src/event.rs` byte for byte.
 *
 * Decoding is `DataView` reads over the ArrayBuffer the native layer handed us,
 * which is *the same allocation Rust wrote into*. `body` and `sender` come back
 * as `Uint8Array` **views**, not copies — `new Uint8Array(buf, offset, len)`
 * does not allocate.
 *
 * The consequence, worth understanding before you hold onto one: any view keeps
 * the entire Rust allocation alive until it is garbage collected. If you only
 * need a few bytes out of a large payload, `.slice()` them and drop the view.
 */

/** Must equal `meshcore::ABI_VERSION`. Asserted at install time. */
export const MESH_ABI_VERSION = 2;

const HEADER_LEN = 16;

export const EventKind = {
  PeerDiscovered: 1,
  PeerLost: 2,
  MessageReceived: 3,
  MessageDelivered: 4,
  TransportState: 5,
  Error: 6,
  MessageExpired: 7,
} as const;

export type EventKindValue = (typeof EventKind)[keyof typeof EventKind];

interface Base {
  seq: number;
  timestamp: number;
}

export interface PeerDiscoveredEvent extends Base {
  type: 'peerDiscovered';
  peer: Uint8Array;
  nickname: string;
  rssi: number;
  hops: number;
}

export interface PeerLostEvent extends Base {
  type: 'peerLost';
  peer: Uint8Array;
}

export interface MessageReceivedEvent extends Base {
  type: 'messageReceived';
  sender: Uint8Array;
  messageId: Uint8Array;
  ttl: number;
  hops: number;
  rssi: number;
  /** Zero-copy view over the decrypted plaintext. */
  body: Uint8Array;
}

export interface MessageDeliveredEvent extends Base {
  type: 'messageDelivered';
  messageId: Uint8Array;
  /** true = handed to a GATT connection, false = flooded. */
  direct: boolean;
}

export interface MessageExpiredEvent extends Base {
  type: 'messageExpired';
  messageId: Uint8Array;
  /** 'no ack' (deadline hit) or 'outbox full' (evicted). */
  reason: string;
}

export interface TransportStateEvent extends Base {
  type: 'transportState';
  running: boolean;
}

export interface ErrorEvent extends Base {
  type: 'error';
  message: string;
}

export type MeshEvent =
  | PeerDiscoveredEvent
  | PeerLostEvent
  | MessageReceivedEvent
  | MessageDeliveredEvent
  | MessageExpiredEvent
  | TransportStateEvent
  | ErrorEvent;

const utf8 = new TextDecoder('utf-8');

/**
 * @throws if the buffer is truncated or carries a version this build cannot
 *         read — both mean a native/JS mismatch, which must fail loudly rather
 *         than produce plausible-looking garbage.
 */
export function decodeEvent(buffer: ArrayBuffer): MeshEvent {
  if (buffer.byteLength < HEADER_LEN) {
    throw new Error(`meshcore: event truncated (${buffer.byteLength} bytes)`);
  }
  const view = new DataView(buffer);

  const version = view.getUint8(0);
  if (version !== MESH_ABI_VERSION) {
    throw new Error(
      `meshcore: event ABI ${version} but JS expects ${MESH_ABI_VERSION} — ` +
        'rebuild the native library',
    );
  }

  const kind = view.getUint8(1);
  const seq = view.getUint32(4, true);
  // Timestamps are u64 ms. getBigUint64 -> Number is exact until year 287396;
  // Number is what every JS date API wants anyway.
  const timestamp = Number(view.getBigUint64(8, true));
  const base: Base = { seq, timestamp };

  let o = HEADER_LEN;

  switch (kind) {
    case EventKind.PeerDiscovered: {
      const peer = new Uint8Array(buffer, o, 32);
      o += 32;
      const rssi = view.getInt8(o++);
      const hops = view.getUint8(o++);
      const nickLen = view.getUint32(o, true);
      o += 4;
      const nickname = utf8.decode(new Uint8Array(buffer, o, nickLen));
      return { ...base, type: 'peerDiscovered', peer, nickname, rssi, hops };
    }

    case EventKind.PeerLost:
      return { ...base, type: 'peerLost', peer: new Uint8Array(buffer, o, 32) };

    case EventKind.MessageReceived: {
      const sender = new Uint8Array(buffer, o, 32);
      o += 32;
      const messageId = new Uint8Array(buffer, o, 16);
      o += 16;
      const ttl = view.getUint8(o++);
      const hops = view.getUint8(o++);
      const rssi = view.getInt8(o++);
      o++; // pad
      const bodyLen = view.getUint32(o, true);
      o += 4;
      const body = new Uint8Array(buffer, o, bodyLen);
      return { ...base, type: 'messageReceived', sender, messageId, ttl, hops, rssi, body };
    }

    case EventKind.MessageDelivered: {
      const messageId = new Uint8Array(buffer, o, 16);
      o += 16;
      return { ...base, type: 'messageDelivered', messageId, direct: view.getUint8(o) !== 0 };
    }

    case EventKind.MessageExpired: {
      const messageId = new Uint8Array(buffer, o, 16);
      o += 16;
      const len = view.getUint32(o, true);
      o += 4;
      const reason = utf8.decode(new Uint8Array(buffer, o, len));
      return { ...base, type: 'messageExpired', messageId, reason };
    }

    case EventKind.TransportState:
      return { ...base, type: 'transportState', running: view.getUint8(o) !== 0 };

    case EventKind.Error: {
      const len = view.getUint32(o, true);
      o += 4;
      return { ...base, type: 'error', message: utf8.decode(new Uint8Array(buffer, o, len)) };
    }

    default:
      throw new Error(`meshcore: unknown event kind ${kind}`);
  }
}

export interface PeerInfo {
  id: Uint8Array;
  nickname: string;
  rssi: number;
  hops: number;
  lastSeen: number;
}

/** Mirrors the layout documented on `mesh_peers` in `c_api.rs`. */
export function decodePeers(buffer: ArrayBuffer): PeerInfo[] {
  if (buffer.byteLength < 4) return [];
  const view = new DataView(buffer);
  const count = view.getUint32(0, true);
  const peers: PeerInfo[] = [];
  let o = 4;
  for (let i = 0; i < count; i++) {
    const id = new Uint8Array(buffer, o, 32);
    o += 32;
    const rssi = view.getInt8(o);
    const hops = view.getUint8(o + 1);
    o += 4; // rssi + hops + 2 pad
    const lastSeen = Number(view.getBigUint64(o, true));
    o += 8;
    const nickLen = view.getUint32(o, true);
    o += 4;
    const nickname = utf8.decode(new Uint8Array(buffer, o, nickLen));
    o += nickLen;
    peers.push({ id, nickname, rssi, hops, lastSeen });
  }
  return peers;
}

/** Peer ids are 32 raw bytes; this is the form you put in a React key. */
export function peerIdToHex(id: Uint8Array): string {
  let s = '';
  for (let i = 0; i < id.length; i++) s += id[i]!.toString(16).padStart(2, '0');
  return s;
}

export function hexToPeerId(hex: string): Uint8Array {
  if (hex.length !== 64) throw new Error('peer id must be 64 hex chars');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
