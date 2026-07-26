/**
 * Contract test: the TypeScript decoder against bytes produced by the *actual*
 * Rust encoder.
 *
 *   node --test test/decode.test.mjs
 *
 * It shells out to `cargo run --example dump_event_fixtures`, so it fails the
 * moment `event.rs` and `events.ts` drift apart — which is the single most
 * likely way this project breaks, since the two files have no compiler between
 * them.
 *
 * The decoder is imported by stripping TS types with the built-in type-stripping
 * in Node 22, so there is one source of truth (src/events.ts) and no compiled
 * copy to go stale.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const here = dirname(fileURLToPath(import.meta.url));
const rustDir = join(here, '..', '..', 'rust');

/**
 * Import src/events.ts directly using Node's built-in type stripping, so the
 * test exercises the exact file the app ships — no compiled copy to go stale.
 * This also keeps events.ts honest about using only erasable TS syntax.
 */
async function importDecoder() {
  return import(pathToFileURL(join(here, '..', 'src', 'events.ts')).href);
}

function fixtures() {
  const out = execFileSync(
    'cargo',
    ['run', '-q', '-p', 'meshcore', '--example', 'dump_event_fixtures'],
    { cwd: rustDir, encoding: 'utf8' },
  );
  return JSON.parse(out);
}

function toArrayBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes.buffer;
}

const { decodeEvent, peerIdToHex, hexToPeerId } = await importDecoder();
const cases = Object.fromEntries(fixtures().map((f) => [f.name, f]));

test('peerDiscovered round-trips, including non-ASCII nicknames', () => {
  const f = cases.peerDiscovered;
  const e = decodeEvent(toArrayBuffer(f.hex));
  assert.equal(e.type, 'peerDiscovered');
  assert.equal(e.seq, f.seq);
  assert.equal(e.timestamp, f.ts);
  assert.equal(e.nickname, 'ada-löve');
  assert.equal(e.rssi, -42, 'rssi must decode as signed');
  assert.equal(e.hops, 3);
  assert.equal(peerIdToHex(e.peer), 'aa'.repeat(32));
});

test('peerLost round-trips', () => {
  const e = decodeEvent(toArrayBuffer(cases.peerLost.hex));
  assert.equal(e.type, 'peerLost');
  assert.equal(peerIdToHex(e.peer), 'aa'.repeat(32));
});

test('messageReceived round-trips with correct body and signed rssi', () => {
  const e = decodeEvent(toArrayBuffer(cases.messageReceived.hex));
  assert.equal(e.type, 'messageReceived');
  assert.equal(peerIdToHex(e.sender), 'aa'.repeat(32));
  assert.equal(peerIdToHex(e.messageId), 'bb'.repeat(16));
  assert.equal(e.ttl, 6);
  assert.equal(e.hops, 2);
  assert.equal(e.rssi, -71);
  assert.equal(new TextDecoder().decode(e.body), 'hello mesh');
});

test('message body is a view, not a copy', () => {
  const buf = toArrayBuffer(cases.messageReceived.hex);
  const e = decodeEvent(buf);
  assert.equal(e.body.buffer, buf, 'body must alias the source ArrayBuffer');
  assert.equal(e.body.byteLength, 10);
});

test('messageDelivered round-trips', () => {
  const e = decodeEvent(toArrayBuffer(cases.messageDelivered.hex));
  assert.equal(e.type, 'messageDelivered');
  assert.equal(e.direct, true);
  assert.equal(peerIdToHex(e.messageId), 'bb'.repeat(16));
});

test('transportState round-trips', () => {
  const e = decodeEvent(toArrayBuffer(cases.transportState.hex));
  assert.equal(e.type, 'transportState');
  assert.equal(e.running, true);
});

test('error round-trips', () => {
  const e = decodeEvent(toArrayBuffer(cases.error.hex));
  assert.equal(e.type, 'error');
  assert.equal(e.message, 'radio failure: scan denied');
});

test('an ABI version bump fails loudly instead of decoding garbage', () => {
  const buf = toArrayBuffer(cases.messageReceived.hex);
  new Uint8Array(buf)[0] = 99;
  assert.throws(() => decodeEvent(buf), /ABI 99/);
});

test('a truncated event throws', () => {
  assert.throws(() => decodeEvent(new ArrayBuffer(8)), /truncated/);
});

test('an unknown event kind throws', () => {
  const buf = toArrayBuffer(cases.transportState.hex);
  new Uint8Array(buf)[1] = 77;
  assert.throws(() => decodeEvent(buf), /unknown event kind 77/);
});

test('peer id hex conversion is symmetric', () => {
  const id = new Uint8Array(32).map((_, i) => i);
  assert.deepEqual(hexToPeerId(peerIdToHex(id)), id);
});
