// Turns packet summaries into vehicles.
//
// TIMING-FAITHFUL ROAD: every vehicle in a lane moves at the lane's constant
// speed, so a vehicle's distance from its entry gate is exactly
// (now - arrival_time) × lane_speed — the road is a scrolling timeline and
// same-lane spacing IS real inter-arrival spacing. Packets don't brake, and
// neither do vehicles; because same-lane speeds never differ, overtaking
// (the only way vehicles could ghost through each other) cannot happen.
//
// Collision avoidance is purely positional, at admission time:
//   * a packet arriving while the previous one still occupies the entry
//     window takes the parallel SUB-lane (two files per lane);
//   * if both files are occupied, the burst accumulates into a CONVOY —
//     one road-train = N packets (click it for the breakdown), the same
//     packet→flow shift sFlow/NetFlow make at scale.
// Every packet always counts in the dashboard stats; only visuals aggregate.
import {
  FAIL_RED, FLAG_COLORS, HALF_LEN, HIGHWAY, LANES, LANE_SPEED, PROTO_COLORS,
  TYPE_SPECS, flowKeyOf, laneFor, sublaneX, vehicleTypeFor,
} from './config.js';
import { FlarePool, VehiclePool } from './vehicles.js';

const MAX_CONVOY_SAMPLES = 8;
const GAP_BUFFER = 2.4; // bumper-to-bumper clearance at spawn, world units

// ICMP messages that are error reports, not probes (ride with red bodies)
const ICMP_ERR_V4 = new Set([3, 5, 11, 12]);
const ICMP_ERR_V6 = new Set([1, 2, 3, 4]);

function hash01(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967296;
}

function dimColor(hex) {
  const r = ((hex >> 16) & 255) * 0.16 | 0;
  const g = ((hex >> 8) & 255) * 0.16 | 0;
  const b = (hex & 255) * 0.16 | 0;
  return (r << 16) | (g << 8) | b;
}

export class TrafficController {
  constructor(scene, laneX) {
    this.laneX = laneX;
    this.pools = {};
    for (const type of Object.keys(TYPE_SPECS)) this.pools[type] = new VehiclePool(scene, type);
    this.flares = new FlarePool(scene);
    this.queue = [];            // live batches: [{due, pkt}], due is monotonic
    this.tails = new Map();     // `${lane}|${dir}|${sub}` -> last spawned rec
    this.lastSub = new Map();   // `${lane}|${dir}` -> sub used last (alternate files)
    this.pendingAgg = new Map();// `${lane}|${dir}` -> accumulating burst
    this.spawned = 0;
    this.aggregatedPkts = 0;    // packets that rode inside a convoy
    this.highlightKey = null;   // flow highlight (click a vehicle)
    this.shoulderX = HIGHWAY.medianWidth / 2 + LANES.length * HIGHWAY.laneWidth + HIGHWAY.shoulder * 0.55;
  }

  get meshes() { return [...Object.values(this.pools).map((p) => p.mesh), this.flares.mesh]; }
  get recycled() { return Object.values(this.pools).reduce((n, p) => n + p.recycled, 0); }
  activeCount() { return Object.values(this.pools).reduce((n, p) => n + p.active.size, 0); }

  /** PCAP playback path. */
  ingest(pkt) { this.schedule(pkt); }

  /** Live path: spread a batch over `spreadMs` so arrivals look continuous. */
  ingestBatch(items, spreadMs = 100) {
    const now = performance.now();
    const step = spreadMs / Math.max(items.length, 1);
    for (let i = 0; i < items.length; i++) this.queue.push({ due: now + i * step, pkt: items[i] });
  }

  /** True when a vehicle of length `len` fits at the entry of this sub-lane. */
  roomIn(laneKey, sub, len) {
    const tail = this.tails.get(`${laneKey}|${sub}`);
    if (!tail || tail.gone) return true;
    const spawnZ = -tail.dirSign * (HALF_LEN + 4);
    return (tail.z - spawnZ) * tail.dirSign >= (tail.len + len) / 2 + GAP_BUFFER;
  }

  schedule(pkt) {
    const lane = laneFor(pkt);
    const key = `${lane}|${pkt.dir}`;
    const agg = this.pendingAgg.get(key);
    if (agg) {
      this.addToAgg(agg, pkt); // a burst is in progress — join it
      return;
    }
    if (!this.spawnVehicle(pkt, lane)) {
      this.pendingAgg.set(key, this.newAgg(lane, pkt));
    }
  }

  newAgg(lane, pkt) {
    const agg = {
      aggregate: true, lane, dir: pkt.dir, count: 0, bytes: 0,
      tsFirst: pkt.ts, tsLast: pkt.ts, protos: {}, samples: [],
    };
    this.addToAgg(agg, pkt);
    return agg;
  }

  addToAgg(agg, pkt) {
    agg.count++;
    agg.bytes += pkt.size;
    agg.tsLast = pkt.ts;
    agg.protos[pkt.proto] = (agg.protos[pkt.proto] ?? 0) + 1;
    if (agg.samples.length < MAX_CONVOY_SAMPLES) agg.samples.push(pkt);
  }

  /** Pending bursts flush as soon as their lane has entry room again. */
  flushAggs() {
    for (const [key, agg] of this.pendingAgg) {
      const ok = agg.count === 1
        ? this.spawnVehicle(agg.samples[0], agg.lane)
        : this.spawnConvoy(agg);
      if (ok) this.pendingAgg.delete(key);
    }
  }

  /** Pick a sub-lane with room (alternating files for visual balance). */
  pickSub(laneKey, len) {
    const prefer = 1 - (this.lastSub.get(laneKey) ?? 1);
    if (this.roomIn(laneKey, prefer, len)) return prefer;
    if (this.roomIn(laneKey, 1 - prefer, len)) return 1 - prefer;
    return -1;
  }

  /** Common placement path. Returns false when the lane entry is full. */
  place(type, lane, dirKey, { color, beaconColor, scaleL = 1, meta }) {
    const spec = TYPE_SPECS[type];
    const len = spec.len * scaleL;
    const laneKey = `${lane}|${dirKey}`;
    const dirSign = dirKey === 'in' ? 1 : -1;
    const center = this.laneX[lane][dirKey];
    const speed = LANE_SPEED[lane];

    if (type === 'drone') {
      // airborne: altitude separation, no sub-lane bookkeeping needed —
      // same lane speed still means drones never overlap their own kind
      // longitudinally if spawned apart; altitude varies the rest
      const rec = this.pools.drone.spawn({
        x: center + (Math.random() - 0.5) * 2.4, dirSign, speed, color, scaleL, meta,
        len: spec.len, yBase: 3.0 + Math.random() * 2.4,
      });
      this.afterSpawn(this.pools.drone, rec, lane, dirKey, -1);
      return true;
    }

    const sub = this.pickSub(laneKey, len);
    if (sub === -1) return false;
    const rec = this.pools[type].spawn({
      x: sublaneX(center, dirKey, sub) + (Math.random() - 0.5) * 0.7,
      dirSign, speed, color, scaleL, meta, len: spec.len, yBase: 0,
      beaconColor,
    });
    this.tails.set(`${laneKey}|${sub}`, rec);
    this.lastSub.set(laneKey, sub);
    this.afterSpawn(this.pools[type], rec, lane, dirKey, sub);
    return true;
  }

  afterSpawn(pool, rec, lane, dirKey, sub) {
    rec.lane = lane;
    rec.dir = dirKey;
    rec.sub = sub;
    this.spawned++;
    if (this.highlightKey) pool.tint(rec.idx, this.displayColor(rec));
  }

  spawnVehicle(pkt, lane = laneFor(pkt)) {
    const type = vehicleTypeFor(pkt);
    let color = PROTO_COLORS[pkt.proto] ?? PROTO_COLORS.OTHER;
    let beaconColor;
    if (type === 'signal') {
      color = PROTO_COLORS.TCP;                       // body stays "TCP gray"
      const strobe = pkt.flags.includes('R') ? 'R' : pkt.flags.includes('F') ? 'F'
        : pkt.flags.includes('A') ? 'SA' : 'S';
      beaconColor = FLAG_COLORS[strobe];
    } else if (type === 'police') {
      const v6 = !!pkt.src && pkt.src.includes(':');
      const err = pkt.icmp_type != null
        && (v6 ? ICMP_ERR_V6 : ICMP_ERR_V4).has(pkt.icmp_type);
      color = err ? FAIL_RED : PROTO_COLORS.ICMP;     // error reports ride red
      beaconColor = 0xffffff;                         // tinted red/blue per frame
    } else if (pkt.dns_qr === 1 && (pkt.dns_rcode === 2 || pkt.dns_rcode === 3)) {
      color = FAIL_RED;                               // failed-lookup motorcycle
    }
    let scaleL = 1;
    if (type === 'van') scaleL = Math.min(1 + pkt.size / 1200, 1.8);
    else if (type === 'truck') scaleL = Math.min(0.9 + pkt.size / 2200, 2.2);

    return this.place(type, lane, pkt.dir, { color, beaconColor, scaleL, meta: pkt });
  }

  spawnConvoy(agg) {
    let dominant = 'OTHER', max = 0;
    for (const [proto, n] of Object.entries(agg.protos)) {
      if (n > max) { max = n; dominant = proto; }
    }
    // log scale: engineers think in orders of magnitude, and a linear cap
    // would make a 30-packet burst look like a 3000-packet flood
    const scaleL = Math.min(0.8 + Math.log10(1 + agg.count) * 0.85, 3.2);
    const ok = this.place('convoy', agg.lane, agg.dir, {
      color: PROTO_COLORS[dominant] ?? PROTO_COLORS.OTHER, scaleL, meta: agg,
    });
    if (ok) this.aggregatedPkts += agg.count;
    return ok;
  }

  /** Roadside flare for a failed handshake; stacks per target service. */
  spawnFlare(event) {
    const syn = event.syn;
    const key = `${syn.dst}:${syn.dport}`;
    const dirSign = syn.dir === 'in' ? 1 : -1;
    const side = syn.dir === 'in' ? 1 : -1;
    this.flares.spawn({
      x: side * this.shoulderX,
      z: dirSign * HALF_LEN * (0.12 + 0.76 * hash01(key)), // stable per target
      color: event.kind === 'refused' ? 0xef4444 : 0xfbbf24,
      meta: { flowEvent: event.kind, syn, rst: event.rst ?? null },
      key,
    });
  }

  /** Roadside flare for a DNS failure; stacks per name (NXDOMAIN) or server. */
  spawnDnsFlare(event) {
    const ref = event.query ?? event.resp;
    if (!ref) return;
    const key = event.kind === 'nxdomain'
      ? `dns:${event.resp?.dns_qname ?? ref.dns_qname ?? '?'}`
      : `dns:${event.kind === 'dnstimeout' ? ref.dst : ref.src}`; // server
    const dirSign = ref.dir === 'in' ? 1 : -1;
    const side = ref.dir === 'in' ? 1 : -1;
    const color = event.kind === 'nxdomain' ? 0xef4444
      : event.kind === 'servfail' ? 0xf43f5e : 0xfbbf24;
    this.flares.spawn({
      x: side * this.shoulderX,
      z: dirSign * HALF_LEN * (0.12 + 0.76 * hash01(key)),
      color,
      meta: { flowEvent: event.kind, dns: true, query: event.query, resp: event.resp, syn: ref },
      key,
    });
  }

  /** Click-to-follow-flow: matching vehicles keep their color, rest dim. */
  setHighlight(key) {
    if (key === this.highlightKey) return;
    this.highlightKey = key;
    for (const pool of Object.values(this.pools)) {
      for (const rec of pool.active.values()) pool.tint(rec.idx, this.displayColor(rec));
    }
  }

  displayColor(rec) {
    if (!this.highlightKey) return rec.baseColor;
    const m = rec.meta;
    const match = m && !m.aggregate && flowKeyOf(m) === this.highlightKey;
    return match ? rec.baseColor : dimColor(rec.baseColor);
  }

  update(dt, t) {
    const now = performance.now();
    if (this.queue.length) {
      let i = 0;
      while (i < this.queue.length && this.queue[i].due <= now) i++;
      if (i > 0) for (const { pkt } of this.queue.splice(0, i)) this.schedule(pkt);
      if (this.queue.length > 4000) this.queue.length = 0; // backgrounded tab — drop stale spawns
    }
    this.flushAggs();
    for (const pool of Object.values(this.pools)) pool.update(dt, t);
    this.flares.update(dt, t);
  }

  clear() {
    this.queue.length = 0;
    this.tails.clear();
    this.lastSub.clear();
    this.pendingAgg.clear();
    this.highlightKey = null;
    for (const pool of Object.values(this.pools)) pool.clear();
    this.flares.clear();
  }
}
