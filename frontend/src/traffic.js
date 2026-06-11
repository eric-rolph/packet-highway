// Turns packet summaries into vehicles.
//
// Density strategy (how real traffic maps to the road):
//   * Every packet still counts in the stats — the road only controls VISUALS.
//   * Each lane enforces a minimum headway between vehicles, so vehicles
//     never overlap or stack.
//   * Packets arriving faster than the lane can admit are merged into a
//     CONVOY — one long road-train representing the whole burst (click it to
//     see the breakdown). This mirrors how network tooling shifts from
//     per-packet to flow/aggregate views as rates climb.
import {
  FLAG_COLORS, HALF_LEN, HEADWAY_MS, HIGHWAY, LANES, PROTO_COLORS,
  TYPE_SPECS, laneFor, vehicleTypeFor,
} from './config.js';
import { FlarePool, VehiclePool } from './vehicles.js';

const MAX_CONVOY_SAMPLES = 8;

export class TrafficController {
  constructor(scene, laneX) {
    this.laneX = laneX;
    this.pools = {};
    for (const type of Object.keys(TYPE_SPECS)) this.pools[type] = new VehiclePool(scene, type);
    this.flares = new FlarePool(scene);
    this.queue = [];          // live batches: [{due, pkt}], due is monotonic
    this.laneStates = new Map(); // `${lane}|${dir}` -> {nextFree, agg}
    this.spawned = 0;
    this.aggregatedPkts = 0;  // packets that rode inside a convoy
    this.shoulderX = HIGHWAY.medianWidth / 2 + LANES.length * HIGHWAY.laneWidth + HIGHWAY.shoulder * 0.55;
  }

  get meshes() { return [...Object.values(this.pools).map((p) => p.mesh), this.flares.mesh]; }
  get recycled() { return Object.values(this.pools).reduce((n, p) => n + p.recycled, 0); }
  activeCount() { return Object.values(this.pools).reduce((n, p) => n + p.active.size, 0); }

  laneState(key) {
    let st = this.laneStates.get(key);
    if (!st) { st = { nextFree: 0, agg: null }; this.laneStates.set(key, st); }
    return st;
  }

  /** PCAP playback path: schedule against lane headway immediately. */
  ingest(pkt) { this.schedule(pkt); }

  /** Live path: spread a batch over `spreadMs` so arrivals look continuous. */
  ingestBatch(items, spreadMs = 100) {
    const now = performance.now();
    const step = spreadMs / Math.max(items.length, 1);
    for (let i = 0; i < items.length; i++) this.queue.push({ due: now + i * step, pkt: items[i] });
  }

  schedule(pkt) {
    const lane = laneFor(pkt);
    const key = `${lane}|${pkt.dir}`;
    const st = this.laneState(key);
    const now = performance.now();
    if (now >= st.nextFree && !st.agg) {
      st.nextFree = now + HEADWAY_MS;
      this.spawnVehicle(pkt);
    } else if (st.agg) {
      this.addToAgg(st.agg, pkt);
    } else {
      st.agg = this.newAgg(lane, pkt);
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

  flushLanes(now) {
    for (const st of this.laneStates.values()) {
      if (!st.agg || now < st.nextFree) continue;
      const agg = st.agg;
      st.agg = null;
      if (agg.count === 1) {
        st.nextFree = now + HEADWAY_MS;
        this.spawnVehicle(agg.samples[0]);
      } else {
        st.nextFree = now + HEADWAY_MS * 1.6;
        this.spawnConvoy(agg);
      }
    }
  }

  spawnVehicle(pkt) {
    const type = vehicleTypeFor(pkt);
    const lane = laneFor(pkt);
    const dirSign = pkt.dir === 'in' ? 1 : -1;
    const laneX = this.laneX[lane][pkt.dir === 'in' ? 'in' : 'out'];

    let color = PROTO_COLORS[pkt.proto] ?? PROTO_COLORS.OTHER;
    let beaconColor;
    if (type === 'signal') {
      color = PROTO_COLORS.TCP;                       // body stays "TCP gray"
      beaconColor = FLAG_COLORS[pkt.flags] ?? 0xfbbf24;
    } else if (type === 'police') {
      color = PROTO_COLORS.ICMP;
      beaconColor = 0xffffff;                         // tinted red/blue per frame
    }
    let scaleL = 1;
    if (type === 'van') scaleL = Math.min(1 + pkt.size / 1200, 1.8);
    else if (type === 'truck') scaleL = Math.min(0.9 + pkt.size / 2200, 2.2);

    this.pools[type].spawn({ laneX, dirSign, color, scaleL, beaconColor, meta: pkt });
    this.spawned++;
  }

  spawnConvoy(agg) {
    const dirSign = agg.dir === 'in' ? 1 : -1;
    const laneX = this.laneX[agg.lane][agg.dir === 'in' ? 'in' : 'out'];
    let dominant = 'OTHER', max = 0;
    for (const [proto, n] of Object.entries(agg.protos)) {
      if (n > max) { max = n; dominant = proto; }
    }
    const scaleL = Math.min(0.8 + agg.count / 14, 2.4);
    this.pools.convoy.spawn({
      laneX, dirSign, scaleL,
      color: PROTO_COLORS[dominant] ?? PROTO_COLORS.OTHER,
      meta: agg,
    });
    this.spawned++;
    this.aggregatedPkts += agg.count;
  }

  /** Roadside flare for a failed handshake (see FlowTracker). */
  spawnFlare(event) {
    const syn = event.syn;
    const dirSign = syn.dir === 'in' ? 1 : -1;
    const side = syn.dir === 'in' ? 1 : -1;
    this.flares.spawn({
      x: side * this.shoulderX,
      z: dirSign * HALF_LEN * (0.35 + Math.random() * 0.3),
      color: event.kind === 'refused' ? 0xef4444 : 0xfbbf24,
      meta: { flowEvent: event.kind, syn, rst: event.rst ?? null },
    });
  }

  update(dt, t) {
    const now = performance.now();
    if (this.queue.length) {
      let i = 0;
      while (i < this.queue.length && this.queue[i].due <= now) i++;
      if (i > 0) for (const { pkt } of this.queue.splice(0, i)) this.schedule(pkt);
      if (this.queue.length > 4000) this.queue.length = 0; // backgrounded tab — drop stale spawns
    }
    this.flushLanes(now);
    for (const pool of Object.values(this.pools)) pool.update(dt, t);
    this.flares.update(dt, t);
  }

  clear() {
    this.queue.length = 0;
    this.laneStates.clear();
    for (const pool of Object.values(this.pools)) pool.clear();
    this.flares.clear();
  }
}
