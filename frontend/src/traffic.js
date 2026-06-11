// Turns packet summaries into vehicles.
//
// Density strategy (how real traffic maps to the road):
//   * Every packet still counts in the stats — the road only controls VISUALS.
//   * Each protocol lane has TWO sub-lanes (cruise + passing). Within a
//     sub-lane vehicles obey a follow-the-leader model — they slow behind
//     slower traffic instead of ghosting through it — and a blocked faster
//     vehicle changes into the other sub-lane to overtake when there's a gap.
//   * Packets arriving faster than a lane can admit are merged into a
//     CONVOY — one long road-train representing the whole burst (click it to
//     see the breakdown), mirroring how network tooling shifts from
//     per-packet to flow/aggregate views as rates climb.
//   * Drones (UDP) are airborne and separate by altitude instead.
import {
  FLAG_COLORS, HALF_LEN, HEADWAY_MS, HIGHWAY, LANES, PASS_SPEED, PROTO_COLORS,
  TYPE_SPECS, laneFor, sublaneX, vehicleTypeFor,
} from './config.js';
import { FlarePool, VehiclePool } from './vehicles.js';

const MAX_CONVOY_SAMPLES = 8;
const FOLLOW_BUFFER = 2.2;   // bumper-to-bumper clearance, world units
const SOFT_ZONE = 10;        // start matching leader speed this far behind
const SPAWN_Z = (dirSign) => -dirSign * (HALF_LEN + 4);

export class TrafficController {
  constructor(scene, laneX) {
    this.laneX = laneX;
    this.pools = {};
    for (const type of Object.keys(TYPE_SPECS)) this.pools[type] = new VehiclePool(scene, type);
    this.flares = new FlarePool(scene);
    this.queue = [];             // live batches: [{due, pkt}], due is monotonic
    this.laneStates = new Map(); // `${lane}|${dir}` -> {nextFree, agg}  (admission)
    this.registry = new Map();   // `${lane}|${dir}|${sub}` -> [rec] front-first (follow model)
    this.spawned = 0;
    this.aggregatedPkts = 0;     // packets that rode inside a convoy
    this.laneChanges = 0;
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

  subQueue(laneKey, sub) {
    const key = `${laneKey}|${sub}`;
    let q = this.registry.get(key);
    if (!q) { q = []; this.registry.set(key, q); }
    return q;
  }

  /** PCAP playback path: schedule against lane admission immediately. */
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

  /** Common spawn path: sub-lane choice, registration, pool spawn. */
  placeVehicle(type, lane, dirKey, { color, beaconColor, scaleL = 1, meta }) {
    const spec = TYPE_SPECS[type];
    const dirSign = dirKey === 'in' ? 1 : -1;
    const center = this.laneX[lane][dirKey];
    const laneKey = `${lane}|${dirKey}`;
    const len = spec.len * scaleL;

    if (type === 'drone') {
      // airborne: altitude separation instead of sub-lanes
      const rec = this.pools.drone.spawn({
        x: center + (Math.random() - 0.5) * 2.4, dirSign, color, scaleL, meta,
        len: spec.len, yBase: 3.0 + Math.random() * 2.4,
      });
      this.spawned++;
      return rec;
    }

    let sub = spec.speed >= PASS_SPEED ? 0 : 1;
    const spawnZ = SPAWN_Z(dirSign);
    const lastLive = (s) => {
      const q = this.subQueue(laneKey, s);
      for (let i = q.length - 1; i >= 0; i--) if (!q[i].gone) return q[i];
      return null;
    };
    const roomIn = (s) => {
      const last = lastLive(s);
      return !last || (last.z - spawnZ) * dirSign >= (last.len + len) / 2 + FOLLOW_BUFFER;
    };
    if (!roomIn(sub) && roomIn(1 - sub)) sub = 1 - sub;
    // both blocked: enter the road further back instead of on top of the tail
    let z = spawnZ;
    const tail = lastLive(sub);
    if (tail) {
      const minZ = tail.z - dirSign * ((tail.len + len) / 2 + FOLLOW_BUFFER);
      if ((tail.z - z) * dirSign < (tail.len + len) / 2 + FOLLOW_BUFFER) z = minZ;
    }

    const rec = this.pools[type].spawn({
      x: sublaneX(center, dirKey, sub) + (Math.random() - 0.5) * 0.8,
      z, dirSign, color, scaleL, beaconColor, meta, len: spec.len, yBase: 0,
    });
    rec.lane = lane;
    rec.dir = dirKey;
    rec.laneKey = laneKey;
    rec.sub = sub;
    this.subQueue(laneKey, sub).push(rec);
    this.spawned++;
    return rec;
  }

  spawnVehicle(pkt) {
    const type = vehicleTypeFor(pkt);
    const lane = laneFor(pkt);
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

    this.placeVehicle(type, lane, pkt.dir, { color, beaconColor, scaleL, meta: pkt });
  }

  spawnConvoy(agg) {
    let dominant = 'OTHER', max = 0;
    for (const [proto, n] of Object.entries(agg.protos)) {
      if (n > max) { max = n; dominant = proto; }
    }
    const scaleL = Math.min(0.8 + agg.count / 14, 2.4);
    this.placeVehicle('convoy', agg.lane, agg.dir, {
      color: PROTO_COLORS[dominant] ?? PROTO_COLORS.OTHER, scaleL, meta: agg,
    });
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

  /**
   * Follow-the-leader pass. Queues are front-first and stay z-ordered by
   * construction (no overtaking *within* a sub-lane — passing happens by
   * changing sub-lanes). Leaders run first so curSpeed propagates backward.
   */
  updateFollow(dt) {
    for (const q of this.registry.values()) {
      // compact released vehicles
      let w = 0;
      for (let r = 0; r < q.length; r++) if (!q[r].gone) q[w++] = q[r];
      q.length = w;
      // repair ordering if a mid-frame insertion ever broke monotonicity
      // (cheap: queues are small and this is rare)
      for (let i = 1; i < q.length; i++) {
        if ((q[i - 1].z - q[i].z) * q[i].dirSign < 0) {
          const dirSign = q[0].dirSign;
          q.sort((p, n) => (n.z - p.z) * dirSign);
          break;
        }
      }

      for (let i = 0; i < q.length; i++) {
        const rec = q[i];
        if (rec.changeCd > 0) rec.changeCd = Math.max(0, rec.changeCd - dt);
        if (i === 0) { rec.curSpeed = rec.speed; continue; }
        const leader = q[i - 1];
        const minGap = (leader.len + rec.len) / 2 + FOLLOW_BUFFER;
        const gap = (leader.z - rec.z) * rec.dirSign - minGap;
        if (gap < 0) {
          rec.curSpeed = Math.max(0, leader.curSpeed + gap * 4); // hard brake
        } else if (gap < SOFT_ZONE) {
          rec.curSpeed = leader.curSpeed + (gap / SOFT_ZONE) * Math.max(rec.speed - leader.curSpeed, 0);
          if (rec.speed > leader.curSpeed + 4 && rec.changeCd === 0 && this.tryLaneChange(q, i, rec)) i--;
        } else {
          rec.curSpeed = rec.speed;
        }
      }
    }
  }

  tryLaneChange(q, i, rec) {
    const sib = this.subQueue(rec.laneKey, 1 - rec.sub);
    // find live neighbors around rec's z (released entries have stale z)
    let idx = 0, ahead = null, behind = null;
    for (let s = 0; s < sib.length; s++) {
      if (sib[s].gone) continue;
      if ((sib[s].z - rec.z) * rec.dirSign > 0) { ahead = sib[s]; idx = s + 1; }
      else { behind = sib[s]; idx = s; break; }
    }
    // entry gaps include a closing-speed allowance so the mover doesn't
    // nose into the leader (or get rear-ended) right after merging
    const closeA = ahead ? Math.max(rec.speed - ahead.curSpeed, 0) * 0.3 : 0;
    const closeB = behind ? Math.max(behind.curSpeed - rec.speed, 0) * 0.3 : 0;
    const gapA = ahead ? (ahead.z - rec.z) * rec.dirSign - (ahead.len + rec.len) / 2 - FOLLOW_BUFFER - closeA : 1;
    const gapB = behind ? (rec.z - behind.z) * rec.dirSign - (behind.len + rec.len) / 2 - FOLLOW_BUFFER - 1.5 - closeB : 1;
    if (gapA < 0 || gapB < 0) { rec.changeCd = 0.6; return false; }
    q.splice(i, 1);
    sib.splice(idx, 0, rec);
    rec.sub = 1 - rec.sub;
    rec.targetX = sublaneX(this.laneX[rec.lane][rec.dir], rec.dir, rec.sub) + (Math.random() - 0.5) * 0.8;
    rec.changeCd = 1.6;
    // sibling may already have run this frame — don't carry full speed into the gap
    if (ahead) rec.curSpeed = Math.min(rec.curSpeed, ahead.curSpeed + Math.max(gapA, 0) * 2);
    this.laneChanges++;
    return true;
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
    this.updateFollow(dt);
    for (const pool of Object.values(this.pools)) pool.update(dt, t);
    this.flares.update(dt, t);
  }

  clear() {
    this.queue.length = 0;
    this.laneStates.clear();
    this.registry.clear();
    for (const pool of Object.values(this.pools)) pool.clear();
    this.flares.clear();
  }
}
