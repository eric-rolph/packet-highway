// Rolling-window statistics engine. Mode-agnostic: "now" is wall-clock time
// in live mode and the playback clock in PCAP mode.
//
// Aggregates into per-second buckets at add() time, so snapshot cost depends
// on the window length (≤60 buckets), not the packet rate — at thousands of
// packets/sec the old per-event array melted the frame budget.
import { LANES, PROTO_LANE, isBroadcast } from './config.js';

const LANE_IDX = Object.fromEntries(LANES.map((l, i) => [l.key, i]));
const N_LANES = LANES.length;

export class StatsEngine {
  constructor(windowSec = 60) {
    this.windowSec = windowSec;
    this.reset();
  }

  reset() {
    this.buckets = new Map(); // epoch-second -> bucket
    this.totalPkts = 0;
    this.totalBytes = 0;
  }

  add(p) {
    const sec = Math.floor(p.ts);
    let b = this.buckets.get(sec);
    if (!b) {
      b = { pkts: 0, bytes: 0, bytesIn: 0, bytesOut: 0, bcast: 0, protos: new Map(), talkers: new Map() };
      this.buckets.set(sec, b);
    }
    b.pkts++;
    b.bytes += p.size;
    if (isBroadcast(p)) b.bcast++;
    if (p.dir === 'in') b.bytesIn += p.size; else b.bytesOut += p.size;
    const pr = b.protos.get(p.proto) ?? { pkts: 0, bytes: 0 };
    pr.pkts++; pr.bytes += p.size;
    b.protos.set(p.proto, pr);
    for (const ip of [p.src, p.dst]) { // both endpoints: flooded receivers chart too
      if (!ip) continue;
      const tk = b.talkers.get(ip) ?? { bytes: 0, pkts: 0 };
      tk.bytes += p.size; tk.pkts++;
      b.talkers.set(ip, tk);
    }
    this.totalPkts++;
    this.totalBytes += p.size;
  }

  prune(now) {
    const cutoff = Math.floor(now) - this.windowSec - 2;
    for (const sec of this.buckets.keys()) {
      if (sec < cutoff) this.buckets.delete(sec);
    }
  }

  snapshot(now) {
    this.prune(now);
    const nowSec = Math.floor(now);
    let bwIn = 0, bwOut = 0, pps = 0, winPkts = 0, bcastPps = 0, bcastWin = 0;
    const protos = new Map();
    const talkers = new Map();
    const series = new Float64Array(this.windowSec); // bytes/sec, oldest first
    const laneSeries = new Float64Array(this.windowSec * N_LANES); // stacked by lane

    for (const [sec, b] of this.buckets) {
      const age = nowSec - sec;
      if (age < 0 || age >= this.windowSec) continue;
      const col = this.windowSec - 1 - age;
      series[col] += b.bytes;
      winPkts += b.pkts;
      bcastWin += b.bcast;
      if (age <= 1) { bwIn += b.bytesIn; bwOut += b.bytesOut; }
      if (age === 1) { pps = b.pkts; bcastPps = b.bcast; } // last COMPLETED second
      for (const [proto, v] of b.protos) {
        const agg = protos.get(proto) ?? { pkts: 0, bytes: 0 };
        agg.pkts += v.pkts; agg.bytes += v.bytes;
        protos.set(proto, agg);
        laneSeries[col * N_LANES + (LANE_IDX[PROTO_LANE[proto] ?? 'OTHER'] ?? N_LANES - 1)] += v.bytes;
      }
      for (const [ip, v] of b.talkers) {
        const agg = talkers.get(ip) ?? { bytes: 0, pkts: 0 };
        agg.bytes += v.bytes; agg.pkts += v.pkts;
        talkers.set(ip, agg);
      }
    }
    if (pps === 0) pps = this.buckets.get(nowSec)?.pkts ?? 0; // first second of a stream

    const totalWinPkts = winPkts || 1;
    return {
      bpsIn: (bwIn / 2) * 8,
      bpsOut: (bwOut / 2) * 8,
      pps,
      bcastPps,
      bcastWin,
      totalPkts: this.totalPkts,
      totalBytes: this.totalBytes,
      protoDist: [...protos.entries()]
        .map(([proto, v]) => ({ proto, ...v, frac: v.pkts / totalWinPkts }))
        .sort((a, b) => b.pkts - a.pkts),
      topTalkers: [...talkers.entries()]
        .map(([ip, v]) => ({ ip, ...v }))
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 5),
      buckets: series,
      laneSeries,
    };
  }
}

export function fmtBytes(n) {
  if (n < 1024) return `${n.toFixed(0)} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`;
  return `${(n / 1073741824).toFixed(2)} GB`;
}

export function fmtBps(n) {
  if (n < 1000) return `${n.toFixed(0)} bps`;
  if (n < 1e6) return `${(n / 1e3).toFixed(1)} Kbps`;
  if (n < 1e9) return `${(n / 1e6).toFixed(2)} Mbps`;
  return `${(n / 1e9).toFixed(2)} Gbps`;
}
