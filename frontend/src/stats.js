// Rolling-window statistics engine. Mode-agnostic: "now" is wall-clock time
// in live mode and the playback clock in PCAP mode, so the dashboard shows
// the truth for whichever timeline is driving the scene.

export class StatsEngine {
  constructor(windowSec = 60) {
    this.windowSec = windowSec;
    this.reset();
  }

  reset() {
    this.events = [];        // {t, bytes, proto, src, dir} sorted by arrival
    this.totalPkts = 0;
    this.totalBytes = 0;
  }

  add(p) {
    this.events.push({ t: p.ts, bytes: p.size, proto: p.proto, src: p.src, dir: p.dir });
    this.totalPkts++;
    this.totalBytes += p.size;
  }

  prune(now) {
    const cutoff = now - this.windowSec;
    let n = 0;
    while (n < this.events.length && this.events[n].t < cutoff) n++;
    if (n > 0) this.events.splice(0, n);
  }

  snapshot(now) {
    this.prune(now);
    let bwIn = 0, bwOut = 0, pps = 0;
    const protos = new Map();
    const talkers = new Map();
    const buckets = new Float64Array(this.windowSec); // bytes per second, index 0 = oldest

    for (const e of this.events) {
      const age = now - e.t;
      if (age <= 2.0) { // bandwidth over the last 2 s
        if (e.dir === 'in') bwIn += e.bytes; else bwOut += e.bytes;
      }
      if (age <= 1.0) pps++;
      const pr = protos.get(e.proto) ?? { pkts: 0, bytes: 0 };
      pr.pkts++; pr.bytes += e.bytes;
      protos.set(e.proto, pr);
      if (e.src) {
        const tk = talkers.get(e.src) ?? { bytes: 0, pkts: 0 };
        tk.bytes += e.bytes; tk.pkts++;
        talkers.set(e.src, tk);
      }
      const b = this.windowSec - 1 - Math.floor(age);
      if (b >= 0 && b < this.windowSec) buckets[b] += e.bytes;
    }

    const totalWinPkts = this.events.length || 1;
    return {
      bpsIn: (bwIn / 2) * 8,
      bpsOut: (bwOut / 2) * 8,
      pps,
      totalPkts: this.totalPkts,
      totalBytes: this.totalBytes,
      protoDist: [...protos.entries()]
        .map(([proto, v]) => ({ proto, ...v, frac: v.pkts / totalWinPkts }))
        .sort((a, b) => b.pkts - a.pkts),
      topTalkers: [...talkers.entries()]
        .map(([ip, v]) => ({ ip, ...v }))
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 5),
      buckets,
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
