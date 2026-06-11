// TCP handshake health tracker.
//
// Watches the SYN -> SYN-ACK exchange per 4-tuple and surfaces the three
// failure shapes a network engineer looks for first:
//   * half-open  — SYN never answered (filtered port, dead host, asymmetric
//                  routing, or a scanner probing you)
//   * refused    — SYN answered with RST (port closed / actively rejected)
//   * resets     — RSTs overall (mid-session resets included)
// Clock-agnostic: pass packet timestamps in, and tick() with the same
// timeline's "now" (wall clock in live mode, the playback clock in PCAP
// mode — so pausing playback pauses the timeout, and scrubbing resets it).

const PENDING_CAP = 2000; // SYN-flood guard

export class FlowTracker {
  constructor(timeoutSec = 3) {
    this.timeoutSec = timeoutSec;
    this.pending = new Map(); // "src:sport>dst:dport" -> {t, pkt}
    this.counts = {};
    this.reset();
  }

  reset() {
    this.pending.clear();
    this.counts = { synSent: 0, established: 0, halfOpen: 0, refused: 0, resets: 0 };
  }

  /** Feed every packet. Returns a failure event to visualize, or null. */
  add(p) {
    if (p.transport !== 'TCP' || !p.flags) return null;
    const f = p.flags;
    if (f === 'S') {
      this.counts.synSent++;
      if (this.pending.size >= PENDING_CAP) {
        this.pending.delete(this.pending.keys().next().value);
      }
      this.pending.set(`${p.src}:${p.sport}>${p.dst}:${p.dport}`, { t: p.ts, pkt: p });
    } else if (f === 'SA') {
      // SYN-ACK answers the reversed tuple
      if (this.pending.delete(`${p.dst}:${p.dport}>${p.src}:${p.sport}`)) {
        this.counts.established++;
      }
    } else if (f === 'R' || f === 'RA') {
      this.counts.resets++;
      const k = `${p.dst}:${p.dport}>${p.src}:${p.sport}`;
      const pend = this.pending.get(k);
      if (pend) {
        // RST directly answering a pending SYN: connection refused
        this.pending.delete(k);
        this.counts.refused++;
        return { kind: 'refused', syn: pend.pkt, rst: p };
      }
      // sender aborting its own attempt
      this.pending.delete(`${p.src}:${p.sport}>${p.dst}:${p.dport}`);
    }
    return null;
  }

  /** Expire unanswered SYNs. Returns half-open events to visualize. */
  tick(now) {
    const out = [];
    for (const [k, v] of this.pending) {
      if (now - v.t > this.timeoutSec) {
        this.pending.delete(k);
        this.counts.halfOpen++;
        out.push({ kind: 'halfopen', syn: v.pkt });
      }
    }
    return out;
  }

  get pendingCount() { return this.pending.size; }
}
