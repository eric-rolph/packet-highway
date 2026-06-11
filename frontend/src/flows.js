// TCP handshake health tracker.
//
// Watches the SYN -> SYN-ACK exchange per 4-tuple and surfaces the failure
// shapes a network engineer looks for first:
//   * half-open  — SYN never answered (filtered port, dead host, scanner)
//   * refused    — SYN answered with RST (port closed / actively rejected)
//   * resets     — RSTs overall (mid-session resets included)
// plus two passive measurements that come free with the matching:
//   * handshake RTT (SYN -> SYN-ACK), rolling median/p95
//   * SYN retries (kernel retransmits of an unanswered SYN)
//
// Flags are matched by MEMBERSHIP (scapy order, e.g. "SEC" = SYN+ECE+CWR,
// "SAE" = SYN-ACK+ECE) — exact-string matching would misread every
// ECN-negotiated handshake as a failure.
//
// Clock-agnostic: feed packet timestamps, tick() with the same timeline's
// "now" (wall clock live, playback clock in PCAP mode — pausing playback
// pauses timeouts, scrubbing resets).

const PENDING_CAP = 2000;     // SYN-flood guard
const REFAIL_WINDOW = 30;     // sec: suppress re-counting a known-dead target

export class FlowTracker {
  constructor(timeoutSec = 3) {
    this.timeoutSec = timeoutSec;
    this.pending = new Map();     // "src:sport>dst:dport" -> {t, pkt, refail}
    this.recentFail = new Map();  // same key -> last failure time
    this.rtts = [];               // ms, rolling
    this.counts = {};
    this.reset();
  }

  reset() {
    this.pending.clear();
    this.recentFail.clear();
    this.rtts.length = 0;
    this.counts = {
      synSent: 0, synRetries: 0, established: 0,
      halfOpen: 0, refused: 0, resets: 0,
    };
  }

  /** Feed every packet. Returns a failure event to visualize, or null. */
  add(p) {
    if (p.transport !== 'TCP' || !p.flags) return null;
    const f = p.flags;
    const isSyn = f.includes('S') && !f.includes('A') && !f.includes('R') && !f.includes('F');
    const isSynAck = f.includes('S') && f.includes('A') && !f.includes('R');
    const isRst = f.includes('R');
    const key = `${p.src}:${p.sport}>${p.dst}:${p.dport}`;
    const rkey = `${p.dst}:${p.dport}>${p.src}:${p.sport}`;

    if (isSyn) {
      const existing = this.pending.get(key);
      if (existing) {
        // kernel retransmit of an unanswered SYN — same attempt, fresh timer
        this.counts.synRetries++;
        existing.t = p.ts;
        return null;
      }
      const lastFail = this.recentFail.get(key);
      if (lastFail !== undefined && p.ts - lastFail < REFAIL_WINDOW) {
        // OS retry schedules (1,2,4,8,16 s) outlive our timeout; don't count
        // one dead connect() as several failures
        this.counts.synRetries++;
        this.pending.set(key, { t: p.ts, pkt: p, refail: true });
        return null;
      }
      this.counts.synSent++;
      if (this.pending.size >= PENDING_CAP) {
        this.pending.delete(this.pending.keys().next().value);
      }
      this.pending.set(key, { t: p.ts, pkt: p, refail: false });
    } else if (isSynAck) {
      const pend = this.pending.get(rkey);
      if (pend) {
        this.pending.delete(rkey);
        this.recentFail.delete(rkey);
        this.counts.established++;
        const rtt = (p.ts - pend.t) * 1000;
        if (rtt >= 0 && rtt < 10_000) {
          this.rtts.push(rtt);
          if (this.rtts.length > 200) this.rtts.shift();
        }
      }
    } else if (isRst) {
      this.counts.resets++;
      const pend = this.pending.get(rkey);
      if (pend) {
        // RST directly answering a pending SYN: connection refused
        this.pending.delete(rkey);
        this.recentFail.set(rkey, p.ts);
        if (!pend.refail) {
          this.counts.refused++;
          return { kind: 'refused', syn: pend.pkt, rst: p };
        }
      } else {
        this.pending.delete(key); // sender aborting its own attempt
      }
    }
    return null;
  }

  /** Expire unanswered SYNs. Returns half-open events to visualize. */
  tick(now) {
    const out = [];
    for (const [k, v] of this.pending) {
      if (now - v.t > this.timeoutSec) {
        this.pending.delete(k);
        this.recentFail.set(k, now);
        if (!v.refail) {
          this.counts.halfOpen++;
          out.push({ kind: 'halfopen', syn: v.pkt });
        }
      }
    }
    if (this.recentFail.size > 500) {
      for (const [k, t] of this.recentFail) {
        if (now - t > REFAIL_WINDOW) this.recentFail.delete(k);
      }
    }
    return out;
  }

  get pendingCount() { return this.pending.size; }

  /** Rolling handshake RTT {med, p95, n} in ms, or null before any sample. */
  get rttStats() {
    const n = this.rtts.length;
    if (!n) return null;
    const s = [...this.rtts].sort((a, b) => a - b);
    return { med: s[n >> 1], p95: s[Math.min(Math.floor(n * 0.95), n - 1)], n };
  }
}
