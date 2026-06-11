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

import { flowKeyOf } from './config.js';

const PENDING_CAP = 2000;     // SYN-flood guard
const REFAIL_WINDOW = 30;     // sec: suppress re-counting a known-dead target
const SEQ_CAP = 3000;         // flows tracked for retransmission
const LOG_CAP = 80;           // recent-failure evidence entries

export class FlowTracker {
  constructor(timeoutSec = 3) {
    this.timeoutSec = timeoutSec;
    this.pending = new Map();     // "src:sport>dst:dport" -> {t, pkt, refail}
    this.recentFail = new Map();  // same key -> last failure time
    this.seqHi = new Map();       // directional flow -> highest seq end seen
    this.flowSni = new Map();     // canonical flow key -> TLS server name
    this.open = new Map();        // canonical flow key -> ts established
    this.rtts = [];               // ms, rolling
    this.log = [];                // recent failure events for drill-down
    this.counts = {};
    this.reset();
  }

  reset() {
    this.pending.clear();
    this.recentFail.clear();
    this.seqHi.clear();
    this.flowSni.clear();
    this.open.clear();
    this.rtts.length = 0;
    this.log.length = 0;
    this.counts = {
      synSent: 0, synRetries: 0, established: 0,
      halfOpen: 0, refused: 0, resets: 0, retrans: 0,
    };
  }

  pushLog(kind, target, extra = '') {
    this.log.push({ kind, target, extra, ts: this._lastTs ?? 0 });
    if (this.log.length > LOG_CAP) this.log.shift();
  }

  /** Recent failure evidence for a category, grouped by target. */
  recent(kind) {
    const grouped = new Map();
    for (const e of this.log) {
      if (e.kind !== kind) continue;
      const g = grouped.get(e.target) ?? { target: e.target, extra: e.extra, count: 0, last: 0 };
      g.count++;
      if (e.ts > g.last) { g.last = e.ts; g.extra = e.extra || g.extra; }
      grouped.set(e.target, g);
    }
    return [...grouped.values()].sort((a, b) => b.last - a.last);
  }

  sniFor(key) { return key ? this.flowSni.get(key) ?? null : null; }

  /** Sequence tracking: a data segment ending at-or-before the highest seen
   *  end is a RETRANSMISSION — the same truck making the trip twice. */
  trackSeq(p) {
    if (p.seq == null || (p.plen ?? 0) < 8) return;
    const k = `${p.src}:${p.sport}>${p.dst}:${p.dport}`;
    const end = (p.seq + p.plen) >>> 0;
    const hi = this.seqHi.get(k);
    if (hi !== undefined && ((hi - end) >>> 0) < 0x40000000) {
      this.counts.retrans++;
      p.retrans = true;
      this.pushLog('retrans', `${p.src} → ${p.dst}:${p.dport}`, `${p.plen} B segment`);
      return;
    }
    if (hi === undefined || ((end - hi) >>> 0) < 0x40000000) {
      if (this.seqHi.size >= SEQ_CAP) this.seqHi.delete(this.seqHi.keys().next().value);
      this.seqHi.set(k, end);
    }
  }

  /** Feed every packet. Returns a failure event to visualize, or null. */
  add(p) {
    if (p.transport !== 'TCP') return null;
    this._lastTs = p.ts;
    if (p.sni) {
      if (this.flowSni.size >= 500) this.flowSni.delete(this.flowSni.keys().next().value);
      this.flowSni.set(flowKeyOf(p), p.sni);
    }
    this.trackSeq(p);
    if (!p.flags) return null;
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
        if (this.open.size >= 5000) this.open.delete(this.open.keys().next().value);
        this.open.set(flowKeyOf(p), p.ts);
        const rtt = (p.ts - pend.t) * 1000;
        if (rtt >= 0 && rtt < 10_000) {
          this.rtts.push(rtt);
          if (this.rtts.length > 200) this.rtts.shift();
        }
      }
    } else if (f.includes('F')) {
      this.open.delete(flowKeyOf(p)); // FIN starts teardown — count it closed
    } else if (isRst) {
      this.counts.resets++;
      this.open.delete(flowKeyOf(p));
      this.pushLog('rst', `${p.src} → ${p.dst}${p.dport != null ? ':' + p.dport : ''}`);
      const pend = this.pending.get(rkey);
      if (pend) {
        // RST directly answering a pending SYN: connection refused
        this.pending.delete(rkey);
        this.recentFail.set(rkey, p.ts);
        if (!pend.refail) {
          this.counts.refused++;
          this.pushLog('refused', `${pend.pkt.dst}:${pend.pkt.dport}`, `client ${pend.pkt.src}`);
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
          this.pushLog('halfopen', `${v.pkt.dst}:${v.pkt.dport}`, `client ${v.pkt.src}`);
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

  /** Connections currently established (seen open, not yet FIN/RST). */
  get openCount() { return this.open.size; }

  /** Rolling handshake RTT {med, p95, n} in ms, or null before any sample. */
  get rttStats() {
    const n = this.rtts.length;
    if (!n) return null;
    const s = [...this.rtts].sort((a, b) => a - b);
    return { med: s[n >> 1], p95: s[Math.min(Math.floor(n * 0.95), n - 1)], n };
  }
}
