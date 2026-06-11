// DNS transaction health tracker — the DNS analog of FlowTracker.
//
// Matches queries to responses by (transaction id, endpoints) and surfaces
// the failure classes behind most "the internet is down" tickets:
//   * NXDOMAIN  — the name does not exist (typo, dead domain, broken search list)
//   * SERVFAIL  — the resolver failed (upstream unreachable, DNSSEC, lame delegation)
//   * timeout   — the resolver never answered at all
// plus passive lookup latency (query -> response, rolling median).
//
// Multicast queries (mDNS/LLMNR discovery) are counted but never tracked as
// pending — they are routinely unanswered by design and would flood the
// timeout counter with false alarms.

const PENDING_CAP = 1000;

function isMulticastDst(p) {
  const d = p.dst ?? '';
  if (d === '255.255.255.255') return true;
  const first = parseInt(d, 10);
  if (first >= 224 && first <= 239) return true;
  return d.includes(':') && d.toLowerCase().startsWith('ff');
}

export class DnsTracker {
  constructor(timeoutSec = 5) {
    this.timeoutSec = timeoutSec;
    this.pending = new Map(); // "id|client>server" -> {t, pkt}
    this.rtts = [];
    this.counts = {};
    this.reset();
  }

  reset() {
    this.pending.clear();
    this.rtts.length = 0;
    this.log = [];
    this.counts = { queries: 0, ok: 0, nxdomain: 0, servfail: 0, timeouts: 0 };
  }

  pushLog(kind, target, extra = '') {
    this.log.push({ kind, target, extra, ts: this._lastTs ?? 0 });
    if (this.log.length > 80) this.log.shift();
  }

  /** Recent failure evidence for a category, grouped by name/resolver. */
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

  /** Feed every packet. Returns a failure event to visualize, or null. */
  add(p) {
    if (p.proto !== 'DNS' || p.dns_qr == null) return null;
    this._lastTs = p.ts;
    if (p.dns_qr === 0) {
      this.counts.queries++;
      if (isMulticastDst(p)) return null; // discovery chatter — no answer expected
      if (this.pending.size >= PENDING_CAP) {
        this.pending.delete(this.pending.keys().next().value);
      }
      this.pending.set(`${p.dns_id}|${p.src}:${p.sport}>${p.dst}:${p.dport}`, { t: p.ts, pkt: p });
      return null;
    }
    // response: match the reversed tuple
    const k = `${p.dns_id}|${p.dst}:${p.dport}>${p.src}:${p.sport}`;
    const pend = this.pending.get(k);
    if (pend) {
      this.pending.delete(k);
      const rtt = (p.ts - pend.t) * 1000;
      if (rtt >= 0 && rtt < 30_000) {
        this.rtts.push(rtt);
        if (this.rtts.length > 200) this.rtts.shift();
      }
    }
    if (p.dns_rcode === 3) {
      this.counts.nxdomain++;
      this.pushLog('nxdomain', p.dns_qname ?? '(unknown name)', `resolver ${p.src}`);
      return { kind: 'nxdomain', query: pend?.pkt ?? null, resp: p };
    }
    if (p.dns_rcode === 2) {
      this.counts.servfail++;
      this.pushLog('servfail', p.dns_qname ?? '(unknown name)', `resolver ${p.src}`);
      return { kind: 'servfail', query: pend?.pkt ?? null, resp: p };
    }
    this.counts.ok++;
    return null;
  }

  /** Expire unanswered queries. Returns timeout events to visualize. */
  tick(now) {
    const out = [];
    for (const [k, v] of this.pending) {
      if (now - v.t > this.timeoutSec) {
        this.pending.delete(k);
        this.counts.timeouts++;
        this.pushLog('dnstimeout', v.pkt.dst, v.pkt.dns_qname ? `name ${v.pkt.dns_qname}` : '');
        out.push({ kind: 'dnstimeout', query: v.pkt, resp: null });
      }
    }
    return out;
  }

  /** Rolling lookup latency {med, n} in ms, or null. */
  get rttStats() {
    const n = this.rtts.length;
    if (!n) return null;
    const s = [...this.rtts].sort((a, b) => a - b);
    return { med: s[n >> 1], n };
  }
}
