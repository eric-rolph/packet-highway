// Browser Standalone Engine for Packet Highway (GitHub Pages / zero-backend mode).
// Provides:
//   1. Live synthetic highway traffic stream matching backend/packets.py schema
//   2. 60-second multi-incident sample capture for PCAP scrubber demo
//   3. Pure-JS binary .pcap / .pcapng parser (Ethernet, Linux SLL, Raw IP, IPv4/IPv6,
//      TCP flags/seq/TLS SNI, UDP, ICMP, ARP, DNS qname/rcode) running 100% locally.

const LOCAL_IP = '192.168.1.42';
const LOCAL_MAC = 'aa:bb:cc:11:22:42';
const GW_MAC = 'aa:bb:cc:00:00:01';

const PORT_CLASSES = [
  ['DNS', new Set([53, 5353, 5355])],
  ['HTTPS', new Set([443, 8443])],
  ['HTTP', new Set([80, 8080, 8000, 8008])],
  ['SSH', new Set([22])],
  ['RDP', new Set([3389])],
  ['SMB', new Set([445, 139, 137, 138])],
  ['FTP', new Set([20, 21])],
  ['SNMP', new Set([161, 162])],
  ['DHCP', new Set([67, 68, 546, 547])],
  ['NTP', new Set([123])],
  ['SYSLOG', new Set([514, 6514])],
  ['VPN', new Set([1194, 51820, 500, 4500])],
  ['MAIL', new Set([25, 110, 143, 465, 587, 993, 995])],
];

const DEMO_HOSTS = [
  { ip: '140.82.114.4', sni: 'api.github.com', port: 443, proto: 'HTTPS' },
  { ip: '104.18.32.7', sni: 'cdn.cloudflare.com', port: 443, proto: 'HTTPS' },
  { ip: '172.64.155.209', sni: 'api.openai.com', port: 443, proto: 'HTTPS' },
  { ip: '151.101.1.69', sni: 'pypi.org', port: 443, proto: 'HTTPS' },
  { ip: '142.250.190.78', sni: 'youtube.com', port: 443, proto: 'HTTPS' },
  { ip: '198.51.100.22', sni: null, port: 22, proto: 'SSH' },
  { ip: '192.168.1.10', sni: null, port: 445, proto: 'SMB' },
  { ip: '203.0.113.55', sni: null, port: 51820, proto: 'VPN' },
  { ip: '1.1.1.1', sni: null, port: 53, proto: 'DNS' },
  { ip: '162.159.200.1', sni: null, port: 123, proto: 'NTP' },
];

const DEMO_DOMAINS = [
  'api.github.com', 'cdn.cloudflare.com', 'pypi.org', 'api.openai.com',
  'registry.npmjs.org', 'fonts.gstatic.com', 'telemetry.internal.local',
];

function classify(transport, sport, dport) {
  if (transport === 'ICMP') return 'ICMP';
  for (const [name, ports] of PORT_CLASSES) {
    if ((sport && ports.has(sport)) || (dport && ports.has(dport))) return name;
  }
  if (transport === 'TCP' || transport === 'UDP' || transport === 'ARP') return transport;
  return 'OTHER';
}

function isPrivateIp(ip) {
  if (!ip) return false;
  return (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    ip === '::1' ||
    ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80:') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  );
}

function inferDir(src, dst, refSet) {
  if (src && refSet.has(src)) return 'out';
  if (dst && refSet.has(dst)) return 'in';
  const sp = isPrivateIp(src);
  const dp = isPrivateIp(dst);
  if (sp && !dp) return 'out';
  if (dp && !sp) return 'in';
  return 'out';
}

function makePkt(overrides) {
  return {
    id: 0,
    ts: Date.now() / 1000,
    src: LOCAL_IP,
    dst: '140.82.114.4',
    smac: LOCAL_MAC,
    dmac: GW_MAC,
    sport: 52000,
    dport: 443,
    transport: 'TCP',
    proto: 'HTTPS',
    size: 512,
    flags: 'PA',
    ttl: 64,
    icmp_type: null,
    icmp_code: null,
    dns_id: null,
    dns_qr: null,
    dns_rcode: null,
    dns_qname: null,
    seq: null,
    plen: null,
    sni: null,
    dir: 'out',
    ...overrides,
  };
}

class SynthEmitter {
  constructor() {
    this.pid = 1;
    this.dnsId = 0x1000;
    this.sport = 49152;
    this.seq = 10000;
    this.pending = [];
  }

  nextPort() {
    this.sport = 49152 + ((this.sport - 49151) % 15000);
    return this.sport;
  }

  emitBurst(now) {
    const out = [];
    // Flush scheduled follow-ups (SYN-ACK, ACK, DNS replies, payload bursts)
    const keep = [];
    for (const item of this.pending) {
      if (item.at <= now) out.push({ ...item.pkt, id: this.pid++, ts: now });
      else keep.push(item);
    }
    this.pending = keep;

    const r = Math.random();
    if (r < 0.42) {
      // HTTPS / TLS flow (ClientHello + inbound response stream)
      const h = DEMO_HOSTS[Math.floor(Math.random() * 5)];
      const sp = this.nextPort();
      const s0 = (this.seq += 4000);
      out.push(makePkt({
        id: this.pid++, ts: now, src: LOCAL_IP, dst: h.ip, sport: sp, dport: 443,
        proto: 'HTTPS', transport: 'TCP', size: 74, flags: 'S', seq: s0, plen: 0, dir: 'out',
      }));
      this.pending.push({
        at: now + 0.03 + Math.random() * 0.04,
        pkt: makePkt({
          src: h.ip, dst: LOCAL_IP, smac: GW_MAC, dmac: LOCAL_MAC, sport: 443, dport: sp,
          proto: 'HTTPS', transport: 'TCP', size: 74, flags: 'SA', seq: 80000, plen: 0, dir: 'in',
        }),
      });
      this.pending.push({
        at: now + 0.08,
        pkt: makePkt({
          src: LOCAL_IP, dst: h.ip, sport: sp, dport: 443, proto: 'HTTPS', transport: 'TCP',
          size: 312, flags: 'PA', seq: s0 + 1, plen: 258, sni: h.sni, dir: 'out',
        }),
      });
      const chunks = 2 + Math.floor(Math.random() * 5);
      for (let k = 0; k < chunks; k++) {
        this.pending.push({
          at: now + 0.14 + k * 0.05,
          pkt: makePkt({
            src: h.ip, dst: LOCAL_IP, smac: GW_MAC, dmac: LOCAL_MAC, sport: 443, dport: sp,
            proto: 'HTTPS', transport: 'TCP', size: 900 + Math.floor(Math.random() * 560),
            flags: 'PA', seq: 80001 + k * 1400, plen: 1400, sni: h.sni, dir: 'in',
          }),
        });
      }
      // Occasional single retransmission for visual realism
      if (Math.random() < 0.04) {
        this.pending.push({
          at: now + 0.35,
          pkt: makePkt({
            src: h.ip, dst: LOCAL_IP, smac: GW_MAC, dmac: LOCAL_MAC, sport: 443, dport: sp,
            proto: 'HTTPS', transport: 'TCP', size: 1454, flags: 'PA', seq: 80001, plen: 1400, dir: 'in',
          }),
        });
      }
    } else if (r < 0.62) {
      // DNS lookup + reply (occasional NXDOMAIN)
      const qid = (this.dnsId = (this.dnsId + 1) & 0xffff);
      const sp = this.nextPort();
      const bad = Math.random() < 0.08;
      const qname = bad ? 'stale-node.internal.example' : DEMO_DOMAINS[Math.floor(Math.random() * DEMO_DOMAINS.length)];
      out.push(makePkt({
        id: this.pid++, ts: now, src: LOCAL_IP, dst: '1.1.1.1', sport: sp, dport: 53,
        proto: 'DNS', transport: 'UDP', size: 84, flags: '', dns_id: qid, dns_qr: 0, dns_rcode: 0, dns_qname: qname, dir: 'out',
      }));
      this.pending.push({
        at: now + 0.02 + Math.random() * 0.05,
        pkt: makePkt({
          src: '1.1.1.1', dst: LOCAL_IP, smac: GW_MAC, dmac: LOCAL_MAC, sport: 53, dport: sp,
          proto: 'DNS', transport: 'UDP', size: 132, flags: '', dns_id: qid, dns_qr: 1,
          dns_rcode: bad ? 3 : 0, dns_qname: qname, dir: 'in',
        }),
      });
    } else if (r < 0.76) {
      // QUIC UDP/443 drones
      const h = DEMO_HOSTS[Math.floor(Math.random() * 5)];
      const sp = this.nextPort();
      const inbound = Math.random() < 0.65;
      out.push(makePkt({
        id: this.pid++, ts: now,
        src: inbound ? h.ip : LOCAL_IP, dst: inbound ? LOCAL_IP : h.ip,
        sport: inbound ? 443 : sp, dport: inbound ? sp : 443,
        proto: 'HTTPS', transport: 'UDP', size: inbound ? 1280 : 420, flags: '', dir: inbound ? 'in' : 'out',
      }));
    } else if (r < 0.85) {
      // SSH / SMB / VPN freight
      const h = DEMO_HOSTS[5 + Math.floor(Math.random() * 3)];
      const inbound = Math.random() < 0.5;
      const tr = h.proto === 'VPN' ? 'UDP' : 'TCP';
      out.push(makePkt({
        id: this.pid++, ts: now,
        src: inbound ? h.ip : LOCAL_IP, dst: inbound ? LOCAL_IP : h.ip,
        sport: inbound ? h.port : 53110, dport: inbound ? 53110 : h.port,
        proto: h.proto, transport: tr, size: 180 + Math.floor(Math.random() * 1100),
        flags: tr === 'TCP' ? 'PA' : '', dir: inbound ? 'in' : 'out',
      }));
    } else if (r < 0.92) {
      // ICMP patrol police car
      out.push(makePkt({
        id: this.pid++, ts: now, src: LOCAL_IP, dst: '8.8.8.8', sport: null, dport: null,
        proto: 'ICMP', transport: 'ICMP', size: 98, flags: '', icmp_type: 8, icmp_code: 0, dir: 'out',
      }));
      this.pending.push({
        at: now + 0.04,
        pkt: makePkt({
          src: '8.8.8.8', dst: LOCAL_IP, smac: GW_MAC, dmac: LOCAL_MAC, sport: null, dport: null,
          proto: 'ICMP', transport: 'ICMP', size: 98, flags: '', icmp_type: 0, icmp_code: 0, dir: 'in',
        }),
      });
    } else if (r < 0.96) {
      // NTP drone or ARP cart
      if (Math.random() < 0.5) {
        out.push(makePkt({
          id: this.pid++, ts: now, src: LOCAL_IP, dst: '162.159.200.1', sport: 123, dport: 123,
          proto: 'NTP', transport: 'UDP', size: 90, flags: '', dir: 'out',
        }));
      } else {
        out.push(makePkt({
          id: this.pid++, ts: now, src: LOCAL_IP, dst: '192.168.1.1', sport: null, dport: null,
          proto: 'ARP', transport: 'ARP', size: 60, flags: '', dir: 'out',
        }));
      }
    } else {
      // Refused TCP port probe (SYN -> RST) so breakdown shoulder feature shines
      const sp = this.nextPort();
      out.push(makePkt({
        id: this.pid++, ts: now, src: LOCAL_IP, dst: '198.51.100.99', sport: sp, dport: 8443,
        proto: 'HTTPS', transport: 'TCP', size: 66, flags: 'S', seq: (this.seq += 100), plen: 0, dir: 'out',
      }));
      this.pending.push({
        at: now + 0.03,
        pkt: makePkt({
          src: '198.51.100.99', dst: LOCAL_IP, smac: GW_MAC, dmac: LOCAL_MAC, sport: 8443, dport: sp,
          proto: 'HTTPS', transport: 'TCP', size: 60, flags: 'RA', seq: 0, plen: 0, dir: 'in',
        }),
      });
    }
    return out;
  }
}

export class BrowserDemoStream {
  constructor(handlers) {
    this.h = handlers;
    this.timer = null;
    this.emitter = new SynthEmitter();
  }

  start() {
    if (this.timer) return;
    this.h.onHello?.({ type: 'hello', mode: 'demo', browserOnly: true });
    this.timer = setInterval(() => {
      const items = this.emitter.emitBurst(Date.now() / 1000);
      if (items.length) this.h.onPackets?.(items, 0);
    }, 95);
  }

  stop() {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
    this.h.onClose?.();
  }

  get running() {
    return this.timer !== null;
  }
}

export function generateSampleTimeline() {
  const emitter = new SynthEmitter();
  const t0 = Math.floor(Date.now() / 1000) - 60;
  const packets = [];
  for (let i = 0; i < 420; i++) {
    const t = t0 + (i / 420) * 60.0;
    const batch = emitter.emitBurst(t);
    for (const p of batch) packets.push(p);
  }
  packets.sort((a, b) => a.ts - b.ts);
  const start = packets[0].ts;
  const end = packets[packets.length - 1].ts;
  return {
    meta: {
      filename: 'browser-sample-traffic.pcap',
      count: packets.length,
      truncated: false,
      limit: 50000,
      start,
      end,
      duration: Math.max(end - start, 0.001),
      vantage: LOCAL_IP,
    },
    packets,
  };
}

// ------------------------------------------------------------------ Binary PCAP / PCAPNG parser

function formatMac(u8, off) {
  let s = '';
  for (let i = 0; i < 6; i++) {
    if (i) s += ':';
    s += u8[off + i].toString(16).padStart(2, '0');
  }
  return s;
}

function formatIPv4(u8, off) {
  return `${u8[off]}.${u8[off + 1]}.${u8[off + 2]}.${u8[off + 3]}`;
}

function formatIPv6(dv, off) {
  const parts = [];
  for (let i = 0; i < 8; i++) parts.push(dv.getUint16(off + i * 2, false).toString(16));
  return parts.join(':');
}

function extractSni(u8, off, end) {
  const len = end - off;
  if (len < 60 || u8[off] !== 0x16 || u8[off + 1] !== 0x03 || u8[off + 5] !== 0x01) return null;
  let i = off + 9 + 2 + 32;
  if (i >= end) return null;
  i += 1 + u8[i];
  if (i + 2 > end) return null;
  i += 2 + ((u8[i] << 8) | u8[i + 1]);
  if (i + 1 > end) return null;
  i += 1 + u8[i];
  if (i + 2 > end) return null;
  const extEnd = Math.min(i + 2 + ((u8[i] << 8) | u8[i + 1]), end);
  i += 2;
  while (i + 4 <= extEnd) {
    const etype = (u8[i] << 8) | u8[i + 1];
    const elen = (u8[i + 2] << 8) | u8[i + 3];
    i += 4;
    if (etype === 0 && i + 5 <= extEnd) {
      const nlen = (u8[i + 3] << 8) | u8[i + 4];
      if (i + 5 + nlen <= extEnd) {
        return new TextDecoder().decode(u8.subarray(i + 5, i + 5 + nlen)).slice(0, 120);
      }
    }
    i += elen;
  }
  return null;
}

function parseDns(u8, off, end) {
  if (end - off < 12) return null;
  const id = (u8[off] << 8) | u8[off + 1];
  const fl = (u8[off + 2] << 8) | u8[off + 3];
  const qr = (fl >> 15) & 1;
  const rcode = fl & 0x0f;
  const qdcount = (u8[off + 4] << 8) | u8[off + 5];
  let qname = null;
  if (qdcount > 0) {
    let p = off + 12;
    const labels = [];
    for (let guard = 0; guard < 32 && p < end; guard++) {
      const l = u8[p++];
      if (l === 0 || (l & 0xc0) === 0xc0) break;
      if (p + l > end) break;
      labels.push(new TextDecoder().decode(u8.subarray(p, p + l)));
      p += l;
    }
    if (labels.length) qname = labels.join('.').slice(0, 120);
  }
  return { id, qr, rcode, qname };
}

function decodeFrame(u8, dv, off, capLen, origLen, linkType, ts, pid) {
  const end = off + capLen;
  let l3Off = off;
  let ethType = null;
  let smac = null;
  let dmac = null;

  if (linkType === 1) {
    // Ethernet II
    if (capLen < 14) return null;
    dmac = formatMac(u8, off);
    smac = formatMac(u8, off + 6);
    ethType = dv.getUint16(off + 12, false);
    l3Off = off + 14;
    if (ethType === 0x8100 && l3Off + 4 <= end) {
      ethType = dv.getUint16(l3Off + 2, false);
      l3Off += 4;
    }
  } else if (linkType === 113) {
    // Linux SLL
    if (capLen < 16) return null;
    ethType = dv.getUint16(off + 14, false);
    l3Off = off + 16;
  } else if (linkType === 276) {
    // Linux SLL2
    if (capLen < 20) return null;
    ethType = dv.getUint16(off, false);
    l3Off = off + 20;
  } else if (linkType === 0) {
    // BSD Null/Loopback
    if (capLen < 4) return null;
    const fam = dv.getUint32(off, true);
    ethType = fam === 2 ? 0x0800 : 0x86dd;
    l3Off = off + 4;
  } else if (linkType === 101) {
    // Raw IP
    if (capLen < 1) return null;
    const ver = u8[off] >> 4;
    ethType = ver === 6 ? 0x86dd : 0x0800;
  } else {
    return null;
  }

  let src = null, dst = null, ttl = null, transport = 'OTHER', protoNum = null;
  let l4Off = null;

  if (ethType === 0x0806 && l3Off + 28 <= end) {
    transport = 'ARP';
    src = formatIPv4(u8, l3Off + 14);
    dst = formatIPv4(u8, l3Off + 24);
  } else if (ethType === 0x0800 && l3Off + 20 <= end) {
    const ihl = (u8[l3Off] & 0x0f) * 4;
    if (ihl < 20 || l3Off + ihl > end) return null;
    ttl = u8[l3Off + 8];
    protoNum = u8[l3Off + 9];
    src = formatIPv4(u8, l3Off + 12);
    dst = formatIPv4(u8, l3Off + 16);
    l4Off = l3Off + ihl;
  } else if (ethType === 0x86dd && l3Off + 40 <= end) {
    protoNum = u8[l3Off + 6];
    ttl = u8[l3Off + 7];
    src = formatIPv6(dv, l3Off + 8);
    dst = formatIPv6(dv, l3Off + 24);
    l4Off = l3Off + 40;
  } else {
    return null;
  }

  let sport = null, dport = null, flags = '', seq = null, plen = null, sni = null;
  let icmp_type = null, icmp_code = null;
  let l4PayloadOff = null;

  if (l4Off !== null) {
    if (protoNum === 6 && l4Off + 20 <= end) {
      transport = 'TCP';
      sport = dv.getUint16(l4Off, false);
      dport = dv.getUint16(l4Off + 2, false);
      seq = dv.getUint32(l4Off + 4, false);
      const dataOff = (u8[l4Off + 12] >> 4) * 4;
      const fl = u8[l4Off + 13];
      flags = (fl & 0x01 ? 'F' : '') + (fl & 0x02 ? 'S' : '') + (fl & 0x04 ? 'R' : '') +
              (fl & 0x08 ? 'P' : '') + (fl & 0x10 ? 'A' : '') + (fl & 0x20 ? 'U' : '');
      l4PayloadOff = l4Off + Math.max(20, dataOff);
      plen = Math.max(0, end - l4PayloadOff);
      if (plen > 50 && u8[l4PayloadOff] === 0x16) sni = extractSni(u8, l4PayloadOff, end);
    } else if (protoNum === 17 && l4Off + 8 <= end) {
      transport = 'UDP';
      sport = dv.getUint16(l4Off, false);
      dport = dv.getUint16(l4Off + 2, false);
      l4PayloadOff = l4Off + 8;
    } else if ((protoNum === 1 || protoNum === 58) && l4Off + 2 <= end) {
      transport = 'ICMP';
      icmp_type = u8[l4Off];
      icmp_code = u8[l4Off + 1];
    }
  }

  let proto = classify(transport, sport, dport);
  if (transport === 'OTHER' && (protoNum === 50 || protoNum === 51)) proto = 'VPN';

  let dns_id = null, dns_qr = null, dns_rcode = null, dns_qname = null;
  if (proto === 'DNS' && l4PayloadOff !== null && l4PayloadOff < end) {
    const dnsOff = transport === 'TCP' ? l4PayloadOff + 2 : l4PayloadOff;
    const d = parseDns(u8, dnsOff, end);
    if (d) { dns_id = d.id; dns_qr = d.qr; dns_rcode = d.rcode; dns_qname = d.qname; }
  }

  return makePkt({
    id: pid, ts, src, dst, smac, dmac, sport, dport, transport, proto,
    size: origLen, flags, ttl, icmp_type, icmp_code,
    dns_id, dns_qr, dns_rcode, dns_qname, seq, plen, sni, dir: 'out',
  });
}

export function parsePcapBuffer(buffer, filename = 'capture.pcap', limit = 50000) {
  const u8 = new Uint8Array(buffer);
  const dv = new DataView(buffer);
  if (u8.length < 24) throw new Error('File too small to be a valid PCAP/PCAPNG capture.');

  const magic = dv.getUint32(0, false);
  const packets = [];
  let truncated = false;

  if (magic === 0x0a0d0d0a) {
    // PCAPNG
    let off = 0;
    const ifaces = [];
    let le = true;
    while (off + 12 <= u8.length) {
      const btype = dv.getUint32(off, le);
      if (btype === 0x0a0d0d0a) {
        const bom = dv.getUint32(off + 8, true);
        le = bom === 0x1a2b3c4d;
      }
      const blen = dv.getUint32(off + 4, le);
      if (blen < 12 || off + blen > u8.length) break;
      if (btype === 0x00000001 && blen >= 20) {
        ifaces.push(dv.getUint16(off + 8, le)); // linkType
      } else if (btype === 0x00000006 && blen >= 32) {
        if (packets.length >= limit) { truncated = true; break; }
        const ifaceId = dv.getUint32(off + 8, le);
        const tsHi = dv.getUint32(off + 12, le);
        const tsLo = dv.getUint32(off + 16, le);
        const ts = (tsHi * 4294967296 + tsLo) / 1e6;
        const capLen = dv.getUint32(off + 20, le);
        const origLen = dv.getUint32(off + 24, le);
        const linkType = ifaces[ifaceId] ?? 1;
        if (off + 28 + capLen <= off + blen) {
          const p = decodeFrame(u8, dv, off + 28, capLen, origLen, linkType, ts, packets.length);
          if (p) packets.push(p);
        }
      }
      off += blen;
    }
  } else {
    // Classic libpcap
    let le = false;
    let nano = false;
    if (magic === 0xd4c3b2a1) { le = true; }
    else if (magic === 0x4d3cb2a1) { le = true; nano = true; }
    else if (magic === 0xa1b2c3d4) { le = false; }
    else if (magic === 0xa1b23c4d) { le = false; nano = true; }
    else throw new Error('Unrecognized capture format (expected .pcap or .pcapng).');

    const linkType = dv.getUint32(20, le);
    let off = 24;
    while (off + 16 <= u8.length) {
      if (packets.length >= limit) { truncated = true; break; }
      const tsSec = dv.getUint32(off, le);
      const tsSub = dv.getUint32(off + 4, le);
      const capLen = dv.getUint32(off + 8, le);
      const origLen = dv.getUint32(off + 12, le);
      off += 16;
      if (off + capLen > u8.length) break;
      const ts = tsSec + tsSub / (nano ? 1e9 : 1e6);
      const p = decodeFrame(u8, dv, off, capLen, origLen, linkType, ts, packets.length);
      if (p) packets.push(p);
      off += capLen;
    }
  }

  if (!packets.length) throw new Error('No parseable IP/ARP packets found in this capture.');

  // Infer vantage point (most frequent private address)
  const counts = new Map();
  for (const p of packets) {
    if (p.src) counts.set(p.src, (counts.get(p.src) || 0) + 1);
    if (p.dst) counts.set(p.dst, (counts.get(p.dst) || 0) + 1);
  }
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([ip]) => ip);
  const vantage = ranked.find(isPrivateIp) ?? ranked[0] ?? null;
  const ref = new Set(vantage ? [vantage] : []);
  for (const p of packets) p.dir = inferDir(p.src, p.dst, ref);

  packets.sort((a, b) => a.ts - b.ts);
  const start = packets[0].ts;
  const end = packets[packets.length - 1].ts;
  return {
    meta: {
      filename,
      count: packets.length,
      truncated,
      limit,
      start,
      end,
      duration: Math.max(end - start, 0.001),
      vantage,
    },
    packets,
  };
}
