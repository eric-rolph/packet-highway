// Shared constants: protocol taxonomy, lanes, colors, vehicle types.
// The legend is GENERATED from this file (see LEGEND below), so swatches in
// the UI always match what's rendered on the road.
//
// TIMING MODEL: every vehicle in a lane moves at the SAME constant speed
// (the lane's speed below). Position is therefore an exact linear function
// of arrival time — the road is a scrolling timeline, and the spacing
// between same-lane vehicles IS their real inter-arrival spacing. Because
// speeds never differ within a lane, overtaking (and therefore collision/
// ghosting) is geometrically impossible. Near-simultaneous arrivals take
// the parallel sub-lane; bursts beyond both sub-lanes become convoys.

// Theme: 'night' (default) or 'colorblind' — a deuteranopia-oriented palette
// (Okabe-Ito based) that never leans on red-vs-green. Picked at load from
// ?theme= or localStorage; the legend regenerates from whatever is active.
export const THEME = (() => {
  try {
    const q = new URLSearchParams(location.search).get('theme');
    return (q ?? localStorage.getItem('ph-theme')) === 'colorblind' ? 'colorblind' : 'night';
  } catch {
    return 'night';
  }
})();
const CB = THEME === 'colorblind';

export const PROTO_COLORS = CB ? {
  HTTPS:  0x0072b2, // blue
  HTTP:   0xe69f00, // orange
  DNS:    0xf0e442, // yellow
  ICMP:   0xf1f5f9, // white
  SSH:    0x56b4e9, // sky
  RDP:    0xcc79a7, // mauve
  SNMP:   0x009e73, // teal-green
  DHCP:   0x35c297,
  NTP:    0x88ccee,
  SYSLOG: 0xaa4499,
  VPN:    0x7c6fd0,
  MAIL:   0x44aa99,
  SMB:    0xddaa33,
  FTP:    0xb85c7a,
  TCP:    0x94a3b8,
  UDP:    0xbbbbdd,
  ARP:    0xd6d3d1,
  OTHER:  0x64748b,
} : {
  HTTPS:  0x10b981, // emerald — encrypted web (incl. QUIC)
  HTTP:   0xf97316, // orange  — cleartext web (deliberately "warning" colored)
  DNS:    0xfacc15, // yellow
  ICMP:   0xf1f5f9, // white   — police cars
  SSH:    0x38bdf8, // sky
  RDP:    0x818cf8, // indigo
  SNMP:   0x2dd4bf, // teal
  DHCP:   0xa3e635, // lime
  NTP:    0x22d3ee, // cyan
  SYSLOG: 0xd946ef, // fuchsia
  VPN:    0x8b5cf6, // violet
  MAIL:   0x0891b2, // dark cyan
  SMB:    0xfb7185, // rose
  FTP:    0xf43f5e, // crimson
  TCP:    0x94a3b8, // slate — unclassified TCP (also TCP control bodies)
  UDP:    0xc4b5fd, // lavender — unclassified UDP
  ARP:    0xd6d3d1, // warm gray
  OTHER:  0x64748b,
};

export const PROTO_CSS = Object.fromEntries(
  Object.entries(PROTO_COLORS).map(([k, v]) => [k, '#' + v.toString(16).padStart(6, '0')])
);

// TCP control car body colors (opening / accepted / closing / reset)
export const FLAG_COLORS = CB
  ? { S: 0xe69f00, SA: 0x56b4e9, F: 0xcc79a7, FA: 0xcc79a7, R: 0xd55e00, RA: 0xd55e00 }
  : { S: 0xfbbf24, SA: 0x4ade80, F: 0xc084fc, FA: 0xc084fc, R: 0xf87171, RA: 0xf87171 };

// Lane speed = world units/sec for EVERY vehicle in that lane (see header).
export const LANES = [
  { key: 'WEB',   label: 'WEB · 80/443',       speed: 46 },
  { key: 'DNS',   label: 'DNS · 53',           speed: 92 },
  { key: 'MGMT',  label: 'MGMT · 22/3389',     speed: 62 },
  { key: 'INFRA', label: 'INFRA · SNMP/NTP',   speed: 52 },
  { key: 'FILE',  label: 'FILE · 445/21',      speed: 46 },
  { key: 'OTHER', label: 'OTHER',              speed: 58 },
  { key: 'ICMP',  label: 'ICMP',               speed: 70 },
];
export const LANE_SPEED = Object.fromEntries(LANES.map((l) => [l.key, l.speed]));

const PROTO_LANE = {
  HTTP: 'WEB', HTTPS: 'WEB',
  DNS: 'DNS',
  SSH: 'MGMT', RDP: 'MGMT',
  SNMP: 'INFRA', DHCP: 'INFRA', NTP: 'INFRA', SYSLOG: 'INFRA', VPN: 'INFRA', MAIL: 'INFRA',
  SMB: 'FILE', FTP: 'FILE',
  ICMP: 'ICMP',
};

export const HIGHWAY = {
  length: 620,
  laneWidth: 8.4,   // wide enough for two sub-lanes
  medianWidth: 11,
  shoulder: 8,
};
export const HALF_LEN = HIGHWAY.length / 2;

// Two sub-lanes per protocol lane absorb near-simultaneous arrivals.
export const SUBLANE_OFFSET = 2.1;

export function laneOffset(i) {
  return HIGHWAY.medianWidth / 2 + (i + 0.5) * HIGHWAY.laneWidth;
}

/** World X of a sub-lane center. dir 'in' drives on +X, 'out' on -X. */
export function sublaneX(laneCenterX, dir, sub) {
  const sign = dir === 'in' ? 1 : -1;
  return laneCenterX + (sub === 0 ? -1 : 1) * sign * SUBLANE_OFFSET;
}

export function laneFor(p) {
  if (p.transport === 'ICMP') return 'ICMP';
  return PROTO_LANE[p.proto] ?? 'OTHER';
}

/** TCP control packets (handshake/teardown) — flag MEMBERSHIP, not equality,
 *  so ECN-marked handshakes ("SEC"/"SAE") classify correctly. */
export function isControl(p) {
  if (p.transport !== 'TCP' || !p.flags || p.size > 120) return false;
  return p.flags.includes('S') || p.flags.includes('F') || p.flags.includes('R');
}

/** Canonical flow key for a packet (order-independent 4-tuple), or null. */
export function flowKeyOf(p) {
  if (!p || p.sport == null || p.dport == null) return null;
  const a = `${p.src}:${p.sport}`;
  const b = `${p.dst}:${p.dport}`;
  return a < b ? `${a}|${b}` : `${b}|${a}`;
}

// Vehicle metaphors:
//   motorcycle — DNS: small queries weaving through fast
//   van/truck  — payload carriers (web, file transfer), length scales w/ bytes
//   sedan      — generic / interactive TCP (SSH, RDP)
//   police     — ICMP: the network's patrol & diagnostics (red/blue strobes;
//                error messages like unreachable/TTL-exceeded ride red-bodied)
//   signal     — TCP control packets (SYN/SYN-ACK/FIN/RST), flag-colored strobe
//   drone      — UDP: connectionless, never touches the road
//   cart       — L2 housekeeping (ARP etc.): slow maintenance vehicle
//   convoy     — aggregate of a traffic burst (N packets as one road-train)
const VAN_PROTOS = new Set(['SMB', 'FTP', 'VPN', 'MAIL']);
export function vehicleTypeFor(p) {
  if (isControl(p)) return 'signal';
  if (p.transport === 'ICMP') return 'police';
  if (p.proto === 'DNS') return 'motorcycle';
  if (p.proto === 'HTTP' || p.proto === 'HTTPS') return p.size > 900 ? 'truck' : 'van';
  if (VAN_PROTOS.has(p.proto)) return 'van';
  if (p.transport === 'TCP') return 'sedan';
  if (p.transport === 'UDP') return 'drone';
  return 'cart';
}

// cap = instance pool size, len = visual length at scale 1 (for spacing math)
export const TYPE_SPECS = {
  motorcycle: { cap: 280, len: 3.2 },
  van:        { cap: 260, len: 5.6 },
  truck:      { cap: 160, len: 8.6 },
  sedan:      { cap: 320, len: 5.0 },
  police:     { cap: 140, len: 5.0 },
  signal:     { cap: 220, len: 3.8 },
  drone:      { cap: 200, len: 2.4 },
  cart:       { cap: 140, len: 3.2 },
  convoy:     { cap: 120, len: 11.0 },
};

export const FLAG_NAMES = {
  F: 'FIN', S: 'SYN', R: 'RST', P: 'PSH', A: 'ACK', U: 'URG', E: 'ECE', C: 'CWR',
};

// Failure tint shared by DNS-failure motorcycles, ICMP error cruisers,
// retransmissions, and shoulder wrecks. Vermillion under the CB theme.
export const FAIL_RED = CB ? 0xd55e00 : 0xef4444;

// Representative color per lane, for the stacked scrubber histogram.
export const LANE_REPR = {
  WEB: PROTO_COLORS.HTTPS, DNS: PROTO_COLORS.DNS, MGMT: PROTO_COLORS.SSH,
  INFRA: PROTO_COLORS.SNMP, FILE: PROTO_COLORS.SMB, OTHER: PROTO_COLORS.TCP,
  ICMP: PROTO_COLORS.ICMP,
};

/** Broadcast / multicast destination (L2 or L3). */
export function isBroadcast(p) {
  if (p.dmac === 'ff:ff:ff:ff:ff:ff') return true;
  const d = p.dst ?? '';
  if (d === '255.255.255.255') return true;
  const first = parseInt(d, 10);
  if (first >= 224 && first <= 239) return true;
  return d.includes(':') && d.toLowerCase().startsWith('ff');
}

// Rows for the auto-generated legend (color always = PROTO_COLORS).
export const LEGEND = [
  { proto: 'DNS',   text: 'DNS — motorcycles (fast lane)' },
  { proto: 'HTTPS', text: 'HTTPS/QUIC — vans/trucks · length = bytes' },
  { proto: 'HTTP',  text: 'HTTP (cleartext) — vans/trucks' },
  { proto: 'ICMP',  text: 'ICMP — police cars (errors ride red)' },
  { proto: 'SSH',   text: 'SSH — sedans (MGMT lane)' },
  { proto: 'RDP',   text: 'RDP — sedans (MGMT lane)' },
  { proto: 'SMB',   text: 'SMB/FTP — cargo vans (FILE lane)' },
  { proto: 'SNMP',  text: 'SNMP — drones (INFRA lane)' },
  { proto: 'DHCP',  text: 'DHCP · NTP · syslog — drones' },
  { proto: 'UDP',   text: 'Other UDP — drones (airborne)' },
  { proto: 'TCP',   text: 'Other TCP — sedans' },
  { proto: 'ARP',   text: 'ARP/L2 — maintenance carts' },
  { css: '#ef4444', text: 'Red bodies = failures (NXDOMAIN/SERVFAIL bikes, ICMP errors)' },
];
