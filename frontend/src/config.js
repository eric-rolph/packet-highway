// Shared constants: protocol taxonomy, lane layout, vehicle types, colors.
// The legend is GENERATED from this file (see LEGEND below), so swatches in
// the UI always match what's rendered on the road.

export const PROTO_COLORS = {
  HTTPS:  0x10b981, // emerald — encrypted web
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

// Strobe colors for TCP control (signal cars)
export const FLAG_COLORS = { S: 0xfbbf24, SA: 0x4ade80, F: 0xc084fc, FA: 0xc084fc, R: 0xf87171, RA: 0xf87171 };

export const LANES = [
  { key: 'WEB',   label: 'WEB · 80/443' },
  { key: 'DNS',   label: 'DNS · 53' },
  { key: 'MGMT',  label: 'MGMT · 22/3389' },
  { key: 'INFRA', label: 'INFRA · SNMP/NTP' },
  { key: 'FILE',  label: 'FILE · 445/21' },
  { key: 'OTHER', label: 'OTHER' },
  { key: 'ICMP',  label: 'ICMP' },
];

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
  laneWidth: 8.4,   // wide enough for two sub-lanes (cruise + passing)
  medianWidth: 11,
  shoulder: 8,
};
export const HALF_LEN = HIGHWAY.length / 2;

// Each protocol lane is split into two sub-lanes so faster vehicles can
// overtake instead of ghosting through slower ones: sub 0 = passing (inner,
// nearer the median), sub 1 = cruise (outer).
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

const CONTROL_FLAGS = new Set(['S', 'SA', 'F', 'FA', 'R', 'RA']);
export function isControl(p) {
  return p.transport === 'TCP' && CONTROL_FLAGS.has(p.flags) && p.size <= 120;
}

// Vehicle metaphors:
//   motorcycle — DNS: small queries weaving through fast
//   van/truck  — payload carriers (web, file transfer), length scales w/ bytes
//   sedan      — generic / interactive TCP (SSH, RDP)
//   police     — ICMP: the network's patrol & diagnostics (red/blue strobes)
//   signal     — TCP control packets (SYN/SYN-ACK/FIN/RST), flag-colored strobe
//   drone      — UDP: connectionless, never touches the road surface
//   cart       — L2 housekeeping (ARP etc.): slow maintenance vehicle
//   convoy     — aggregate of a traffic burst (N packets as one long hauler)
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

// speed = world units/sec, cap = instance pool size,
// len = visual length at scale 1 (used for follow-gap math)
export const TYPE_SPECS = {
  motorcycle: { speed: 95, cap: 280, len: 3.2 },
  van:        { speed: 55, cap: 260, len: 5.6 },
  truck:      { speed: 40, cap: 160, len: 8.6 },
  sedan:      { speed: 62, cap: 320, len: 5.0 },
  police:     { speed: 70, cap: 140, len: 5.0 },
  signal:     { speed: 75, cap: 220, len: 3.8 },
  drone:      { speed: 48, cap: 200, len: 2.4 },
  cart:       { speed: 38, cap: 140, len: 3.2 },
  convoy:     { speed: 45, cap: 120, len: 11.0 },
};

// Vehicles at or above this base speed prefer the passing sub-lane.
export const PASS_SPEED = 60;

// Minimum time between vehicles entering the same lane (prevents overlap);
// bursts beyond this are merged into convoys.
export const HEADWAY_MS = 130;

export const FLAG_NAMES = {
  F: 'FIN', S: 'SYN', R: 'RST', P: 'PSH', A: 'ACK', U: 'URG', E: 'ECE', C: 'CWR',
};

// Rows for the auto-generated legend (color always = PROTO_COLORS).
export const LEGEND = [
  { proto: 'DNS',   text: 'DNS — motorcycles (small & fast)' },
  { proto: 'HTTPS', text: 'HTTPS — vans/trucks · length = bytes' },
  { proto: 'HTTP',  text: 'HTTP (cleartext) — vans/trucks' },
  { proto: 'ICMP',  text: 'ICMP — police cars (red/blue strobe)' },
  { proto: 'SSH',   text: 'SSH — sedans (MGMT lane)' },
  { proto: 'RDP',   text: 'RDP — sedans (MGMT lane)' },
  { proto: 'SMB',   text: 'SMB/FTP — cargo vans (FILE lane)' },
  { proto: 'SNMP',  text: 'SNMP — drones (INFRA lane)' },
  { proto: 'DHCP',  text: 'DHCP · NTP · syslog — drones' },
  { proto: 'UDP',   text: 'Other UDP — drones (connectionless: airborne)' },
  { proto: 'TCP',   text: 'Other TCP — sedans' },
  { proto: 'ARP',   text: 'ARP/L2 — maintenance carts' },
];
