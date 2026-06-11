// Canvas renderers for the playback histogram and the bandwidth sparkline.
//
// The scrubber histogram is stacked by LANE (same colors as the road) and
// carries failure tick marks — red for RSTs, amber for DNS failures — so
// "scrub to the anomaly" works at a glance.
import { LANES, LANE_REPR, laneFor } from './config.js';

const LANE_KEYS = LANES.map((l) => l.key);
const LANE_IDX = Object.fromEntries(LANE_KEYS.map((k, i) => [k, i]));
const LANE_CSS = LANE_KEYS.map((k) => '#' + LANE_REPR[k].toString(16).padStart(6, '0'));

function prepCanvas(canvas) {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
  }
  const g = canvas.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { g, w, h };
}

/** Lane-stacked packet counts + failure markers across the capture. */
export function computeBuckets(packets, meta, n = 240) {
  const L = LANE_KEYS.length;
  const stacks = new Float32Array(n * L);
  const totals = new Float32Array(n);
  const tickRst = new Uint8Array(n);   // bucket contains RSTs
  const tickDns = new Uint8Array(n);   // bucket contains DNS failures
  const span = meta.duration || 1;
  for (const p of packets) {
    let b = Math.floor(((p.ts - meta.start) / span) * n);
    if (b >= n) b = n - 1;
    if (b < 0) b = 0;
    stacks[b * L + (LANE_IDX[laneFor(p)] ?? L - 1)]++;
    totals[b]++;
    if (p.flags && p.flags.includes('R')) tickRst[b] = 1;
    if (p.dns_qr === 1 && (p.dns_rcode === 2 || p.dns_rcode === 3)) tickDns[b] = 1;
  }
  let max = 1;
  for (const v of totals) if (v > max) max = v;
  return { stacks, totals, tickRst, tickDns, n, L, max };
}

export function drawHistogram(canvas, H, playheadFrac) {
  const { g, w, h } = prepCanvas(canvas);
  g.clearRect(0, 0, w, h);
  if (!H) return;
  const { stacks, tickRst, tickDns, n, L, max } = H;
  const bw = w / n;
  const usable = h - 8; // leave headroom for tick marks
  for (let i = 0; i < n; i++) {
    let y = h;
    for (let l = 0; l < L; l++) {
      const v = stacks[i * L + l];
      if (!v) continue;
      const seg = (v / max) * usable;
      g.fillStyle = LANE_CSS[l];
      g.globalAlpha = 0.8;
      g.fillRect(i * bw + 0.5, y - seg, Math.max(bw - 1, 1), seg);
      y -= seg;
    }
    g.globalAlpha = 1;
    if (tickRst[i]) { g.fillStyle = '#ef4444'; g.fillRect(i * bw + 0.5, 0, Math.max(bw - 1, 1.5), 3); }
    if (tickDns[i]) { g.fillStyle = '#fbbf24'; g.fillRect(i * bw + 0.5, 4, Math.max(bw - 1, 1.5), 3); }
  }
  // dim the un-played region instead of redrawing two color states
  const x = playheadFrac * w;
  g.fillStyle = 'rgba(5, 8, 15, 0.55)';
  g.fillRect(x, 0, w - x, h);
  g.fillStyle = 'rgba(248, 250, 252, 0.9)';
  g.fillRect(x - 0.75, 0, 1.5, h);
}

/** Bandwidth sparkline stacked by lane — same color language as the road. */
export function drawSparkline(canvas, totals, laneSeries) {
  const { g, w, h } = prepCanvas(canvas);
  g.clearRect(0, 0, w, h);
  const n = totals.length;
  let max = 1;
  for (const v of totals) if (v > max) max = v;
  const bw = w / n;
  const L = LANE_KEYS.length;
  for (let i = 0; i < n; i++) {
    let y = h;
    for (let l = 0; l < L; l++) {
      const v = laneSeries ? laneSeries[i * L + l] : 0;
      if (!v) continue;
      const seg = (v / max) * (h - 4);
      g.fillStyle = LANE_CSS[l];
      g.globalAlpha = 0.85;
      g.fillRect(i * bw, y - seg, Math.max(bw - 0.5, 0.75), seg);
      y -= seg;
    }
  }
  g.globalAlpha = 1;
  // total envelope line on top
  g.beginPath();
  for (let i = 0; i < n; i++) {
    const x = (i + 0.5) * bw, y = h - (totals[i] / max) * (h - 4);
    i === 0 ? g.moveTo(x, y) : g.lineTo(x, y);
  }
  g.strokeStyle = 'rgba(226, 232, 240, 0.5)';
  g.lineWidth = 1;
  g.stroke();
}
