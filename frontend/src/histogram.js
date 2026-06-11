// Canvas renderers for the playback histogram and the bandwidth sparkline.

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

/** Bucket packet counts across the capture for the scrubber background. */
export function computeBuckets(packets, meta, n = 240) {
  const buckets = new Float64Array(n);
  const span = meta.duration || 1;
  for (const p of packets) {
    let b = Math.floor(((p.ts - meta.start) / span) * n);
    if (b >= n) b = n - 1;
    if (b < 0) b = 0;
    buckets[b]++;
  }
  return buckets;
}

export function drawHistogram(canvas, buckets, playheadFrac) {
  const { g, w, h } = prepCanvas(canvas);
  g.clearRect(0, 0, w, h);
  if (!buckets) return;
  let max = 1;
  for (const v of buckets) if (v > max) max = v;
  const bw = w / buckets.length;
  for (let i = 0; i < buckets.length; i++) {
    const frac = buckets[i] / max;
    const bh = Math.max(frac * (h - 6), buckets[i] > 0 ? 1.5 : 0);
    const played = i / buckets.length <= playheadFrac;
    g.fillStyle = played ? `rgba(34, 211, 238, ${0.35 + frac * 0.6})`
                         : `rgba(100, 116, 139, ${0.25 + frac * 0.45})`;
    g.fillRect(i * bw + 0.5, h - bh, Math.max(bw - 1, 1), bh);
  }
  // playhead
  const x = playheadFrac * w;
  g.fillStyle = 'rgba(248, 250, 252, 0.9)';
  g.fillRect(x - 0.75, 0, 1.5, h);
}

export function drawSparkline(canvas, buckets) {
  const { g, w, h } = prepCanvas(canvas);
  g.clearRect(0, 0, w, h);
  let max = 1;
  for (const v of buckets) if (v > max) max = v;
  const bw = w / buckets.length;
  g.beginPath();
  g.moveTo(0, h);
  for (let i = 0; i < buckets.length; i++) {
    g.lineTo((i + 0.5) * bw, h - (buckets[i] / max) * (h - 4));
  }
  g.lineTo(w, h);
  g.closePath();
  g.fillStyle = 'rgba(34, 211, 238, 0.18)';
  g.fill();
  g.beginPath();
  for (let i = 0; i < buckets.length; i++) {
    const x = (i + 0.5) * bw, y = h - (buckets[i] / max) * (h - 4);
    i === 0 ? g.moveTo(x, y) : g.lineTo(x, y);
  }
  g.strokeStyle = 'rgba(34, 211, 238, 0.85)';
  g.lineWidth = 1.5;
  g.stroke();
}
