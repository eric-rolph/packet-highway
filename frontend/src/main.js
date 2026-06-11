// Packet Highway — entry point. Wires scene, traffic, flow tracking, data
// sources, and UI, and runs the render loop. Two sources can drive the road:
//   LIVE  — WebSocket stream of capture (or demo) packets, wall-clock time
//   PCAP  — uploaded capture replayed through the Playback engine's clock
import { createScene } from './scene.js';
import { buildHighway } from './highway.js';
import { TrafficController } from './traffic.js';
import { Picker } from './picking.js';
import { StatsEngine } from './stats.js';
import { FlowTracker } from './flows.js';
import { Playback } from './playback.js';
import { LiveSource, fetchInterfaces, fetchSample, uploadPcap } from './sources.js';
import { computeBuckets } from './histogram.js';
import { UI, fmtDur } from './ui.js';

const canvas = document.getElementById('scene-canvas');
const { renderer, scene, camera, controls } = createScene(canvas);
const laneX = buildHighway(scene);
const traffic = new TrafficController(scene, laneX);
const stats = new StatsEngine(60);
const flows = new FlowTracker(3);
const playback = new Playback();

let mode = 'live';
let liveDropped = 0;

function ingestPacket(p) {
  traffic.ingest(p);
  trackPacket(p);
}

function trackPacket(p) {
  stats.add(p);
  const ev = flows.add(p);
  if (ev) traffic.spawnFlare(ev);
}

function resetWorld() {
  traffic.clear();
  stats.reset();
  flows.reset();
  picker.deselect();
}

const live = new LiveSource({
  onHello: (msg) => {
    ui.setCaptureState(true);
    ui.toast(msg.mode === 'demo'
      ? 'Demo traffic stream started — synthetic packets, no capture needed.'
      : `Capturing on ${msg.iface ?? 'default interface'}${msg.bpf ? ` (filter: ${msg.bpf})` : ''}`,
      'success');
  },
  onPackets: (items, dropped) => {
    if (mode !== 'live') return;
    traffic.ingestBatch(items, 110);
    for (const p of items) trackPacket(p);
    liveDropped = dropped;
  },
  onError: (msg) => ui.toast(msg, 'error'),
  onClose: () => ui.setCaptureState(false),
});

const ui = new UI({
  onModeSwitch(next) {
    if (next === mode) return;
    mode = next;
    if (live.running) live.stop();
    playback.playing = false;
    resetWorld();
    ui.setMode(mode);
    ui.setPlaybackVisible(mode === 'pcap' && playback.loaded);
  },
  onCaptureToggle() {
    if (live.running) { live.stop(); return; }
    resetWorld();
    const sel = document.getElementById('iface-select').value;
    const bpf = document.getElementById('bpf-input').value.trim();
    live.start(sel === '__demo__' ? { demo: true } : { iface: sel, bpf });
  },
  async onFileSelected(file) {
    ui.setPcapMeta(`parsing ${file.name}…`);
    try {
      loadTimeline(await uploadPcap(file));
    } catch (err) {
      ui.setPcapMeta('');
      ui.toast(String(err.message ?? err), 'error');
    }
  },
  async onLoadSample() {
    ui.setPcapMeta('generating sample capture…');
    try {
      loadTimeline(await fetchSample());
    } catch (err) {
      ui.setPcapMeta('');
      ui.toast(String(err.message ?? err), 'error');
    }
  },
  onPlayToggle() {
    if (mode !== 'pcap' || !playback.loaded) return;
    if (playback.atEnd) { seekTo(0); }
    playback.playing = !playback.playing;
  },
  onSpeedChange(speed) { playback.speed = speed; },
  onScrub(frac) { if (playback.loaded) seekTo(frac); },
  onSeekRelative(sec) {
    if (mode !== 'pcap' || !playback.loaded) return;
    seekTo((playback.t + sec - playback.meta.start) / playback.meta.duration);
  },
  onDetailClose() { picker.deselect(); },
});

const picker = new Picker(canvas, camera, traffic, (meta) => ui.showDetail(meta));
scene.add(picker.ring);

function seekTo(frac) {
  playback.seekFrac(frac);
  resetWorld(); // vehicles/window/pending-SYNs belong to the old position
}

function loadTimeline(data) {
  playback.load(data);
  ui.setHistogram(computeBuckets(data.packets, data.meta));
  ui.setPlaybackVisible(true);
  const m = data.meta;
  ui.setPcapMeta(
    `${m.filename} · ${m.count.toLocaleString()} pkts · ${fmtDur(m.duration)}` +
    `${m.vantage ? ` · vantage ${m.vantage}` : ''}${m.truncated ? ` · truncated at ${m.limit.toLocaleString()}` : ''}`
  );
  if (m.truncated) ui.toast(`Large capture: showing the first ${m.limit.toLocaleString()} packets.`, 'info');
  resetWorld();
  playback.playing = true;
  ui.toast(`Loaded ${m.count.toLocaleString()} packets — press SPACE to pause, drag the timeline to scrub.`, 'success');
}

// Debug/automation handle (read-only access for testing)
window.__ph = { scene, camera, traffic, playback, stats, flows, picker: () => picker };

ui.setMode('live');
(function loadInterfaces(attempt = 0) {
  fetchInterfaces()
    .then((list) => {
      if (list.length) ui.fillInterfaces(list);
      else if (attempt < 5) setTimeout(() => loadInterfaces(attempt + 1), 1500);
    })
    .catch(() => { if (attempt < 5) setTimeout(() => loadInterfaces(attempt + 1), 1500); });
})();

// ------------------------------------------------------------ render loop
let last = performance.now();
let fps = 60;
let uiTimer = 0;

function step(now, render) {
  const dt = Math.min((now - last) / 1000, 1.0); // clamp huge deltas (tab switch)
  last = now;
  const t = now / 1000;
  if (render) fps = fps * 0.95 + (dt > 0 ? 1 / dt : 60) * 0.05;

  if (mode === 'pcap' && playback.loaded) {
    for (const p of playback.tick(dt)) ingestPacket(p);
    if (render) ui.updatePlayback(playback);
  }

  traffic.update(dt, t);

  if (render) {
    picker.update(t);
    controls.update();
    renderer.render(scene, camera);
  }

  uiTimer += dt;
  if (uiTimer >= 0.25) {
    uiTimer = 0;
    const statsNow = mode === 'pcap' ? (playback.loaded ? playback.t : 0) : Date.now() / 1000;
    for (const ev of flows.tick(statsNow)) traffic.spawnFlare(ev);
    const snap = stats.snapshot(statsNow);
    ui.renderStats(snap, { counts: flows.counts, pending: flows.pendingCount });
    ui.hud({
      fps,
      active: traffic.activeCount(),
      pps: snap.pps,
      merged: traffic.aggregatedPkts + traffic.recycled + liveDropped,
    });
  }
}

function frame(now) {
  requestAnimationFrame(frame);
  step(now, true);
}
requestAnimationFrame(frame);

// Browsers suspend rAF for hidden tabs; keep the world ticking (~1 Hz) so
// stats, playback, and lane queues stay current while the page is hidden.
setInterval(() => {
  if (document.hidden) step(performance.now(), false);
}, 1000);
