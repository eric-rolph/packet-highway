// Packet Highway — entry point. Wires scene, traffic, flow tracking, data
// sources, and UI, and runs the render loop. Two sources can drive the road:
//   LIVE  — WebSocket stream of capture (or demo) packets, wall-clock time
//   PCAP  — uploaded capture replayed through the Playback engine's clock
import { flowKeyOf } from './config.js';
import { createScene } from './scene.js';
import { buildHighway } from './highway.js';
import { TrafficController } from './traffic.js';
import { Picker } from './picking.js';
import { StatsEngine } from './stats.js';
import { FlowTracker } from './flows.js';
import { DnsTracker } from './dns.js';
import { Playback } from './playback.js';
import { LiveSource, fetchInterfaces, fetchSample, uploadPcap } from './sources.js';
import { computeBuckets } from './histogram.js';
import { UI, fmtDur } from './ui.js';

const canvas = document.getElementById('scene-canvas');
const { renderer, scene, camera, composer, setPreset, setChase, setOrbit, update: updateCamera } = createScene(canvas);
const laneX = buildHighway(scene);
const traffic = new TrafficController(scene, laneX);
const stats = new StatsEngine(60);
const flows = new FlowTracker(3);
const dns = new DnsTracker(5);
const playback = new Playback();

let mode = 'live';
let liveDropped = 0;
let lastStormWarn = -1e9;
let currentReasons = [];
let frozen = false;     // live mode: road frozen for inspection (stats continue)
let shotPending = false;
const statusRing = []; // counter snapshots for windowed status verdicts

function trackPacket(p) {
  stats.add(p);
  const ev = flows.add(p); // also sets p.retrans before the vehicle spawns
  if (ev) traffic.spawnFlare(ev);
  const dnsEv = dns.add(p);
  if (dnsEv) traffic.spawnDnsFlare(dnsEv);
}

function ingestPacket(p) {
  trackPacket(p);   // analysis first: spawn colors depend on it
  traffic.ingest(p);
}

function resetWorld() {
  traffic.clear();
  stats.reset();
  flows.reset();
  dns.reset();
  liveDropped = 0;
  statusRing.length = 0; // counters restarted — stale baselines would go negative
  frozen = false;
  ui.setFrozen(false);
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
    for (const p of items) trackPacket(p); // analysis first (retrans/SNI marks)
    if (!frozen) traffic.ingestBatch(items, 110); // frozen road: count, don't spawn
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
    if (mode === 'live') {
      // freeze-frame: stop the road so fast vehicles can be inspected/clicked;
      // analysis and stats keep running on the live stream underneath
      frozen = !frozen;
      ui.setFrozen(frozen);
      return;
    }
    if (!playback.loaded) return;
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
  onCameraPreset(n) {
    if (n === 5) {
      setOrbit();
      ui.toast('Auto-orbit — drag or press 1/2/3 to take back control.', 'info');
      return;
    }
    if (n === 4) {
      const sel = picker.selected;
      if (sel?.rec && !sel.rec.gone) {
        setChase(() => {
          const s = picker.selected;
          return s?.rec && !s.rec.gone ? s.rec : null;
        });
        ui.toast('Chase cam — riding with the selected packet. 1/2/3 or drag to exit.', 'info');
      } else {
        ui.toast('Click a vehicle first, then press 4 to chase it.', 'info');
      }
      return;
    }
    setPreset(n);
  },
  onScreenshot() { shotPending = true; },
  onThemeToggle() {
    try {
      const next = localStorage.getItem('ph-theme') === 'colorblind' ? 'night' : 'colorblind';
      localStorage.setItem('ph-theme', next);
    } catch { /* private mode */ }
    location.reload();
  },
  onTalkerClick(ip) {
    traffic.setHighlight({ type: 'host', key: ip });
    ui.toast(`Spotlighting ${ip} — everything touching this host stays lit. Click empty road to clear.`, 'info');
  },
  onHealthClick(kind, title) {
    const hints = {
      halfopen: 'SYNs that were never answered — filtered ports, dead hosts, or scanners.',
      refused: 'SYNs answered by RST — the port is closed or rejecting.',
      rst: 'All resets seen, including mid-session aborts.',
      retrans: 'Data segments sent twice — the signature of packet loss.',
      nxdomain: 'Names that do not exist — typos, dead domains, broken search lists.',
      servfail: 'The resolver failed these lookups — upstream or DNSSEC trouble.',
      dnstimeout: 'Resolvers that never answered at all.',
    };
    const source = ['nxdomain', 'servfail', 'dnstimeout'].includes(kind) ? dns : flows;
    ui.showHealthList(title, source.recent(kind), hints[kind]);
  },
  onStatusClick() {
    const entries = currentReasons.length
      ? currentReasons.map((r) => ({ target: r, count: 1, extra: '' }))
      : [];
    ui.showHealthList('Network status', entries,
      currentReasons.length
        ? 'Active issues — click the health rows on the left for per-target evidence.'
        : 'No active issues. Verdict turns amber/red on TCP failures, DNS failures, packet loss, broadcast storms, or server-side drops.');
  },
});

const picker = new Picker(canvas, camera, traffic, (meta) => {
  // enrich with the flow's TLS server name when known
  if (meta && !meta.aggregate && !meta.flowEvent && !meta.sni) {
    meta._sni = flows.sniFor(flowKeyOf(meta));
  }
  ui.showDetail(meta);
  // spotlight the clicked packet's conversation (breakdowns spotlight their SYN's)
  const flowPkt = meta?.flowEvent ? meta.syn : meta;
  const key = flowPkt && !flowPkt.aggregate ? flowKeyOf(flowPkt) : null;
  traffic.setHighlight(key ? { type: 'flow', key } : null);
});
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
window.__ph = { scene, camera, traffic, playback, stats, flows, dns, picker: () => picker };

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

  if (!(frozen && mode === 'live')) traffic.update(dt, t);

  if (render) {
    picker.update(t);
    updateCamera(now);
    composer.render();
    if (shotPending) {
      shotPending = false;
      canvas.toBlob((blob) => { // capture in the same frame the buffer is valid
        if (!blob) return;
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `packet-highway-${new Date().toISOString().replace(/[:.]/g, '-')}.png`;
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 5000);
      });
    }
  }

  uiTimer += dt;
  if (uiTimer >= 0.25) {
    uiTimer = 0;
    const statsNow = mode === 'pcap' ? (playback.loaded ? playback.t : 0) : Date.now() / 1000;
    for (const ev of flows.tick(statsNow)) traffic.spawnFlare(ev);
    for (const ev of dns.tick(statsNow)) traffic.spawnDnsFlare(ev);
    const snap = stats.snapshot(statsNow);
    ui.renderStats(snap, {
      counts: flows.counts,
      pending: flows.pendingCount,
      open: flows.openCount,
      rtt: flows.rttStats,
    }, {
      counts: dns.counts,
      rtt: dns.rttStats,
    });
    if (snap.bcastPps > 50 && statsNow - lastStormWarn > 30) {
      lastStormWarn = statsNow;
      ui.toast(`Broadcast storm? ${snap.bcastPps}/s broadcast-multicast frames in the last second.`, 'error');
    }

    // glanceable verdict — over the last ~60 s, not session-cumulative,
    // so an old incident ages out and a new one isn't diluted by history
    const c = flows.counts, dc = dns.counts;
    statusRing.push({
      t: statsNow, est: c.established, half: c.halfOpen, ref: c.refused,
      retrans: c.retrans, fail: dc.nxdomain + dc.servfail + dc.timeouts,
      ok: dc.ok, pkts: snap.totalPkts,
    });
    while (statusRing.length > 2 && statusRing[0].t < statsNow - 62) statusRing.shift();
    const base = statusRing[0];
    const w = {
      est: c.established - base.est,
      half: c.halfOpen - base.half,
      ref: c.refused - base.ref,
      retrans: c.retrans - base.retrans,
      dnsFail: dc.nxdomain + dc.servfail + dc.timeouts - base.fail,
      dnsOk: dc.ok - base.ok,
      pkts: snap.totalPkts - base.pkts,
    };
    const reasons = [];
    let level = 0; // 0 ok, 1 degraded, 2 problem
    const attempts = w.est + w.half + w.ref;
    if (attempts >= 8 && w.est / attempts < 0.8) { reasons.push('TCP connections failing'); level = 2; }
    const lookups = w.dnsOk + w.dnsFail;
    if (lookups >= 8 && w.dnsFail / lookups > 0.15) { reasons.push('DNS failures'); level = 2; }
    if (w.pkts > 300 && w.retrans / w.pkts > 0.02) { reasons.push('packet loss (retransmissions)'); level = Math.max(level, 1); }
    if (snap.bcastPps > 50) { reasons.push('broadcast storm'); level = 2; }
    if (liveDropped > 0) { reasons.push('view incomplete (capture drops)'); level = Math.max(level, 1); }
    currentReasons = reasons;
    ui.setStatus(level === 2 ? 'problem' : level === 1 ? 'degraded' : 'ok', reasons);
    ui.hud({
      fps,
      active: traffic.activeCount(),
      pps: snap.pps,
      merged: traffic.aggregatedPkts, // packets riding in convoys (by design)
      recycled: traffic.recycled,     // visuals reclaimed early (pool pressure)
      dropped: liveDropped,           // server-side losses (red = data missing)
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
