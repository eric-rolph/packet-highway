// DOM overlay: mode tabs, capture controls, stats dashboard, TCP health,
// packet/convoy/flare detail panel, playback bar, toasts. Pure view layer —
// main.js supplies callbacks. The legend is generated from config.js so its
// colors are, by construction, the colors used on the road.
import { FAIL_RED, FLAG_COLORS, FLAG_NAMES, LEGEND, PROTO_CSS, THEME, isBroadcast } from './config.js';

const hex = (n) => '#' + n.toString(16).padStart(6, '0');
import { drawHistogram, drawSparkline } from './histogram.js';
import { fmtBps, fmtBytes } from './stats.js';

const esc = (s) => String(s ?? '—').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

export function fmtDur(sec) {
  const s = Math.max(sec, 0);
  const m = Math.floor(s / 60);
  return `${m}:${(s - m * 60).toFixed(1).padStart(4, '0')}`;
}

export function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const ms = String(Math.floor((ts % 1) * 1000)).padStart(3, '0');
  return `${d.toLocaleTimeString([], { hour12: false })}.${ms}`;
}

const ICMP_NAMES_V4 = {
  0: 'echo reply', 3: 'destination unreachable', 5: 'redirect',
  8: 'echo request', 11: 'time exceeded (TTL)', 12: 'parameter problem',
};
const ICMP_NAMES_V6 = {
  1: 'destination unreachable', 2: 'packet too big', 3: 'time exceeded',
  4: 'parameter problem', 128: 'echo request', 129: 'echo reply',
  133: 'router solicitation', 134: 'router advertisement',
  135: 'neighbor solicitation', 136: 'neighbor advertisement',
};

function icmpName(p) {
  const v6 = !!p.src && p.src.includes(':');
  const name = (v6 ? ICMP_NAMES_V6 : ICMP_NAMES_V4)[p.icmp_type];
  return `type ${p.icmp_type}/${p.icmp_code ?? 0}${name ? ` — ${name}` : ''}`;
}

export class UI {
  constructor(callbacks) {
    this.cb = callbacks;
    this.el = {};
    for (const id of [
      'tab-live', 'tab-pcap', 'live-controls', 'pcap-controls', 'iface-select',
      'bpf-input', 'btn-capture', 'file-input', 'btn-sample', 'pcap-meta',
      'stat-bw-in', 'stat-bw-out', 'stat-total', 'spark-canvas', 'proto-list',
      'talkers-list', 'legend-list', 'hud-fps', 'hud-active', 'hud-pps',
      'hud-merged', 'hud-recycled', 'hud-dropped',
      'tcph-est', 'tcph-pending', 'tcph-half', 'tcph-refused', 'tcph-rst',
      'tcph-retries', 'tcph-retrans', 'tcph-rtt', 'tcph-bar',
      'dnsh-ok', 'dnsh-nx', 'dnsh-sf', 'dnsh-to', 'dnsh-rtt',
      'status-pill', 'btn-theme', 'btn-shot', 'frozen-pill', 'tcph-open',
      'detail-panel', 'detail-body', 'detail-close', 'playback-bar', 'btn-play',
      'sel-speed', 'time-cur', 'time-total', 'time-abs', 'scrub', 'hist-canvas',
      'toasts',
    ]) this.el[id] = document.getElementById(id);

    this.scrubbing = false;
    this.histBuckets = null;
    this.buildLegend();

    this.el['tab-live'].onclick = () => this.cb.onModeSwitch('live');
    this.el['tab-pcap'].onclick = () => this.cb.onModeSwitch('pcap');
    this.el['btn-capture'].onclick = () => this.cb.onCaptureToggle();
    this.el['btn-sample'].onclick = () => this.cb.onLoadSample();
    this.el['file-input'].onchange = (e) => {
      const f = e.target.files[0];
      if (f) this.cb.onFileSelected(f);
      e.target.value = '';
    };
    this.el['btn-play'].onclick = () => this.cb.onPlayToggle();
    this.el['sel-speed'].onchange = (e) => this.cb.onSpeedChange(parseFloat(e.target.value));
    this.el['detail-close'].onclick = () => this.cb.onDetailClose();

    const scrub = this.el['scrub'];
    scrub.addEventListener('pointerdown', () => { this.scrubbing = true; });
    scrub.addEventListener('pointerup', () => { this.scrubbing = false; });
    scrub.addEventListener('pointercancel', () => { this.scrubbing = false; });
    scrub.addEventListener('input', () => this.cb.onScrub(scrub.value / 1000));

    document.addEventListener('keydown', (e) => {
      if (/INPUT|SELECT|TEXTAREA/.test(e.target.tagName)) return;
      if (e.code === 'Space') { e.preventDefault(); this.cb.onPlayToggle(); }
      else if (e.code === 'ArrowRight') this.cb.onSeekRelative(5);
      else if (e.code === 'ArrowLeft') this.cb.onSeekRelative(-5);
      else if (e.code === 'Digit1') this.cb.onCameraPreset(1);
      else if (e.code === 'Digit2') this.cb.onCameraPreset(2);
      else if (e.code === 'Digit3') this.cb.onCameraPreset(3);
      else if (e.code === 'Digit4') this.cb.onCameraPreset(4);
      else if (e.code === 'Digit5') this.cb.onCameraPreset(5);
    });
    this.el['btn-shot'].addEventListener('click', () => this.cb.onScreenshot());

    // colorblind-safe palette toggle
    const themeBtn = this.el['btn-theme'];
    if (THEME === 'colorblind') {
      themeBtn.classList.add('bg-cyan-500/20', 'text-cyan-300', 'border-cyan-500/50');
      themeBtn.title = 'colorblind-safe palette ON — click for the night palette';
    }
    themeBtn.addEventListener('click', () => this.cb.onThemeToggle());

    // health rows drill down into recent evidence
    const drill = {
      'tcph-half': ['halfopen', 'Half-open connections'],
      'tcph-refused': ['refused', 'Refused connections'],
      'tcph-rst': ['rst', 'Recent resets'],
      'tcph-retrans': ['retrans', 'Retransmissions'],
      'dnsh-nx': ['nxdomain', 'NXDOMAIN names'],
      'dnsh-sf': ['servfail', 'SERVFAIL lookups'],
      'dnsh-to': ['dnstimeout', 'DNS timeouts'],
    };
    for (const [id, [kind, title]] of Object.entries(drill)) {
      const row = this.el[id]?.parentElement;
      if (!row) continue;
      row.classList.add('cursor-pointer', 'hover:bg-slate-800/60', 'rounded', 'px-1', '-mx-1');
      row.title = 'click for recent evidence';
      row.addEventListener('click', () => this.cb.onHealthClick(kind, title));
    }
    this.el['status-pill'].addEventListener('click', () => this.cb.onStatusClick());

    // Top Talkers: click an IP to spotlight everything touching it
    this.el['talkers-list'].addEventListener('click', (e) => {
      const ip = e.target.closest('[data-ip]')?.dataset.ip;
      if (ip) this.cb.onTalkerClick(ip);
    });
  }

  /** Freeze-frame indicator for live mode. */
  setFrozen(frozen) {
    this.el['frozen-pill'].classList.toggle('hidden', !frozen);
  }

  /** Glanceable verdict: 'ok' | 'degraded' | 'problem' + reason list. */
  setStatus(verdict, reasons) {
    const pill = this.el['status-pill'];
    const base = 'w-full mb-1 px-3 py-2 rounded-lg text-xs font-bold tracking-wide text-left border transition-colors cursor-pointer ';
    if (verdict === 'ok') {
      pill.className = base + 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
      pill.textContent = '● NETWORK OK';
    } else if (verdict === 'degraded') {
      pill.className = base + 'bg-amber-500/15 text-amber-300 border-amber-500/40';
      pill.textContent = `⚠ DEGRADED — ${reasons[0] ?? ''}`;
    } else {
      pill.className = base + 'bg-red-500/20 text-red-300 border-red-500/50';
      pill.textContent = `✖ PROBLEM — ${reasons.join(' · ')}`;
    }
    pill.title = reasons.length ? reasons.join('\n') + '\n(click for details)' : 'no active issues';
  }

  /** Drill-down list in the detail panel (health rows, status pill). */
  showHealthList(title, entries, hint) {
    const rows = entries.length
      ? entries.slice(0, 14).map((e) => `
        <div class="flex justify-between gap-3 py-1.5 border-b border-slate-800/80">
          <span class="num font-mono text-slate-200 break-all">${esc(e.target)}</span>
          <span class="text-slate-400 shrink-0 text-right">×${e.count}${e.extra ? `<div class="text-[10px] text-slate-500">${esc(e.extra)}</div>` : ''}</span>
        </div>`).join('')
      : '<div class="text-slate-500 py-2">nothing recorded in this session yet</div>';
    this.el['detail-body'].innerHTML = `
      <div class="badge bg-slate-200/10 text-slate-100 mb-2">${esc(title)}</div>
      ${hint ? `<p class="text-slate-400 mb-2">${esc(hint)}</p>` : ''}
      ${rows}`;
    this.el['detail-panel'].classList.remove('hidden');
  }

  buildLegend() {
    const rows = LEGEND.map((l) => `
      <div><i class="inline-block w-2.5 h-2.5 rounded-sm mr-1.5 align-middle"
              style="background:${l.css ?? PROTO_CSS[l.proto]}"></i>${esc(l.text)}</div>`);
    rows.push(`
      <div class="mt-1 text-slate-400">🚦 Control cars (whole body =
        <span style="color:${hex(FLAG_COLORS.S)}">opening</span> ·
        <span style="color:${hex(FLAG_COLORS.SA)}">accepted</span> ·
        <span style="color:${hex(FLAG_COLORS.F)}">closing</span> ·
        <span style="color:${hex(FLAG_COLORS.R)}">reset</span>)</div>
      <div class="text-slate-400">🚨 Breakdowns on the shoulder = failures
        (<span class="text-amber-300">no answer</span> ·
        <span style="color:${hex(FAIL_RED)}">refused / bad name</span>) — repeats grow them; click for the story</div>
      <div class="text-slate-500 mt-1">right side → inbound · left side → outbound · ×N road-train = burst · lane glow = load</div>
      <div class="text-slate-500">⏱ same-lane spacing = real inter-arrival timing · click a vehicle or talker to spotlight</div>`);
    this.el['legend-list'].innerHTML = rows.join('');
  }

  setMode(mode) {
    const live = mode === 'live';
    this.el['tab-live'].className = `px-4 py-1.5 ${live ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-slate-200'}`;
    this.el['tab-pcap'].className = `px-4 py-1.5 ${!live ? 'bg-fuchsia-500/20 text-fuchsia-300' : 'text-slate-400 hover:text-slate-200'}`;
    this.el['live-controls'].classList.toggle('hidden', !live);
    this.el['pcap-controls'].classList.toggle('hidden', live);
  }

  setCaptureState(running) {
    const b = this.el['btn-capture'];
    b.textContent = running ? '■ STOP' : '▶ START';
    b.className = `px-4 py-1.5 rounded-md font-bold transition-colors ${
      running ? 'bg-red-500/90 hover:bg-red-400 text-red-950'
              : 'bg-emerald-500/90 hover:bg-emerald-400 text-emerald-950'}`;
  }

  fillInterfaces(list) {
    const sel = this.el['iface-select'];
    sel.innerHTML = '<option value="__demo__">Demo traffic (no capture)</option>';
    for (const i of list) {
      const opt = document.createElement('option');
      opt.value = i.id;
      const ip = i.ips?.[0] ? ` — ${i.ips[0]}` : '';
      opt.textContent = `${i.description}${ip}`;
      sel.appendChild(opt);
    }
  }

  setPlaybackVisible(visible) {
    this.el['playback-bar'].classList.toggle('hidden', !visible);
    this.el['playback-bar'].classList.toggle('flex', visible);
  }

  setPcapMeta(text) { this.el['pcap-meta'].textContent = text; }
  setHistogram(buckets) { this.histBuckets = buckets; }

  updatePlayback(pb) {
    if (!pb.loaded) return;
    // called every frame — skip everything when nothing changed (paused),
    // and cache the Intl-formatted date per second (toLocale* is costly)
    if (this._lastT === pb.t && !this.scrubbing) return;
    this._lastT = pb.t;
    this.el['btn-play'].textContent = pb.playing ? '❚❚' : '▶';
    this.el['time-cur'].textContent = fmtDur(pb.t - pb.meta.start);
    this.el['time-total'].textContent = fmtDur(pb.meta.duration);
    const sec = Math.floor(pb.t);
    if (this._dateSec !== sec) {
      this._dateSec = sec;
      this._dateStr = new Date(sec * 1000).toLocaleDateString();
    }
    this.el['time-abs'].textContent = `${this._dateStr} ${fmtTime(pb.t)}`;
    if (!this.scrubbing) this.el['scrub'].value = Math.round(pb.progress * 1000);
    drawHistogram(this.el['hist-canvas'], this.histBuckets, pb.progress);
  }

  renderStats(s, flow, dns) {
    this.el['stat-bw-in'].textContent = fmtBps(s.bpsIn);
    this.el['stat-bw-out'].textContent = fmtBps(s.bpsOut);
    this.el['stat-total'].textContent =
      `${s.totalPkts.toLocaleString()} pkts · ${fmtBytes(s.totalBytes)}`
      + (s.bcastWin > 0 ? ` · ${s.bcastWin.toLocaleString()} bcast` : '');
    drawSparkline(this.el['spark-canvas'], s.buckets, s.laneSeries);

    this.el['proto-list'].innerHTML = s.protoDist.slice(0, 8).map((p) => `
      <div class="flex items-center gap-2">
        <i class="w-2.5 h-2.5 rounded-sm shrink-0" style="background:${PROTO_CSS[p.proto] ?? '#64748b'}"></i>
        <span class="w-14 font-semibold text-slate-300">${esc(p.proto)}</span>
        <div class="grow h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div class="h-full rounded-full" style="width:${(p.frac * 100).toFixed(1)}%;background:${PROTO_CSS[p.proto] ?? '#64748b'}"></div>
        </div>
        <span class="num text-slate-400 w-12 text-right">${p.pkts.toLocaleString()}</span>
      </div>`).join('') || '<div class="text-slate-600">no traffic yet</div>';

    const maxB = s.topTalkers[0]?.bytes || 1;
    this.el['talkers-list'].innerHTML = s.topTalkers.map((t) => `
      <div class="flex items-center gap-2 cursor-pointer hover:bg-slate-800/60 rounded px-1 -mx-1" data-ip="${esc(t.ip)}" title="click to spotlight this host on the road">
        <span class="w-32 truncate text-slate-300 pointer-events-none">${esc(t.ip)}</span>
        <div class="grow h-1.5 bg-slate-800 rounded-full overflow-hidden">
          <div class="h-full bg-cyan-500/80 rounded-full" style="width:${((t.bytes / maxB) * 100).toFixed(1)}%"></div>
        </div>
        <span class="text-slate-400 w-14 text-right">${fmtBytes(t.bytes)}</span>
      </div>`).join('') || '<div class="text-slate-600">no traffic yet</div>';

    if (flow) {
      const c = flow.counts;
      this.el['tcph-est'].textContent = c.established.toLocaleString();
      this.el['tcph-pending'].textContent = flow.pending.toLocaleString();
      this.el['tcph-open'].textContent = (flow.open ?? 0).toLocaleString();
      this.el['tcph-half'].textContent = c.halfOpen.toLocaleString();
      this.el['tcph-refused'].textContent = c.refused.toLocaleString();
      this.el['tcph-rst'].textContent = c.resets.toLocaleString();
      this.el['tcph-retries'].textContent = c.synRetries.toLocaleString();
      this.el['tcph-retrans'].textContent = c.retrans.toLocaleString();
      this.el['tcph-rtt'].textContent = flow.rtt
        ? `${flow.rtt.med.toFixed(0)} / ${flow.rtt.p95.toFixed(0)} ms`
        : '—';
      const attempts = c.established + c.halfOpen + c.refused;
      const okFrac = attempts ? c.established / attempts : 1;
      this.el['tcph-bar'].style.width = `${(okFrac * 100).toFixed(1)}%`;
      this.el['tcph-bar'].className = `h-full rounded-full ${okFrac > 0.9 ? 'bg-emerald-500' : okFrac > 0.6 ? 'bg-amber-500' : 'bg-red-500'}`;
    }
    if (dns) {
      const d = dns.counts;
      this.el['dnsh-ok'].textContent = d.ok.toLocaleString();
      this.el['dnsh-nx'].textContent = d.nxdomain.toLocaleString();
      this.el['dnsh-sf'].textContent = d.servfail.toLocaleString();
      this.el['dnsh-to'].textContent = d.timeouts.toLocaleString();
      this.el['dnsh-rtt'].textContent = dns.rtt ? `${dns.rtt.med.toFixed(0)} ms` : '—';
    }
  }

  hud({ fps, active, pps, merged, recycled, dropped }) {
    this.el['hud-fps'].textContent = fps.toFixed(0);
    this.el['hud-fps'].className = fps >= 55 ? 'text-emerald-400' : fps >= 30 ? 'text-amber-400' : 'text-red-400';
    this.el['hud-active'].textContent = active.toLocaleString();
    this.el['hud-pps'].textContent = pps.toLocaleString();
    this.el['hud-merged'].textContent = merged.toLocaleString();
    this.el['hud-recycled'].textContent = recycled.toLocaleString();
    const drop = this.el['hud-dropped'];
    drop.textContent = dropped.toLocaleString();
    drop.className = dropped > 0 ? 'text-red-400 font-bold' : 'text-slate-100';
  }

  showDetail(meta) {
    if (!meta) { this.el['detail-panel'].classList.add('hidden'); return; }
    let html;
    if (meta.flowEvent) html = this.flowDetail(meta);
    else if (meta.aggregate) html = this.convoyDetail(meta);
    else html = this.packetDetail(meta);
    this.el['detail-body'].innerHTML = html;
    this.el['detail-panel'].classList.remove('hidden');
  }

  row(k, v) {
    return `
      <div class="flex justify-between gap-3 py-1.5 border-b border-slate-800/80">
        <span class="text-slate-500 shrink-0">${k}</span>
        <span class="num font-mono text-slate-200 text-right break-all">${v}</span>
      </div>`;
  }

  dirBadge(dir) {
    return dir === 'in'
      ? '<span class="badge bg-cyan-500/20 text-cyan-300">▼ INBOUND</span>'
      : '<span class="badge bg-fuchsia-500/20 text-fuchsia-300">▲ OUTBOUND</span>';
  }

  packetDetail(p) {
    const flagStr = p.flags
      ? p.flags.split('').map((f) => FLAG_NAMES[f] ?? f).join(' + ')
      : '—';
    const protoColor = PROTO_CSS[p.proto] ?? '#64748b';
    const dnsRow = p.dns_qr != null
      ? this.row('DNS', esc(`${p.dns_qr === 0 ? 'query' : 'response'}${p.dns_qname ? ' · ' + p.dns_qname : ''}${p.dns_qr === 1 ? ' · ' + ({ 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN' }[p.dns_rcode] ?? 'rcode ' + p.dns_rcode) : ''}`))
      : '';
    const sni = p.sni ?? p._sni;
    return `
      <div class="flex items-center gap-2 mb-2 flex-wrap">
        <span class="badge" style="background:${protoColor}22;color:${protoColor}">${esc(p.proto)}</span>
        ${this.dirBadge(p.dir)}
        <span class="badge bg-slate-700/60 text-slate-300">${esc(p.transport)}</span>
        ${isBroadcast(p) ? '<span class="badge bg-amber-500/20 text-amber-300">📢 BROADCAST</span>' : ''}
        ${p.retrans ? '<span class="badge bg-red-500/20 text-red-300">🔁 RETRANSMISSION</span>' : ''}
      </div>
      ${this.row('Timestamp', esc(fmtTime(p.ts)))}
      ${this.row('Epoch', esc(p.ts.toFixed(6)))}
      ${this.row('Source IP', `${esc(p.src)}${p.sport != null ? ':' + esc(p.sport) : ''}`)}
      ${this.row('Dest IP', `${esc(p.dst)}${p.dport != null ? ':' + esc(p.dport) : ''}`)}
      ${this.row('Source MAC', esc(p.smac))}
      ${this.row('Dest MAC', esc(p.dmac))}
      ${this.row('Size', `${esc(p.size.toLocaleString())} bytes`)}
      ${this.row('TTL', esc(p.ttl ?? '—'))}
      ${this.row('TCP flags', esc(flagStr))}
      ${p.icmp_type != null ? this.row('ICMP', esc(icmpName(p))) : ''}
      ${dnsRow}
      ${sni ? this.row('Server name (SNI)', esc(sni)) : ''}
      ${this.row('Packet #', esc('#' + p.id))}
    `;
  }

  convoyDetail(a) {
    const protoRows = Object.entries(a.protos).sort((x, y) => y[1] - x[1])
      .map(([proto, n]) => `<span class="badge mr-1 mb-1" style="background:${PROTO_CSS[proto] ?? '#64748b'}22;color:${PROTO_CSS[proto] ?? '#94a3b8'}">${esc(proto)} ×${n}</span>`)
      .join('');
    const samples = a.samples.map((p) => `
      <div class="num font-mono text-[10px] text-slate-400 py-0.5 border-b border-slate-800/60">
        ${esc(p.proto)} ${esc(p.src)}${p.sport ? ':' + p.sport : ''} → ${esc(p.dst)}${p.dport ? ':' + p.dport : ''} · ${p.size} B
      </div>`).join('');
    return `
      <div class="flex items-center gap-2 mb-2 flex-wrap">
        <span class="badge bg-slate-200/10 text-slate-100">🚛 CONVOY — packet burst</span>
        ${this.dirBadge(a.dir)}
      </div>
      <p class="text-slate-400 mb-2">Burst merged to keep the lane readable. Every packet is still counted in the stats.</p>
      ${this.row('Packets', a.count.toLocaleString())}
      ${this.row('Bytes', fmtBytes(a.bytes))}
      ${this.row('Lane', esc(a.lane))}
      ${this.row('Window', `${esc(fmtTime(a.tsFirst))} → ${esc(fmtTime(a.tsLast))}`)}
      ${this.row('Span', `${((a.tsLast - a.tsFirst) * 1000).toFixed(0)} ms`)}
      <div class="mt-2 mb-1">${protoRows}</div>
      <div class="text-slate-500 mt-2 mb-1">First ${a.samples.length} packets:</div>
      ${samples}
    `;
  }

  flowDetail(m) {
    if (m.dns) return this.dnsDetail(m);
    const p = m.syn;
    const refused = m.flowEvent === 'refused';
    const title = refused
      ? '<span class="badge bg-red-500/20 text-red-300">⛔ CONNECTION REFUSED</span>'
      : '<span class="badge bg-amber-500/20 text-amber-300">⚠ HALF-OPEN (no SYN-ACK)</span>';
    const hint = refused
      ? 'The target answered the SYN with RST: the port is closed or actively rejecting connections.'
      : 'The SYN was never answered. Typical causes: firewall drop (filtered port), dead host, asymmetric routing — or a scanner probing and not completing handshakes.';
    return `
      <div class="flex items-center gap-2 mb-2 flex-wrap">${title} ${this.dirBadge(p.dir)}</div>
      <p class="text-slate-400 mb-2">${hint}</p>
      ${m.attempts > 1 ? this.row('Failed attempts', esc(`×${m.attempts} against this target`)) : ''}
      ${this.row('Last SYN', esc(fmtTime(p.ts)))}
      ${this.row('Client', `${esc(p.src)}:${esc(p.sport)}`)}
      ${this.row('Target', `${esc(p.dst)}:${esc(p.dport)}`)}
      ${m.rst ? this.row('RST received', esc(fmtTime(m.rst.ts))) : ''}
      ${m.rst ? this.row('Refused after', esc(`${((m.rst.ts - p.ts) * 1000).toFixed(1)} ms`)) : ''}
      ${this.row('Source MAC', esc(p.smac))}
      ${this.row('TTL', esc(p.ttl ?? '—'))}
    `;
  }

  dnsDetail(m) {
    const q = m.query, r = m.resp;
    const ref = q ?? r;
    const kinds = {
      nxdomain: ['<span class="badge bg-red-500/20 text-red-300">⛔ NXDOMAIN</span>',
        'The name does not exist. Typo, dead domain, or a broken search suffix appending garbage.'],
      servfail: ['<span class="badge bg-red-500/20 text-rose-300">⛔ SERVFAIL</span>',
        'The resolver could not answer — upstream unreachable, DNSSEC validation failure, or a lame delegation.'],
      dnstimeout: ['<span class="badge bg-amber-500/20 text-amber-300">⚠ DNS TIMEOUT</span>',
        'The resolver never answered. Resolver down, UDP/53 blocked, or severe packet loss.'],
    };
    const [title, hint] = kinds[m.flowEvent] ?? ['DNS event', ''];
    const qname = r?.dns_qname ?? q?.dns_qname;
    return `
      <div class="flex items-center gap-2 mb-2 flex-wrap">${title} ${this.dirBadge(ref.dir)}</div>
      <p class="text-slate-400 mb-2">${hint}</p>
      ${m.attempts > 1 ? this.row('Occurrences', esc(`×${m.attempts}`)) : ''}
      ${qname ? this.row('Name', esc(qname)) : ''}
      ${q ? this.row('Query sent', esc(fmtTime(q.ts))) : ''}
      ${r ? this.row('Answered', esc(fmtTime(r.ts))) : ''}
      ${q && r ? this.row('Lookup time', esc(`${((r.ts - q.ts) * 1000).toFixed(1)} ms`)) : ''}
      ${this.row('Client', q ? `${esc(q.src)}:${esc(q.sport)}` : '—')}
      ${this.row('Resolver', esc(q ? q.dst : r?.src))}
      ${this.row('Txn id', esc(ref.dns_id ?? '—'))}
    `;
  }

  toast(message, kind = 'info') {
    const colors = {
      info: 'border-cyan-500/60 text-cyan-200',
      error: 'border-red-500/60 text-red-200',
      success: 'border-emerald-500/60 text-emerald-200',
    };
    const div = document.createElement('div');
    div.className = `panel pointer-events-auto px-4 py-3 text-xs border-l-4 ${colors[kind]} shadow-xl`;
    div.textContent = message;
    this.el['toasts'].appendChild(div);
    setTimeout(() => {
      div.style.transition = 'opacity .4s';
      div.style.opacity = '0';
      setTimeout(() => div.remove(), 400);
    }, kind === 'error' ? 9000 : 5000);
  }
}
