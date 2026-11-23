// Data sources: live WebSocket stream + PCAP upload/sample fetch,
// with automatic zero-backend Browser Standalone fallback for GitHub Pages.
import { BrowserDemoStream, generateSampleTimeline, parsePcapBuffer } from './browser_engine.js';

let backendAvailable = null; // null = unknown, true = FastAPI backend, false = static browser mode

export function isBrowserStandalone() {
  return backendAvailable === false;
}

export class LiveSource {
  /**
   * handlers: { onHello(info), onPackets(items, dropped), onError(msg), onClose() }
   */
  constructor(handlers) {
    this.h = handlers;
    this.ws = null;
    this.localDemo = null;
  }

  start({ iface, bpf, demo }) {
    if (backendAvailable === false) {
      this.localDemo = new BrowserDemoStream(this.h);
      this.localDemo.start();
      return;
    }
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const params = new URLSearchParams();
    if (demo) params.set('demo', '1');
    if (iface) params.set('iface', iface);
    if (bpf) params.set('bpf', bpf);
    this.ws = new WebSocket(`${proto}://${location.host}/ws/live?${params}`);
    this.ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      if (msg.type === 'packets') this.h.onPackets(msg.items, msg.dropped ?? 0);
      else if (msg.type === 'hello') this.h.onHello(msg);
      else if (msg.type === 'error') this.h.onError(msg.message);
    };
    this.ws.onerror = () => {
      if (demo && backendAvailable === null) {
        backendAvailable = false;
        this.ws = null;
        this.localDemo = new BrowserDemoStream(this.h);
        this.localDemo.start();
        return;
      }
      this.h.onError('WebSocket error — is the backend still running?');
    };
    this.ws.onclose = () => {
      if (!this.localDemo) this.h.onClose();
    };
  }

  stop() {
    if (this.localDemo) {
      this.localDemo.stop();
      this.localDemo = null;
      return;
    }
    const ws = this.ws;
    if (!ws) return;
    // detach ALL handlers: queued messages must not spawn vehicles after STOP,
    // and closing a still-CONNECTING socket fires a spurious error event
    ws.onmessage = ws.onerror = ws.onclose = null;
    ws.close();
    this.ws = null;
    this.h.onClose();
  }

  get running() {
    return (!!this.localDemo && this.localDemo.running) ||
           (!!this.ws && this.ws.readyState <= WebSocket.OPEN);
  }
}

export async function fetchInterfaces() {
  try {
    const r = await fetch('./api/interfaces');
    const ct = r.headers.get('content-type') || '';
    if (!r.ok || !ct.includes('application/json')) {
      backendAvailable = false;
      return [];
    }
    backendAvailable = true;
    return await r.json();
  } catch {
    backendAvailable = false;
    return [];
  }
}

export async function uploadPcap(file) {
  if (backendAvailable === false) {
    return parsePcapBuffer(await file.arrayBuffer(), file.name);
  }
  try {
    const form = new FormData();
    form.append('file', file);
    const r = await fetch('./api/pcap', { method: 'POST', body: form });
    const ct = r.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      backendAvailable = false;
      return parsePcapBuffer(await file.arrayBuffer(), file.name);
    }
    const body = await r.json();
    if (!r.ok) throw new Error(body.error ?? `Upload failed (${r.status})`);
    return body;
  } catch {
    backendAvailable = false;
    return parsePcapBuffer(await file.arrayBuffer(), file.name);
  }
}

export async function fetchSample() {
  if (backendAvailable === false) {
    return generateSampleTimeline();
  }
  try {
    const r = await fetch('./api/sample');
    const ct = r.headers.get('content-type') || '';
    if (!r.ok || !ct.includes('application/json')) {
      backendAvailable = false;
      return generateSampleTimeline();
    }
    return await r.json();
  } catch {
    backendAvailable = false;
    return generateSampleTimeline();
  }
}
