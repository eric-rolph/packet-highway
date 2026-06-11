// Data sources: live WebSocket stream + PCAP upload/sample fetch.

export class LiveSource {
  /**
   * handlers: { onHello(info), onPackets(items, dropped), onError(msg), onClose() }
   */
  constructor(handlers) {
    this.h = handlers;
    this.ws = null;
  }

  start({ iface, bpf, demo }) {
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
    this.ws.onerror = () => this.h.onError('WebSocket error — is the backend still running?');
    this.ws.onclose = () => this.h.onClose();
  }

  stop() {
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
      this.h.onClose();
    }
  }

  get running() { return !!this.ws && this.ws.readyState <= WebSocket.OPEN; }
}

export async function fetchInterfaces() {
  const r = await fetch('/api/interfaces');
  if (!r.ok) return [];
  return r.json();
}

export async function uploadPcap(file) {
  const form = new FormData();
  form.append('file', file);
  const r = await fetch('/api/pcap', { method: 'POST', body: form });
  const body = await r.json();
  if (!r.ok) throw new Error(body.error ?? `Upload failed (${r.status})`);
  return body;
}

export async function fetchSample() {
  const r = await fetch('/api/sample');
  const body = await r.json();
  if (!r.ok) throw new Error(body.error ?? `Sample failed (${r.status})`);
  return body;
}
