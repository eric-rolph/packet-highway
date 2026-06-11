// PCAP timeline playback engine: play / pause / scrub / variable speed.
// Owns a virtual clock `t` in capture-time seconds; tick() returns the
// packets whose timestamps were crossed since the last frame.

export class Playback {
  constructor() {
    this.packets = [];
    this.meta = null;
    this.t = 0;
    this.i = 0;
    this.playing = false;
    this.speed = 1;
  }

  load(data) {
    this.packets = data.packets;
    this.meta = data.meta;
    this.t = this.meta.start;
    this.i = 0;
    this.playing = false;
  }

  get loaded() { return !!this.meta; }
  get progress() {
    if (!this.meta) return 0;
    return (this.t - this.meta.start) / this.meta.duration;
  }
  get atEnd() { return this.meta && this.t >= this.meta.end; }

  seekFrac(frac) {
    if (!this.meta) return;
    this.seek(this.meta.start + frac * this.meta.duration);
  }

  seek(t) {
    this.t = Math.min(Math.max(t, this.meta.start), this.meta.end);
    // binary search: first packet with ts >= t
    let lo = 0, hi = this.packets.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.packets[mid].ts < this.t) lo = mid + 1;
      else hi = mid;
    }
    this.i = lo;
  }

  /** Advance by dt wall-seconds; returns packets crossed. */
  tick(dt) {
    if (!this.playing || !this.meta) return [];
    this.t += dt * this.speed;
    const out = [];
    while (this.i < this.packets.length && this.packets[this.i].ts <= this.t) {
      out.push(this.packets[this.i++]);
    }
    if (this.t >= this.meta.end) {
      this.t = this.meta.end;
      this.playing = false;
    }
    return out;
  }
}
