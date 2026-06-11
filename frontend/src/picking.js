// Click-to-inspect: raycast against the instanced vehicle meshes, resolve the
// hit instanceId back to its pool record, and float a glowing ring under the
// selected vehicle while it's still on the road.
import * as THREE from 'three';

export class Picker {
  constructor(canvas, camera, traffic, onSelect) {
    this.camera = camera;
    this.traffic = traffic;
    this.onSelect = onSelect;
    this.raycaster = new THREE.Raycaster();
    this.pointer = new THREE.Vector2();
    this.selected = null; // {pool, idx}

    this.ring = new THREE.Mesh(
      new THREE.TorusGeometry(3.4, 0.16, 10, 36),
      new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.9 })
    );
    this.ring.rotation.x = Math.PI / 2;
    this.ring.visible = false;

    let downX = 0, downY = 0;
    canvas.addEventListener('pointerdown', (e) => { downX = e.clientX; downY = e.clientY; });
    canvas.addEventListener('pointerup', (e) => {
      if (Math.hypot(e.clientX - downX, e.clientY - downY) > 6) return; // it was an orbit drag
      this.pick(e.clientX, e.clientY);
    });
  }

  pick(x, y) {
    this.pointer.set((x / window.innerWidth) * 2 - 1, -(y / window.innerHeight) * 2 + 1);
    this.raycaster.setFromCamera(this.pointer, this.camera);
    const hits = this.raycaster.intersectObjects(this.traffic.meshes, false);
    for (const hit of hits) {
      const pool = hit.object.userData.pool;
      if (!pool || hit.instanceId === undefined) continue;
      const rec = pool.active.get(hit.instanceId);
      if (!rec) continue;
      this.selected = { pool, idx: hit.instanceId };
      this.ring.visible = true;
      this.onSelect(rec.meta);
      return;
    }
    this.deselect();
  }

  deselect() {
    this.selected = null;
    this.ring.visible = false;
    this.onSelect(null);
  }

  /** Keep the ring glued to the selected vehicle; hide it once the vehicle despawns. */
  update(t) {
    if (!this.selected) return;
    const rec = this.selected.pool.active.get(this.selected.idx);
    if (!rec) { this.selected = null; this.ring.visible = false; return; }
    const y = this.selected.pool.type === 'drone' ? 4 : 0.25;
    this.ring.position.set(rec.laneX, rec.yBase + y, rec.z);
    const s = 1 + 0.12 * Math.sin(t * 5);
    this.ring.scale.set(s, s, s);
  }
}
