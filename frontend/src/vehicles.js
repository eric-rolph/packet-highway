// Vehicle meshes & object pooling.
//
// Each vehicle type is ONE InstancedMesh (thousands of vehicles = ~10 draw
// calls). The instance slots ARE the object pool: spawn() pops a free slot
// index and writes its matrix; release() zero-scales it and returns the index
// to the free list. Nothing is allocated per packet.
//
// IMPORTANT (raycasting): three.js computes an InstancedMesh boundingSphere
// once and never refreshes it as instances move — with all slots parked at
// spawn time that sphere is degenerate and every click-ray misses. We assign
// a fixed sphere covering the whole highway instead.
import * as THREE from 'three';
import { mergeGeometries } from 'three/addons/utils/BufferGeometryUtils.js';
import { HALF_LEN, TYPE_SPECS } from './config.js';

const WHITE = 0xffffff;       // tintable body parts (instance color multiplies)
const DARK = 0x14171f;        // wheels, accents — barely affected by tint
const GLASS = 0x0d1726;

function colored(geo, color) {
  const c = new THREE.Color(color);
  const n = geo.attributes.position.count;
  const arr = new Float32Array(n * 3);
  for (let i = 0; i < n; i++) c.toArray(arr, i * 3);
  geo.setAttribute('color', new THREE.BufferAttribute(arr, 3));
  return geo;
}

function box(w, h, d, x, y, z, color) {
  const g = new THREE.BoxGeometry(w, h, d);
  g.translate(x, y, z);
  return colored(g, color);
}

function wheel(r, len, x, y, z) {
  const g = new THREE.CylinderGeometry(r, r, len, 10);
  g.rotateZ(Math.PI / 2);
  g.translate(x, y, z);
  return colored(g, DARK);
}

function sedanParts() {
  return [
    box(1.9, 0.62, 4.1, 0, 0.74, 0, WHITE),
    box(1.65, 0.55, 2.0, 0, 1.32, -0.15, GLASS),
    wheel(0.42, 0.3, 0.85, 0.42, 1.3), wheel(0.42, 0.3, -0.85, 0.42, 1.3),
    wheel(0.42, 0.3, 0.85, 0.42, -1.3), wheel(0.42, 0.3, -0.85, 0.42, -1.3),
  ];
}

// All builders face +Z (front of the vehicle toward positive Z).
const BUILDERS = {
  motorcycle: () => mergeGeometries([
    box(0.55, 0.5, 2.3, 0, 0.85, 0, WHITE),
    box(0.5, 0.65, 0.5, 0, 1.4, -0.35, DARK),
    wheel(0.42, 0.22, 0, 0.42, 0.9),
    wheel(0.42, 0.22, 0, 0.42, -0.9),
  ]),
  sedan: () => mergeGeometries(sedanParts()),
  van: () => mergeGeometries([
    box(2.1, 1.5, 3.4, 0, 1.18, -0.55, WHITE),
    box(2.0, 0.95, 1.5, 0, 0.92, 1.85, WHITE),
    box(1.8, 0.5, 0.25, 0, 1.45, 2.6, GLASS),
    wheel(0.48, 0.32, 0.95, 0.48, 1.7), wheel(0.48, 0.32, -0.95, 0.48, 1.7),
    wheel(0.48, 0.32, 0.95, 0.48, -1.45), wheel(0.48, 0.32, -0.95, 0.48, -1.45),
  ]),
  truck: () => mergeGeometries([
    box(2.4, 2.25, 6.2, 0, 1.6, -1.0, WHITE),
    box(2.2, 1.55, 1.9, 0, 1.15, 3.1, WHITE),
    box(2.0, 0.6, 0.25, 0, 1.7, 4.0, GLASS),
    wheel(0.55, 0.34, 1.05, 0.55, 3.2), wheel(0.55, 0.34, -1.05, 0.55, 3.2),
    wheel(0.55, 0.34, 1.05, 0.55, -0.6), wheel(0.55, 0.34, -1.05, 0.55, -0.6),
    wheel(0.55, 0.34, 1.05, 0.55, -2.6), wheel(0.55, 0.34, -1.05, 0.55, -2.6),
  ]),
  // ICMP: black & white cruiser, light bar gets the red/blue strobe overlay
  police: () => mergeGeometries([
    ...sedanParts(),
    box(1.95, 0.18, 1.2, 0, 1.08, 1.4, DARK),   // hood stripe
    box(1.95, 0.18, 1.0, 0, 1.08, -1.6, DARK),  // trunk stripe
    box(1.1, 0.14, 0.42, 0, 1.66, -0.15, DARK), // light-bar base
  ]),
  // TCP control: compact car, single-color strobe overlay
  signal: () => mergeGeometries([
    box(1.7, 0.6, 3.4, 0, 0.72, 0, WHITE),
    box(1.5, 0.5, 1.6, 0, 1.25, -0.1, GLASS),
    box(0.9, 0.14, 0.4, 0, 1.57, -0.1, DARK),
    wheel(0.4, 0.28, 0.78, 0.4, 1.1), wheel(0.4, 0.28, -0.78, 0.4, 1.1),
    wheel(0.4, 0.28, 0.78, 0.4, -1.1), wheel(0.4, 0.28, -0.78, 0.4, -1.1),
  ]),
  // UDP: connectionless — never touches the road
  drone: () => {
    const rotor = (x, z) => {
      const g = new THREE.CylinderGeometry(0.5, 0.5, 0.07, 12);
      g.translate(x, 0.34, z);
      return colored(g, 0x2a3346);
    };
    return mergeGeometries([
      box(0.85, 0.3, 0.85, 0, 0, 0, WHITE),
      box(2.1, 0.1, 0.16, 0, 0.18, 0, DARK),
      box(0.16, 0.1, 2.1, 0, 0.18, 0, DARK),
      rotor(0.95, 0.95), rotor(-0.95, 0.95), rotor(0.95, -0.95), rotor(-0.95, -0.95),
    ]);
  },
  // ARP & friends: slow three-wheeled maintenance cart with amber cab light
  cart: () => mergeGeometries([
    box(1.3, 0.8, 1.9, 0, 0.85, -0.3, WHITE),      // tool bed
    box(1.1, 0.9, 1.0, 0, 0.95, 0.95, WHITE),      // cab
    box(0.95, 0.35, 0.2, 0, 1.25, 1.5, GLASS),
    box(0.3, 0.18, 0.3, 0, 1.5, 0.95, DARK),       // beacon stub
    wheel(0.34, 0.24, 0.6, 0.34, -0.85), wheel(0.34, 0.24, -0.6, 0.34, -0.85),
    wheel(0.34, 0.24, 0, 0.34, 1.15),
  ]),
  // Aggregated burst: articulated road train (cab + 3 trailers)
  convoy: () => mergeGeometries([
    box(2.2, 1.6, 1.9, 0, 1.2, 4.6, WHITE),        // cab
    box(2.0, 0.6, 0.25, 0, 1.75, 5.55, GLASS),
    box(2.3, 1.9, 2.6, 0, 1.45, 2.2, WHITE),       // trailer 1
    box(2.3, 1.9, 2.6, 0, 1.45, -0.8, WHITE),      // trailer 2
    box(2.3, 1.9, 2.6, 0, 1.45, -3.8, WHITE),      // trailer 3
    wheel(0.5, 0.34, 1.0, 0.5, 4.6), wheel(0.5, 0.34, -1.0, 0.5, 4.6),
    wheel(0.5, 0.34, 1.0, 0.5, 2.0), wheel(0.5, 0.34, -1.0, 0.5, 2.0),
    wheel(0.5, 0.34, 1.0, 0.5, -1.0), wheel(0.5, 0.34, -1.0, 0.5, -1.0),
    wheel(0.5, 0.34, 1.0, 0.5, -4.0), wheel(0.5, 0.34, -1.0, 0.5, -4.0),
  ]),
};

const _dummy = new THREE.Object3D();
const _color = new THREE.Color();
const POLICE_RED = new THREE.Color(0xef4444);
const POLICE_BLUE = new THREE.Color(0x3b82f6);

function parkMatrix() {
  _dummy.position.set(0, -1000, 0);
  _dummy.rotation.set(0, 0, 0);
  _dummy.scale.setScalar(0.0001);
  _dummy.updateMatrix();
  return _dummy.matrix;
}

export class VehiclePool {
  constructor(scene, type) {
    const spec = TYPE_SPECS[type];
    this.type = type;
    this.cap = spec.cap;
    this.baseSpeed = spec.speed;
    this.hasBeacon = type === 'police' || type === 'signal';

    const mat = new THREE.MeshStandardMaterial({ vertexColors: true, metalness: 0.2, roughness: 0.55 });
    this.mesh = new THREE.InstancedMesh(BUILDERS[type](), mat, this.cap);
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.mesh.frustumCulled = false;
    this.mesh.userData.pool = this;
    // Fixed bounding sphere covering the road — see header comment.
    this.mesh.boundingSphere = new THREE.Sphere(new THREE.Vector3(0, 2, 0), HALF_LEN + 120);
    for (let i = 0; i < this.cap; i++) {
      this.mesh.setMatrixAt(i, parkMatrix());
      this.mesh.setColorAt(i, _color.set(0xffffff));
    }
    scene.add(this.mesh);

    this.beacons = null;
    if (this.hasBeacon) {
      this.beaconMat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 1 });
      this.beacons = new THREE.InstancedMesh(new THREE.BoxGeometry(0.55, 0.3, 1.1), this.beaconMat, this.cap);
      this.beacons.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      this.beacons.frustumCulled = false;
      this.beacons.raycast = () => {};            // clicks go to the car body
      for (let i = 0; i < this.cap; i++) {
        this.beacons.setMatrixAt(i, parkMatrix());
        this.beacons.setColorAt(i, _color.set(0xffffff));
      }
      scene.add(this.beacons);
    }

    this.free = [];
    for (let i = this.cap - 1; i >= 0; i--) this.free.push(i);
    this.active = new Map(); // idx -> record (insertion order = age)
    this.recycled = 0;
  }

  /** opts: {laneX, dirSign, color, scaleL, meta, beaconColor} */
  spawn(opts) {
    let idx = this.free.pop();
    if (idx === undefined) {
      const oldest = this.active.keys().next().value;
      this.release(oldest);
      idx = this.free.pop();
      this.recycled++;
    }
    const rec = {
      idx,
      laneX: opts.laneX + (Math.random() - 0.5) * 1.6,
      dirSign: opts.dirSign,
      z: -opts.dirSign * (HALF_LEN + 4 + Math.random() * 6),
      speed: this.baseSpeed * (0.9 + Math.random() * 0.2),
      scaleL: opts.scaleL ?? 1,
      yBase: 0,
      bobPhase: Math.random() * Math.PI * 2,
      meta: opts.meta,
    };
    this.active.set(idx, rec);
    this.mesh.setColorAt(idx, _color.set(opts.color));
    this.mesh.instanceColor.needsUpdate = true;
    if (this.beacons) {
      this.beacons.setColorAt(idx, _color.set(opts.beaconColor ?? 0xffffff));
      this.beacons.instanceColor.needsUpdate = true;
    }
    return rec;
  }

  release(idx) {
    if (!this.active.delete(idx)) return;
    this.mesh.setMatrixAt(idx, parkMatrix());
    if (this.beacons) this.beacons.setMatrixAt(idx, parkMatrix());
    this.free.push(idx);
  }

  update(dt, t) {
    const done = [];
    const droneY = this.type === 'drone';
    for (const rec of this.active.values()) {
      rec.z += rec.dirSign * rec.speed * dt;
      if (Math.abs(rec.z) > HALF_LEN + 16) { done.push(rec.idx); continue; }
      const y = droneY ? 4 + Math.sin(t * 3 + rec.bobPhase) * 0.7 : 0;
      _dummy.position.set(rec.laneX, y, rec.z);
      _dummy.rotation.set(0, rec.dirSign > 0 ? 0 : Math.PI, 0);
      _dummy.scale.set(1, 1, rec.scaleL);
      _dummy.updateMatrix();
      this.mesh.setMatrixAt(rec.idx, _dummy.matrix);
      if (this.beacons) {
        _dummy.position.y = y + (this.type === 'police' ? 1.85 : 1.72);
        _dummy.scale.set(1, 1, 1);
        _dummy.updateMatrix();
        this.beacons.setMatrixAt(rec.idx, _dummy.matrix);
      }
    }
    for (const idx of done) this.release(idx);
    this.mesh.instanceMatrix.needsUpdate = true;
    if (this.beacons) {
      this.beacons.instanceMatrix.needsUpdate = true;
      this.beaconMat.opacity = 0.3 + 0.7 * Math.abs(Math.sin(t * 9));
      // police: whole bar alternates red/blue; signal cars: per-instance flag color
      if (this.type === 'police') {
        this.beaconMat.color.copy(Math.floor(t * 4) % 2 ? POLICE_RED : POLICE_BLUE);
      }
    }
  }

  clear() {
    for (const idx of [...this.active.keys()]) this.release(idx);
  }
}

/**
 * Roadside markers for failed TCP handshakes: an amber flare (half-open, no
 * SYN-ACK) or red flare (connection refused / RST). Clickable like vehicles —
 * exposes the same {userData.pool, active} shape the Picker expects.
 */
export class FlarePool {
  constructor(scene, cap = 64) {
    this.type = 'flare';
    this.cap = cap;
    const geo = new THREE.ConeGeometry(1.3, 3.2, 8);
    geo.translate(0, 1.6, 0);
    this.mat = new THREE.MeshBasicMaterial({ transparent: true, opacity: 0.92 });
    this.mesh = new THREE.InstancedMesh(geo, this.mat, cap);
    this.mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    this.mesh.frustumCulled = false;
    this.mesh.userData.pool = this;
    this.mesh.boundingSphere = new THREE.Sphere(new THREE.Vector3(0, 2, 0), HALF_LEN + 120);
    for (let i = 0; i < cap; i++) {
      this.mesh.setMatrixAt(i, parkMatrix());
      this.mesh.setColorAt(i, _color.set(0xffffff));
    }
    scene.add(this.mesh);
    this.free = [];
    for (let i = cap - 1; i >= 0; i--) this.free.push(i);
    this.active = new Map();
    this.ttl = 9; // seconds a flare stays on the shoulder
  }

  spawn({ x, z, color, meta }) {
    let idx = this.free.pop();
    if (idx === undefined) {
      const oldest = this.active.keys().next().value;
      this.release(oldest);
      idx = this.free.pop();
    }
    this.active.set(idx, { idx, laneX: x, z, yBase: 0, born: -1, meta });
    this.mesh.setColorAt(idx, _color.set(color));
    this.mesh.instanceColor.needsUpdate = true;
  }

  release(idx) {
    if (!this.active.delete(idx)) return;
    this.mesh.setMatrixAt(idx, parkMatrix());
    this.free.push(idx);
  }

  update(dt, t) {
    const done = [];
    for (const rec of this.active.values()) {
      if (rec.born < 0) rec.born = t;
      const age = t - rec.born;
      if (age > this.ttl) { done.push(rec.idx); continue; }
      const fade = age > this.ttl - 2 ? (this.ttl - age) / 2 : 1;
      const pulse = 1 + 0.15 * Math.sin(t * 6 + rec.idx);
      _dummy.position.set(rec.laneX, 0, rec.z);
      _dummy.rotation.set(0, 0, 0);
      _dummy.scale.set(pulse * fade, fade, pulse * fade);
      _dummy.updateMatrix();
      this.mesh.setMatrixAt(rec.idx, _dummy.matrix);
    }
    for (const idx of done) this.release(idx);
    this.mesh.instanceMatrix.needsUpdate = true;
    this.mat.opacity = 0.55 + 0.45 * Math.abs(Math.sin(t * 5));
  }

  clear() {
    for (const idx of [...this.active.keys()]) this.release(idx);
  }
}
