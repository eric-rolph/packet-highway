// Builds the divided highway: asphalt, dashed lane lines, glowing edges,
// lane label sprites, gateway arches, and a small skyline at the LAN end.
//
// Geography: the road runs along Z. z = +HALF_LEN is "LOCALHOST" (your
// machine / LAN), z = -HALF_LEN is "INTERNET" (the WAN). Inbound vehicles
// drive toward +Z on the +X side; outbound drive toward -Z on the -X side.
import * as THREE from 'three';
import { HALF_LEN, HIGHWAY, LANES, laneOffset } from './config.js';

function dashTexture() {
  const c = document.createElement('canvas');
  c.width = 16; c.height = 128;
  const g = c.getContext('2d');
  g.fillStyle = '#aab4cc';
  g.fillRect(5, 8, 6, 48);
  const tex = new THREE.CanvasTexture(c);
  tex.wrapS = tex.wrapT = THREE.RepeatWrapping;
  tex.repeat.set(1, HIGHWAY.length / 14);
  return tex;
}

function textSprite(text, color = '#cbd5e1', scale = 1) {
  const c = document.createElement('canvas');
  c.width = 512; c.height = 96;
  const g = c.getContext('2d');
  g.font = 'bold 52px ui-monospace, monospace';
  g.textAlign = 'center';
  g.textBaseline = 'middle';
  g.shadowColor = color;
  g.shadowBlur = 18;
  g.fillStyle = color;
  g.fillText(text, 256, 48);
  const tex = new THREE.CanvasTexture(c);
  const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
  const spr = new THREE.Sprite(mat);
  spr.scale.set(36 * scale, 6.75 * scale, 1);
  return spr;
}

export function buildHighway(scene) {
  const group = new THREE.Group();
  const nLanes = LANES.length;
  const sideW = nLanes * HIGHWAY.laneWidth;
  const totalW = HIGHWAY.medianWidth + 2 * (sideW + HIGHWAY.shoulder);

  // Asphalt slab
  const road = new THREE.Mesh(
    new THREE.BoxGeometry(totalW, 1, HIGHWAY.length),
    new THREE.MeshStandardMaterial({ color: 0x111a2b, roughness: 0.92 })
  );
  road.position.y = -0.5;
  group.add(road);

  // Median strip with glowing center line
  const median = new THREE.Mesh(
    new THREE.BoxGeometry(HIGHWAY.medianWidth, 1.3, HIGHWAY.length),
    new THREE.MeshStandardMaterial({ color: 0x0a1020, roughness: 1 })
  );
  median.position.y = -0.35;
  group.add(median);
  const centerLine = new THREE.Mesh(
    new THREE.PlaneGeometry(0.8, HIGHWAY.length),
    new THREE.MeshBasicMaterial({ color: 0x312e81 })
  );
  centerLine.rotation.x = -Math.PI / 2;
  centerLine.position.y = 0.31;
  group.add(centerLine);

  // Dashed separators + glowing outer edges, mirrored per side.
  const dashes = dashTexture();
  const dashMat = new THREE.MeshBasicMaterial({ map: dashes, transparent: true, opacity: 0.5, depthWrite: false });
  for (const side of [1, -1]) {
    for (let i = 1; i < nLanes; i++) {
      const x = side * (HIGHWAY.medianWidth / 2 + i * HIGHWAY.laneWidth);
      const m = new THREE.Mesh(new THREE.PlaneGeometry(0.35, HIGHWAY.length), dashMat);
      m.rotation.x = -Math.PI / 2;
      m.position.set(x, 0.02, 0);
      group.add(m);
    }
    // outer edge glow: cyan = inbound side (+X), fuchsia = outbound (-X)
    const edgeX = side * (HIGHWAY.medianWidth / 2 + sideW + 0.6);
    const edge = new THREE.Mesh(
      new THREE.PlaneGeometry(0.9, HIGHWAY.length),
      new THREE.MeshBasicMaterial({ color: side > 0 ? 0x0e7490 : 0x86198f })
    );
    edge.rotation.x = -Math.PI / 2;
    edge.position.set(edgeX, 0.02, 0);
    group.add(edge);
    // inner edge line at median
    const inner = new THREE.Mesh(
      new THREE.PlaneGeometry(0.35, HIGHWAY.length),
      new THREE.MeshBasicMaterial({ color: 0x475569 })
    );
    inner.rotation.x = -Math.PI / 2;
    inner.position.set(side * (HIGHWAY.medianWidth / 2 + 0.3), 0.02, 0);
    group.add(inner);
  }

  // Lane label sprites at both ends of each lane, both sides
  LANES.forEach((lane, i) => {
    for (const side of [1, -1]) {
      const x = side * laneOffset(i);
      for (const endZ of [HALF_LEN - 18, -HALF_LEN + 18]) {
        const spr = textSprite(lane.label, side > 0 ? '#67e8f9' : '#f0abfc', 0.55);
        spr.position.set(x, 7.5, endZ);
        group.add(spr);
      }
    }
  });

  // Gateway arches at each end
  for (const [z, label, color] of [
    [HALF_LEN + 6, '⌂ LOCALHOST', '#22d3ee'],
    [-HALF_LEN - 6, '☁ INTERNET', '#e879f9'],
  ]) {
    const arch = new THREE.Group();
    const postMat = new THREE.MeshStandardMaterial({
      color: 0x1e293b, emissive: new THREE.Color(color), emissiveIntensity: 0.25, roughness: 0.6,
    });
    for (const side of [1, -1]) {
      const post = new THREE.Mesh(new THREE.BoxGeometry(2.2, 26, 2.2), postMat);
      post.position.set(side * (totalW / 2 + 3), 13, 0);
      arch.add(post);
    }
    const beam = new THREE.Mesh(new THREE.BoxGeometry(totalW + 10, 2.6, 2.6), postMat);
    beam.position.y = 26;
    arch.add(beam);
    const spr = textSprite(label, color, 1.6);
    spr.position.set(0, 33, 0);
    arch.add(spr);
    arch.position.z = z;
    group.add(arch);
  }

  // Tiny skyline behind the LOCALHOST end — somewhere for packets to "arrive".
  const rng = mulberry32(42);
  const cityGeoms = [];
  const cityMat = new THREE.MeshStandardMaterial({ vertexColors: true, roughness: 0.7 });
  for (let i = 0; i < 46; i++) {
    const w = 6 + rng() * 14, h = 8 + rng() * 46, d = 6 + rng() * 14;
    const g = new THREE.BoxGeometry(w, h, d);
    g.translate((rng() - 0.5) * totalW * 2.6, h / 2, HALF_LEN + 40 + rng() * 130);
    const shade = 0.05 + rng() * 0.07;
    const col = new THREE.Color(shade, shade * 1.3, shade * 2.2);
    const n = g.attributes.position.count;
    const colors = new Float32Array(n * 3);
    for (let v = 0; v < n; v++) col.toArray(colors, v * 3);
    g.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    cityGeoms.push(g);
  }
  import('three/addons/utils/BufferGeometryUtils.js').then(({ mergeGeometries }) => {
    group.add(new THREE.Mesh(mergeGeometries(cityGeoms), cityMat));
  });

  scene.add(group);

  // Lane X positions, keyed by lane and direction.
  // Inbound (dir 'in') drives on +X toward +Z; outbound on -X toward -Z.
  const laneX = {};
  LANES.forEach((lane, i) => {
    laneX[lane.key] = { in: laneOffset(i), out: -laneOffset(i) };
  });
  return laneX;
}

function mulberry32(seed) {
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
