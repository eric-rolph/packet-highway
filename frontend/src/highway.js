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

  // Dashed separators + glowing outer edges, mirrored per side. Each protocol
  // lane also gets a fainter center divider splitting it into two sub-lanes
  // (cruise + passing).
  const dashes = dashTexture();
  const dashMat = new THREE.MeshBasicMaterial({ map: dashes, transparent: true, opacity: 0.55, depthWrite: false });
  const subDashMat = new THREE.MeshBasicMaterial({ map: dashes, transparent: true, opacity: 0.16, depthWrite: false });
  for (const side of [1, -1]) {
    for (let i = 1; i < nLanes; i++) {
      const x = side * (HIGHWAY.medianWidth / 2 + i * HIGHWAY.laneWidth);
      const m = new THREE.Mesh(new THREE.PlaneGeometry(0.35, HIGHWAY.length), dashMat);
      m.rotation.x = -Math.PI / 2;
      m.position.set(x, 0.02, 0);
      group.add(m);
    }
    for (let i = 0; i < nLanes; i++) {
      const m = new THREE.Mesh(new THREE.PlaneGeometry(0.28, HIGHWAY.length), subDashMat);
      m.rotation.x = -Math.PI / 2;
      m.position.set(side * laneOffset(i), 0.02, 0);
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

  // Lane labels live ON the gantries (like real overhead signage) instead of
  // floating mid-air, where they stacked into word soup at low camera angles.
  const signPlate = (text, tint) => {
    const c = document.createElement('canvas');
    c.width = 256; c.height = 56;
    const g = c.getContext('2d');
    g.fillStyle = 'rgba(8, 14, 28, 0.94)';
    g.fillRect(0, 0, 256, 56);
    g.strokeStyle = tint;
    g.lineWidth = 3;
    g.strokeRect(2, 2, 252, 52);
    g.font = 'bold 26px ui-monospace, monospace';
    g.textAlign = 'center';
    g.textBaseline = 'middle';
    g.fillStyle = tint;
    g.fillText(text, 128, 30);
    const tex = new THREE.CanvasTexture(c);
    return new THREE.MeshBasicMaterial({ map: tex, transparent: true, toneMapped: false });
  };
  const plateGeo = new THREE.PlaneGeometry(7.4, 1.9);
  for (const gateZ of [HALF_LEN + 6, -HALF_LEN - 6]) {
    LANES.forEach((lane, i) => {
      for (const side of [1, -1]) {
        const mat = signPlate(lane.label, side > 0 ? '#67e8f9' : '#f0abfc');
        for (const face of [1, -1]) { // readable from both directions
          const m = new THREE.Mesh(plateGeo, mat);
          m.position.set(side * laneOffset(i), 23.3, gateZ + face * 1.6);
          if (face < 0) m.rotation.y = Math.PI;
          group.add(m);
        }
      }
    });
  }

  // Faint lane names painted on the asphalt for mid-road orientation —
  // foreshortened at low angles exactly like real road paint.
  const paintGeo = new THREE.PlaneGeometry(5.6, 2.4);
  const paintCache = {};
  const roadPaint = (key) => {
    if (!paintCache[key]) {
      const c = document.createElement('canvas');
      c.width = 192; c.height = 80;
      const g = c.getContext('2d');
      g.font = 'bold 44px ui-monospace, monospace';
      g.textAlign = 'center';
      g.textBaseline = 'middle';
      g.fillStyle = '#cbd5e1';
      g.fillText(key, 96, 42);
      const tex = new THREE.CanvasTexture(c);
      paintCache[key] = new THREE.MeshBasicMaterial({
        map: tex, transparent: true, opacity: 0.26, depthWrite: false,
      });
    }
    return paintCache[key];
  };
  LANES.forEach((lane, i) => {
    for (const side of [1, -1]) {
      for (const z of [-130, 90]) {
        const m = new THREE.Mesh(paintGeo, roadPaint(lane.key));
        m.rotation.x = -Math.PI / 2;
        m.rotation.z = side > 0 ? Math.PI : 0; // baseline faces oncoming drivers
        m.position.set(side * laneOffset(i), 0.03, z + side * 25);
        m.raycast = () => {};
        group.add(m);
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
      color: 0x1e293b, emissive: new THREE.Color(color), emissiveIntensity: 1.4, roughness: 0.6,
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

  // Tiny skyline behind the LOCALHOST end — somewhere for packets to "arrive",
  // with lit windows so it reads as a city at night, not cargo crates.
  const rng = mulberry32(42);
  const cityGeoms = [];
  const windowGeoms = [];
  const cityMat = new THREE.MeshStandardMaterial({ vertexColors: true, roughness: 0.7 });
  const warm = new THREE.Color(0xffd9a0), cool = new THREE.Color(0x9fd8ff);
  for (let i = 0; i < 46; i++) {
    const w = 6 + rng() * 14, h = 8 + rng() * 46, d = 6 + rng() * 14;
    const bx = (rng() - 0.5) * totalW * 2.6, bz = HALF_LEN + 40 + rng() * 130;
    const g = new THREE.BoxGeometry(w, h, d);
    g.translate(bx, h / 2, bz);
    const shade = 0.05 + rng() * 0.07;
    const col = new THREE.Color(shade, shade * 1.3, shade * 2.2);
    const n = g.attributes.position.count;
    const colors = new Float32Array(n * 3);
    for (let v = 0; v < n; v++) col.toArray(colors, v * 3);
    g.setAttribute('color', new THREE.BufferAttribute(colors, 3));
    cityGeoms.push(g);
    // window grid on the road-facing wall
    const cols = Math.max(Math.floor(w / 2.2), 1);
    const rows = Math.max(Math.floor(h / 3.2), 1);
    for (let r = 0; r < rows; r++) {
      for (let cidx = 0; cidx < cols; cidx++) {
        if (rng() > 0.42) continue; // most windows dark
        const wg = new THREE.PlaneGeometry(0.95, 1.35);
        wg.rotateY(Math.PI);
        wg.translate(
          bx - w / 2 + (cidx + 0.5) * (w / cols),
          2.2 + r * 3.2,
          bz - d / 2 - 0.06,
        );
        const wc = rng() < 0.7 ? warm : cool;
        const wn = wg.attributes.position.count;
        const warr = new Float32Array(wn * 3);
        for (let v = 0; v < wn; v++) wc.toArray(warr, v * 3);
        wg.setAttribute('color', new THREE.BufferAttribute(warr, 3));
        windowGeoms.push(wg);
      }
    }
  }
  import('three/addons/utils/BufferGeometryUtils.js').then(({ mergeGeometries }) => {
    group.add(new THREE.Mesh(mergeGeometries(cityGeoms), cityMat));
    if (windowGeoms.length) {
      const winMesh = new THREE.Mesh(
        mergeGeometries(windowGeoms),
        new THREE.MeshBasicMaterial({ vertexColors: true, toneMapped: false }),
      );
      winMesh.raycast = () => {};
      group.add(winMesh);
    }
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
