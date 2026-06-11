// Renderer, camera, lights, post-processing, orbit controls, camera presets.
//
// The look: night highway. ACES tone mapping + bloom make every emissive
// element (headlights, strobes, gates, lane glow, hazard wrecks) actually
// glow; a PMREM room environment gives bodies and glass real reflections.
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';
import { HALF_LEN } from './config.js';

// 1 = overview · 2 = top-down "barcode timeline" · 3 = gate-level view
const PRESETS = {
  1: { pos: [118, 88, 205], target: [0, 0, 30] },
  2: { pos: [0, 540, 31], target: [0, 0, 30] },
  3: { pos: [-30, 15, HALF_LEN + 55], target: [0, 5, 0] },
};

export function createScene(canvas) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.15;

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x05080f);
  scene.fog = new THREE.Fog(0x05080f, 320, 900);

  // image-based lighting: cheap reflections on car bodies and glass
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  scene.environmentIntensity = 0.35;
  pmrem.dispose();

  const camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.5, 2000);
  camera.position.set(...PRESETS[1].pos);

  const controls = new OrbitControls(camera, canvas);
  controls.target.set(...PRESETS[1].target);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;
  controls.maxPolarAngle = 1.52;
  controls.minDistance = 25;
  controls.maxDistance = 760;

  scene.add(new THREE.HemisphereLight(0x96a8cc, 0x0a0e1a, 0.65));
  const sun = new THREE.DirectionalLight(0xcfe3ff, 0.95);
  sun.position.set(140, 220, 90);
  scene.add(sun);
  const rim = new THREE.DirectionalLight(0x7c3aed, 0.35);
  rim.position.set(-120, 60, -160);
  scene.add(rim);

  const grid = new THREE.GridHelper(1600, 64, 0x16202f, 0x101826);
  grid.position.y = -0.2;
  scene.add(grid);

  // starfield shell
  {
    const n = 1400;
    const pos = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      const r = 650 + Math.random() * 350;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(Math.random() * 0.9); // bias above the horizon
      pos[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      pos[i * 3 + 1] = Math.abs(r * Math.cos(phi)) + 10;
      pos[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
    }
    const g = new THREE.BufferGeometry();
    g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const stars = new THREE.Points(g, new THREE.PointsMaterial({
      color: 0x9db4d8, size: 1.4, sizeAttenuation: false, transparent: true, opacity: 0.75, fog: false,
    }));
    stars.raycast = () => {};
    scene.add(stars);
  }

  // post-processing: render -> bloom -> output (tone map + color space)
  const composer = new EffectComposer(renderer);
  composer.setPixelRatio(renderer.getPixelRatio());
  composer.addPass(new RenderPass(scene, camera));
  const bloom = new UnrealBloomPass(
    new THREE.Vector2(window.innerWidth, window.innerHeight), 0.55, 0.45, 0.85);
  composer.addPass(bloom);
  composer.addPass(new OutputPass());

  // smooth camera-preset tweens + chase cam; any manual drag cancels both
  let tween = null;
  let chase = null; // () => vehicle rec | null
  controls.addEventListener('start', () => { tween = null; chase = null; });

  function setPreset(n) {
    const p = PRESETS[n];
    if (!p) return;
    chase = null;
    tween = {
      t0: performance.now(),
      fromPos: camera.position.clone(), toPos: new THREE.Vector3(...p.pos),
      fromTarget: controls.target.clone(), toTarget: new THREE.Vector3(...p.target),
    };
  }

  /** Follow a vehicle: getter returns its rec each frame, null when gone. */
  function setChase(getter) {
    tween = null;
    chase = getter;
  }

  const _chasePos = new THREE.Vector3();
  const _chaseTarget = new THREE.Vector3();
  let lastNow = performance.now();

  function update(now) {
    const dt = Math.min((now - lastNow) / 1000, 0.1);
    lastNow = now;
    if (chase) {
      const r = chase();
      if (!r) {
        chase = null;
        setPreset(1); // the vehicle reached its gate — drift back to overview
      } else {
        const d = r.dirSign;
        const side = r.x >= 0 ? 9 : -9;
        _chasePos.set(r.x + side, 10, r.z - d * 17);
        _chaseTarget.set(r.x, 2, r.z + d * 14);
        const k = 1 - Math.exp(-4.5 * dt);
        camera.position.lerp(_chasePos, k);
        controls.target.lerp(_chaseTarget, k);
      }
    } else if (tween) {
      const a = Math.min((now - tween.t0) / 1100, 1);
      const e = a < 0.5 ? 2 * a * a : 1 - ((-2 * a + 2) ** 2) / 2;
      camera.position.lerpVectors(tween.fromPos, tween.toPos, e);
      controls.target.lerpVectors(tween.fromTarget, tween.toTarget, e);
      if (a >= 1) tween = null;
    }
    controls.update();
  }

  window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(window.innerWidth, window.innerHeight);
    composer.setPixelRatio(renderer.getPixelRatio());
    composer.setSize(window.innerWidth, window.innerHeight);
  });

  return { renderer, scene, camera, controls, composer, setPreset, setChase, update };
}
