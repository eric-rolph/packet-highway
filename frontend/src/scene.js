// Renderer, camera, lights, orbit controls, resize handling.
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

export function createScene(canvas) {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, powerPreference: 'high-performance' });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(window.innerWidth, window.innerHeight);

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x05080f);
  scene.fog = new THREE.Fog(0x05080f, 320, 900);

  const camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.5, 2000);
  camera.position.set(118, 88, 205);

  const controls = new OrbitControls(camera, canvas);
  controls.target.set(0, 0, 30);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;
  controls.maxPolarAngle = 1.52;
  controls.minDistance = 25;
  controls.maxDistance = 750;

  scene.add(new THREE.HemisphereLight(0x96a8cc, 0x0a0e1a, 0.95));
  const sun = new THREE.DirectionalLight(0xcfe3ff, 1.25);
  sun.position.set(140, 220, 90);
  scene.add(sun);
  const rim = new THREE.DirectionalLight(0x7c3aed, 0.35);
  rim.position.set(-120, 60, -160);
  scene.add(rim);

  const grid = new THREE.GridHelper(1600, 64, 0x16202f, 0x101826);
  grid.position.y = -0.2;
  scene.add(grid);

  window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2)); // DPR can change across monitors
    renderer.setSize(window.innerWidth, window.innerHeight);
  });

  return { renderer, scene, camera, controls };
}
