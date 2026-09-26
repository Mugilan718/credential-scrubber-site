(function () {
  const canvas = document.getElementById("hero-canvas");
  if (!canvas || typeof THREE === "undefined") return;

  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  let width = window.innerWidth;
  let height = window.innerHeight;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
  camera.position.z = 6;

  const renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  renderer.setSize(width, height);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  // A simple icosahedron, wireframe over a translucent solid, glowing accent color.
  const geometry = new THREE.IcosahedronGeometry(1.8, 1);

  const solidMaterial = new THREE.MeshBasicMaterial({
    color: 0x00e5c7,
    transparent: true,
    opacity: 0.08,
  });
  const solid = new THREE.Mesh(geometry, solidMaterial);
  scene.add(solid);

  const wireMaterial = new THREE.MeshBasicMaterial({
    color: 0x7c4dff,
    wireframe: true,
    transparent: true,
    opacity: 0.55,
  });
  const wire = new THREE.Mesh(geometry, wireMaterial);
  scene.add(wire);

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height);
  }
  window.addEventListener("resize", resize);

  let frameId;
  function animate() {
    frameId = requestAnimationFrame(animate);
    solid.rotation.y += 0.0022;
    solid.rotation.x += 0.0009;
    wire.rotation.y += 0.0022;
    wire.rotation.x += 0.0009;
    renderer.render(scene, camera);
  }

  if (prefersReducedMotion) {
    // Render a single static frame instead of a continuous animation loop.
    renderer.render(scene, camera);
  } else {
    animate();
  }

  // Stop rendering if the tab is hidden, to avoid wasting battery/CPU.
  document.addEventListener("visibilitychange", () => {
    if (document.hidden && frameId) {
      cancelAnimationFrame(frameId);
      frameId = null;
    } else if (!document.hidden && !frameId && !prefersReducedMotion) {
      animate();
    }
  });
})();
