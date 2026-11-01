import React, { useEffect, useRef } from 'react';
import * as THREE from 'three';

export default function Ghost3DCanvas() {
  const mountRef = useRef(null);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    const width = container.clientWidth || 460;
    const height = container.clientHeight || 460;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(36, width / height, 1, 2000);
    camera.position.set(0, 0, 780);

    const renderer = new THREE.WebGLRenderer({
      alpha: true,
      antialias: true,
      powerPreference: 'high-performance',
    });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 2. Texture Loader
    const textureLoader = new THREE.TextureLoader();
    const mascotTexture = textureLoader.load('/mascot.png');
    const depthTexture = textureLoader.load('/mascot_depth.png');

    mascotTexture.generateMipmaps = true;
    mascotTexture.minFilter = THREE.LinearMipmapLinearFilter;
    mascotTexture.magFilter = THREE.LinearFilter;

    // 3. Shader Material - Organic Head & Eye Articulation (Matching Reference Monkey!)
    const uniforms = {
      uTexture: { value: mascotTexture },
      uDepthMap: { value: depthTexture },
      uMouse: { value: new THREE.Vector2(0, 0) },
      uTargetMouse: { value: new THREE.Vector2(0, 0) },
      uHeadYaw: { value: 0 },
      uHeadPitch: { value: 0 },
      uHeadRoll: { value: 0 },
      uTime: { value: 0 },
      uDepthScale: { value: 75.0 },
    };

    const vertexShader = `
      uniform float uTime;
      uniform float uHeadYaw;
      uniform float uHeadPitch;
      uniform float uHeadRoll;
      uniform float uDepthScale;
      uniform sampler2D uDepthMap;

      varying vec2 vUv;
      varying float vDepth;
      varying vec3 vPosition;

      void main() {
        vUv = uv;
        
        // Sample volumetric depth map for round 3D sculpt
        float rawDepth = texture2D(uDepthMap, uv).r;
        vDepth = rawDepth;
        
        vec3 pos = position;
        
        // 1. Volumetric Z-curvature (curves the head and body in real depth)
        pos.z += rawDepth * uDepthScale;
        
        // 2. NECK PIVOT & HEAD ROTATION (Matching Reference Images!)
        // Body (skirt/hands) stays stable in place.
        // Head smoothly pivots on the neck to turn and look at the cursor!
        vec3 neckPivot = vec3(0.0, 15.0, 30.0);
        
        // Weight: 0.0 on body/skirt, ramps up across neck, 1.0 on head
        float headWeight = smoothstep(0.38, 0.72, uv.y);
        
        vec3 p = pos - neckPivot;
        
        // Roll (Z rotation) - head tilts into the gaze
        float cz = cos(uHeadRoll), sz = sin(uHeadRoll);
        vec3 pz = vec3(cz * p.x - sz * p.y, sz * p.x + cz * p.y, p.z);
        
        // Pitch (X rotation) - looks up when cursor is up, down when cursor is down
        float cx = cos(uHeadPitch), sx = sin(uHeadPitch);
        vec3 px = vec3(pz.x, cx * pz.y - sx * pz.z, sx * pz.y + cx * pz.z);
        
        // Yaw (Y rotation) - turns head left and right
        float cy = cos(uHeadYaw), sy = sin(uHeadYaw);
        vec3 py = vec3(cy * px.x + sy * px.z, px.y, -sy * px.x + cy * px.z);
        
        vec3 rotatedHeadPos = neckPivot + py;
        
        // Blend: body stays stable, head articulates naturally
        pos = mix(pos, rotatedHeadPos, headWeight);
        
        // Gentle organic breathing
        float breath = sin(uTime * 1.8) * 0.012;
        pos.xyz *= (1.0 + breath);
        
        vPosition = pos;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(pos, 1.0);
      }
    `;

    const fragmentShader = `
      uniform sampler2D uTexture;
      uniform vec2 uMouse;
      uniform float uTime;

      varying vec2 vUv;
      varying float vDepth;
      varying vec3 vPosition;

      void main() {
        vec4 color = texture2D(uTexture, vUv);
        
        // Discard background transparent pixels
        if (color.a < 0.06) {
          discard;
        }

        // ========================================================
        // DARK EYE MASK:
        // Eye pixels have luminance < 0.20, white skin has luminance > 0.70.
        // This mask is strictly 1.0 inside the dark eye and 0.0 on skin.
        // Guarantees white pupils CANNOT bleed onto the face skin!
        // ========================================================
        float eyeLuminance = (color.r + color.g + color.b) / 3.0;
        float isDarkEye = 1.0 - smoothstep(0.10, 0.22, eyeLuminance);

        // Eye centers in UV coordinates:
        // Left eye: (0.355, 0.638), Right eye: (0.501, 0.655)
        vec2 leftEyeCenter = vec2(0.355, 0.638);
        vec2 rightEyeCenter = vec2(0.501, 0.655);

        // Dynamic pupil offsets tracking cursor (left, right, up, down)
        // Kept strictly within the safe inner boundaries of the eye oval
        vec2 leftPupilPos = leftEyeCenter + vec2(0.002, 0.008) + vec2(uMouse.x * 0.007, uMouse.y * 0.012);
        vec2 rightPupilPos = rightEyeCenter + vec2(0.004, 0.010) + vec2(uMouse.x * 0.011, uMouse.y * 0.013);

        float dLeft = length(vUv - leftPupilPos);
        float dRight = length(vUv - rightPupilPos);

        // Circular crisp white pupils with soft glow halo
        float leftCore = smoothstep(0.012, 0.003, dLeft);
        float leftGlow = smoothstep(0.019, 0.006, dLeft) * 0.35;

        float rightCore = smoothstep(0.013, 0.004, dRight);
        float rightGlow = smoothstep(0.022, 0.007, dRight) * 0.35;

        // Multiply by isDarkEye so pupils ONLY render on the dark eye surface!
        float pupilAlpha = ((leftCore + leftGlow) + (rightCore + rightGlow)) * isDarkEye;
        
        color.rgb = mix(color.rgb, vec3(1.0, 1.0, 1.0), clamp(pupilAlpha, 0.0, 1.0));
        
        gl_FragColor = color;
      }
    `;

    const customMaterial = new THREE.ShaderMaterial({
      uniforms: uniforms,
      vertexShader: vertexShader,
      fragmentShader: fragmentShader,
      transparent: true,
      side: THREE.DoubleSide,
    });

    // 4. Dense 3D Plane Mesh (128x128 for smooth curvature)
    const meshSize = 440;
    const geometry = new THREE.PlaneGeometry(meshSize, meshSize, 128, 128);
    const ghostMesh = new THREE.Mesh(geometry, customMaterial);
    
    // Group wrapper
    const ghostGroup = new THREE.Group();
    ghostGroup.add(ghostMesh);
    scene.add(ghostGroup);

    // 5. Symmetric Mouse Interaction Tracking (Responsive across entire hero)
    const handleMouseMove = (e) => {
      const rect = container.getBoundingClientRect();
      const mascotX = rect.left + rect.width / 2;
      const mascotY = rect.top + rect.height * 0.45;

      const deltaX = e.clientX - mascotX;
      const deltaY = -(e.clientY - mascotY); // Up is positive

      // Sensitivity: reaching ~220px to the left or right triggers full turn
      const sensitivityX = 220;
      const sensitivityY = 180;

      let normX = deltaX / sensitivityX;
      let normY = deltaY / sensitivityY;

      normX = Math.max(-1.0, Math.min(1.0, normX));
      normY = Math.max(-1.0, Math.min(1.0, normY));

      uniforms.uTargetMouse.value.set(normX, normY);
    };

    const handleMouseLeave = () => {
      uniforms.uTargetMouse.value.set(0, 0);
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    window.addEventListener('mouseleave', handleMouseLeave);

    // 6. Resize Observer
    const resizeObserver = new ResizeObserver(() => {
      if (!container) return;
      const w = container.clientWidth || 460;
      const h = container.clientHeight || 460;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    });
    resizeObserver.observe(container);

    // 7. Animation Loop: Head & Eye Articulation (Matching Reference Images!)
    let animationFrameId;
    const clock = new THREE.Clock();

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate);

      const elapsedTime = clock.getElapsedTime();
      uniforms.uTime.value = elapsedTime;

      // Smooth spring interpolation for natural character response
      const targetX = uniforms.uTargetMouse.value.x;
      const targetY = uniforms.uTargetMouse.value.y;

      uniforms.uMouse.value.x += (targetX - uniforms.uMouse.value.x) * 0.085;
      uniforms.uMouse.value.y += (targetY - uniforms.uMouse.value.y) * 0.085;

      const currentX = uniforms.uMouse.value.x;
      const currentY = uniforms.uMouse.value.y;

      // ========================================================
      // HEAD ARTICULATION (Like the Reference Monkey!):
      // - Cursor left  -> head turns left
      // - Cursor right -> head turns right (0.42 rad ~ 24 deg)
      // - Cursor up    -> head tilts back & chin lifts (-0.22 rad)
      // - Cursor down  -> head tilts forward & down (+0.22 rad)
      // - Head rolls slightly into the turn (-currentX * 0.07 rad)
      // ========================================================
      const yaw = currentX >= 0 ? currentX * 0.42 : currentX * 0.36;
      const pitch = -currentY * 0.22;
      const roll = -currentX * 0.07;

      uniforms.uHeadYaw.value = yaw;
      uniforms.uHeadPitch.value = pitch;
      uniforms.uHeadRoll.value = roll;

      // ========================================================
      // BODY STABILITY:
      // The body stays rooted and stable in place (only 12px micro-sway)
      // with a gentle mid-air floating hover!
      // ========================================================
      const floatHover = Math.sin(elapsedTime * 2.2) * 8.0;
      ghostGroup.position.set(currentX * 12.0, currentY * 6.0 + floatHover, 0);

      renderer.render(scene, camera);
    };

    animate();

    // 8. Cleanup
    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseleave', handleMouseLeave);
      resizeObserver.disconnect();
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      geometry.dispose();
      customMaterial.dispose();
      mascotTexture.dispose();
      depthTexture.dispose();
      renderer.dispose();
    };
  }, []);

  return (
    <div
      ref={mountRef}
      className="relative w-full h-[460px] max-w-[480px] lg:max-w-[540px] flex items-center justify-center select-none"
    />
  );
}
