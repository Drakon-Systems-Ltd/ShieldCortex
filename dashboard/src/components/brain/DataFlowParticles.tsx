'use client';

/**
 * Data Flow Particles
 * Animated particles flowing between brain regions
 */

import { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

interface DataFlowParticlesProps {
  count?: number;
  speed?: number;
}

export function DataFlowParticles({
  count = 150,
  speed = 0.5,
}: DataFlowParticlesProps) {
  const pointsRef = useRef<THREE.Points>(null);

  // Initialize particle data
  const { positions, velocities, colors, opacities } = useMemo(() => {
    const pos = new Float32Array(count * 3);
    const vel = new Float32Array(count * 3);
    const col = new Float32Array(count * 3);
    const opa = new Float32Array(count);

    for (let i = 0; i < count; i++) {
      const i3 = i * 3;

      // Random position within brain bounds
      pos[i3] = (Math.random() - 0.5) * 8;
      pos[i3 + 1] = (Math.random() - 0.5) * 6;
      pos[i3 + 2] = (Math.random() - 0.5) * 7;

      // Velocity - flowing from front to back (STM to LTM direction)
      vel[i3] = (Math.random() - 0.5) * 0.01;
      vel[i3 + 1] = (Math.random() - 0.5) * 0.01;
      vel[i3 + 2] = -0.015 - Math.random() * 0.02;

      // Initial opacity
      opa[i] = 0.3 + Math.random() * 0.4;

      // Color based on z-position
      updateColor(col, i3, pos[i3 + 2]);
    }

    return { positions: pos, velocities: vel, colors: col, opacities: opa };
  }, [count]);

  function updateColor(col: Float32Array, i3: number, z: number) {
    if (z > 1.5) {
      // Short-term region - orange
      col[i3] = 0.976;
      col[i3 + 1] = 0.451;
      col[i3 + 2] = 0.086;
    } else if (z < -1.5) {
      // Long-term region - blue
      col[i3] = 0.231;
      col[i3 + 1] = 0.51;
      col[i3 + 2] = 0.965;
    } else {
      // Episodic region - purple
      col[i3] = 0.545;
      col[i3 + 1] = 0.361;
      col[i3 + 2] = 0.965;
    }
  }

  useFrame(() => {
    if (!pointsRef.current) return;

    const posAttr = pointsRef.current.geometry.attributes.position;
    const colAttr = pointsRef.current.geometry.attributes.color;

    for (let i = 0; i < count; i++) {
      const i3 = i * 3;

      // Update position
      posAttr.array[i3] += velocities[i3] * speed;
      posAttr.array[i3 + 1] += velocities[i3 + 1] * speed;
      posAttr.array[i3 + 2] += velocities[i3 + 2] * speed;

      // Reset if out of bounds (wrap around)
      if (posAttr.array[i3 + 2] < -4) {
        posAttr.array[i3 + 2] = 4;
        posAttr.array[i3] = (Math.random() - 0.5) * 8;
        posAttr.array[i3 + 1] = (Math.random() - 0.5) * 6;
      }

      // Update color based on new position
      updateColor(colAttr.array as Float32Array, i3, posAttr.array[i3 + 2]);
    }

    posAttr.needsUpdate = true;
    colAttr.needsUpdate = true;
  });

  return (
    <points ref={pointsRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          args={[positions, 3]}
        />
        <bufferAttribute
          attach="attributes-color"
          args={[colors, 3]}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.06}
        vertexColors
        transparent
        opacity={0.6}
        sizeAttenuation
        depthWrite={false}
      />
    </points>
  );
}
