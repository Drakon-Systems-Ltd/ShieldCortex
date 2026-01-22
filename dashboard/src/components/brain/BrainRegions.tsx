'use client';

/**
 * Brain Regions
 * Visual indicators for the three memory regions
 */

import { useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

export function BrainRegions() {
  const stmRef = useRef<THREE.Mesh>(null);
  const ltmRef = useRef<THREE.Mesh>(null);
  const epiRef = useRef<THREE.Mesh>(null);

  // Subtle breathing animation
  useFrame((state) => {
    const t = state.clock.elapsedTime;

    if (stmRef.current) {
      stmRef.current.scale.setScalar(1 + Math.sin(t * 0.5) * 0.02);
    }
    if (ltmRef.current) {
      ltmRef.current.scale.setScalar(1 + Math.sin(t * 0.4 + 1) * 0.02);
    }
    if (epiRef.current) {
      epiRef.current.scale.setScalar(1 + Math.sin(t * 0.45 + 2) * 0.02);
    }
  });

  return (
    <group>
      {/* Short-term region (front) - Orange tint */}
      <mesh ref={stmRef} position={[0, 0, 2.5]}>
        <sphereGeometry args={[3.5, 32, 32, 0, Math.PI * 2, 0, Math.PI / 2]} />
        <meshBasicMaterial
          color="#F97316"
          transparent
          opacity={0.03}
          side={THREE.DoubleSide}
          depthWrite={false}
        />
      </mesh>

      {/* Long-term region (back) - Blue tint */}
      <mesh ref={ltmRef} position={[0, 0, -2.5]}>
        <sphereGeometry args={[3.5, 32, 32, 0, Math.PI * 2, Math.PI / 2, Math.PI / 2]} />
        <meshBasicMaterial
          color="#3B82F6"
          transparent
          opacity={0.03}
          side={THREE.DoubleSide}
          depthWrite={false}
        />
      </mesh>

      {/* Episodic region (middle) - Purple tint */}
      <mesh ref={epiRef} position={[0, 0, 0]}>
        <torusGeometry args={[3, 1.2, 16, 48]} />
        <meshBasicMaterial
          color="#8B5CF6"
          transparent
          opacity={0.02}
          side={THREE.DoubleSide}
          depthWrite={false}
        />
      </mesh>

      {/* Wireframe structure */}
      <mesh>
        <sphereGeometry args={[5, 16, 12]} />
        <meshBasicMaterial
          color="#334155"
          wireframe
          transparent
          opacity={0.1}
        />
      </mesh>

      {/* Central axis line */}
      <mesh>
        <cylinderGeometry args={[0.02, 0.02, 8, 8]} />
        <meshBasicMaterial color="#475569" transparent opacity={0.3} />
      </mesh>
    </group>
  );
}
