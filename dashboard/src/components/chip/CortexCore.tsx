'use client';

/**
 * Cortex Core
 * Central processing element with pulsing golden glow
 * The focal point of the memory chip
 */

import { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import * as THREE from 'three';

interface CortexCoreProps {
  position?: [number, number, number];
  size?: number;
  activity?: number; // 0-1, affects pulse intensity
  showLabel?: boolean;
}

export function CortexCore({
  position = [0, 0, 0],
  size = 2,
  activity = 0.5,
  showLabel = true,
}: CortexCoreProps) {
  const coreRef = useRef<THREE.Mesh>(null);
  const glow1Ref = useRef<THREE.Mesh>(null);
  const glow2Ref = useRef<THREE.Mesh>(null);
  const glow3Ref = useRef<THREE.Mesh>(null);

  // Core material - bright gold center
  const coreMaterial = useMemo(() => {
    return new THREE.MeshStandardMaterial({
      color: '#FFD700',
      emissive: '#FFD700',
      emissiveIntensity: 0.8,
      metalness: 0.3,
      roughness: 0.4,
    });
  }, []);

  // Glow materials - progressively fainter
  const glowMaterials = useMemo(() => {
    return [
      new THREE.MeshBasicMaterial({
        color: '#FFD700',
        transparent: true,
        opacity: 0.4,
        side: THREE.BackSide,
      }),
      new THREE.MeshBasicMaterial({
        color: '#FFB347',
        transparent: true,
        opacity: 0.2,
        side: THREE.BackSide,
      }),
      new THREE.MeshBasicMaterial({
        color: '#FF8C00',
        transparent: true,
        opacity: 0.1,
        side: THREE.BackSide,
      }),
    ];
  }, []);

  // Animate pulse
  useFrame((state) => {
    const time = state.clock.elapsedTime;
    const basePulse = Math.sin(time * 2) * 0.5 + 0.5;
    const activityBoost = activity * 0.3;

    // Core pulse
    if (coreRef.current) {
      const material = coreRef.current.material as THREE.MeshStandardMaterial;
      material.emissiveIntensity = 0.6 + basePulse * 0.4 + activityBoost;
    }

    // Glow layers pulse with phase offset
    if (glow1Ref.current) {
      const mat = glow1Ref.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.3 + basePulse * 0.2 + activityBoost * 0.5;
      glow1Ref.current.scale.setScalar(1 + basePulse * 0.05);
    }

    if (glow2Ref.current) {
      const phase2 = Math.sin(time * 2 + 0.5) * 0.5 + 0.5;
      const mat = glow2Ref.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.15 + phase2 * 0.1 + activityBoost * 0.3;
      glow2Ref.current.scale.setScalar(1 + phase2 * 0.03);
    }

    if (glow3Ref.current) {
      const phase3 = Math.sin(time * 2 + 1) * 0.5 + 0.5;
      const mat = glow3Ref.current.material as THREE.MeshBasicMaterial;
      mat.opacity = 0.08 + phase3 * 0.05 + activityBoost * 0.2;
      glow3Ref.current.scale.setScalar(1 + phase3 * 0.02);
    }
  });

  return (
    <group position={position}>
      {/* Core block - rounded rectangle */}
      <mesh ref={coreRef} material={coreMaterial}>
        <boxGeometry args={[size, size * 0.6, 0.3]} />
      </mesh>

      {/* Inner detail - circuit pattern */}
      <CoreCircuitPattern size={size} />

      {/* Glow layer 1 */}
      <mesh ref={glow1Ref}>
        <boxGeometry args={[size * 1.1, size * 0.7, 0.4]} />
        <primitive object={glowMaterials[0]} />
      </mesh>

      {/* Glow layer 2 */}
      <mesh ref={glow2Ref}>
        <boxGeometry args={[size * 1.3, size * 0.85, 0.5]} />
        <primitive object={glowMaterials[1]} />
      </mesh>

      {/* Glow layer 3 */}
      <mesh ref={glow3Ref}>
        <boxGeometry args={[size * 1.5, size, 0.6]} />
        <primitive object={glowMaterials[2]} />
      </mesh>

      {/* Activity indicator dot */}
      <ActivityIndicator activity={activity} size={size} />

      {/* Label */}
      {showLabel && (
        <Html
          position={[0, -size * 0.45, 0.2]}
          center
          style={{
            pointerEvents: 'none',
            userSelect: 'none',
          }}
        >
          <div className="text-[10px] font-mono text-amber-400/80 whitespace-nowrap tracking-wider">
            CORTEX CORE
          </div>
        </Html>
      )}
    </group>
  );
}

// Circuit pattern on core surface
function CoreCircuitPattern({ size }: { size: number }) {
  const linesGeometry = useMemo(() => {
    const points: THREE.Vector3[] = [];
    const halfSize = size / 2;
    const z = 0.16;

    // Horizontal lines
    for (let i = -2; i <= 2; i++) {
      const y = i * 0.12;
      points.push(new THREE.Vector3(-halfSize * 0.7, y, z));
      points.push(new THREE.Vector3(halfSize * 0.7, y, z));
    }

    // Vertical lines
    for (let i = -4; i <= 4; i++) {
      const x = i * 0.18;
      points.push(new THREE.Vector3(x, -size * 0.2, z));
      points.push(new THREE.Vector3(x, size * 0.2, z));
    }

    return new THREE.BufferGeometry().setFromPoints(points);
  }, [size]);

  return (
    <lineSegments>
      <primitive object={linesGeometry} />
      <lineBasicMaterial color="#8B6914" opacity={0.5} transparent />
    </lineSegments>
  );
}

// Pulsing activity indicator
function ActivityIndicator({ activity, size }: { activity: number; size: number }) {
  const dotRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (dotRef.current) {
      const pulse = Math.sin(state.clock.elapsedTime * 4) * 0.5 + 0.5;
      const scale = 0.8 + pulse * 0.4 + activity * 0.3;
      dotRef.current.scale.setScalar(scale);

      const material = dotRef.current.material as THREE.MeshBasicMaterial;
      material.opacity = 0.6 + pulse * 0.4;
    }
  });

  const isActive = activity > 0.1;

  return (
    <mesh ref={dotRef} position={[size * 0.35, size * 0.2, 0.2]}>
      <circleGeometry args={[0.08, 16]} />
      <meshBasicMaterial
        color={isActive ? '#22c55e' : '#6b7280'}
        transparent
        opacity={0.8}
      />
    </mesh>
  );
}
