'use client';

/**
 * Memory Node
 * Individual memory rendered as a glowing neuron in 3D space
 *
 * Performance optimizations:
 * - Reduced polygon counts on spheres (8 segments for glow, 12 for main)
 * - Memoized geometries and materials to prevent recreation
 * - Lazy-loaded HTML tooltips (only on hover)
 * - Selection ring uses fewer segments
 */

import { useRef, useState, useMemo, memo } from 'react';
import { useFrame, useThree } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import * as THREE from 'three';
import { Memory } from '@/types/memory';
import { getCategoryColor } from '@/lib/category-colors';
import { calculateDecayFactor } from '@/lib/position-algorithm';

interface MemoryNodeProps {
  memory: Memory;
  position: [number, number, number];
  onSelect: (memory: Memory) => void;
  isSelected: boolean;
}

// Shared geometries (created once, reused by all nodes)
const GLOW_GEOMETRY = new THREE.SphereGeometry(1, 8, 8);
const NODE_GEOMETRY = new THREE.SphereGeometry(1, 12, 12);
const RING_GEOMETRY = new THREE.RingGeometry(1, 1.15, 24);

function MemoryNodeInner({
  memory,
  position,
  onSelect,
  isSelected,
}: MemoryNodeProps) {
  const meshRef = useRef<THREE.Mesh>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);
  const { camera } = useThree();

  // Calculate visual properties (memoized)
  const decayFactor = useMemo(() => calculateDecayFactor(memory), [memory]);
  const baseColor = useMemo(() => getCategoryColor(memory.category), [memory.category]);

  // Node size based on salience (0.15 to 0.4)
  const size = useMemo(() => 0.15 + memory.salience * 0.25, [memory.salience]);

  // Glow intensity based on decay
  const glowIntensity = useMemo(
    () => memory.salience * decayFactor,
    [memory.salience, decayFactor]
  );

  // Memoized materials to prevent recreation
  const glowMaterial = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: baseColor,
        transparent: true,
        opacity: glowIntensity * 0.2,
        depthWrite: false,
      }),
    [baseColor, glowIntensity]
  );

  const nodeMaterial = useMemo(
    () =>
      new THREE.MeshStandardMaterial({
        color: baseColor,
        emissive: baseColor,
        emissiveIntensity: glowIntensity,
        metalness: 0.3,
        roughness: 0.4,
        transparent: true,
        opacity: 0.7 + decayFactor * 0.3,
      }),
    [baseColor, glowIntensity, decayFactor]
  );

  // Animation with frustum culling check
  useFrame((state) => {
    if (!meshRef.current) return;

    // Simple frustum culling - skip animation if far from camera
    const distanceToCamera = meshRef.current.position.distanceTo(camera.position);
    if (distanceToCamera > 30) return;

    // Breathing animation - faster for higher salience
    const pulseSpeed = 0.5 + memory.salience * 1.5;
    const pulse = Math.sin(state.clock.elapsedTime * pulseSpeed) * 0.08;
    meshRef.current.scale.setScalar(size * (1 + pulse * glowIntensity));

    if (glowRef.current) {
      // Glow pulsing
      const glowPulse = Math.sin(state.clock.elapsedTime * 0.8) * 0.3 + 0.7;
      glowRef.current.scale.setScalar(size * 1.8 * (1 + glowPulse * 0.15));
      (glowRef.current.material as THREE.MeshBasicMaterial).opacity =
        glowIntensity * 0.3 * glowPulse;
    }

    // Update emissive intensity on hover
    if (hovered) {
      (meshRef.current.material as THREE.MeshStandardMaterial).emissiveIntensity =
        glowIntensity * 1.5;
    }
  });

  return (
    <group position={position}>
      {/* Outer glow - using shared geometry, scaled */}
      <mesh ref={glowRef} geometry={GLOW_GEOMETRY} material={glowMaterial} scale={size * 1.8} />

      {/* Main node - using shared geometry, scaled */}
      <mesh
        ref={meshRef}
        geometry={NODE_GEOMETRY}
        material={nodeMaterial}
        scale={size}
        onClick={(e) => {
          e.stopPropagation();
          onSelect(memory);
        }}
        onPointerOver={(e) => {
          e.stopPropagation();
          setHovered(true);
          document.body.style.cursor = 'pointer';
        }}
        onPointerOut={() => {
          setHovered(false);
          document.body.style.cursor = 'default';
        }}
      />

      {/* Selection ring - only rendered when selected */}
      {isSelected && (
        <mesh geometry={RING_GEOMETRY} rotation={[Math.PI / 2, 0, 0]} scale={size + 0.15}>
          <meshBasicMaterial color="#ffffff" transparent opacity={0.9} side={THREE.DoubleSide} />
        </mesh>
      )}

      {/* Hover tooltip - lazy loaded only on hover */}
      {hovered && !isSelected && (
        <Html
          distanceFactor={8}
          style={{
            pointerEvents: 'none',
            transform: 'translate(-50%, -120%)',
          }}
        >
          <div className="bg-slate-900/95 border border-slate-700 px-3 py-2 rounded-lg shadow-xl backdrop-blur-sm whitespace-nowrap">
            <div className="text-white font-medium text-sm">{memory.title}</div>
            <div className="flex items-center gap-2 mt-1 text-xs">
              <span
                className="px-1.5 py-0.5 rounded"
                style={{ backgroundColor: baseColor + '30', color: baseColor }}
              >
                {memory.category}
              </span>
              <span className="text-slate-400">
                {(memory.salience * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </Html>
      )}
    </group>
  );
}

// Memoize the component to prevent re-renders when other nodes change
export const MemoryNode = memo(MemoryNodeInner, (prev, next) => {
  return (
    prev.memory.id === next.memory.id &&
    prev.memory.salience === next.memory.salience &&
    prev.memory.category === next.memory.category &&
    prev.isSelected === next.isSelected &&
    prev.position[0] === next.position[0] &&
    prev.position[1] === next.position[1] &&
    prev.position[2] === next.position[2]
  );
});
