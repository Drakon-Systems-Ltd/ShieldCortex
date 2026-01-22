'use client';

/**
 * Memory Node
 * Individual memory rendered as a glowing neuron in 3D space
 */

import { useRef, useState, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
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

export function MemoryNode({
  memory,
  position,
  onSelect,
  isSelected,
}: MemoryNodeProps) {
  const meshRef = useRef<THREE.Mesh>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const [hovered, setHovered] = useState(false);

  // Calculate visual properties
  const decayFactor = useMemo(() => calculateDecayFactor(memory), [memory]);
  const baseColor = useMemo(() => getCategoryColor(memory.category), [memory.category]);

  // Node size based on salience (0.15 to 0.4)
  const size = 0.15 + memory.salience * 0.25;

  // Glow intensity based on decay
  const glowIntensity = memory.salience * decayFactor;

  // Animation
  useFrame((state) => {
    if (meshRef.current) {
      // Breathing animation - faster for higher salience
      const pulseSpeed = 0.5 + memory.salience * 1.5;
      const pulse = Math.sin(state.clock.elapsedTime * pulseSpeed) * 0.08;
      meshRef.current.scale.setScalar(1 + pulse * glowIntensity);
    }

    if (glowRef.current) {
      // Glow pulsing
      const glowPulse = Math.sin(state.clock.elapsedTime * 0.8) * 0.3 + 0.7;
      glowRef.current.scale.setScalar(1.8 + glowPulse * 0.3);
      (glowRef.current.material as THREE.MeshBasicMaterial).opacity =
        glowIntensity * 0.3 * glowPulse;
    }
  });

  return (
    <group position={position}>
      {/* Outer glow */}
      <mesh ref={glowRef}>
        <sphereGeometry args={[size * 1.8, 16, 16]} />
        <meshBasicMaterial
          color={baseColor}
          transparent
          opacity={glowIntensity * 0.2}
          depthWrite={false}
        />
      </mesh>

      {/* Main node */}
      <mesh
        ref={meshRef}
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
      >
        <sphereGeometry args={[size, 24, 24]} />
        <meshStandardMaterial
          color={baseColor}
          emissive={baseColor}
          emissiveIntensity={glowIntensity * (hovered ? 1.5 : 1)}
          metalness={0.3}
          roughness={0.4}
          transparent
          opacity={0.7 + decayFactor * 0.3}
        />
      </mesh>

      {/* Selection ring */}
      {isSelected && (
        <mesh rotation={[Math.PI / 2, 0, 0]}>
          <ringGeometry args={[size + 0.15, size + 0.22, 32]} />
          <meshBasicMaterial
            color="#ffffff"
            transparent
            opacity={0.9}
            side={THREE.DoubleSide}
          />
        </mesh>
      )}

      {/* Hover tooltip */}
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
