'use client';

/**
 * Memory Cell
 * Standard rectangular memory node for the chip grid
 * Color-coded by category with glow based on salience
 */

import { useRef, useMemo, useState, useCallback } from 'react';
import { useFrame, ThreeEvent } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import * as THREE from 'three';
import { Memory, MemoryCategory } from '@/types/memory';

// Category color mapping
const CATEGORY_COLORS: Record<MemoryCategory, string> = {
  architecture: '#06b6d4', // cyan
  pattern: '#22c55e', // green
  preference: '#eab308', // yellow
  error: '#ef4444', // red
  context: '#f97316', // orange
  learning: '#84cc16', // lime
  todo: '#a855f7', // purple
  note: '#3b82f6', // blue
  relationship: '#6366f1', // indigo
  custom: '#ec4899', // pink
};

interface MemoryCellProps {
  memory: Memory;
  position: [number, number, number];
  onSelect?: (memory: Memory | null) => void;
  isSelected?: boolean;
  size?: number;
}

// Shared geometry for performance
const CELL_GEOMETRY = new THREE.BoxGeometry(0.8, 0.5, 0.15);

export function MemoryCell({
  memory,
  position,
  onSelect,
  isSelected = false,
  size = 1,
}: MemoryCellProps) {
  const meshRef = useRef<THREE.Mesh>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const [isHovered, setIsHovered] = useState(false);

  const color = CATEGORY_COLORS[memory.category] || CATEGORY_COLORS.custom;

  // Main material
  const material = useMemo(() => {
    return new THREE.MeshStandardMaterial({
      color: color,
      emissive: color,
      emissiveIntensity: 0.3 + memory.salience * 0.4,
      metalness: 0.2,
      roughness: 0.6,
    });
  }, [color, memory.salience]);

  // Glow material
  const glowMaterial = useMemo(() => {
    return new THREE.MeshBasicMaterial({
      color: color,
      transparent: true,
      opacity: 0.15 + memory.salience * 0.2,
      side: THREE.BackSide,
    });
  }, [color, memory.salience]);

  // Selection ring material
  const selectionMaterial = useMemo(() => {
    return new THREE.MeshBasicMaterial({
      color: '#ffffff',
      transparent: true,
      opacity: 0.8,
      side: THREE.DoubleSide,
    });
  }, []);

  // Animate pulse
  useFrame((state) => {
    if (!meshRef.current) return;

    const time = state.clock.elapsedTime;
    const mat = meshRef.current.material as THREE.MeshStandardMaterial;

    // Base pulse based on salience (higher salience = faster pulse)
    const pulseSpeed = 1 + memory.salience * 2;
    const pulse = Math.sin(time * pulseSpeed) * 0.5 + 0.5;

    // Adjust emissive intensity
    mat.emissiveIntensity = 0.2 + memory.salience * 0.3 + pulse * 0.15;

    // Hover effect
    if (isHovered || isSelected) {
      mat.emissiveIntensity += 0.3;
    }

    // Glow pulse
    if (glowRef.current) {
      const glowMat = glowRef.current.material as THREE.MeshBasicMaterial;
      glowMat.opacity = 0.1 + pulse * 0.1 + memory.salience * 0.15;
      if (isHovered || isSelected) {
        glowMat.opacity += 0.15;
      }
    }
  });

  const handleClick = useCallback(
    (e: ThreeEvent<MouseEvent>) => {
      e.stopPropagation();
      onSelect?.(isSelected ? null : memory);
    },
    [memory, onSelect, isSelected]
  );

  const handlePointerOver = useCallback((e: ThreeEvent<PointerEvent>) => {
    e.stopPropagation();
    setIsHovered(true);
    document.body.style.cursor = 'pointer';
  }, []);

  const handlePointerOut = useCallback(() => {
    setIsHovered(false);
    document.body.style.cursor = 'auto';
  }, []);

  return (
    <group position={position} scale={size}>
      {/* Main cell */}
      <mesh
        ref={meshRef}
        geometry={CELL_GEOMETRY}
        material={material}
        onClick={handleClick}
        onPointerOver={handlePointerOver}
        onPointerOut={handlePointerOut}
      />

      {/* Glow layer */}
      <mesh ref={glowRef} scale={1.15}>
        <boxGeometry args={[0.85, 0.55, 0.2]} />
        <primitive object={glowMaterial} />
      </mesh>

      {/* Selection indicator */}
      {isSelected && (
        <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0, 0.1]}>
          <ringGeometry args={[0.5, 0.55, 4]} />
          <primitive object={selectionMaterial} />
        </mesh>
      )}

      {/* Tooltip on hover */}
      {isHovered && (
        <Html
          position={[0, 0.5, 0]}
          center
          style={{
            pointerEvents: 'none',
            transform: 'translateY(-100%)',
          }}
        >
          <div className="bg-slate-900/95 border border-slate-600 rounded-lg px-3 py-2 text-xs max-w-[200px] backdrop-blur-sm shadow-lg">
            <div className="font-semibold text-white truncate">{memory.title}</div>
            <div className="text-slate-400 mt-1 flex items-center gap-2">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="capitalize">{memory.category}</span>
              <span className="text-slate-500">|</span>
              <span>{Math.round(memory.salience * 100)}%</span>
            </div>
          </div>
        </Html>
      )}
    </group>
  );
}

// Flash effect when memory is accessed
export function MemoryCellFlash({
  position,
  color,
  onComplete,
}: {
  position: [number, number, number];
  color: string;
  onComplete: () => void;
}) {
  const meshRef = useRef<THREE.Mesh>(null);
  const startTime = useRef(Date.now());

  useFrame(() => {
    if (!meshRef.current) return;

    const elapsed = Date.now() - startTime.current;
    const duration = 400;
    const progress = elapsed / duration;

    if (progress >= 1) {
      onComplete();
      return;
    }

    // Expand and fade
    const scale = 1 + progress * 0.5;
    meshRef.current.scale.setScalar(scale);

    const mat = meshRef.current.material as THREE.MeshBasicMaterial;
    mat.opacity = 0.8 * (1 - progress);
  });

  return (
    <mesh ref={meshRef} position={position}>
      <boxGeometry args={[0.9, 0.6, 0.2]} />
      <meshBasicMaterial color={color} transparent opacity={0.8} />
    </mesh>
  );
}
