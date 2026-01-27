'use client';

/**
 * Quantum Cell
 * High-salience memories rendered as rotating Bloch spheres
 * Represents "quantum" memories with special visual treatment
 */

import { useRef, useMemo, useState, useCallback } from 'react';
import { useFrame, ThreeEvent } from '@react-three/fiber';
import { Html } from '@react-three/drei';
import * as THREE from 'three';
import { Memory, MemoryCategory } from '@/types/memory';

// Category color mapping (same as MemoryCell)
const CATEGORY_COLORS: Record<MemoryCategory, string> = {
  architecture: '#06b6d4',
  pattern: '#22c55e',
  preference: '#eab308',
  error: '#ef4444',
  context: '#f97316',
  learning: '#84cc16',
  todo: '#a855f7',
  note: '#3b82f6',
  relationship: '#6366f1',
  custom: '#ec4899',
};

// Category angles for state vector direction (in radians)
const CATEGORY_ANGLES: Record<MemoryCategory, number> = {
  architecture: 0,
  pattern: Math.PI / 5,
  preference: (2 * Math.PI) / 5,
  error: (3 * Math.PI) / 5,
  context: (4 * Math.PI) / 5,
  learning: Math.PI,
  todo: (6 * Math.PI) / 5,
  note: (7 * Math.PI) / 5,
  relationship: (8 * Math.PI) / 5,
  custom: (9 * Math.PI) / 5,
};

interface QuantumCellProps {
  memory: Memory;
  position: [number, number, number];
  onSelect?: (memory: Memory | null) => void;
  isSelected?: boolean;
  size?: number;
}

export function QuantumCell({
  memory,
  position,
  onSelect,
  isSelected = false,
  size = 1,
}: QuantumCellProps) {
  const groupRef = useRef<THREE.Group>(null);
  const sphereRef = useRef<THREE.LineSegments>(null);
  const arrowRef = useRef<THREE.Group>(null);
  const glowRef = useRef<THREE.Mesh>(null);
  const interferenceRef = useRef<THREE.Points>(null);
  const [isHovered, setIsHovered] = useState(false);

  const color = CATEGORY_COLORS[memory.category] || CATEGORY_COLORS.custom;
  const stateAngle = CATEGORY_ANGLES[memory.category] || 0;

  // Sphere wireframe geometry
  const sphereGeometry = useMemo(() => {
    const sphere = new THREE.SphereGeometry(0.4, 16, 12);
    return new THREE.EdgesGeometry(sphere);
  }, []);

  // Wireframe material
  const wireMaterial = useMemo(() => {
    return new THREE.LineBasicMaterial({
      color: color,
      transparent: true,
      opacity: 0.6,
    });
  }, [color]);

  // Glow sphere material
  const glowMaterial = useMemo(() => {
    return new THREE.MeshBasicMaterial({
      color: color,
      transparent: true,
      opacity: 0.15,
      side: THREE.BackSide,
    });
  }, [color]);

  // Interference pattern particles
  const interferenceGeometry = useMemo(() => {
    const positions = new Float32Array(60 * 3);
    for (let i = 0; i < 60; i++) {
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      const r = 0.35 + Math.random() * 0.1;
      positions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      positions[i * 3 + 2] = r * Math.cos(phi);
    }
    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    return geometry;
  }, []);

  // Animate rotation and effects
  useFrame((state) => {
    if (!groupRef.current) return;

    const time = state.clock.elapsedTime;
    const rotationSpeed = 0.3 + memory.salience * 0.3;

    // Continuous rotation
    groupRef.current.rotation.y = time * rotationSpeed;
    groupRef.current.rotation.x = Math.sin(time * 0.5) * 0.1;

    // Hover/select: speed up rotation
    if (isHovered || isSelected) {
      groupRef.current.rotation.y = time * rotationSpeed * 2;
    }

    // Wireframe pulse
    if (sphereRef.current) {
      const mat = sphereRef.current.material as THREE.LineBasicMaterial;
      const pulse = Math.sin(time * 2) * 0.5 + 0.5;
      mat.opacity = 0.4 + pulse * 0.3 + memory.salience * 0.2;
      if (isHovered || isSelected) {
        mat.opacity += 0.2;
      }
    }

    // Glow pulse
    if (glowRef.current) {
      const mat = glowRef.current.material as THREE.MeshBasicMaterial;
      const pulse = Math.sin(time * 1.5) * 0.5 + 0.5;
      mat.opacity = 0.1 + pulse * 0.15;
      glowRef.current.scale.setScalar(1.2 + pulse * 0.1);
    }

    // Interference shimmer
    if (interferenceRef.current) {
      const positions = interferenceRef.current.geometry.attributes.position.array as Float32Array;
      for (let i = 0; i < positions.length / 3; i++) {
        const idx = i * 3;
        const shimmer = Math.sin(time * 3 + i * 0.5) * 0.02;
        // Just modify radius slightly for shimmer effect
        const x = positions[idx];
        const y = positions[idx + 1];
        const z = positions[idx + 2];
        const r = Math.sqrt(x * x + y * y + z * z);
        const newR = 0.38 + shimmer;
        const scale = newR / r;
        positions[idx] = x * scale;
        positions[idx + 1] = y * scale;
        positions[idx + 2] = z * scale;
      }
      interferenceRef.current.geometry.attributes.position.needsUpdate = true;
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
      <group
        ref={groupRef}
        onClick={handleClick}
        onPointerOver={handlePointerOver}
        onPointerOut={handlePointerOut}
      >
        {/* Wireframe Bloch sphere */}
        <lineSegments ref={sphereRef} geometry={sphereGeometry} material={wireMaterial} />

        {/* Axis lines */}
        <AxisLines color={color} />

        {/* State vector arrow */}
        <group ref={arrowRef} rotation={[0, stateAngle, Math.PI / 4]}>
          <StateVector color={color} />
        </group>

        {/* Glow sphere */}
        <mesh ref={glowRef}>
          <sphereGeometry args={[0.5, 12, 8]} />
          <primitive object={glowMaterial} />
        </mesh>

        {/* Interference pattern particles */}
        <points ref={interferenceRef} geometry={interferenceGeometry}>
          <pointsMaterial
            color={color}
            size={0.03}
            transparent
            opacity={0.4}
            sizeAttenuation
          />
        </points>

        {/* Clickable invisible sphere */}
        <mesh visible={false}>
          <sphereGeometry args={[0.5, 8, 6]} />
          <meshBasicMaterial transparent opacity={0} />
        </mesh>
      </group>

      {/* Selection ring */}
      {isSelected && (
        <mesh rotation={[Math.PI / 2, 0, 0]} position={[0, 0, 0]}>
          <ringGeometry args={[0.55, 0.6, 32]} />
          <meshBasicMaterial color="#ffffff" transparent opacity={0.7} side={THREE.DoubleSide} />
        </mesh>
      )}

      {/* Quantum label */}
      <Html
        position={[0, -0.6, 0]}
        center
        style={{ pointerEvents: 'none' }}
      >
        <div className="text-[8px] font-mono text-amber-400/60 whitespace-nowrap">
          |Q{memory.id}⟩
        </div>
      </Html>

      {/* Tooltip on hover */}
      {isHovered && (
        <Html
          position={[0, 0.7, 0]}
          center
          style={{
            pointerEvents: 'none',
            transform: 'translateY(-100%)',
          }}
        >
          <div className="bg-slate-900/95 border border-amber-600/50 rounded-lg px-3 py-2 text-xs max-w-[220px] backdrop-blur-sm shadow-lg">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-amber-400 text-[10px]">QUANTUM</span>
              <span className="text-slate-500">|</span>
              <span className="text-slate-400">{Math.round(memory.salience * 100)}% salience</span>
            </div>
            <div className="font-semibold text-white truncate">{memory.title}</div>
            <div className="text-slate-400 mt-1 flex items-center gap-2">
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="capitalize">{memory.category}</span>
            </div>
          </div>
        </Html>
      )}
    </group>
  );
}

// Axis lines (x, y, z) inside the Bloch sphere
function AxisLines({ color }: { color: string }) {
  const geometry = useMemo(() => {
    const points = [
      // X axis
      new THREE.Vector3(-0.35, 0, 0),
      new THREE.Vector3(0.35, 0, 0),
      // Y axis
      new THREE.Vector3(0, -0.35, 0),
      new THREE.Vector3(0, 0.35, 0),
      // Z axis
      new THREE.Vector3(0, 0, -0.35),
      new THREE.Vector3(0, 0, 0.35),
    ];
    return new THREE.BufferGeometry().setFromPoints(points);
  }, []);

  return (
    <lineSegments geometry={geometry}>
      <lineBasicMaterial color={color} transparent opacity={0.3} />
    </lineSegments>
  );
}

// State vector arrow pointing in a direction
function StateVector({ color }: { color: string }) {
  return (
    <group>
      {/* Arrow shaft */}
      <mesh position={[0, 0.15, 0]}>
        <cylinderGeometry args={[0.02, 0.02, 0.3, 8]} />
        <meshBasicMaterial color={color} />
      </mesh>
      {/* Arrow head */}
      <mesh position={[0, 0.32, 0]}>
        <coneGeometry args={[0.05, 0.1, 8]} />
        <meshBasicMaterial color={color} />
      </mesh>
    </group>
  );
}
