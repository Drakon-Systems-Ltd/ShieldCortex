'use client';

/**
 * Chip Substrate
 * The base silicon die with grid texture, borders, and corner pins
 */

import { useMemo, useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

interface ChipSubstrateProps {
  width?: number;
  height?: number;
  position?: [number, number, number];
}

// Shared geometries for performance
const PIN_GEOMETRY = new THREE.SphereGeometry(0.15, 8, 8);
const PIN_MATERIAL = new THREE.MeshStandardMaterial({
  color: '#9ca3af',
  metalness: 0.8,
  roughness: 0.2,
});

export function ChipSubstrate({
  width = 16,
  height = 12,
  position = [0, 0, 0],
}: ChipSubstrateProps) {
  const gridRef = useRef<THREE.LineSegments>(null);

  // Create substrate plane with grid texture
  const substrateMaterial = useMemo(() => {
    return new THREE.MeshStandardMaterial({
      color: '#1a1a2e',
      metalness: 0.1,
      roughness: 0.8,
      side: THREE.DoubleSide,
    });
  }, []);

  // Create grid lines
  const gridGeometry = useMemo(() => {
    const points: THREE.Vector3[] = [];
    const gridSpacing = 0.5;
    const halfWidth = width / 2;
    const halfHeight = height / 2;

    // Vertical lines
    for (let x = -halfWidth; x <= halfWidth; x += gridSpacing) {
      points.push(new THREE.Vector3(x, -halfHeight, 0.01));
      points.push(new THREE.Vector3(x, halfHeight, 0.01));
    }

    // Horizontal lines
    for (let y = -halfHeight; y <= halfHeight; y += gridSpacing) {
      points.push(new THREE.Vector3(-halfWidth, y, 0.01));
      points.push(new THREE.Vector3(halfWidth, y, 0.01));
    }

    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    return geometry;
  }, [width, height]);

  // Create border lines
  const borderGeometry = useMemo(() => {
    const halfWidth = width / 2;
    const halfHeight = height / 2;
    const inset = 0.3;

    const points = [
      // Outer border
      new THREE.Vector3(-halfWidth, -halfHeight, 0.02),
      new THREE.Vector3(halfWidth, -halfHeight, 0.02),
      new THREE.Vector3(halfWidth, -halfHeight, 0.02),
      new THREE.Vector3(halfWidth, halfHeight, 0.02),
      new THREE.Vector3(halfWidth, halfHeight, 0.02),
      new THREE.Vector3(-halfWidth, halfHeight, 0.02),
      new THREE.Vector3(-halfWidth, halfHeight, 0.02),
      new THREE.Vector3(-halfWidth, -halfHeight, 0.02),
      // Inner border (etched)
      new THREE.Vector3(-halfWidth + inset, -halfHeight + inset, 0.02),
      new THREE.Vector3(halfWidth - inset, -halfHeight + inset, 0.02),
      new THREE.Vector3(halfWidth - inset, -halfHeight + inset, 0.02),
      new THREE.Vector3(halfWidth - inset, halfHeight - inset, 0.02),
      new THREE.Vector3(halfWidth - inset, halfHeight - inset, 0.02),
      new THREE.Vector3(-halfWidth + inset, halfHeight - inset, 0.02),
      new THREE.Vector3(-halfWidth + inset, halfHeight - inset, 0.02),
      new THREE.Vector3(-halfWidth + inset, -halfHeight + inset, 0.02),
    ];

    return new THREE.BufferGeometry().setFromPoints(points);
  }, [width, height]);

  // Section divider positions (for STM, Episodic, LTM sections)
  const sectionDividers = useMemo(() => {
    const halfWidth = width / 2;
    const sectionHeight = height / 3;
    const halfHeight = height / 2;

    return [
      // Top divider (between STM and Episodic)
      {
        y: halfHeight - sectionHeight,
        points: [
          new THREE.Vector3(-halfWidth + 0.3, halfHeight - sectionHeight, 0.02),
          new THREE.Vector3(halfWidth - 0.3, halfHeight - sectionHeight, 0.02),
        ],
      },
      // Bottom divider (between Episodic and LTM)
      {
        y: -halfHeight + sectionHeight,
        points: [
          new THREE.Vector3(-halfWidth + 0.3, -halfHeight + sectionHeight, 0.02),
          new THREE.Vector3(halfWidth - 0.3, -halfHeight + sectionHeight, 0.02),
        ],
      },
    ];
  }, [width, height]);

  // Corner pin positions
  const pinPositions = useMemo(() => {
    const halfWidth = width / 2;
    const halfHeight = height / 2;
    const offset = 0.5;

    return [
      [-halfWidth + offset, halfHeight - offset, 0.1],
      [halfWidth - offset, halfHeight - offset, 0.1],
      [-halfWidth + offset, -halfHeight + offset, 0.1],
      [halfWidth - offset, -halfHeight + offset, 0.1],
    ] as [number, number, number][];
  }, [width, height]);

  // Subtle grid pulse animation
  useFrame((state) => {
    if (gridRef.current) {
      const material = gridRef.current.material as THREE.LineBasicMaterial;
      material.opacity = 0.08 + Math.sin(state.clock.elapsedTime * 0.5) * 0.02;
    }
  });

  return (
    <group position={position}>
      {/* Main substrate plane */}
      <mesh rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[width, height]} />
        <primitive object={substrateMaterial} />
      </mesh>

      {/* Grid overlay */}
      <lineSegments ref={gridRef} rotation={[-Math.PI / 2, 0, 0]}>
        <primitive object={gridGeometry} />
        <lineBasicMaterial color="#2d3748" opacity={0.1} transparent />
      </lineSegments>

      {/* Border lines */}
      <lineSegments rotation={[-Math.PI / 2, 0, 0]}>
        <primitive object={borderGeometry} />
        <lineBasicMaterial color="#4a5568" linewidth={2} />
      </lineSegments>

      {/* Section dividers */}
      {sectionDividers.map((divider, i) => (
        <lineSegments key={i} rotation={[-Math.PI / 2, 0, 0]}>
          <bufferGeometry>
            <primitive
              object={
                new THREE.BufferAttribute(
                  new Float32Array(divider.points.flatMap((p) => [p.x, p.y, p.z])),
                  3
                )
              }
              attach="attributes-position"
            />
          </bufferGeometry>
          <lineBasicMaterial color="#4a5568" opacity={0.6} transparent />
        </lineSegments>
      ))}

      {/* Corner pins */}
      {pinPositions.map((pos, i) => (
        <mesh key={i} position={pos} geometry={PIN_GEOMETRY} material={PIN_MATERIAL} />
      ))}

      {/* Decorative edge traces */}
      <EdgeTraces width={width} height={height} />
    </group>
  );
}

// Decorative circuit traces along edges
function EdgeTraces({ width, height }: { width: number; height: number }) {
  const traces = useMemo(() => {
    const halfWidth = width / 2;
    const halfHeight = height / 2;
    const traceLength = 1.5;
    const points: THREE.Vector3[] = [];

    // Top edge traces
    for (let i = 0; i < 6; i++) {
      const x = -halfWidth + 2 + i * 2;
      points.push(new THREE.Vector3(x, halfHeight - 0.1, 0.02));
      points.push(new THREE.Vector3(x, halfHeight - 0.1 - traceLength * 0.3, 0.02));
    }

    // Bottom edge traces
    for (let i = 0; i < 6; i++) {
      const x = -halfWidth + 2 + i * 2;
      points.push(new THREE.Vector3(x, -halfHeight + 0.1, 0.02));
      points.push(new THREE.Vector3(x, -halfHeight + 0.1 + traceLength * 0.3, 0.02));
    }

    // Left edge traces
    for (let i = 0; i < 4; i++) {
      const y = -halfHeight + 2 + i * 2.5;
      points.push(new THREE.Vector3(-halfWidth + 0.1, y, 0.02));
      points.push(new THREE.Vector3(-halfWidth + 0.1 + traceLength * 0.3, y, 0.02));
    }

    // Right edge traces
    for (let i = 0; i < 4; i++) {
      const y = -halfHeight + 2 + i * 2.5;
      points.push(new THREE.Vector3(halfWidth - 0.1, y, 0.02));
      points.push(new THREE.Vector3(halfWidth - 0.1 - traceLength * 0.3, y, 0.02));
    }

    return new THREE.BufferGeometry().setFromPoints(points);
  }, [width, height]);

  return (
    <lineSegments rotation={[-Math.PI / 2, 0, 0]}>
      <primitive object={traces} />
      <lineBasicMaterial color="#FFB347" opacity={0.3} transparent />
    </lineSegments>
  );
}
