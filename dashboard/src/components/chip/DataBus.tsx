'use client';

/**
 * Data Bus
 * Trace lines connecting the Cortex Core to memory banks
 * Supports pulse animations for access events
 */

import { useMemo, useRef } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

interface DataBusProps {
  chipWidth?: number;
  chipHeight?: number;
  coreWidth?: number;
  coreHeight?: number;
}

interface BusLineProps {
  start: [number, number, number];
  end: [number, number, number];
  color?: string;
}

// Single bus trace line
function BusLine({ start, end, color = '#FFB347' }: BusLineProps) {
  const geometry = useMemo(() => {
    const points = [new THREE.Vector3(...start), new THREE.Vector3(...end)];
    return new THREE.BufferGeometry().setFromPoints(points);
  }, [start, end]);

  return (
    <line>
      <primitive object={geometry} />
      <lineBasicMaterial color={color} opacity={0.6} transparent linewidth={2} />
    </line>
  );
}

// Branching bus traces (main trunk + branches)
function BusBranch({
  trunk,
  branches,
  color = '#FFB347',
}: {
  trunk: { start: [number, number, number]; end: [number, number, number] };
  branches: { start: [number, number, number]; end: [number, number, number] }[];
  color?: string;
}) {
  return (
    <group>
      <BusLine start={trunk.start} end={trunk.end} color={color} />
      {branches.map((branch, i) => (
        <BusLine key={i} start={branch.start} end={branch.end} color={color} />
      ))}
    </group>
  );
}

export function DataBus({
  chipWidth = 16,
  chipHeight = 12,
  coreWidth = 2,
  coreHeight = 1.2,
}: DataBusProps) {
  const sectionHeight = chipHeight / 3;
  const halfChipHeight = chipHeight / 2;
  const halfCoreHeight = coreHeight / 2;
  const halfCoreWidth = coreWidth / 2;

  // Z position for all traces (slightly above substrate)
  const z = 0.05;

  // Generate bus traces
  const busTraces = useMemo(() => {
    // Main vertical trunk to STM (top)
    const stmTrunk = {
      start: [0, halfCoreHeight + 0.1, z] as [number, number, number],
      end: [0, halfChipHeight - sectionHeight * 0.3, z] as [number, number, number],
    };

    // Branches to STM grid columns
    const stmBranches: { start: [number, number, number]; end: [number, number, number] }[] = [];
    const branchY = halfChipHeight - sectionHeight * 0.5;
    for (let i = -3; i <= 3; i++) {
      if (i !== 0) {
        const x = i * 1.5;
        stmBranches.push({
          start: [0, branchY, z],
          end: [x, branchY, z],
        });
        // Vertical segment to grid
        stmBranches.push({
          start: [x, branchY, z],
          end: [x, halfChipHeight - sectionHeight * 0.2, z],
        });
      }
    }

    // Main vertical trunk to LTM (bottom)
    const ltmTrunk = {
      start: [0, -halfCoreHeight - 0.1, z] as [number, number, number],
      end: [0, -halfChipHeight + sectionHeight * 0.3, z] as [number, number, number],
    };

    // Branches to LTM grid columns
    const ltmBranches: { start: [number, number, number]; end: [number, number, number] }[] = [];
    const ltmBranchY = -halfChipHeight + sectionHeight * 0.5;
    for (let i = -3; i <= 3; i++) {
      if (i !== 0) {
        const x = i * 1.5;
        ltmBranches.push({
          start: [0, ltmBranchY, z],
          end: [x, ltmBranchY, z],
        });
        // Vertical segment to grid
        ltmBranches.push({
          start: [x, ltmBranchY, z],
          end: [x, -halfChipHeight + sectionHeight * 0.2, z],
        });
      }
    }

    // Horizontal traces to Episodic (left)
    const episodicLeftTrunk = {
      start: [-halfCoreWidth - 0.1, 0, z] as [number, number, number],
      end: [-chipWidth / 2 + 1.5, 0, z] as [number, number, number],
    };

    const episodicLeftBranches: { start: [number, number, number]; end: [number, number, number] }[] = [];
    for (let i = 0; i < 3; i++) {
      const x = -halfCoreWidth - 1 - i * 1.5;
      episodicLeftBranches.push({
        start: [x, 0, z],
        end: [x, sectionHeight * 0.3, z],
      });
      episodicLeftBranches.push({
        start: [x, 0, z],
        end: [x, -sectionHeight * 0.3, z],
      });
    }

    // Horizontal traces to Episodic (right)
    const episodicRightTrunk = {
      start: [halfCoreWidth + 0.1, 0, z] as [number, number, number],
      end: [chipWidth / 2 - 1.5, 0, z] as [number, number, number],
    };

    const episodicRightBranches: { start: [number, number, number]; end: [number, number, number] }[] = [];
    for (let i = 0; i < 3; i++) {
      const x = halfCoreWidth + 1 + i * 1.5;
      episodicRightBranches.push({
        start: [x, 0, z],
        end: [x, sectionHeight * 0.3, z],
      });
      episodicRightBranches.push({
        start: [x, 0, z],
        end: [x, -sectionHeight * 0.3, z],
      });
    }

    return {
      stm: { trunk: stmTrunk, branches: stmBranches },
      ltm: { trunk: ltmTrunk, branches: ltmBranches },
      episodicLeft: { trunk: episodicLeftTrunk, branches: episodicLeftBranches },
      episodicRight: { trunk: episodicRightTrunk, branches: episodicRightBranches },
    };
  }, [chipWidth, chipHeight, halfChipHeight, halfCoreHeight, halfCoreWidth, sectionHeight]);

  return (
    <group>
      {/* STM bus (top) */}
      <BusBranch trunk={busTraces.stm.trunk} branches={busTraces.stm.branches} color="#FFB347" />

      {/* LTM bus (bottom) */}
      <BusBranch trunk={busTraces.ltm.trunk} branches={busTraces.ltm.branches} color="#FFB347" />

      {/* Episodic bus (left) */}
      <BusBranch trunk={busTraces.episodicLeft.trunk} branches={busTraces.episodicLeft.branches} color="#FFB347" />

      {/* Episodic bus (right) */}
      <BusBranch trunk={busTraces.episodicRight.trunk} branches={busTraces.episodicRight.branches} color="#FFB347" />

      {/* Junction nodes at branch points */}
      <JunctionNodes chipWidth={chipWidth} chipHeight={chipHeight} coreWidth={coreWidth} />
    </group>
  );
}

// Small glowing nodes at bus junctions
function JunctionNodes({
  chipWidth,
  chipHeight,
  coreWidth,
}: {
  chipWidth: number;
  chipHeight: number;
  coreWidth: number;
}) {
  const nodesRef = useRef<THREE.InstancedMesh>(null);
  const nodeGeometry = useMemo(() => new THREE.CircleGeometry(0.06, 8), []);
  const nodeMaterial = useMemo(
    () =>
      new THREE.MeshBasicMaterial({
        color: '#FFD700',
        transparent: true,
        opacity: 0.8,
      }),
    []
  );

  const positions = useMemo(() => {
    const sectionHeight = chipHeight / 3;
    const halfChipHeight = chipHeight / 2;
    const halfCoreWidth = coreWidth / 2;
    const z = 0.06;

    const nodes: [number, number, number][] = [
      // Core connection points
      [0, halfCoreWidth * 0.6 + 0.1, z],
      [0, -halfCoreWidth * 0.6 - 0.1, z],
      [-halfCoreWidth - 0.1, 0, z],
      [halfCoreWidth + 0.1, 0, z],
    ];

    // STM branch junctions
    const stmBranchY = halfChipHeight - sectionHeight * 0.5;
    for (let i = -3; i <= 3; i++) {
      if (i !== 0) {
        nodes.push([i * 1.5, stmBranchY, z]);
      }
    }

    // LTM branch junctions
    const ltmBranchY = -halfChipHeight + sectionHeight * 0.5;
    for (let i = -3; i <= 3; i++) {
      if (i !== 0) {
        nodes.push([i * 1.5, ltmBranchY, z]);
      }
    }

    // Episodic branch junctions
    for (let i = 0; i < 3; i++) {
      nodes.push([-halfCoreWidth - 1 - i * 1.5, 0, z]);
      nodes.push([halfCoreWidth + 1 + i * 1.5, 0, z]);
    }

    return nodes;
  }, [chipHeight, coreWidth]);

  // Animate junction glow
  useFrame((state) => {
    if (nodesRef.current) {
      const material = nodesRef.current.material as THREE.MeshBasicMaterial;
      const pulse = Math.sin(state.clock.elapsedTime * 3) * 0.5 + 0.5;
      material.opacity = 0.5 + pulse * 0.3;
    }
  });

  return (
    <instancedMesh
      ref={nodesRef}
      args={[nodeGeometry, nodeMaterial, positions.length]}
    >
      {positions.map((pos, i) => {
        const matrix = new THREE.Matrix4().setPosition(...pos);
        nodesRef.current?.setMatrixAt(i, matrix);
        return null;
      })}
    </instancedMesh>
  );
}

// Pulse that travels along the data bus
export interface AccessPulseData {
  id: number;
  memoryId: number;
  section: 'stm' | 'episodic' | 'ltm';
  gridPosition: [number, number]; // Column, row in grid
  color: string;
  startTime: number;
}

interface DataBusPulseProps {
  pulse: AccessPulseData;
  chipWidth: number;
  chipHeight: number;
  onComplete: (id: number) => void;
}

export function DataBusPulse({
  pulse,
  chipWidth,
  chipHeight,
  onComplete,
}: DataBusPulseProps) {
  const pulseRef = useRef<THREE.Mesh>(null);
  const trailRef = useRef<THREE.Mesh>(null);
  const startTimeRef = useRef(pulse.startTime);

  const sectionHeight = chipHeight / 3;
  const halfChipHeight = chipHeight / 2;

  // Calculate path based on section
  const path = useMemo(() => {
    const z = 0.1;
    const [col] = pulse.gridPosition;
    const targetX = (col - 3) * 1.5; // Map grid column to x position

    let targetY: number;
    let midY: number;

    switch (pulse.section) {
      case 'stm':
        targetY = halfChipHeight - sectionHeight * 0.3;
        midY = halfChipHeight - sectionHeight * 0.5;
        return [
          [0, 0, z], // Start at core
          [0, midY, z], // Up the trunk
          [targetX, midY, z], // Along branch
          [targetX, targetY, z], // To memory
        ];
      case 'ltm':
        targetY = -halfChipHeight + sectionHeight * 0.3;
        midY = -halfChipHeight + sectionHeight * 0.5;
        return [
          [0, 0, z],
          [0, midY, z],
          [targetX, midY, z],
          [targetX, targetY, z],
        ];
      case 'episodic':
      default:
        const side = col < 3 ? -1 : 1;
        targetX;
        return [
          [0, 0, z],
          [side * (Math.abs(targetX) + 1), 0, z],
          [side * (Math.abs(targetX) + 1), pulse.gridPosition[1] * 0.8, z],
        ];
    }
  }, [pulse, halfChipHeight, sectionHeight]);

  const duration = 500; // ms

  useFrame(() => {
    if (!pulseRef.current) return;

    const elapsed = Date.now() - startTimeRef.current;
    const progress = Math.min(elapsed / duration, 1);

    if (progress >= 1) {
      onComplete(pulse.id);
      return;
    }

    // Interpolate position along path
    const totalSegments = path.length - 1;
    const segmentProgress = progress * totalSegments;
    const segmentIndex = Math.floor(segmentProgress);
    const segmentT = segmentProgress - segmentIndex;

    const currentIdx = Math.min(segmentIndex, totalSegments - 1);
    const start = path[currentIdx];
    const end = path[Math.min(currentIdx + 1, path.length - 1)];

    pulseRef.current.position.set(
      start[0] + (end[0] - start[0]) * segmentT,
      start[1] + (end[1] - start[1]) * segmentT,
      start[2] + (end[2] - start[2]) * segmentT
    );

    // Scale down as it travels
    const scale = 1 - progress * 0.3;
    pulseRef.current.scale.setScalar(scale);

    // Trail follows slightly behind
    if (trailRef.current && progress > 0.1) {
      const trailProgress = Math.max(0, progress - 0.1);
      const trailSegmentProgress = trailProgress * totalSegments;
      const trailSegmentIndex = Math.floor(trailSegmentProgress);
      const trailSegmentT = trailSegmentProgress - trailSegmentIndex;

      const trailIdx = Math.min(trailSegmentIndex, totalSegments - 1);
      const trailStart = path[trailIdx];
      const trailEnd = path[Math.min(trailIdx + 1, path.length - 1)];

      trailRef.current.position.set(
        trailStart[0] + (trailEnd[0] - trailStart[0]) * trailSegmentT,
        trailStart[1] + (trailEnd[1] - trailStart[1]) * trailSegmentT,
        trailStart[2] + (trailEnd[2] - trailStart[2]) * trailSegmentT
      );
      trailRef.current.scale.setScalar(scale * 0.6);

      const trailMaterial = trailRef.current.material as THREE.MeshBasicMaterial;
      trailMaterial.opacity = 0.4 * (1 - progress);
    }
  });

  return (
    <group>
      {/* Main pulse */}
      <mesh ref={pulseRef} position={[0, 0, 0.1]}>
        <circleGeometry args={[0.12, 16]} />
        <meshBasicMaterial color={pulse.color} transparent opacity={0.9} />
      </mesh>

      {/* Trail */}
      <mesh ref={trailRef} position={[0, 0, 0.1]}>
        <circleGeometry args={[0.08, 12]} />
        <meshBasicMaterial color={pulse.color} transparent opacity={0.4} />
      </mesh>
    </group>
  );
}
