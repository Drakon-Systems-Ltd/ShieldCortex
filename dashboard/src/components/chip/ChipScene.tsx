'use client';

/**
 * Chip Scene - Circuit Board Style
 * Clean top-down orthographic view of memory as a PCB
 */

import { Suspense, useMemo, useState, useCallback, useRef } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrthographicCamera } from '@react-three/drei';
import { EffectComposer, Bloom } from '@react-three/postprocessing';
import { Memory, MemoryLink } from '@/types/memory';
import { useMemoryWebSocket } from '@/lib/websocket';
import * as THREE from 'three';

// Layout constants
const CHIP_WIDTH = 24;
const CHIP_HEIGHT = 16;
const NODE_SPACING = 1.2;
const SECTION_GAP = 2;

// Category colors
const CATEGORY_COLORS: Record<string, string> = {
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

interface ChipSceneProps {
  memories: Memory[];
  links?: MemoryLink[];
  selectedMemory: Memory | null;
  onSelectMemory: (memory: Memory | null) => void;
}

export function ChipScene({
  memories = [],
  links = [],
  selectedMemory,
  onSelectMemory,
}: ChipSceneProps) {
  const [hoveredMemory, setHoveredMemory] = useState<Memory | null>(null);

  // Group memories by type
  const groupedMemories = useMemo(() => {
    const stm = memories.filter((m) => m.type === 'short_term');
    const episodic = memories.filter((m) => m.type === 'episodic');
    const ltm = memories.filter((m) => m.type === 'long_term');
    return { stm, episodic, ltm };
  }, [memories]);

  return (
    <div className="w-full h-full bg-[#0a0a12]">
      <Canvas
        orthographic
        camera={{ zoom: 40, position: [0, 0, 100], near: 0.1, far: 1000 }}
        gl={{ antialias: true }}
        onClick={() => onSelectMemory(null)}
      >
        <Suspense fallback={null}>
          <ChipContent
            memories={memories}
            groupedMemories={groupedMemories}
            links={links}
            selectedMemory={selectedMemory}
            hoveredMemory={hoveredMemory}
            onSelectMemory={onSelectMemory}
            onHoverMemory={setHoveredMemory}
          />
        </Suspense>
      </Canvas>

      {/* Hover tooltip */}
      {hoveredMemory && (
        <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-slate-900/95 border border-slate-600 rounded-lg px-4 py-2 text-sm backdrop-blur-sm pointer-events-none z-50">
          <div className="font-semibold text-white">{hoveredMemory.title}</div>
          <div className="text-slate-400 text-xs mt-1 flex items-center gap-2">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: CATEGORY_COLORS[hoveredMemory.category] }}
            />
            <span className="capitalize">{hoveredMemory.category}</span>
            <span className="text-slate-500">|</span>
            <span>{Math.round(hoveredMemory.salience * 100)}% salience</span>
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-slate-900/90 border border-slate-700 rounded-lg p-3 text-xs backdrop-blur-sm">
        <h4 className="font-semibold text-white mb-2">Memory Banks</h4>
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-sm bg-orange-500/30 border border-orange-500" />
            <span className="text-slate-300">STM</span>
            <span className="text-slate-500 ml-auto">{groupedMemories.stm.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-sm bg-purple-500/30 border border-purple-500" />
            <span className="text-slate-300">Episodic</span>
            <span className="text-slate-500 ml-auto">{groupedMemories.episodic.length}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-sm bg-blue-500/30 border border-blue-500" />
            <span className="text-slate-300">Long-Term</span>
            <span className="text-slate-500 ml-auto">{groupedMemories.ltm.length}</span>
          </div>
        </div>
        <div className="mt-3 pt-2 border-t border-slate-700 text-slate-400">
          {memories.length} total memories
        </div>
      </div>

      {/* Status */}
      <div className="absolute top-4 right-4 text-xs text-slate-500 font-mono">
        CORTEX PCB v1.0
      </div>
    </div>
  );
}

interface ChipContentProps {
  memories: Memory[];
  groupedMemories: { stm: Memory[]; episodic: Memory[]; ltm: Memory[] };
  links: MemoryLink[];
  selectedMemory: Memory | null;
  hoveredMemory: Memory | null;
  onSelectMemory: (memory: Memory | null) => void;
  onHoverMemory: (memory: Memory | null) => void;
}

function ChipContent({
  memories,
  groupedMemories,
  links,
  selectedMemory,
  hoveredMemory,
  onSelectMemory,
  onHoverMemory,
}: ChipContentProps) {
  // Calculate grid layout for each section
  const layoutConfig = useMemo(() => {
    const cols = 12;
    const stmRows = Math.ceil(groupedMemories.stm.length / cols) || 1;
    const episodicRows = Math.ceil(groupedMemories.episodic.length / cols) || 1;
    const ltmRows = Math.ceil(groupedMemories.ltm.length / cols) || 1;

    const totalHeight = (stmRows + episodicRows + ltmRows) * NODE_SPACING + SECTION_GAP * 2;
    const startY = totalHeight / 2;

    return {
      cols,
      stm: {
        startY: startY - NODE_SPACING / 2,
        rows: stmRows,
      },
      episodic: {
        startY: startY - stmRows * NODE_SPACING - SECTION_GAP,
        rows: episodicRows,
      },
      ltm: {
        startY: startY - stmRows * NODE_SPACING - episodicRows * NODE_SPACING - SECTION_GAP * 2,
        rows: ltmRows,
      },
    };
  }, [groupedMemories]);

  // Calculate positions for all memories
  const memoryPositions = useMemo(() => {
    const positions = new Map<number, [number, number]>();
    const gridWidth = layoutConfig.cols * NODE_SPACING;
    const startX = -gridWidth / 2 + NODE_SPACING / 2;

    // STM positions
    groupedMemories.stm.forEach((m, i) => {
      const col = i % layoutConfig.cols;
      const row = Math.floor(i / layoutConfig.cols);
      const x = startX + col * NODE_SPACING;
      const y = layoutConfig.stm.startY - row * NODE_SPACING;
      positions.set(m.id, [x, y]);
    });

    // Episodic positions
    groupedMemories.episodic.forEach((m, i) => {
      const col = i % layoutConfig.cols;
      const row = Math.floor(i / layoutConfig.cols);
      const x = startX + col * NODE_SPACING;
      const y = layoutConfig.episodic.startY - row * NODE_SPACING;
      positions.set(m.id, [x, y]);
    });

    // LTM positions
    groupedMemories.ltm.forEach((m, i) => {
      const col = i % layoutConfig.cols;
      const row = Math.floor(i / layoutConfig.cols);
      const x = startX + col * NODE_SPACING;
      const y = layoutConfig.ltm.startY - row * NODE_SPACING;
      positions.set(m.id, [x, y]);
    });

    return positions;
  }, [groupedMemories, layoutConfig]);

  return (
    <>
      {/* Subtle ambient light */}
      <ambientLight intensity={0.5} />

      {/* PCB Background */}
      <PCBBackground width={CHIP_WIDTH} height={CHIP_HEIGHT} />

      {/* Section dividers and labels */}
      <SectionDividers layoutConfig={layoutConfig} cols={layoutConfig.cols} />

      {/* Memory links (PCB traces) */}
      <MemoryTraces links={links} positions={memoryPositions} />

      {/* Memory nodes */}
      {memories.map((memory) => {
        const pos = memoryPositions.get(memory.id);
        if (!pos) return null;

        return (
          <MemoryNode
            key={memory.id}
            memory={memory}
            position={pos}
            isSelected={selectedMemory?.id === memory.id}
            isHovered={hoveredMemory?.id === memory.id}
            onSelect={onSelectMemory}
            onHover={onHoverMemory}
          />
        );
      })}

      {/* Post-processing - subtle bloom */}
      <EffectComposer>
        <Bloom
          luminanceThreshold={0.6}
          luminanceSmoothing={0.5}
          intensity={0.4}
          radius={0.4}
        />
      </EffectComposer>
    </>
  );
}

// PCB-style background with grid
function PCBBackground({ width, height }: { width: number; height: number }) {
  const gridGeometry = useMemo(() => {
    const points: THREE.Vector3[] = [];
    const spacing = 1;

    // Vertical lines
    for (let x = -width / 2; x <= width / 2; x += spacing) {
      points.push(new THREE.Vector3(x, -height / 2, 0));
      points.push(new THREE.Vector3(x, height / 2, 0));
    }

    // Horizontal lines
    for (let y = -height / 2; y <= height / 2; y += spacing) {
      points.push(new THREE.Vector3(-width / 2, y, 0));
      points.push(new THREE.Vector3(width / 2, y, 0));
    }

    return new THREE.BufferGeometry().setFromPoints(points);
  }, [width, height]);

  return (
    <group>
      {/* Dark background */}
      <mesh position={[0, 0, -1]}>
        <planeGeometry args={[width + 4, height + 4]} />
        <meshBasicMaterial color="#0d1117" />
      </mesh>

      {/* PCB substrate */}
      <mesh position={[0, 0, -0.5]}>
        <planeGeometry args={[width, height]} />
        <meshBasicMaterial color="#1a1f2e" />
      </mesh>

      {/* Grid lines */}
      <lineSegments geometry={gridGeometry}>
        <lineBasicMaterial color="#252d3d" opacity={0.5} transparent />
      </lineSegments>

      {/* Border */}
      <lineLoop>
        <bufferGeometry>
          <float32BufferAttribute
            attach="attributes-position"
            args={[
              new Float32Array([
                -width / 2, -height / 2, 0,
                width / 2, -height / 2, 0,
                width / 2, height / 2, 0,
                -width / 2, height / 2, 0,
              ]),
              3,
            ]}
          />
        </bufferGeometry>
        <lineBasicMaterial color="#3d4a5c" />
      </lineLoop>
    </group>
  );
}

// Section dividers and labels
function SectionDividers({
  layoutConfig,
  cols,
}: {
  layoutConfig: { stm: { startY: number; rows: number }; episodic: { startY: number; rows: number }; ltm: { startY: number; rows: number }; cols: number };
  cols: number;
}) {
  const gridWidth = cols * NODE_SPACING;

  // Divider line between STM and Episodic
  const divider1Y = layoutConfig.stm.startY - layoutConfig.stm.rows * NODE_SPACING - SECTION_GAP / 2 + NODE_SPACING / 2;
  // Divider line between Episodic and LTM
  const divider2Y = layoutConfig.episodic.startY - layoutConfig.episodic.rows * NODE_SPACING - SECTION_GAP / 2 + NODE_SPACING / 2;

  return (
    <group>
      {/* STM label */}
      <SectionLabel
        text="STM"
        position={[-gridWidth / 2 - 1.5, layoutConfig.stm.startY - (layoutConfig.stm.rows * NODE_SPACING) / 2 + NODE_SPACING / 2, 0]}
        color="#f97316"
      />

      {/* Divider 1 */}
      <line>
        <bufferGeometry>
          <float32BufferAttribute
            attach="attributes-position"
            args={[new Float32Array([-gridWidth / 2 - 0.5, divider1Y, 0, gridWidth / 2 + 0.5, divider1Y, 0]), 3]}
          />
        </bufferGeometry>
        <lineBasicMaterial color="#3d4a5c" opacity={0.5} transparent />
      </line>

      {/* Episodic label */}
      <SectionLabel
        text="EPISODIC"
        position={[-gridWidth / 2 - 1.5, layoutConfig.episodic.startY - (layoutConfig.episodic.rows * NODE_SPACING) / 2 + NODE_SPACING / 2, 0]}
        color="#a855f7"
      />

      {/* Divider 2 */}
      <line>
        <bufferGeometry>
          <float32BufferAttribute
            attach="attributes-position"
            args={[new Float32Array([-gridWidth / 2 - 0.5, divider2Y, 0, gridWidth / 2 + 0.5, divider2Y, 0]), 3]}
          />
        </bufferGeometry>
        <lineBasicMaterial color="#3d4a5c" opacity={0.5} transparent />
      </line>

      {/* LTM label */}
      <SectionLabel
        text="LTM"
        position={[-gridWidth / 2 - 1.5, layoutConfig.ltm.startY - (layoutConfig.ltm.rows * NODE_SPACING) / 2 + NODE_SPACING / 2, 0]}
        color="#3b82f6"
      />
    </group>
  );
}

// Section label as 3D text alternative (simple box with color)
function SectionLabel({ text, position, color }: { text: string; position: [number, number, number]; color: string }) {
  return (
    <group position={position}>
      <mesh>
        <planeGeometry args={[0.1, 0.8]} />
        <meshBasicMaterial color={color} />
      </mesh>
    </group>
  );
}

// Memory traces (connections between related memories)
function MemoryTraces({
  links,
  positions,
}: {
  links: MemoryLink[];
  positions: Map<number, [number, number]>;
}) {
  const traceGeometry = useMemo(() => {
    const points: number[] = [];

    links.forEach((link) => {
      const sourcePos = positions.get(link.source_id);
      const targetPos = positions.get(link.target_id);
      if (sourcePos && targetPos) {
        points.push(sourcePos[0], sourcePos[1], 0.1);
        points.push(targetPos[0], targetPos[1], 0.1);
      }
    });

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute('position', new THREE.Float32BufferAttribute(points, 3));
    return geometry;
  }, [links, positions]);

  if (links.length === 0) return null;

  return (
    <lineSegments geometry={traceGeometry}>
      <lineBasicMaterial color="#FFB347" opacity={0.15} transparent />
    </lineSegments>
  );
}

// Individual memory node
function MemoryNode({
  memory,
  position,
  isSelected,
  isHovered,
  onSelect,
  onHover,
}: {
  memory: Memory;
  position: [number, number];
  isSelected: boolean;
  isHovered: boolean;
  onSelect: (memory: Memory | null) => void;
  onHover: (memory: Memory | null) => void;
}) {
  const color = CATEGORY_COLORS[memory.category] || CATEGORY_COLORS.custom;
  const isQuantum = memory.salience >= 0.7;

  // Size based on salience
  const baseSize = 0.25;
  const size = baseSize + memory.salience * 0.15;

  return (
    <group position={[position[0], position[1], 0]}>
      {/* Main node */}
      <mesh
        onClick={(e) => {
          e.stopPropagation();
          onSelect(isSelected ? null : memory);
        }}
        onPointerOver={(e) => {
          e.stopPropagation();
          onHover(memory);
          document.body.style.cursor = 'pointer';
        }}
        onPointerOut={() => {
          onHover(null);
          document.body.style.cursor = 'auto';
        }}
      >
        <circleGeometry args={[size, 16]} />
        <meshBasicMaterial color={color} />
      </mesh>

      {/* Quantum glow ring */}
      {isQuantum && (
        <mesh>
          <ringGeometry args={[size + 0.05, size + 0.12, 32]} />
          <meshBasicMaterial color="#FFD700" transparent opacity={0.6} />
        </mesh>
      )}

      {/* Selection ring */}
      {isSelected && (
        <mesh>
          <ringGeometry args={[size + 0.15, size + 0.22, 32]} />
          <meshBasicMaterial color="#ffffff" transparent opacity={0.8} />
        </mesh>
      )}

      {/* Hover highlight */}
      {isHovered && !isSelected && (
        <mesh>
          <ringGeometry args={[size + 0.08, size + 0.14, 32]} />
          <meshBasicMaterial color={color} transparent opacity={0.5} />
        </mesh>
      )}
    </group>
  );
}
