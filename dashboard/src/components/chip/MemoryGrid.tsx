'use client';

/**
 * Memory Grid
 * Organizes memories in a grid layout within each memory bank section
 * Automatically switches between MemoryCell and QuantumCell based on salience
 */

import { useMemo } from 'react';
import { Memory, MemoryType } from '@/types/memory';
import { MemoryCell } from './MemoryCell';
import { QuantumCell } from './QuantumCell';

// Salience threshold for quantum cells
const QUANTUM_THRESHOLD = 0.7;

interface GridConfig {
  columns: number;
  cellWidth: number;
  cellHeight: number;
  horizontalGap: number;
  verticalGap: number;
}

interface MemoryGridProps {
  memories: Memory[];
  memoryType: MemoryType;
  chipWidth: number;
  chipHeight: number;
  selectedMemory: Memory | null;
  onSelectMemory: (memory: Memory | null) => void;
}

// Calculate grid position for a memory at given index
function calculateGridPosition(
  index: number,
  config: GridConfig,
  sectionOffset: { x: number; y: number; z: number },
  sectionWidth: number
): [number, number, number] {
  const { columns, cellWidth, horizontalGap, verticalGap } = config;

  const col = index % columns;
  const row = Math.floor(index / columns);

  // Calculate total grid width
  const gridWidth = columns * cellWidth + (columns - 1) * horizontalGap;
  const startX = -gridWidth / 2 + cellWidth / 2;

  const x = sectionOffset.x + startX + col * (cellWidth + horizontalGap);
  const y = sectionOffset.y - row * (cellWidth * 0.6 + verticalGap);
  const z = sectionOffset.z;

  return [x, y, z];
}

export function MemoryGrid({
  memories,
  memoryType,
  chipWidth,
  chipHeight,
  selectedMemory,
  onSelectMemory,
}: MemoryGridProps) {
  const sectionHeight = chipHeight / 3;
  const halfChipHeight = chipHeight / 2;

  // Grid configuration
  const gridConfig: GridConfig = useMemo(
    () => ({
      columns: 8,
      cellWidth: 1.0,
      cellHeight: 0.6,
      horizontalGap: 0.4,
      verticalGap: 0.3,
    }),
    []
  );

  // Section offset based on memory type
  const sectionOffset = useMemo(() => {
    switch (memoryType) {
      case 'short_term':
        return {
          x: 0,
          y: halfChipHeight - sectionHeight * 0.35,
          z: 0.2,
        };
      case 'long_term':
        return {
          x: 0,
          y: -halfChipHeight + sectionHeight * 0.65,
          z: 0.2,
        };
      case 'episodic':
      default:
        return {
          x: 0,
          y: 0,
          z: 0.2,
        };
    }
  }, [memoryType, halfChipHeight, sectionHeight]);

  // Filter memories by type
  const filteredMemories = useMemo(() => {
    return memories.filter((m) => m.type === memoryType);
  }, [memories, memoryType]);

  // Sort memories by salience (highest first) for better visual hierarchy
  const sortedMemories = useMemo(() => {
    return [...filteredMemories].sort((a, b) => b.salience - a.salience);
  }, [filteredMemories]);

  return (
    <group>
      {sortedMemories.map((memory, index) => {
        const position = calculateGridPosition(
          index,
          gridConfig,
          sectionOffset,
          chipWidth
        );

        const isQuantum = memory.salience >= QUANTUM_THRESHOLD;

        if (isQuantum) {
          return (
            <QuantumCell
              key={memory.id}
              memory={memory}
              position={position}
              onSelect={onSelectMemory}
              isSelected={selectedMemory?.id === memory.id}
              size={1.2}
            />
          );
        }

        return (
          <MemoryCell
            key={memory.id}
            memory={memory}
            position={position}
            onSelect={onSelectMemory}
            isSelected={selectedMemory?.id === memory.id}
          />
        );
      })}
    </group>
  );
}

// Get grid position for a specific memory (used by pulse animations)
export function getMemoryGridPosition(
  memory: Memory,
  memories: Memory[],
  chipWidth: number,
  chipHeight: number
): [number, number, number] | null {
  const sectionHeight = chipHeight / 3;
  const halfChipHeight = chipHeight / 2;

  const gridConfig: GridConfig = {
    columns: 8,
    cellWidth: 1.0,
    cellHeight: 0.6,
    horizontalGap: 0.4,
    verticalGap: 0.3,
  };

  // Get section offset
  let sectionOffset: { x: number; y: number; z: number };
  switch (memory.type) {
    case 'short_term':
      sectionOffset = {
        x: 0,
        y: halfChipHeight - sectionHeight * 0.35,
        z: 0.2,
      };
      break;
    case 'long_term':
      sectionOffset = {
        x: 0,
        y: -halfChipHeight + sectionHeight * 0.65,
        z: 0.2,
      };
      break;
    case 'episodic':
    default:
      sectionOffset = {
        x: 0,
        y: 0,
        z: 0.2,
      };
  }

  // Find index of this memory in its section (sorted by salience)
  const sectionMemories = memories
    .filter((m) => m.type === memory.type)
    .sort((a, b) => b.salience - a.salience);

  const index = sectionMemories.findIndex((m) => m.id === memory.id);
  if (index === -1) return null;

  return calculateGridPosition(index, gridConfig, sectionOffset, chipWidth);
}

// Episodic memories need special handling since they're split left/right of core
export function EpisodicMemoryGrid({
  memories,
  chipWidth,
  chipHeight,
  coreWidth,
  selectedMemory,
  onSelectMemory,
}: {
  memories: Memory[];
  chipWidth: number;
  chipHeight: number;
  coreWidth: number;
  selectedMemory: Memory | null;
  onSelectMemory: (memory: Memory | null) => void;
}) {
  const episodicMemories = useMemo(() => {
    return memories
      .filter((m) => m.type === 'episodic')
      .sort((a, b) => b.salience - a.salience);
  }, [memories]);

  // Split memories between left and right of core
  const leftMemories = episodicMemories.filter((_, i) => i % 2 === 0);
  const rightMemories = episodicMemories.filter((_, i) => i % 2 === 1);

  const gridConfig: GridConfig = {
    columns: 3,
    cellWidth: 1.0,
    cellHeight: 0.6,
    horizontalGap: 0.4,
    verticalGap: 0.3,
  };

  const leftOffset = {
    x: -coreWidth - 2,
    y: 0.5,
    z: 0.2,
  };

  const rightOffset = {
    x: coreWidth + 2,
    y: 0.5,
    z: 0.2,
  };

  return (
    <group>
      {/* Left side */}
      {leftMemories.map((memory, index) => {
        const position = calculateGridPosition(
          index,
          gridConfig,
          leftOffset,
          chipWidth / 2 - coreWidth
        );

        const isQuantum = memory.salience >= QUANTUM_THRESHOLD;

        if (isQuantum) {
          return (
            <QuantumCell
              key={memory.id}
              memory={memory}
              position={position}
              onSelect={onSelectMemory}
              isSelected={selectedMemory?.id === memory.id}
              size={1.2}
            />
          );
        }

        return (
          <MemoryCell
            key={memory.id}
            memory={memory}
            position={position}
            onSelect={onSelectMemory}
            isSelected={selectedMemory?.id === memory.id}
          />
        );
      })}

      {/* Right side */}
      {rightMemories.map((memory, index) => {
        const position = calculateGridPosition(
          index,
          gridConfig,
          rightOffset,
          chipWidth / 2 - coreWidth
        );

        const isQuantum = memory.salience >= QUANTUM_THRESHOLD;

        if (isQuantum) {
          return (
            <QuantumCell
              key={memory.id}
              memory={memory}
              position={position}
              onSelect={onSelectMemory}
              isSelected={selectedMemory?.id === memory.id}
              size={1.2}
            />
          );
        }

        return (
          <MemoryCell
            key={memory.id}
            memory={memory}
            position={position}
            onSelect={onSelectMemory}
            isSelected={selectedMemory?.id === memory.id}
          />
        );
      })}
    </group>
  );
}
