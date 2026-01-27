'use client';

/**
 * Section Label
 * Labels for memory bank sections (STM, Episodic, LTM)
 * Includes count display
 */

import { Html } from '@react-three/drei';
import { MemoryType } from '@/types/memory';

interface SectionLabelProps {
  type: MemoryType;
  count: number;
  maxCount: number;
  position: [number, number, number];
}

const SECTION_CONFIG: Record<MemoryType, { label: string; color: string; bgColor: string }> = {
  short_term: {
    label: 'STM BANK',
    color: '#f97316', // orange
    bgColor: 'rgba(249, 115, 22, 0.1)',
  },
  episodic: {
    label: 'EPISODIC BANK',
    color: '#a855f7', // purple
    bgColor: 'rgba(168, 85, 247, 0.1)',
  },
  long_term: {
    label: 'LONG-TERM BANK',
    color: '#3b82f6', // blue
    bgColor: 'rgba(59, 130, 246, 0.1)',
  },
};

export function SectionLabel({ type, count, maxCount, position }: SectionLabelProps) {
  const config = SECTION_CONFIG[type];

  return (
    <Html
      position={position}
      center
      style={{
        pointerEvents: 'none',
        userSelect: 'none',
      }}
    >
      <div
        className="flex items-center gap-3 px-3 py-1.5 rounded border font-mono text-xs tracking-wider"
        style={{
          backgroundColor: config.bgColor,
          borderColor: `${config.color}40`,
        }}
      >
        <span style={{ color: config.color }}>{config.label}</span>
        <span className="text-slate-500">|</span>
        <span className="text-slate-400">
          {count}/{maxCount}
        </span>
      </div>
    </Html>
  );
}

// All section labels together
interface AllSectionLabelsProps {
  stmCount: number;
  episodicCount: number;
  ltmCount: number;
  chipWidth: number;
  chipHeight: number;
}

export function AllSectionLabels({
  stmCount,
  episodicCount,
  ltmCount,
  chipWidth,
  chipHeight,
}: AllSectionLabelsProps) {
  const sectionHeight = chipHeight / 3;
  const halfChipHeight = chipHeight / 2;
  const halfChipWidth = chipWidth / 2;

  return (
    <group>
      {/* STM label (top) */}
      <SectionLabel
        type="short_term"
        count={stmCount}
        maxCount={100}
        position={[-halfChipWidth + 1.5, halfChipHeight - 0.3, 0.3]}
      />

      {/* Episodic label (middle left) */}
      <SectionLabel
        type="episodic"
        count={episodicCount}
        maxCount={500}
        position={[-halfChipWidth + 1.5, 0, 0.3]}
      />

      {/* LTM label (bottom) */}
      <SectionLabel
        type="long_term"
        count={ltmCount}
        maxCount={1000}
        position={[-halfChipWidth + 1.5, -halfChipHeight + sectionHeight - 0.3, 0.3]}
      />
    </group>
  );
}
