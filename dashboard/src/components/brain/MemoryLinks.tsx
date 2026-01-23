'use client';

/**
 * Memory Links
 * Renders lines between related memories in 3D space
 */

import { useMemo } from 'react';
import { Line } from '@react-three/drei';
import * as THREE from 'three';
import { Memory, MemoryLink } from '@/types/memory';

interface MemoryLinksProps {
  memories: Memory[];
  links: MemoryLink[];
  memoryPositions: Map<number, { x: number; y: number; z: number }>;
}

// Relationship colors
const RELATIONSHIP_COLORS: Record<string, string> = {
  references: '#60a5fa', // blue
  extends: '#34d399',    // green
  contradicts: '#f87171', // red
  related: '#a78bfa',    // purple
};

export function MemoryLinks({ memories, links, memoryPositions }: MemoryLinksProps) {
  // Filter to only links where both memories exist and have positions
  const validLinks = useMemo(() => {
    const memoryIds = new Set(memories.map(m => m.id));
    return links.filter(link =>
      memoryIds.has(link.source_id) &&
      memoryIds.has(link.target_id) &&
      memoryPositions.has(link.source_id) &&
      memoryPositions.has(link.target_id)
    );
  }, [memories, links, memoryPositions]);

  if (validLinks.length === 0) return null;

  return (
    <group name="memory-links">
      {validLinks.map((link) => {
        const sourcePos = memoryPositions.get(link.source_id)!;
        const targetPos = memoryPositions.get(link.target_id)!;
        const color = RELATIONSHIP_COLORS[link.relationship] || '#94a3b8';

        return (
          <Line
            key={`${link.source_id}-${link.target_id}`}
            points={[
              new THREE.Vector3(sourcePos.x, sourcePos.y, sourcePos.z),
              new THREE.Vector3(targetPos.x, targetPos.y, targetPos.z),
            ]}
            color={color}
            lineWidth={1 + link.strength * 2}
            transparent
            opacity={0.3 + link.strength * 0.4}
            dashed={link.relationship === 'contradicts'}
            dashScale={0.5}
            dashSize={0.2}
            gapSize={0.1}
          />
        );
      })}
    </group>
  );
}
