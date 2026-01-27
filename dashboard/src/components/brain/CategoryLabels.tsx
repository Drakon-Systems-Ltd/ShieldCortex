'use client';

/**
 * Category Labels
 *
 * Shows labels around the brain for each category region.
 * Categories are arranged in a circle like a clock face.
 */

import { useMemo } from 'react';
import { Html } from '@react-three/drei';
import { MemoryCategory } from '@/types/memory';
import { getCategoryColor } from '@/lib/category-colors';

// Category positions (angles in degrees, matching position-algorithm.ts)
const CATEGORY_ANGLES: Record<MemoryCategory, number> = {
  architecture: 0,
  pattern: 36,
  preference: 72,
  error: 108,
  context: 144,
  learning: 180,
  todo: 216,
  note: 252,
  relationship: 288,
  custom: 324,
};

// Category icons
const CATEGORY_ICONS: Record<MemoryCategory, string> = {
  architecture: '🏗️',
  pattern: '🔄',
  preference: '⚙️',
  error: '🐛',
  context: '📍',
  learning: '💡',
  todo: '✅',
  note: '📝',
  relationship: '🔗',
  custom: '📦',
};

interface CategoryLabelsProps {
  memoryCounts: Record<string, number>;
  radius?: number;
  showCounts?: boolean;
}

export function CategoryLabels({
  memoryCounts,
  radius = 5.5,
  showCounts = true,
}: CategoryLabelsProps) {
  const labels = useMemo(() => {
    return (Object.keys(CATEGORY_ANGLES) as MemoryCategory[]).map((category) => {
      const angle = CATEGORY_ANGLES[category] * (Math.PI / 180);
      const x = radius * Math.cos(angle);
      const z = radius * Math.sin(angle);
      const count = memoryCounts[category] || 0;
      const color = getCategoryColor(category);

      return {
        category,
        position: [x, 0, z] as [number, number, number],
        count,
        color,
        icon: CATEGORY_ICONS[category],
      };
    });
  }, [memoryCounts, radius]);

  return (
    <group name="category-labels">
      {labels.map(({ category, position, count, color, icon }) => (
        <Html
          key={category}
          position={position}
          center
          style={{ pointerEvents: 'none' }}
          distanceFactor={12}
        >
          <div
            className="flex flex-col items-center gap-0.5 opacity-60 hover:opacity-100 transition-opacity"
            style={{ color }}
          >
            <span className="text-lg">{icon}</span>
            <span className="text-[10px] font-medium capitalize whitespace-nowrap">
              {category}
            </span>
            {showCounts && count > 0 && (
              <span
                className="text-[9px] px-1.5 py-0.5 rounded-full"
                style={{ backgroundColor: color + '30' }}
              >
                {count}
              </span>
            )}
          </div>
        </Html>
      ))}
    </group>
  );
}
