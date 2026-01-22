/**
 * Category Colors
 * Visual color mappings for memory categories
 */

import { MemoryCategory, MemoryType } from '@/types/memory';

export const CATEGORY_COLORS: Record<MemoryCategory, string> = {
  architecture: '#3B82F6',  // Blue
  pattern: '#8B5CF6',       // Purple
  preference: '#EC4899',    // Pink
  error: '#EF4444',         // Red
  context: '#10B981',       // Green
  learning: '#F59E0B',      // Amber
  todo: '#F97316',          // Orange
  note: '#6B7280',          // Gray
  relationship: '#06B6D4',  // Cyan
  custom: '#A855F7',        // Violet
};

export const TYPE_COLORS: Record<MemoryType, string> = {
  short_term: '#F97316',    // Orange
  long_term: '#3B82F6',     // Blue
  episodic: '#8B5CF6',      // Purple
};

export function getCategoryColor(category: MemoryCategory): string {
  return CATEGORY_COLORS[category] || CATEGORY_COLORS.custom;
}

export function getTypeColor(type: MemoryType): string {
  return TYPE_COLORS[type] || TYPE_COLORS.short_term;
}

export function hexToRgb(hex: string): { r: number; g: number; b: number } {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result
    ? {
        r: parseInt(result[1], 16) / 255,
        g: parseInt(result[2], 16) / 255,
        b: parseInt(result[3], 16) / 255,
      }
    : { r: 1, g: 1, b: 1 };
}
