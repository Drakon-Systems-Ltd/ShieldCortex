/**
 * Category Colors
 * Visual color mappings for memory categories
 *
 * Includes both classic (cool blue/purple) and Jarvis (warm gold/orange) palettes
 */

import { MemoryCategory, MemoryType } from '@/types/memory';

// Classic color palette (cool blues and purples)
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

// Jarvis color palette (warm gold/orange holographic style)
export const JARVIS_CATEGORY_COLORS: Record<MemoryCategory, string> = {
  architecture: '#FFD700',  // Bright gold
  pattern: '#FFB347',       // Warm gold
  preference: '#FFA500',    // Pure orange
  error: '#FF6B6B',         // Keep red-ish for errors
  context: '#FFC080',       // Soft peach
  learning: '#FFE4B5',      // Moccasin
  todo: '#FF8C00',          // Deep orange
  note: '#FFCC66',          // Light amber
  relationship: '#00D4FF',  // Cyan accent
  custom: '#FFB347',        // Warm gold
};

export const JARVIS_TYPE_COLORS: Record<MemoryType, string> = {
  short_term: '#FFD700',    // Bright gold (front)
  episodic: '#FFB347',      // Warm gold (middle)
  long_term: '#FF8C00',     // Deep orange (back)
};

// Color mode toggle - defaults to Jarvis mode
let useJarvisColors = true;

export function setUseJarvisColors(value: boolean): void {
  useJarvisColors = value;
}

export function getUseJarvisColors(): boolean {
  return useJarvisColors;
}

export function getCategoryColor(category: MemoryCategory): string {
  if (useJarvisColors) {
    return JARVIS_CATEGORY_COLORS[category] || JARVIS_CATEGORY_COLORS.custom;
  }
  return CATEGORY_COLORS[category] || CATEGORY_COLORS.custom;
}

export function getTypeColor(type: MemoryType): string {
  if (useJarvisColors) {
    return JARVIS_TYPE_COLORS[type] || JARVIS_TYPE_COLORS.short_term;
  }
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
