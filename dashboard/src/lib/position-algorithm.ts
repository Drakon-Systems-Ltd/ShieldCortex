/**
 * Position Algorithm
 * Calculates 3D positions for memories in the brain visualization
 */

import { Memory, Memory3DPosition, MemoryCategory } from '@/types/memory';

const BASE_RADIUS = 4;

// Category angular positions (like brain regions)
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

/**
 * Calculate 3D position for a memory
 * - Z-axis: Memory type (STM front, LTM back, Episodic middle)
 * - Angular position: Category (10 sectors)
 * - Radius: Salience (higher = more central)
 */
export function calculateMemoryPosition(memory: Memory): Memory3DPosition {
  // Region-based z-depth
  const zOffset: Record<string, number> = {
    short_term: 2.5,    // Front (surface)
    long_term: -2.5,    // Back (core)
    episodic: 0,        // Middle
  };

  const z = zOffset[memory.type] || 0;

  // Category determines angular position
  const baseAngle = (CATEGORY_ANGLES[memory.category] || 0) * (Math.PI / 180);

  // Add variation based on memory ID for distribution within category
  const angleVariation = ((memory.id * 137.5) % 36) * (Math.PI / 180);
  const theta = baseAngle + angleVariation;

  // Salience affects radius (higher = more central/prominent)
  const radiusFactor = 1 - (memory.salience * 0.4);
  const radius = BASE_RADIUS * radiusFactor;

  // Add some vertical variation based on access count
  const verticalOffset = (memory.accessCount % 5) * 0.3 - 0.6;

  // Calculate final position
  const x = radius * Math.cos(theta);
  const y = radius * Math.sin(theta) * 0.7 + verticalOffset; // Flatten slightly

  return { x, y, z };
}

/**
 * Calculate decay factor for visual effects
 */
export function calculateDecayFactor(memory: Memory): number {
  if (!memory.lastAccessed) return 1;

  const now = Date.now();
  const lastAccessed = new Date(memory.lastAccessed).getTime();
  const hoursSinceAccess = (now - lastAccessed) / (1000 * 60 * 60);

  // Different decay rates for different types
  const decayRates: Record<string, number> = {
    short_term: 0.995,    // Hourly decay
    long_term: 0.9995,    // Much slower
    episodic: 0.998,      // Medium
  };

  const rate = decayRates[memory.type] || 0.995;
  return Math.pow(rate, hoursSinceAccess);
}

/**
 * Get region bounds for each memory type
 */
export function getRegionBounds() {
  return {
    short_term: { minZ: 1.5, maxZ: 3.5, color: '#F97316' },
    episodic: { minZ: -1.5, maxZ: 1.5, color: '#8B5CF6' },
    long_term: { minZ: -3.5, maxZ: -1.5, color: '#3B82F6' },
  };
}
