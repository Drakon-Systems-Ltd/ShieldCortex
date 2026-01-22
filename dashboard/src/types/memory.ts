/**
 * Memory Types
 * Shared type definitions for the dashboard
 */

export type MemoryType = 'short_term' | 'long_term' | 'episodic';

export type MemoryCategory =
  | 'architecture'
  | 'pattern'
  | 'preference'
  | 'error'
  | 'context'
  | 'learning'
  | 'todo'
  | 'note'
  | 'relationship'
  | 'custom';

export interface Memory {
  id: number;
  type: MemoryType;
  category: MemoryCategory;
  title: string;
  content: string;
  project?: string;
  tags: string[];
  salience: number;
  accessCount: number;
  lastAccessed: string;
  createdAt: string;
  decayedScore?: number;
  metadata?: Record<string, unknown>;
}

export interface MemoryLink {
  id: number;
  source_id: number;
  target_id: number;
  relationship: string;
  strength: number;
  created_at: string;
  source_title?: string;
  target_title?: string;
  source_category?: MemoryCategory;
  target_category?: MemoryCategory;
}

export interface MemoryStats {
  total: number;
  shortTerm: number;
  longTerm: number;
  episodic: number;
  byCategory: Record<string, number>;
  averageSalience: number;
  decayDistribution?: {
    healthy: number;
    fading: number;
    critical: number;
  };
}

export interface MemoryEvent {
  type: 'memory_created' | 'memory_accessed' | 'memory_updated' | 'memory_deleted' | 'consolidation_complete' | 'decay_tick';
  timestamp: string;
  data: unknown;
}

export interface Memory3DPosition {
  x: number;
  y: number;
  z: number;
}
