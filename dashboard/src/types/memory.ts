/**
 * Memory Types
 * Shared type definitions for the dashboard
 */

export type MemoryType = 'short_term' | 'long_term' | 'episodic';
export type MemoryStatus = 'active' | 'archived' | 'suppressed' | 'canonical';
export type MemorySourceKind = 'user' | 'cli' | 'hook' | 'plugin' | 'agent' | 'import' | 'cloud' | 'api' | 'system';
export type MemoryCaptureMethod = 'manual' | 'hook' | 'plugin' | 'import' | 'cloud' | 'api' | 'auto' | 'review';

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
  uuid?: string;
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
  updatedAt?: string;
  decayedScore?: number;
  metadata?: Record<string, unknown>;
  status?: MemoryStatus;
  pinned?: boolean;
  reviewedAt?: string | null;
  reviewedBy?: string | null;
  sourceKind?: MemorySourceKind;
  captureMethod?: MemoryCaptureMethod;
  trustScore?: number;
  sensitivityLevel?: string;
  source?: string | null;
  scope?: 'project' | 'global';
  transferable?: boolean;
  cloudExcluded?: boolean;
  // Graph entity ids attached by GET /api/memories (snake_case on the wire) so
  // the constellation client can map list rows to nodes; also on memory_created
  // / memory_accessed WS events. Consumed by useGraphPulse.
  entity_ids?: number[];
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
  // GET /api/links joins the endpoint memories' node type onto each link row.
  source_type?: MemoryType;
  target_type?: MemoryType;
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
