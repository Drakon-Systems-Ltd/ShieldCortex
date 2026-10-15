import type Database from 'better-sqlite3';
export interface AutoMemoryCandidate {
  title: string; content: string; category: string; salience: number;
  tags: string[]; memoryPurpose?: string;
}
export function saveAutoExtractedMemory(db: Database.Database, memory: AutoMemoryCandidate, project?: string | null, opts?: { source?: string }): Promise<void>;
