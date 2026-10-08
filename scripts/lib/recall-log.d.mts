export interface RecallCandidate {
  id?: number; title?: string; category?: string; memoryPurpose?: string;
  salience?: number; ftsRank?: number | null; source?: 'fts' | 'category-boost';
  effectiveSalience?: number; injected?: boolean;
  dropReason?: string | null;
}
export interface RecallLogEntry {
  ranAt?: string; prompt?: string; promptHash?: string; sessionId?: string;
  project?: string; minSalience?: number; candidates: RecallCandidate[];
  injectedCount?: number; finalContextChars?: number;
}
export interface StoredRecallLogEntry {
  ranAt: string; prompt: string | null; promptHash: string | null;
  sessionId: string | null; project: string | null; minSalience: number | null;
  candidates: RecallCandidate[]; injectedCount: number | null; finalContextChars: number | null;
}
export function writeRecallLog(entry: RecallLogEntry): void;
export function readRecallLog(index?: number): StoredRecallLogEntry | null;
export function listRecallLogs(): Array<{ index: number; entry: StoredRecallLogEntry }>;
export const RECALL_RING_SIZE: number;
export function getRecallLogDir(): string;
