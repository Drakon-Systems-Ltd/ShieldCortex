export interface PrecompactCandidate {
  extractorType?: string; category?: string; memoryPurpose?: string; title?: string;
  salience?: number; saved?: boolean; memoryId?: number | null; dropReason?: string | null;
  frequencyBoost?: number; error?: string | null;
}
export interface PrecompactLogEntry {
  ranAt?: string; thresholdUsed?: number; contextFullnessPct?: number;
  totalMemories?: number; candidates: PrecompactCandidate[];
}
export interface StoredPrecompactLogEntry {
  ranAt: string; thresholdUsed: number | null; contextFullnessPct: number | null;
  totalMemories: number | null; candidates: PrecompactCandidate[];
}
export function writePrecompactLog(entry: PrecompactLogEntry): void;
export function readPrecompactLog(index?: number): StoredPrecompactLogEntry | null;
export function listPrecompactLogs(): Array<{ index: number; entry: StoredPrecompactLogEntry }>;
export const PRECOMPACT_RING_SIZE: number;
export function getPrecompactLogDir(): string;
