export interface RecallRow { id: number; content: string; trust_score?: number; metadata?: unknown; [key: string]: unknown }
export interface RecallDefenceModules {
  filterByTrust: (rows: RecallRow[], minTrust: number, project?: string) => RecallRow[];
  sanitiseInput?: (content: string) => string;
  detectInstructions: (content: string) => { detected: boolean; patterns?: string[] } | null;
  detectEncoding: (content: string) => { detected: boolean; decodedSnippets?: string[]; encodingTypes?: string[] } | null;
  detectMarkdownImageExfil?: (content: string) => { detected: boolean; urls?: string[] } | null;
  scanForCredentials: (content: string) => { findings?: Array<{ action: string }> } | null;
  logAudit: (entry: Record<string, unknown>) => void;
  initDatabase: (path: string) => unknown;
  isDatabaseInitialized?: () => boolean;
  getDatabase?: () => { name: string };
  closeDatabase?: () => void;
}
export function loadRecallDefence(distRootOverride?: string): Promise<RecallDefenceModules | null>;
export function ensureRecallAuditDb(defence: RecallDefenceModules, dbPath: string): void;
export function emitRecallAudit(logAudit: (entry: Record<string, unknown>) => void, entry?: { memoryId?: number; action?: string; layer?: string; reason?: string; project?: string }): void;
export function defendRecallRows<T extends RecallRow>(rows: T[], opts: { minTrust?: number; reviewedPinnedBypass?: boolean; project?: string }, deps: RecallDefenceModules): { kept: T[]; actions: Array<{ id: number; action: string; layer: string | null; reason: string | null }> };
