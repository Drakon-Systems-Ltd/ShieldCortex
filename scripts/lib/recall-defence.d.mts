export interface RecallRow { id: number; content: string; trust_score?: number; metadata?: unknown; [key: string]: unknown }
/**
 * Metadata as defendRecallRows returns it: an object/array input is kept, a JSON
 * string is parsed (any JSON value), and null/undefined/unparseable become {}.
 * Never `undefined` and never the caller's original string.
 */
export type RecallMetadata = Record<string, unknown> | unknown[] | string | number | boolean | null;
/**
 * A row as defendRecallRows returns it: a shallow copy with trust coalesced to a
 * number, metadata parsed, and content possibly redacted by the trust layer.
 * The input row type is deliberately NOT preserved.
 */
export interface DefendedRecallRow { id: number; content: string; trust_score: number; metadata: RecallMetadata; [key: string]: unknown }
/** The part of SanitisationResult (src/defence/input-sanitisation) the shim reads. */
export interface RecallSanitisation { sanitised: string }
export interface RecallDefenceModules {
  filterByTrust: (rows: RecallRow[], minTrust: number, project?: string) => RecallRow[];
  sanitiseInput?: (content: string) => RecallSanitisation | null | undefined;
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
export function defendRecallRows(rows: RecallRow[], opts: { minTrust?: number; reviewedPinnedBypass?: boolean; project?: string } | undefined, deps: RecallDefenceModules): { kept: DefendedRecallRow[]; actions: Array<{ id: number; action: string; layer: string | null; reason: string | null }> };
