export const INJECT_MODE: Readonly<{ OFF: 'off'; START: 'start'; TURN: 'turn'; BOTH: 'both' }>;
export const NATIVE_INJECT_CONTRACT: Readonly<{ DISABLE_NATIVE: 'disable_native_inject'; SC_ONLY: 'sc_only' }>;
export const INJECT_CANDIDATE_LIMIT: 64;
export const SHARED_SENSITIVITY_LEVELS: ReadonlySet<string>;
export const INJECT_CANDIDATE_FIELDS: readonly string[];
export const PACK_HEADER: Readonly<{ BUS: string; SIDECAR: string }>;
export const PACK_FRAME_OVERHEAD_TOKENS: number;
export const INJECT_CEILINGS: Readonly<{
  start: Readonly<{ defaultTokens: number; defaultRows: number; maxPerRowTokens: number; hardMaxTokens: number; hardMaxRows: number }>;
  turn: Readonly<{ defaultTokens: number; defaultRows: number; maxPerRowTokens: number; hardMaxTokens: number; hardMaxRows: number }>;
  sessionCumulative: Readonly<{ defaultTokens: number; hardMaxTokens: number }>;
}>;
export const INJECT_SALIENCE_CEILING: 0.7;
export interface InjectRow {
  id?: number | string; title?: string; content?: string | null; fact?: string;
  status?: string; quarantined?: number | boolean | string; in_quarantine?: number | boolean | string;
  sensitivity_level?: unknown; sensitivity?: string; content_form?: string | null;
  trust_score?: number; trust?: string; defence_verdict?: string; source_attested?: number | boolean;
  pinned?: number | boolean | string; host_id?: string | null; agent_id?: string | null;
  project?: string | null; transferable?: number | boolean | string; salience?: number;
  source?: string | null; source_ids?: string[]; created_at?: string; createdAt?: string;
}
export interface InjectScope { hostId?: string; agentId?: string; project?: string; requireScope?: boolean }
export interface PackItem {
  id?: number | string; title: string; fact: string; content_form: string;
  salience: number; source_ids: string[]; trust: number | string | null;
  age: string | null; content_hash: string; tokens: number;
}
export interface SessionState {
  deliveredHashes?: Iterable<string>;
  pinnedPack?: { items: PackItem[]; tokens: number; content_hashes?: string[] } | null;
  cumulativeTokens?: number;
}
export interface PackOptions {
  mode?: unknown; nativeContract?: unknown; budgets?: { tokens?: number; rows?: number; perRowTokens?: number };
  scope?: InjectScope; sessionState?: SessionState; rehydrate?: boolean;
  compactSignaled?: boolean; candidateCap?: number; sessionCumulativeTokens?: number; frameId?: string;
}
export function selectInjectCandidates(db: { prepare(sql: string): { all(...params: unknown[]): Array<Record<string, unknown>> } }, options?: { project?: string | null }): Array<Record<string, unknown>>;
export function packHeaderFor(nativeContract: unknown): string;
export function packFrameTail(frameId?: string): Readonly<{ id: string; NOTICE: string; CLOSE: string }>;
export function liveClassifyForm(content: string): string;
export function isFormInjectEligible(row: InjectRow): boolean;
export function estimateTokens(s: string): number;
export function contentHashPreimage(row: { id?: number | string; title?: string; fact?: string; content?: string }): string;
export function contentHash(preimage: string): string;
export function normalizeInjectMode(mode: unknown): 'off' | 'start' | 'turn' | 'both';
export function normalizeNativeContract(value: unknown): 'disable_native_inject' | 'sc_only' | null;
export function clampBudgets(kind: 'start' | 'turn', requested?: { tokens?: number; rows?: number; perRowTokens?: number }): { tokens: number; rows: number; perRowTokens: number };
export function isInjectEligible(row: InjectRow, scope?: InjectScope & { project?: string | null }): boolean;
export function clipToTokens(text: string, maxTokens: number): string;
export function clampInjectSalience(raw: unknown): number;
export function toPackItem(row: InjectRow, opts: { perRowTokens: number }): PackItem;
export function neutraliseFactText(text: string): string;
export function serializeItem(item: PackItem): string;
export function stableRank<T extends InjectRow>(rows: T[]): T[];
export function buildStartPack(candidates: InjectRow[], options?: PackOptions): {
  items: PackItem[]; text: string; skipped: string; tokens: number;
  sessionState: { deliveredHashes: string[]; pinnedPack: { items: PackItem[]; tokens: number; content_hashes?: string[] } | null; cumulativeTokens: number };
};
export function readInjectConfig(config?: Record<string, unknown>): {
  mode: 'off' | 'start' | 'turn' | 'both';
  nativeContract: 'disable_native_inject' | 'sc_only' | null;
  hostId: string | null; agentId: string | null; requireScope: boolean;
  budgets: { tokens: unknown; rows: unknown; perRowTokens: unknown };
  plane: unknown;
};
