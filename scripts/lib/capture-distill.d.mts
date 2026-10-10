export const CAPTURE_MODE: Readonly<{ REGEX: 'regex'; DISTILL: 'distill'; DISTILL_REQUIRED: 'distill_required' }>;
export const L1_SALIENCE_CAP: 0.7;
export const DISTILL_MAX_MEMORIES: 8;
export const DISTILL_MAX_INPUT_CHARS: 24000;
export const DISTILL_TIMEOUT_MS: 12000;
export interface DistillMemory {
  title: string; content: string; category: string; salience: number;
  tags: string[]; capture_layer: 'L1'; captureLayer: 'L1';
  source_kind: 'distill'; memoryPurpose: string;
}
export interface DistillProvider {
  configured: boolean; apiKey?: string; baseUrl?: string; model?: string;
  source?: string; auth?: string; anthropicAuth?: string; reason?: string;
}
export function resolveCaptureMode(mode: unknown, opts?: { providerConfigured?: boolean }): 'regex' | 'distill' | 'distill_required';
export function failClosedDistill(errOrNull: Error | null, memories: unknown): { ok: boolean; reason?: string; memories: DistillMemory[] };
export function allowRegexFallback(mode: unknown): boolean;
export function resolveDistillProvider(env?: NodeJS.ProcessEnv, config?: Record<string, unknown> | null): DistillProvider;
export function resolveHermesOAuthProvider(env?: NodeJS.ProcessEnv, config?: Record<string, unknown> | null): DistillProvider;
export function resolveOnDiskDistillProvider(env?: NodeJS.ProcessEnv, config?: Record<string, unknown> | null): DistillProvider;
export function resolveProviderPreference(env?: NodeJS.ProcessEnv, distill?: Record<string, unknown>, hermesHome?: string): string[];
export function resolveClaudeCodeOAuthProvider(env?: NodeJS.ProcessEnv): DistillProvider;
export function buildDistillPrompt(conversationText: string): { system: string; user: string };
export function parseDistillResponseText(text: string): unknown[];
export function callDistillProvider(provider: Required<Pick<DistillProvider, 'apiKey' | 'baseUrl' | 'model'>> & DistillProvider, conversationText: string, opts?: { fetchImpl?: (input: string | URL | Request, init?: RequestInit) => Promise<Pick<Response, 'ok' | 'status' | 'json'>>; timeoutMs?: number }): Promise<unknown[]>;
export function extractCaptureMemories(conversationText: string, opts: {
  mode?: string; env?: NodeJS.ProcessEnv; config?: Record<string, unknown>;
  regexExtract?: () => Array<Record<string, unknown>>;
  log?: (message: string) => void; fetchImpl?: (input: string | URL | Request, init?: RequestInit) => Promise<Pick<Response, 'ok' | 'status' | 'json'>>; timeoutMs?: number;
}): Promise<{ memories: Array<Record<string, unknown>>; path: 'regex' | 'distill' | 'skip'; reason?: string }>;
