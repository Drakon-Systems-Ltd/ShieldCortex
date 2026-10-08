import type { ProcessedSegment } from './extract-memorable-segments.mjs';
export function extractSessionMemories(conversationText: string): ProcessedSegment[];
export function extractSessionMemoriesWithDistill(conversationText: string, opts?: {
  mode?: string; env?: NodeJS.ProcessEnv; openclawHome?: string;
  openclawConfig?: Record<string, unknown>; shieldConfig?: Record<string, unknown>;
  log?: (message: string) => void;
}): Promise<{ memories: Array<{ title: string; content: string; category: string; memoryPurpose: string; tags: string[]; salience?: number; capture_layer: string }>; path: string; reason?: string }>;
export function extractKeywordMemory(content: string, extractorType?: string): Array<{ title: string; content: string; category: string; memoryPurpose: string }>;
export const NON_AUTHORITATIVE_INDICATOR: 'non_authoritative_instruction';
export function screenMemoryCandidate(content: unknown, detect: ((content: string, sourceType: string) => { detected: boolean; patterns?: string[] }) | null, title?: string): string[] | null;
export function loadMemoryCandidateScreen(): Promise<((content: string, title?: string) => string[] | null) | null>;
