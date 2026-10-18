export interface ExtractedSegment {
  title: string;
  content: string;
  extractorType: string;
}
export interface ProcessedSegment extends ExtractedSegment {
  baseSalience: number;
  category: string;
  memoryPurpose: string;
  tags: string[];
  salience: number;
  gateSalience: number;
  frequencyBoost: number;
}
export const MAX_AUTO_MEMORIES: 5;
export const BASE_THRESHOLD: 0.35;
export const AUTO_EXTRACT_SALIENCE_CAP: 0.6;
export const EXTRACTOR_TO_PURPOSE: Record<string, string>;
export const EXTRACTOR_TO_CATEGORY: Record<string, string>;
export const DEFAULT_CATEGORY_THRESHOLDS: Record<string, number>;
export const PRE_COMPACT_CATEGORY_THRESHOLDS: Record<string, number>;
export const ARCHITECTURE_KEYWORDS: string[];
export const ERROR_KEYWORDS: string[];
export const PREFERENCE_KEYWORDS: string[];
export const PATTERN_KEYWORDS: string[];
export const DECISION_KEYWORDS: string[];
export const LEARNING_KEYWORDS: string[];
export const EMOTIONAL_MARKERS: string[];
export const CODE_REFERENCE_PATTERNS: RegExp[];
export const FULL_EXTRACTORS: Array<{ name: string; titlePrefix: string; patterns: RegExp[] }>;
export const STOP_HOOK_EXTRACTORS: Array<{ name: string; titlePrefix: string; patterns: RegExp[] }>;
export function detectKeywords(text: string, keywords: string[]): boolean;
export function detectCodeReferences(content: string): boolean;
export function calculateSalience(text: string, opts?: { autoExtractMode?: boolean }): number;
export function completenessAdjustment(content: string): number;
export function suggestCategory(text: string): string;
export function extractTags(text: string, hookTag?: string | null, extractorName?: string | null): string[];
export function calculateFrequencyBoost(segment: ExtractedSegment, allSegments: ExtractedSegment[]): number;
export function getExtractionThreshold(category: string, dynamicThreshold: number, categoryThresholds?: Record<string, number>): number;
export function extractFirstSentence(text: string, maxLen?: number): string;
export function extractMemorableSegments(conversationText: string, opts?: { mode?: 'full' | 'stop' }): ExtractedSegment[];
export function shouldRejectCandidate(segment: { title: string; content: string; extractorType?: string }, conversationText?: string): { rejected: boolean; reason: string };
export function calculateOverlap(text1: string, text2: string): number;
export function processSegments(segments: ExtractedSegment[], dynamicThreshold?: number, opts?: {
  hookTag?: string | null;
  maxMemories?: number;
  categoryThresholds?: Record<string, number>;
  applyFrequencyBoost?: boolean;
  conversationText?: string;
}): ProcessedSegment[];
