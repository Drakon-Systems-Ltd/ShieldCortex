/**
 * Pure extraction wrapper for the OpenClaw cortex-memory hook.
 *
 * The OpenClaw hook runs inside a LONG-LIVED gateway process. It must NOT
 * touch the native DB path (saveAutoExtractedMemory / initDatabase install
 * global shutdown handlers and open better-sqlite3 — a confirmed crash-loop
 * mechanism). Persistence happens via the existing `callCortex("remember")`
 * shell-out, which runs in a throwaway mcporter subprocess.
 *
 * This module exists so the hook gets the SAME extraction QUALITY as the
 * Claude-Code side (sentence-bounded capture, rejection corpus, deterministic
 * taxonomy, 0.6 salience cap) without importing anything native. It depends
 * ONLY on the pure chunker — string in, plain objects out, no DB, no runtime.
 */

import {
  extractMemorableSegments,
  processSegments,
  shouldRejectCandidate,
  extractFirstSentence,
  EXTRACTOR_TO_CATEGORY,
  EXTRACTOR_TO_PURPOSE,
} from './extract-memorable-segments.mjs';

// Session extraction uses the lighter session-end threshold band. 0.30 is the
// same dynamic threshold the Claude-Code session-end hook passes; the chunker
// then applies its category-aware floors and the 0.6 cap.
const SESSION_DYNAMIC_THRESHOLD = 0.30;

// Explicit keyword captures ("remember this: ...") are plain user notes whose
// content rarely contains a chunker trigger word. When no extractor matches
// the content, treat it as an explicit important-note (category note,
// purpose project) — the chunker's own taxonomy for that type.
const KEYWORD_FALLBACK_EXTRACTOR = 'important-note';

/**
 * Extract memories from a full session transcript.
 *
 * Runs the chunker over the conversation text and returns the processed
 * memories — already rejection-filtered, deduped, taxonomy-pinned,
 * threshold-filtered, and salience-capped at 0.6.
 *
 * @param {string} conversationText
 * @returns {Array<{ title: string, content: string, category: string, memoryPurpose: string, tags: string[] }>}
 */
export function extractSessionMemories(conversationText) {
  if (!conversationText || typeof conversationText !== 'string') return [];

  const segments = extractMemorableSegments(conversationText);
  if (segments.length === 0) return [];

  const processed = processSegments(segments, SESSION_DYNAMIC_THRESHOLD, {
    conversationText,
  });

  return Array.isArray(processed) ? processed : [];
}

/**
 * Derive the chunker extractor type for an explicit keyword capture.
 *
 * Reuses the chunker: if the content itself contains a recognised trigger
 * shape (a decision, a fix, a learning, etc.), adopt that extractor's type so
 * the taxonomy is accurate. Otherwise fall back to an explicit important-note.
 * The longest captured segment wins (most context retained).
 */
function deriveKeywordExtractorType(content) {
  const segments = extractMemorableSegments(content);
  if (segments.length === 0) return KEYWORD_FALLBACK_EXTRACTOR;
  let best = segments[0];
  for (const seg of segments) {
    if (seg.content.length > best.content.length) best = seg;
  }
  return best.extractorType || KEYWORD_FALLBACK_EXTRACTOR;
}

/**
 * Build a single memory from an EXPLICIT keyword trigger.
 *
 * Explicit user intent ("remember this", "for the record", ...) must never be
 * silently dropped by the salience threshold (design B8). So this path applies
 * ONLY the rejection corpus (to drop true malformations) and bypasses the
 * threshold. It still derives category + memory_purpose from the chunker's
 * deterministic taxonomy — no new classification logic.
 *
 * Classification is driven by the AUTHORITATIVE extractorType passed in from
 * the matched trigger (the trigger phrase carries the intent signal, e.g.
 * "the fix was" → error-fix). When extractorType is absent or unknown we fall
 * back to re-scanning the content with the chunker (the truly-generic case).
 * We never silently collapse a typed trigger to a generic `note`.
 *
 * @param {string} content — the captured content after the trigger
 * @param {string} [extractorType] — authoritative chunker extractor type from
 *   the matched trigger (one of EXTRACTOR_TO_CATEGORY's keys). Optional.
 * @returns {Array<{ title: string, content: string, category: string, memoryPurpose: string }>}
 *   exactly ONE memory, or [] if the rejection corpus flags it as malformed.
 */
export function extractKeywordMemory(content, extractorType) {
  if (!content || typeof content !== 'string') return [];
  const trimmed = content.trim();
  if (trimmed.length < 5) return [];

  // The trigger's extractorType is authoritative when supplied & recognised;
  // otherwise re-scan the content (generic triggers like "remember this" whose
  // text may itself carry a decision/fix/learning shape).
  const resolvedType =
    extractorType && extractorType in EXTRACTOR_TO_CATEGORY
      ? extractorType
      : deriveKeywordExtractorType(trimmed);

  const candidate = { title: '', content: trimmed.slice(0, 500), extractorType: resolvedType };

  // Rejection corpus only — drop true malformations (bare imperatives,
  // negation-scope drops, email-body bleed, etc.). NOT the salience threshold.
  if (shouldRejectCandidate(candidate, trimmed).rejected) return [];

  const category = EXTRACTOR_TO_CATEGORY[resolvedType] ?? 'note';
  const memoryPurpose = EXTRACTOR_TO_PURPOSE[resolvedType] ?? 'project';

  // Sentence/word-bounded via the shared chunker helper — never a mid-word
  // slice (was a raw trimmed.slice(0, 80), the one path that bypassed it).
  const title = extractFirstSentence(trimmed.replace(/["\n]/g, ' '), 120);

  return [
    {
      title,
      content: candidate.content,
      category,
      memoryPurpose,
    },
  ];
}
