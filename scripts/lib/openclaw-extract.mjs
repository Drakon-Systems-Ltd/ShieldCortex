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
 * Claude-Code side without opening a DB in the long-lived gateway process.
 * Persistence stays on callCortex("remember").
 *
 * Track C.2: extractSessionMemoriesWithDistill adds optional L1 distill when
 * OpenClaw/Hermes/env credentials resolve; otherwise regex L0.
 */

import {
  extractMemorableSegments,
  processSegments,
  shouldRejectCandidate,
  extractFirstSentence,
  EXTRACTOR_TO_CATEGORY,
  EXTRACTOR_TO_PURPOSE,
} from './extract-memorable-segments.mjs';
import { extractCaptureMemories } from './capture-distill.mjs';
import { resolveOpenClawDistillProvider } from './openclaw-distill-auth.mjs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

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
 * Track C.2 — session extract with optional L1 distill.
 * Fail-closed distill when a provider resolves; else regex L0.
 * Still no DB / native bindings (gateway-safe).
 *
 * @param {string} conversationText
 * @param {object} [opts]
 * @returns {Promise<{ memories: object[], path: string, reason?: string }>}
 */
export async function extractSessionMemoriesWithDistill(conversationText, opts = {}) {
  const log = opts.log || ((msg) => console.log(msg));
  const runtimeEnv = opts.env || process.env;
  const regexExtract = () => extractSessionMemories(conversationText);

  const ocProvider = resolveOpenClawDistillProvider({
    env: runtimeEnv,
    openclawHome: opts.openclawHome,
    config: opts.openclawConfig,
  });

  const distillEnv = { ...runtimeEnv };
  if (ocProvider.configured && ocProvider.apiKey) {
    if (ocProvider.source === 'anthropic') {
      distillEnv["ANTHROPIC_API_KEY"] = ocProvider.apiKey;
    } else {
      distillEnv["OPENAI_API_KEY"] = ocProvider.apiKey;
      if (ocProvider.baseUrl) distillEnv["OPENAI_BASE_URL"] = ocProvider.baseUrl;
    }
    if (ocProvider.model) distillEnv["SHIELDCORTEX_DISTILL_MODEL"] = ocProvider.model;
    // Prefer OC-resolved creds; skip Hermes chain unless caller re-enabled it.
    if (distillEnv["SHIELDCORTEX_DISTILL_OAUTH"] === undefined) {
      distillEnv["SHIELDCORTEX_DISTILL_OAUTH"] = '0';
    }
  }

  const capture = await extractCaptureMemories(conversationText, {
    mode: opts.mode,
    env: distillEnv,
    config: opts.shieldConfig || {},
    regexExtract,
    log,
  });

  const memories = (capture.memories || []).map((m) => ({
    title: m.title,
    content: m.content,
    category: m.category || 'note',
    memoryPurpose: m.memoryPurpose || 'project',
    tags: Array.isArray(m.tags) ? m.tags : [],
    salience: m.salience,
    capture_layer: m.capture_layer || m.captureLayer || (capture.path === 'distill' ? 'L1' : 'L0'),
  }));

  if (ocProvider.configured && capture.path === 'distill') {
    log('[openclaw-extract] distill via ' + ocProvider.auth + ' model=' + ocProvider.model);
  }

  return { memories, path: capture.path, reason: capture.reason };
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

// ==================== L2 candidate screen ====================

/**
 * The indicator name the firewall uses for an L2 hit. Mirrored here because
 * this module must not import the compiled defence barrel at load time.
 */
export const NON_AUTHORITATIVE_INDICATOR = 'non_authoritative_instruction';

/**
 * Pattern names when an AUTO-captured candidate is a non-authoritative
 * instruction, else `null`.
 *
 * Pure and dependency-injected, for the same reason `defendRecallRows` is: the
 * decision is worth unit-testing without a dist build, and the wiring that
 * finds the real detector is a separate, boring problem.
 *
 * TITLE AND CONTENT are screened as ONE string. A title is stored and later
 * recalled into context exactly as content is, so screening only the content
 * examined the longer half of every captured memory and shipped the shorter,
 * more quotable one. They are joined by a newline rather than a space, so the
 * two utterances stay separate clauses to the policy's sentence rules.
 *
 * The label is always `memory_candidate` and never the hook's own identity.
 * The hook IS a trusted writer; the transcript text it lifted is not. Asking
 * the question under the writer's label would answer a different question and
 * always say "fine".
 *
 * Fails OPEN — no detector, a throw, or empty content all return `null`. An
 * additive floor must never turn a missing export into a host that has
 * silently stopped remembering anything.
 */
export function screenMemoryCandidate(content, detect, title) {
  if (typeof detect !== 'function') return null;
  const candidate = candidateText(content, title);
  if (!candidate) return null;
  try {
    const result = detect(candidate, 'memory_candidate');
    if (!result || !result.detected) return null;
    return Array.isArray(result.patterns) ? result.patterns : [];
  } catch {
    return null;
  }
}

/** Title and content as the single string the screen judges. */
function candidateText(content, title) {
  const body = typeof content === 'string' ? content : '';
  const head = typeof title === 'string' ? title : '';
  if (!body) return head || '';
  return head ? `${head}\n${body}` : body;
}

let _candidateScreen;

/**
 * Resolve the built L2 policy once and hand back a synchronous predicate:
 * `(content, title) => string[] | null`.
 *
 * Imports the LEAF policy module, never `dist/defence/pipeline.js` — the hook
 * runs inside a long-lived gateway, and the leaf is a pure regex module with no
 * database, no native binding and no shutdown handler. Returns `null` when the
 * dist build is missing or predates L2, which the caller must treat as "no
 * screen", i.e. exactly the behaviour before this round.
 */
export async function loadMemoryCandidateScreen() {
  if (_candidateScreen !== undefined) return _candidateScreen;
  const here = dirname(fileURLToPath(import.meta.url));
  const policyPath = resolve(here, '..', '..', 'dist', 'defence', 'firewall', 'provenance-policy.js');
  try {
    const mod = await import(pathToFileURL(policyPath).href);
    const detect = mod?.detectNonAuthoritativeInstruction;
    _candidateScreen = typeof detect === 'function'
      ? (content, title) => screenMemoryCandidate(content, detect, title)
      : null;
  } catch {
    _candidateScreen = null;
  }
  return _candidateScreen;
}
