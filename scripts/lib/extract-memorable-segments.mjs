/**
 * Shared chunker / auto-extractor for the ShieldCortex memory hooks.
 *
 * This module is the single source of truth for the regex-based extraction
 * that turns conversation text into memory candidates. The session-end,
 * pre-compact, and stop hooks all consume it.
 *
 * Behaviour-preserving extraction of identical code that previously lived
 * in three near-duplicate hook scripts. Keeping the chunker centralised
 * means rule tightening (e.g. rejection corpus, salience cap) lands in
 * one place.
 */

// ==================== CONSTANTS ====================

export const MAX_AUTO_MEMORIES = 5;
export const BASE_THRESHOLD = 0.35;

// Cap salience for non-LLM-rated auto-extracted memories. The regex
// extractors catch keyword shapes, not semantic confidence, so they should
// not produce 1.0-salience captures (which front-load proactive recall and
// shadow real high-confidence user input). 0.6 sits in the auto-quarantine
// trust band (0.5–0.7) used elsewhere in the pipeline.
export const AUTO_EXTRACT_SALIENCE_CAP = 0.6;

// v4.25.0: deterministic taxonomy. The extractor already knows *why* a
// segment matched (extractorType) — derive memory_purpose and category
// from that signal instead of re-scanning the captured text. Keyword-
// based suggestCategory() stays as a fallback for any extractorType not
// in the map (defensive, not currently used by any in-tree extractor).
//
// memory_purpose follows the global taxonomy (src/memory/types.ts):
//   user      — who the human is
//   feedback  — corrections / instructions the human gave the agent
//   project   — facts about the project (decisions, architecture, fixes)
//   reference — reusable knowledge (learnings, external references)
export const EXTRACTOR_TO_PURPOSE = {
  preference: 'feedback',
  decision: 'project',
  architecture: 'project',
  'error-fix': 'project',
  learning: 'reference',
  'important-note': 'project',
};

// Pinning category by extractorType eliminates the "important-note tagged
// as 'error' because the text mentioned a bug" failure mode.
export const EXTRACTOR_TO_CATEGORY = {
  preference: 'preference',
  decision: 'context',
  architecture: 'architecture',
  'error-fix': 'error',
  learning: 'learning',
  'important-note': 'note',
};

// Default category thresholds (session-end / lighter hooks).
// Pre-compact hook uses tighter thresholds (raised +0.10 in v4.11.0) and
// passes them via processSegments({ categoryThresholds: ... }).
export const DEFAULT_CATEGORY_THRESHOLDS = {
  architecture: 0.28,
  error: 0.30,
  context: 0.32,
  learning: 0.32,
  pattern: 0.35,
  preference: 0.38,
  note: 0.42,
  todo: 0.40,
  relationship: 0.35,
  custom: 0.35,
};

export const PRE_COMPACT_CATEGORY_THRESHOLDS = {
  architecture: 0.38,
  error: 0.40,
  context: 0.42,
  learning: 0.42,
  pattern: 0.45,
  preference: 0.48,
  note: 0.52,
  todo: 0.50,
  relationship: 0.45,
  custom: 0.45,
};

export const ARCHITECTURE_KEYWORDS = [
  'architecture', 'design', 'pattern', 'structure', 'system',
  'database', 'api', 'schema', 'model', 'framework', 'stack',
  'microservice', 'monolith', 'serverless', 'infrastructure',
];

export const ERROR_KEYWORDS = [
  'error', 'bug', 'fix', 'issue', 'problem', 'crash', 'fail',
  'exception', 'debug', 'resolve', 'solution', 'workaround',
];

export const PREFERENCE_KEYWORDS = [
  'prefer', 'always', 'never', 'style', 'convention', 'standard',
  'like', 'want', 'should', 'must', 'require',
];

export const PATTERN_KEYWORDS = [
  'pattern', 'practice', 'approach', 'method', 'technique',
  'implementation', 'strategy', 'algorithm', 'workflow',
];

export const DECISION_KEYWORDS = [
  'decided', 'decision', 'chose', 'chosen', 'selected', 'going with',
  'will use', 'opted for', 'settled on', 'agreed',
];

export const LEARNING_KEYWORDS = [
  'learned', 'discovered', 'realized', 'found out', 'turns out',
  'TIL', 'now know', 'understand now', 'figured out',
];

export const EMOTIONAL_MARKERS = [
  'important', 'critical', 'crucial', 'essential', 'key',
  'finally', 'breakthrough', 'eureka', 'aha', 'got it',
  'frustrating', 'annoying', 'tricky', 'remember',
];

export const CODE_REFERENCE_PATTERNS = [
  /\b[A-Z][a-zA-Z]*\.[a-zA-Z]+\b/,
  /\b[a-z_][a-zA-Z0-9_]*\.(ts|js|py|go|rs)\b/,
  /`[^`]+`/,
  /\b(function|class|interface|type|const|let|var)\s+\w+/i,
  /\bline\s*\d+\b/i,
  /\b(src|lib|app|components?)\/\S+/,
];

const TECH_TAGS = [
  'react', 'vue', 'angular', 'node', 'python', 'typescript', 'javascript',
  'api', 'database', 'sql', 'mongodb', 'postgresql', 'mysql',
  'docker', 'kubernetes', 'aws', 'git', 'testing', 'auth', 'security',
];

// ==================== SALIENCE ====================

export function detectKeywords(text, keywords) {
  const lower = text.toLowerCase();
  return keywords.some((keyword) => lower.includes(keyword.toLowerCase()));
}

export function detectCodeReferences(content) {
  return CODE_REFERENCE_PATTERNS.some((pattern) => pattern.test(content));
}

function detectExplicitRequest(text) {
  const patterns = [
    /\bremember\s+(this|that)\b/i,
    /\bdon'?t\s+forget\b/i,
    /\bkeep\s+(in\s+)?mind\b/i,
    /\bnote\s+(this|that)\b/i,
    /\bsave\s+(this|that)\b/i,
    /\bimportant[:\s]/i,
    /\bfor\s+future\s+reference\b/i,
  ];
  return patterns.some((pattern) => pattern.test(text));
}

/**
 * Compute a 0-1 salience score from keyword + structural signals.
 *
 * @param {string} text
 * @param {object} [opts]
 * @param {boolean} [opts.autoExtractMode=false] — when true, cap the result
 *   at AUTO_EXTRACT_SALIENCE_CAP (0.6) so auto-extracted segments never
 *   compete with explicit `remember()` calls for top-rank in recall.
 *   v4.22.0: keyword bonuses can stack to 1.85 pre-cap, so without the cap
 *   most auto-extracts hit the 1.0 ceiling and dominate recall with
 *   low-signal fragments.
 * @returns {number} salience in [0, 1] (or [0, 0.6] under autoExtractMode)
 */
export function calculateSalience(text, opts = {}) {
  const { autoExtractMode = false } = opts;
  let score = 0.25;
  if (detectExplicitRequest(text)) score += 0.5;
  if (detectKeywords(text, ARCHITECTURE_KEYWORDS)) score += 0.4;
  if (detectKeywords(text, ERROR_KEYWORDS)) score += 0.35;
  if (detectKeywords(text, DECISION_KEYWORDS)) score += 0.35;
  if (detectKeywords(text, LEARNING_KEYWORDS)) score += 0.3;
  if (detectKeywords(text, PATTERN_KEYWORDS)) score += 0.25;
  if (detectKeywords(text, PREFERENCE_KEYWORDS)) score += 0.25;
  if (detectCodeReferences(text)) score += 0.15;
  if (detectKeywords(text, EMOTIONAL_MARKERS)) score += 0.2;
  const ceiling = autoExtractMode ? AUTO_EXTRACT_SALIENCE_CAP : 1.0;
  return Math.min(ceiling, score);
}

// Function words a genuine mid-clause fragment trails off on (conjunctions,
// prepositions, articles, copulas). A capture ending here was cut while the
// thought was still going. A capture ending on a CONTENT word is treated as
// complete even without terminal punctuation — the extractor regex caps at
// ~200 chars with an OPTIONAL terminator, so complete long facts routinely
// arrive unpunctuated and must NOT be mistaken for fragments (review 2026-06-08).
const DANGLING_TAIL =
  /\b(?:and|or|but|nor|the|a|an|to|of|in|on|at|by|for|with|without|from|as|is|are|was|were|be|been|that|which|who|whose|because|so|if|when|while|than|then|into|onto|over|under|via|per|about|after|before|between|during)$/i;

/**
 * Quality signal: reward self-contained captures, discount genuine fragments.
 * The 0.6 cap bounds salience but says nothing about whether a capture is a
 * complete thought — so a mid-clause fragment used to compete on equal footing
 * with a complete fact (Jarvis P2, 2026-06-08). A capture that ends like a
 * complete sentence (terminal punctuation) OR on a content word gets no penalty;
 * only one that trails off on a dangling function word is discounted so it ranks
 * below self-contained facts. Pure + exported for direct testing.
 *
 * @param {string} content
 * @returns {number} 0 for complete captures, a negative penalty for fragments
 */
export function completenessAdjustment(content) {
  if (typeof content !== 'string') return 0;
  const t = content.trim();
  if (!t) return 0;
  if (/[.!?]["')\]]?$/.test(t)) return 0; // ends like a complete sentence
  return DANGLING_TAIL.test(t) ? -0.15 : 0; // dangling function word → fragment
}

export function suggestCategory(text) {
  const lower = text.toLowerCase();
  if (detectKeywords(lower, ARCHITECTURE_KEYWORDS)) return 'architecture';
  if (detectKeywords(lower, ERROR_KEYWORDS)) return 'error';
  if (detectKeywords(lower, DECISION_KEYWORDS)) return 'context';
  if (detectKeywords(lower, LEARNING_KEYWORDS)) return 'learning';
  if (detectKeywords(lower, PREFERENCE_KEYWORDS)) return 'preference';
  if (detectKeywords(lower, PATTERN_KEYWORDS)) return 'pattern';
  if (/\b(todo|fixme|hack|xxx)\b/i.test(lower)) return 'todo';
  return 'note';
}

/**
 * Extract tags. The optional `hookTag` lets each hook stamp its provenance
 * — session-end-hook passes 'session-end', stop-hook passes 'source:stop-hook'
 * (preserving the exact tag strings each hook used pre-refactor),
 * pre-compact-hook passes null.
 */
export function extractTags(text, hookTag = null, extractorName = null) {
  const tags = new Set();
  const hashtagMatches = text.match(/#[a-zA-Z][a-zA-Z0-9_-]*/g);
  if (hashtagMatches) {
    hashtagMatches.forEach((tag) => tags.add(tag.slice(1).toLowerCase()));
  }
  const lowerText = text.toLowerCase();
  TECH_TAGS.forEach((term) => {
    if (lowerText.includes(term)) tags.add(term);
  });
  tags.add('auto-extracted');
  if (hookTag) tags.add(hookTag);
  if (extractorName) tags.add(`source:${extractorName}`);
  return Array.from(tags).slice(0, 12);
}

export function calculateFrequencyBoost(segment, allSegments) {
  const commonWords = new Set([
    'about', 'after', 'before', 'being', 'between', 'could', 'during',
    'every', 'found', 'through', 'would', 'should', 'which', 'where',
    'there', 'these', 'their', 'other', 'using', 'because', 'without',
  ]);
  const words = segment.content.toLowerCase().split(/\s+/);
  const keyTerms = words.filter((w) =>
    w.length > 5 && !commonWords.has(w) && /^[a-z]+$/.test(w)
  );
  let boost = 0;
  const seenTerms = new Set();
  for (const term of keyTerms) {
    if (seenTerms.has(term)) continue;
    seenTerms.add(term);
    const mentions = allSegments.filter((s) =>
      s !== segment && s.content.toLowerCase().includes(term)
    ).length;
    if (mentions > 1) {
      boost += 0.03 * Math.min(mentions, 5);
    }
  }
  return Math.min(0.15, boost);
}

export function getExtractionThreshold(category, dynamicThreshold, categoryThresholds = DEFAULT_CATEGORY_THRESHOLDS) {
  const categoryThreshold = categoryThresholds[category] || BASE_THRESHOLD;
  return Math.min(categoryThreshold, dynamicThreshold);
}

// ==================== EXTRACTOR DEFINITIONS ====================
//
// All capture groups use `[^.!?\n]{N,M}[.!?]?` instead of `.{N,M}`. The
// previous fixed-character-window form (`.{15,200}`) sliced clauses at
// arbitrary offsets, producing memories like
//   "Decision: python3 /home/ubuntu/clawd/scripts/beautyhair_colo..."
// where the regex grabbed 150 chars after the keyword regardless of where
// the sentence ended. The new form stops at the first `.`, `!`, `?`, or
// newline, capping at 200 chars for safety, and optionally consumes the
// terminator so the captured group ends cleanly. v4.24.3.

export const FULL_EXTRACTORS = [
  {
    name: 'decision',
    titlePrefix: 'Decision: ',
    patterns: [
      /(?:we\s+)?decided\s+(?:to\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:going|went)\s+with\s+([^.!?\n]{15,150}[.!?]?)/gi,
      /(?:chose|chosen|selected)\s+([^.!?\n]{15,150}[.!?]?)/gi,
      /the\s+(?:approach|solution|fix)\s+(?:is|was)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:using|will\s+use)\s+([^.!?\n]{15,150}[.!?]?)/gi,
      /(?:opted\s+for|settled\s+on)\s+([^.!?\n]{15,150}[.!?]?)/gi,
    ],
  },
  {
    name: 'error-fix',
    titlePrefix: 'Fix: ',
    patterns: [
      /(?:fixed|solved|resolved)\s+(?:by\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /the\s+(?:fix|solution|workaround)\s+(?:is|was)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:root\s+cause|issue)\s+(?:is|was)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:error|bug)\s+(?:was\s+)?caused\s+by\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:problem|issue)\s+was\s+([^.!?\n]{15,150}[.!?]?)/gi,
      /(?:the\s+)?bug\s+(?:is|was)\s+([^.!?\n]{15,150}[.!?]?)/gi,
      /(?:debugging|debugged)\s+([^.!?\n]{15,150}[.!?]?)/gi,
    ],
  },
  {
    name: 'learning',
    titlePrefix: 'Learned: ',
    patterns: [
      /(?:learned|discovered|realized|found\s+out)\s+(?:that\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /turns\s+out\s+(?:that\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:TIL|today\s+I\s+learned)[:\s]+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:now\s+)?(?:understand|know)\s+(?:that\s+)?([^.!?\n]{15,150}[.!?]?)/gi,
      /(?:figured\s+out|worked\s+out)\s+([^.!?\n]{15,150}[.!?]?)/gi,
    ],
  },
  {
    name: 'architecture',
    titlePrefix: 'Architecture: ',
    patterns: [
      /the\s+architecture\s+(?:is|uses|consists\s+of)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:design|pattern)\s+(?:is|uses)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:system|api|database)\s+(?:structure|design)\s+(?:is|uses)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:created|added|implemented|built)\s+(?:a\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:refactored|updated|changed)\s+(?:the\s+)?([^.!?\n]{15,150}[.!?]?)/gi,
    ],
  },
  {
    name: 'preference',
    titlePrefix: 'Preference: ',
    patterns: [
      /(?:always|never)\s+([^.!?\n]{10,150}[.!?]?)/gi,
      /(?:prefer|want)\s+to\s+([^.!?\n]{10,150}[.!?]?)/gi,
      /(?:should|must)\s+(?:always\s+)?([^.!?\n]{10,150}[.!?]?)/gi,
    ],
  },
  {
    name: 'important-note',
    titlePrefix: 'Note: ',
    patterns: [
      /important[:\s]+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:note|remember)[:\s]+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:key|critical)\s+(?:point|thing)[:\s]+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:this\s+is\s+)?(?:crucial|essential)[:\s]+([^.!?\n]{15,150}[.!?]?)/gi,
      /(?:don't\s+forget|keep\s+in\s+mind)[:\s]+([^.!?\n]{15,150}[.!?]?)/gi,
    ],
  },
];

// stop-hook historically used a thinner extractor set (no architecture,
// no important-note, fewer learning + preference patterns). Preserve the
// pre-refactor surface so its behaviour does not change with this move.
// Same sentence-bounded capture form as FULL_EXTRACTORS (v4.24.3).
export const STOP_HOOK_EXTRACTORS = [
  FULL_EXTRACTORS[0], // decision
  {
    name: 'error-fix',
    titlePrefix: 'Fix: ',
    patterns: [
      /(?:fixed|solved|resolved)\s+(?:by\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /the\s+(?:fix|solution|workaround)\s+(?:is|was)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:root\s+cause|issue)\s+(?:is|was)\s+([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:error|bug)\s+(?:was\s+)?caused\s+by\s+([^.!?\n]{15,200}[.!?]?)/gi,
    ],
  },
  {
    name: 'learning',
    titlePrefix: 'Learned: ',
    patterns: [
      /(?:learned|discovered|realized|found\s+out)\s+(?:that\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /turns\s+out\s+(?:that\s+)?([^.!?\n]{15,200}[.!?]?)/gi,
      /(?:figured\s+out|worked\s+out)\s+([^.!?\n]{15,150}[.!?]?)/gi,
    ],
  },
  {
    name: 'preference',
    titlePrefix: 'Preference: ',
    patterns: [
      /(?:always|never)\s+([^.!?\n]{10,150}[.!?]?)/gi,
      /(?:prefer|want)\s+to\s+([^.!?\n]{10,150}[.!?]?)/gi,
    ],
  },
];

/**
 * Defensive JSON-escape unescape. Some upstream paths re-emit
 * conversation text after a stringify/parse round-trip without unescaping
 * the inner string, so literal `\n` / `\t` / `\r` sequences leak through
 * into matched segments. This fixes the most common leaks idempotently —
 * sequences that are already real newlines / tabs / carriage returns are
 * different characters from the literal 2-char `\n` / `\t` / `\r` so the
 * replacement is a no-op on already-unescaped input. The lookbehind keeps
 * `\\n` (genuine literal backslash + n) intact.
 */
function defensiveUnescape(text) {
  return text
    .replace(/(?<!\\)\\n/g, '\n')
    .replace(/(?<!\\)\\t/g, '\t')
    .replace(/(?<!\\)\\r/g, '\r');
}

/**
 * Take a captured snippet and return the first sentence (or first
 * word-bounded slice up to `maxLen` if no sentence terminator is nearby).
 * Replaces the old `slice(0, 50)` headline which produced mid-clause
 * garbage like "Decision: any command you must be authenticated. Run x..."
 * where the first 50 chars meant nothing without their context.
 */
export function extractFirstSentence(text, maxLen = 120) {
  const trimmed = text.trim().replace(/\s+/g, ' ');
  // Back off to the last word boundary (never mid-word); ellipsis marks the cut.
  const wordBound = (s) => {
    if (s.length <= maxLen) return s;
    const cut = s.slice(0, maxLen);
    const lastSpace = cut.lastIndexOf(' ');
    return (lastSpace > maxLen * 0.5 ? cut.slice(0, lastSpace) : cut).trimEnd() + '…';
  };
  // Find first sentence terminator within reasonable bounds. The terminator
  // must be followed by whitespace OR end-of-string so URLs / decimals /
  // version strings ("v4.24.3") don't fool it. A matched sentence is returned
  // WHOLE when it fits — the old `slice(0, maxLen)` chopped clean sentences
  // mid-word (every truncated title was exactly prefix+80 chars).
  const match = trimmed.match(/^([^.!?\n]{15,160}[.!?])(?:\s|$)/);
  // A matched sentence is COMPLETE (regex-bounded ≤161 chars) — return it whole,
  // terminator intact. Re-truncating it to maxLen stripped the terminator and
  // appended a misleading ellipsis, just moving the truncation cliff 80→120
  // (review 2026-06-08). wordBound + ellipsis is only for the no-terminator path.
  if (match) return match[1];
  return wordBound(trimmed);
}

/**
 * Extract memorable segments from conversation text.
 *
 * @param {string} conversationText
 * @param {{ mode?: 'full' | 'stop' }} [opts]
 * @returns {Array<{ title: string, content: string, extractorType: string }>}
 */
export function extractMemorableSegments(conversationText, opts = {}) {
  const extractors = opts.mode === 'stop' ? STOP_HOOK_EXTRACTORS : FULL_EXTRACTORS;
  const segments = [];

  // v4.24.3: unescape JSON-encoded escapes before regex matching so
  // captured content doesn't include literal `\n` / `\t` sequences.
  const text = defensiveUnescape(conversationText);

  for (const extractor of extractors) {
    for (const pattern of extractor.patterns) {
      // Reset lastIndex defensively — patterns are module-level globals.
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        const content = match[1].trim();
        // Issue #49: a capture group can begin part-way through a sentence (the
        // trigger word was mid-clause) or trail off into a question. Enforce a
        // true sentence-START boundary here so the segmenter never emits a
        // mid-clause slice or an interrogative — the same defects the rejection
        // corpus screens, applied at the source so they never become candidates.
        if (beginsWithContinuation(content) || endsWithInterrogative(content)) {
          continue;
        }
        if (content.length >= 20) {
          // v4.24.3: headline = first sentence (sentence-bounded), not
          // the first 50 chars. Eliminates mid-clause garbage in the
          // MEMORY.md index.
          const headline = extractFirstSentence(content, 120);
          const title = extractor.titlePrefix + headline;
          segments.push({
            title,
            content: content.slice(0, 500),
            extractorType: extractor.name,
          });
        }
      }
    }
  }

  return segments;
}

// ==================== REJECTION RULES ====================

const SUBORDINATE_START_WORDS = new Set([
  'the', 'a', 'an', 'for', 'to', 'of', 'with', 'by', 'from', 'on', 'in',
  'at', 'that', 'which', 'who', 'where', 'when',
]);

// Issue #49: tokens that, when a captured segment BEGINS with them, mark it as
// a mid-clause CONTINUATION — the chunker hit a trigger word part-way through a
// sentence and grabbed the tail of a thought that started earlier (leading
// conjunctions, dangling auxiliaries, pronoun-contraction tails). A genuine
// durable fact never opens on one of these. Closed list, case-insensitive.
const CONTINUATION_START_TOKENS = new Set([
  'and', 'so', 'but', 'yet', 'or', 'because', 'also', 'then', 'plus',
  'have', 'has', "he's", "she's", "you're", "it's", "that's", "there's",
  "we're", "they're", "i'm",
]);

// Verb-shaped tokens (small whitelist + a deterministic suffix heuristic).
// Hoisted so both the subordinate-clause fragment check and the whole-segment
// bare-clause check share one definition.
const VERB_WHITELIST = new Set([
  'is', 'was', 'are', 'were', 'be', 'been', 'being',
  'has', 'have', 'had', 'do', 'does', 'did',
  'uses', 'used', 'wraps', 'consists', 'lives', 'runs', 'sits',
  'returns', 'accepts', 'requires', 'breaks', 'fails', 'works',
  'hosts', 'holds', 'adds', 'applies', 'splits', 'flushes', 'writes',
]);

function normalizeApostrophes(s) {
  // Fold the curly apostrophe (U+2019) and modifier letter apostrophe onto the
  // ASCII one so "it’s" matches the same token as "it's".
  return s.replace(/[‘’ʼ]/g, "'");
}

function isVerbShaped(token) {
  const t = normalizeApostrophes(token.toLowerCase()).replace(/[^a-z']/g, '');
  if (!t) return false;
  if (VERB_WHITELIST.has(t)) return true;
  // -ing / -ed are strong verb signals; -es/-s is noisier (plurals) but kept
  // for backward-compatibility with the original fragment heuristic.
  return /(?:ing|ed|es|s)$/.test(t) && t.length > 3;
}

function hasVerbLike(content) {
  return content.trim().split(/\s+/).some(isVerbShaped);
}

// First word-token of a capture, apostrophe-normalised and lowercased, with a
// trailing contraction kept intact ("you're" stays "you're").
function leadingToken(content) {
  const cleaned = normalizeApostrophes(content.trim().toLowerCase());
  const m = cleaned.match(/^([a-z]+(?:'[a-z]+)?)/);
  return m ? m[1] : '';
}

// (a) Mid-clause continuation opener — see CONTINUATION_START_TOKENS.
function beginsWithContinuation(content) {
  return CONTINUATION_START_TOKENS.has(leadingToken(content));
}

// (b) Trailing interrogative — a question is not a durable declarative fact.
// Allows an optional closing quote/paren after the `?`.
function endsWithInterrogative(content) {
  return /\?["')\]]?\s*$/.test(content.trim());
}

// (d) Meaningful tokens: word-ish tokens with at least two alphanumerics.
// Single letters / bare punctuation don't count toward a complete thought.
const MIN_MEANINGFUL_TOKENS = 3;
function meaningfulTokenCount(content) {
  return content.trim().split(/\s+/).filter((t) => /[a-z0-9]{2,}/i.test(t)).length;
}

// (c) Bare clause: a short capture with no verb-shaped token at all — a noun
// phrase rather than a subject+verb statement ("the brand new build machine").
function looksLikeBareClause(content) {
  return meaningfulTokenCount(content) <= 6 && !hasVerbLike(content);
}

// Bare imperative verbs that almost always indicate the original sentence
// began with a modal or negation that the chunker dropped (e.g. "never
// commit secrets" → captured as "commit secrets"). When a captured segment
// starts with one of these, treat it as a structural malformation.
const BARE_IMPERATIVE_VERBS = new Set([
  'commit', 'delete', 'disable', 'skip', 'make', 'run', 'use', 'set',
  'add', 'remove', 'fix', 'change', 'update', 'push', 'pull', 'install',
  'drop', 'stop', 'allow', 'enable', 'expose', 'leak',
]);

const NEGATION_TOKENS = new Set([
  "don't", 'do', 'not', 'never', 'no', 'avoid', 'refuse', 'stop', "won't",
  'cannot', "can't", "shouldn't", 'avoid',
]);

const IMPERATIVE_TOOL_CALL_PATTERNS = [
  /\b(?:call|invoke|use)\s+(?:the\s+)?[A-Za-z][\w-]*\s+tool\b/i,
  /\b(?:call|invoke|use)\s+this\s+tool\s+now\b/i,
  /\bcomplete\s+this\s+request\.\s*(?:call|invoke|use)\s+this\s+tool\b/i,
];

const EMAIL_BODY_TELLS = [
  /see\s+how\s+fast\s+you\s+reply/i,
  /\bunsubscribe\b/i,
  /\bview\s+in\s+browser\b/i,
  /\bsent\s+from\s+my\b/i,
  /\bthis\s+email\s+was\s+sent\b/i,
];

const PATH_LABEL_PATTERN = /^[A-Z][a-z]+(?:\s+[a-z]+)?\s*:\s+\/[\w/-]+/;

function firstToken(content) {
  const cleaned = content.trim().toLowerCase();
  const match = cleaned.match(/^([a-z']+)\b/);
  return match ? match[1] : '';
}

function looksLikeFragment(content) {
  // Subordinate-clause start: lowercase + first word in the closed list +
  // no verb-shaped token in the next 6 words. Catches "the JSON include?
  // For example:" without false-positiving "the architecture uses X
  // pattern".
  const tokens = content.trim().split(/\s+/, 8);
  if (tokens.length === 0) return false;
  const first = tokens[0].toLowerCase().replace(/[^a-z']/g, '');
  if (!SUBORDINATE_START_WORDS.has(first)) return false;
  // Heuristic: a verb-shaped token in the first 6 words has either an -ing,
  // -ed, -es, or -s suffix, or appears in a tiny verb whitelist.
  const verbWhitelist = new Set([
    'is', 'was', 'are', 'were', 'be', 'been', 'being',
    'has', 'have', 'had', 'do', 'does', 'did',
    'uses', 'used', 'wraps', 'consists', 'lives', 'runs', 'sits',
    'returns', 'accepts', 'requires', 'breaks', 'fails', 'works',
  ]);
  const window = tokens.slice(1, 7);
  for (const tok of window) {
    const t = tok.toLowerCase().replace(/[^a-z]/g, '');
    if (!t) continue;
    if (verbWhitelist.has(t)) return false;
    if (/(?:ing|ed|es|s)$/.test(t) && t.length > 3) return false;
  }
  return true;
}

function looksLikeBareImperative(content) {
  return BARE_IMPERATIVE_VERBS.has(firstToken(content));
}

function looksLikeBeImperative(content) {
  // "be re-scoped: ..." / "be set up by ..."
  return /^be\s+\w+/.test(content.trim().toLowerCase());
}

function looksLikePathLabel(content) {
  return PATH_LABEL_PATTERN.test(content.trim());
}

// Captures that escape a parenthetical leak into the title with a stray
// closing paren — e.g. the orphan "one), so they sit at `project=NULL`..."
// fragment seen in the field. If the content contains a closing paren that
// has no matching opener within the capture, the regex hit fell mid-clause.
function hasUnbalancedClosingParen(content) {
  let depth = 0;
  for (const ch of content) {
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth < 0) return true;
    }
  }
  return false;
}

function looksLikeEmailBody(content) {
  return EMAIL_BODY_TELLS.some(rx => rx.test(content));
}

function looksLikeImperativeToolCall(content) {
  return IMPERATIVE_TOOL_CALL_PATTERNS.some(rx => rx.test(content));
}

function precedingTokens(haystack, needle, count) {
  // Return the last `count` tokens immediately before `needle` in `haystack`,
  // lowercased. Empty array if needle isn't found.
  const idx = haystack.indexOf(needle);
  if (idx <= 0) return [];
  const before = haystack.slice(0, idx).trim();
  if (!before) return [];
  const tokens = before.split(/\s+/);
  return tokens.slice(-count).map(t => t.toLowerCase().replace(/[^a-z']/g, ''));
}

function hasLeadingNegation(segment, conversationText) {
  if (!conversationText || conversationText === segment.content) return false;
  // Look at up to the 3 tokens immediately preceding the captured content.
  const prev = precedingTokens(conversationText, segment.content, 3);
  return prev.some(t => NEGATION_TOKENS.has(t));
}

/**
 * Apply rejection rules to an extracted segment.
 *
 * @param {{ title: string, content: string, extractorType?: string }} segment
 * @param {string} [conversationText] — optional source text. When provided,
 *   enables the negation-scope check (looking 3 tokens before the segment
 *   for words like "never" / "don't"). Without it, the in-content
 *   bare-imperative-verb check is the fallback.
 * @returns {{ rejected: boolean, reason: string }}
 */
export function shouldRejectCandidate(segment, conversationText) {
  const content = segment.content || '';

  if (looksLikeImperativeToolCall(content)) {
    return { rejected: true, reason: 'imperative_tool_call' };
  }
  if (looksLikeEmailBody(content)) {
    return { rejected: true, reason: 'email_body_content' };
  }
  if (looksLikePathLabel(content)) {
    return { rejected: true, reason: 'path_label_fragment' };
  }
  if (hasUnbalancedClosingParen(content)) {
    return { rejected: true, reason: 'unbalanced_close_paren' };
  }
  if (looksLikeBareImperative(content)) {
    return { rejected: true, reason: 'bare_imperative_verb' };
  }
  if (looksLikeBeImperative(content)) {
    return { rejected: true, reason: 'be_imperative_start' };
  }
  if (hasLeadingNegation(segment, conversationText)) {
    return { rejected: true, reason: 'negation_scope' };
  }
  // Issue #49 fragment defects:
  if (beginsWithContinuation(content)) {
    return { rejected: true, reason: 'continuation_start' };
  }
  if (endsWithInterrogative(content)) {
    return { rejected: true, reason: 'interrogative' };
  }
  if (meaningfulTokenCount(content) < MIN_MEANINGFUL_TOKENS) {
    return { rejected: true, reason: 'too_few_tokens' };
  }
  if (looksLikeBareClause(content)) {
    return { rejected: true, reason: 'bare_clause' };
  }
  if (looksLikeFragment(content)) {
    return { rejected: true, reason: 'subordinate_start_fragment' };
  }
  return { rejected: false, reason: '' };
}

export function calculateOverlap(text1, text2) {
  const words1 = new Set(text1.toLowerCase().split(/\s+/));
  const words2 = new Set(text2.toLowerCase().split(/\s+/));
  const intersection = new Set([...words1].filter((w) => words2.has(w)));
  const union = new Set([...words1, ...words2]);
  return intersection.size / union.size;
}

/**
 * Score segments, dedupe by content overlap, apply frequency boost,
 * filter by category-aware threshold, and return the top MAX_AUTO_MEMORIES.
 *
 * @param {Array<{title: string, content: string, extractorType: string}>} segments
 * @param {number} dynamicThreshold
 * @param {{ hookTag?: string|null, maxMemories?: number, categoryThresholds?: Record<string, number>, applyFrequencyBoost?: boolean, conversationText?: string }} [opts]
 */
export function processSegments(segments, dynamicThreshold = BASE_THRESHOLD, opts = {}) {
  const hookTag = opts.hookTag ?? null;
  const maxMemories = opts.maxMemories ?? MAX_AUTO_MEMORIES;
  const categoryThresholds = opts.categoryThresholds ?? DEFAULT_CATEGORY_THRESHOLDS;
  const applyFrequencyBoost = opts.applyFrequencyBoost ?? true;
  const conversationText = opts.conversationText;

  // Rejection: structural malformations (negation drop, fragments,
  // imperative tool-calls, email-body bleed). Applied *before* dedup so
  // rejected candidates never compete for slots.
  const surviving = segments.filter(seg => !shouldRejectCandidate(seg, conversationText).rejected);
  segments = surviving;
  const unique = [];

  for (const seg of segments) {
    const isDupe = unique.some((existing) => calculateOverlap(existing.content, seg.content) > 0.8);
    if (!isDupe) {
      const text = seg.title + ' ' + seg.content;
      const baseSalience = calculateSalience(text);
      // v4.25.0: extractorType drives category and memory_purpose. Fall
      // back to keyword-based suggestCategory only when extractorType is
      // unknown (defensive; no in-tree extractor produces a name outside
      // EXTRACTOR_TO_CATEGORY).
      const category = EXTRACTOR_TO_CATEGORY[seg.extractorType] ?? suggestCategory(text);
      const memoryPurpose = EXTRACTOR_TO_PURPOSE[seg.extractorType] ?? 'project';
      unique.push({
        ...seg,
        baseSalience,
        category,
        memoryPurpose,
        tags: extractTags(text, hookTag, seg.extractorType),
      });
    }
  }

  for (const seg of unique) {
    const frequencyBoost = applyFrequencyBoost ? calculateFrequencyBoost(seg, unique) : 0;
    // The fragment penalty is applied AFTER the cap so a high-keyword fragment
    // can't tie a complete fact at the ceiling — a self-contained fact always
    // out-ranks an otherwise-equivalent fragment (Jarvis P2). The STORED salience
    // carries the penalty (so it ranks lower at recall too), but the SURVIVAL
    // gate below uses the UN-penalised value so the penalty can only re-rank,
    // never silently drop a memory that would otherwise be kept (review 2026-06-08).
    const capped = Math.min(AUTO_EXTRACT_SALIENCE_CAP, seg.baseSalience + frequencyBoost);
    seg.gateSalience = capped;
    seg.salience = Math.max(0, capped + completenessAdjustment(seg.content));
    seg.frequencyBoost = frequencyBoost;
  }

  unique.sort((a, b) => b.salience - a.salience);

  const filtered = unique.filter((seg) => {
    const threshold = getExtractionThreshold(seg.category, dynamicThreshold, categoryThresholds);
    return seg.gateSalience >= threshold;
  });

  return filtered.slice(0, maxMemories);
}
