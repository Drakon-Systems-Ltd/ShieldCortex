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

export function calculateSalience(text) {
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
  return Math.min(1.0, score);
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

const FULL_EXTRACTORS = [
  {
    name: 'decision',
    titlePrefix: 'Decision: ',
    patterns: [
      /(?:we\s+)?decided\s+(?:to\s+)?(.{15,200})/gi,
      /(?:going|went)\s+with\s+(.{15,150})/gi,
      /(?:chose|chosen|selected)\s+(.{15,150})/gi,
      /the\s+(?:approach|solution|fix)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:using|will\s+use)\s+(.{15,150})/gi,
      /(?:opted\s+for|settled\s+on)\s+(.{15,150})/gi,
    ],
  },
  {
    name: 'error-fix',
    titlePrefix: 'Fix: ',
    patterns: [
      /(?:fixed|solved|resolved)\s+(?:by\s+)?(.{15,200})/gi,
      /the\s+(?:fix|solution|workaround)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:root\s+cause|issue)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:error|bug)\s+(?:was\s+)?caused\s+by\s+(.{15,200})/gi,
      /(?:problem|issue)\s+was\s+(.{15,150})/gi,
      /(?:the\s+)?bug\s+(?:is|was)\s+(.{15,150})/gi,
      /(?:debugging|debugged)\s+(.{15,150})/gi,
    ],
  },
  {
    name: 'learning',
    titlePrefix: 'Learned: ',
    patterns: [
      /(?:learned|discovered|realized|found\s+out)\s+(?:that\s+)?(.{15,200})/gi,
      /turns\s+out\s+(?:that\s+)?(.{15,200})/gi,
      /(?:TIL|today\s+I\s+learned)[:\s]+(.{15,200})/gi,
      /(?:now\s+)?(?:understand|know)\s+(?:that\s+)?(.{15,150})/gi,
      /(?:figured\s+out|worked\s+out)\s+(.{15,150})/gi,
    ],
  },
  {
    name: 'architecture',
    titlePrefix: 'Architecture: ',
    patterns: [
      /the\s+architecture\s+(?:is|uses|consists\s+of)\s+(.{15,200})/gi,
      /(?:design|pattern)\s+(?:is|uses)\s+(.{15,200})/gi,
      /(?:system|api|database)\s+(?:structure|design)\s+(?:is|uses)\s+(.{15,200})/gi,
      /(?:created|added|implemented|built)\s+(?:a\s+)?(.{15,200})/gi,
      /(?:refactored|updated|changed)\s+(?:the\s+)?(.{15,150})/gi,
    ],
  },
  {
    name: 'preference',
    titlePrefix: 'Preference: ',
    patterns: [
      /(?:always|never)\s+(.{10,150})/gi,
      /(?:prefer|want)\s+to\s+(.{10,150})/gi,
      /(?:should|must)\s+(?:always\s+)?(.{10,150})/gi,
    ],
  },
  {
    name: 'important-note',
    titlePrefix: 'Note: ',
    patterns: [
      /important[:\s]+(.{15,200})/gi,
      /(?:note|remember)[:\s]+(.{15,200})/gi,
      /(?:key|critical)\s+(?:point|thing)[:\s]+(.{15,200})/gi,
      /(?:this\s+is\s+)?(?:crucial|essential)[:\s]+(.{15,150})/gi,
      /(?:don't\s+forget|keep\s+in\s+mind)[:\s]+(.{15,150})/gi,
    ],
  },
];

// stop-hook historically used a thinner extractor set (no architecture,
// no important-note, fewer learning + preference patterns). Preserve the
// pre-refactor surface so its behaviour does not change with this move.
const STOP_HOOK_EXTRACTORS = [
  FULL_EXTRACTORS[0], // decision
  {
    name: 'error-fix',
    titlePrefix: 'Fix: ',
    patterns: [
      /(?:fixed|solved|resolved)\s+(?:by\s+)?(.{15,200})/gi,
      /the\s+(?:fix|solution|workaround)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:root\s+cause|issue)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:error|bug)\s+(?:was\s+)?caused\s+by\s+(.{15,200})/gi,
    ],
  },
  {
    name: 'learning',
    titlePrefix: 'Learned: ',
    patterns: [
      /(?:learned|discovered|realized|found\s+out)\s+(?:that\s+)?(.{15,200})/gi,
      /turns\s+out\s+(?:that\s+)?(.{15,200})/gi,
      /(?:figured\s+out|worked\s+out)\s+(.{15,150})/gi,
    ],
  },
  {
    name: 'preference',
    titlePrefix: 'Preference: ',
    patterns: [
      /(?:always|never)\s+(.{10,150})/gi,
      /(?:prefer|want)\s+to\s+(.{10,150})/gi,
    ],
  },
];

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

  for (const extractor of extractors) {
    for (const pattern of extractor.patterns) {
      // Reset lastIndex defensively — patterns are module-level globals.
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(conversationText)) !== null) {
        const content = match[1].trim();
        if (content.length >= 20) {
          const titleContent = content.slice(0, 50).replace(/\s+/g, ' ').trim();
          const title = extractor.titlePrefix + (titleContent.length < 50 ? titleContent : titleContent + '...');
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
  if (looksLikeBareImperative(content)) {
    return { rejected: true, reason: 'bare_imperative_verb' };
  }
  if (looksLikeBeImperative(content)) {
    return { rejected: true, reason: 'be_imperative_start' };
  }
  if (hasLeadingNegation(segment, conversationText)) {
    return { rejected: true, reason: 'negation_scope' };
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
      const category = suggestCategory(text);
      unique.push({
        ...seg,
        baseSalience,
        category,
        tags: extractTags(text, hookTag, seg.extractorType),
      });
    }
  }

  for (const seg of unique) {
    const frequencyBoost = applyFrequencyBoost ? calculateFrequencyBoost(seg, unique) : 0;
    seg.salience = Math.min(AUTO_EXTRACT_SALIENCE_CAP, seg.baseSalience + frequencyBoost);
    seg.frequencyBoost = frequencyBoost;
  }

  unique.sort((a, b) => b.salience - a.salience);

  const filtered = unique.filter((seg) => {
    const threshold = getExtractionThreshold(seg.category, dynamicThreshold, categoryThresholds);
    return seg.salience >= threshold;
  });

  return filtered.slice(0, maxMemories);
}
