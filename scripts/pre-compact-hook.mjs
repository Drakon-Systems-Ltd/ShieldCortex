#!/usr/bin/env node
/**
 * Pre-compact hook for ShieldCortex - Automatic Memory Extraction
 *
 * This script runs before context compaction and:
 * 1. Analyzes conversation content for important information
 * 2. Auto-extracts high-salience items (decisions, patterns, errors, etc.)
 * 3. Saves them to the memory database automatically
 * 4. Creates a session marker for continuity
 *
 * The goal: Never lose important context during compaction.
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { encodeClaudeProjectDir } from './lib/claude-project-dir.mjs';
import { saveAutoExtractedMemory } from './lib/save-memory.mjs';
import { readTranscriptText } from './lib/transcript-reader.mjs';
import { getAutoMemoryConfig } from './lib/auto-memory-config.mjs';
import { recordHookInvocation } from './lib/telemetry.mjs';

// Database paths (with legacy fallback)
const NEW_DB_DIR = join(homedir(), '.shieldcortex');
const LEGACY_DB_DIR = join(homedir(), '.claude-cortex');

// Auto-detect: use new path if it exists, or if legacy doesn't exist (new install)
function getDbPath() {
  const newPath = join(NEW_DB_DIR, 'memories.db');
  const legacyPath = join(LEGACY_DB_DIR, 'memories.db');
  if (existsSync(newPath) || !existsSync(legacyPath)) {
    return { dir: NEW_DB_DIR, path: newPath };
  }
  return { dir: LEGACY_DB_DIR, path: legacyPath };
}

const { dir: DB_DIR, path: DB_PATH } = getDbPath();

// Memory limits (should match src/memory/types.ts DEFAULT_CONFIG)
const MAX_SHORT_TERM_MEMORIES = 100;
const MAX_LONG_TERM_MEMORIES = 1000;

// Base salience threshold (will be adjusted dynamically)
// Lowered from 0.45 to capture more content
const BASE_THRESHOLD = 0.35;

// Category-specific extraction thresholds (lower = easier to extract).
// Raised +0.1 across the board in v4.11.0 after fleet evidence showed the
// previous permissive thresholds produced ~5% signal and flooded recall with
// noise. Prefer missing a marginal memory to saving a noisy one.
const CATEGORY_EXTRACTION_THRESHOLDS = {
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

// ==================== PROJECT DETECTION (Mirrors src/context/project-context.ts) ====================

/** Directories to skip when extracting project name from path */
const SKIP_DIRECTORIES = [
  'src', 'lib', 'dist', 'build', 'out',
  'node_modules', '.git', '.next', '.cache',
  'test', 'tests', '__tests__', 'spec',
  'bin', 'scripts', 'config', 'public', 'static',
];

/**
 * Extract project name from a file path.
 * Skips common directory names that don't represent projects.
 */
function extractProjectFromPath(path) {
  if (!path) return null;

  const segments = path.split(/[/\\]/).filter(Boolean);
  if (segments.length === 0) return null;

  // Start from the end and find first non-skipped segment
  for (let i = segments.length - 1; i >= 0; i--) {
    const segment = segments[i];
    if (!SKIP_DIRECTORIES.includes(segment.toLowerCase())) {
      // Skip hidden directories (starting with .)
      if (segment.startsWith('.')) continue;
      return segment;
    }
  }

  return null;
}

// Maximum memories to auto-create per compaction.
// Dropped 5 → 2 in v4.11.0 for the same reason thresholds were raised.
const MAX_AUTO_MEMORIES = 2;

// ==================== DYNAMIC THRESHOLD CALCULATION ====================

/**
 * Get current memory stats from database
 */
function getMemoryStats(db) {
  try {
    const stats = db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN type = 'short_term' THEN 1 ELSE 0 END) as shortTerm,
        SUM(CASE WHEN type = 'long_term' THEN 1 ELSE 0 END) as longTerm
      FROM memories
    `).get();
    return stats || { total: 0, shortTerm: 0, longTerm: 0 };
  } catch {
    return { total: 0, shortTerm: 0, longTerm: 0 };
  }
}

/**
 * Calculate dynamic threshold based on memory fullness
 * When memory is full, be more selective. When sparse, be more permissive.
 * Lowered thresholds to capture more content.
 */
function getDynamicThreshold(memoryCount, maxMemories) {
  const fullness = memoryCount / maxMemories;

  // More selective when memory is full, more permissive when sparse
  if (fullness > 0.8) return 0.50;  // Very full - highly selective
  if (fullness > 0.6) return 0.42;  // Getting full - moderately selective
  if (fullness > 0.4) return 0.35;  // Normal - standard threshold
  if (fullness > 0.2) return 0.30;  // Sparse - more permissive
  return 0.25;                       // Very sparse - accept most valuable items
}

/**
 * Get extraction threshold for a specific category
 * Combines dynamic threshold with category-specific adjustments
 */
function getExtractionThreshold(category, dynamicThreshold) {
  const categoryThreshold = CATEGORY_EXTRACTION_THRESHOLDS[category] || BASE_THRESHOLD;
  // Use whichever is lower (more permissive for valuable categories when memory is sparse)
  return Math.min(categoryThreshold, dynamicThreshold);
}

// ==================== SALIENCE DETECTION (Mirrors src/memory/salience.ts) ====================

const ARCHITECTURE_KEYWORDS = [
  'architecture', 'design', 'pattern', 'structure', 'system',
  'database', 'api', 'schema', 'model', 'framework', 'stack',
  'microservice', 'monolith', 'serverless', 'infrastructure'
];

const ERROR_KEYWORDS = [
  'error', 'bug', 'fix', 'issue', 'problem', 'crash', 'fail',
  'exception', 'debug', 'resolve', 'solution', 'workaround'
];

const PREFERENCE_KEYWORDS = [
  'prefer', 'always', 'never', 'style', 'convention', 'standard',
  'like', 'want', 'should', 'must', 'require'
];

const PATTERN_KEYWORDS = [
  'pattern', 'practice', 'approach', 'method', 'technique',
  'implementation', 'strategy', 'algorithm', 'workflow'
];

const DECISION_KEYWORDS = [
  'decided', 'decision', 'chose', 'chosen', 'selected', 'going with',
  'will use', 'opted for', 'settled on', 'agreed'
];

const LEARNING_KEYWORDS = [
  'learned', 'discovered', 'realized', 'found out', 'turns out',
  'TIL', 'now know', 'understand now', 'figured out'
];

const EMOTIONAL_MARKERS = [
  'important', 'critical', 'crucial', 'essential', 'key',
  'finally', 'breakthrough', 'eureka', 'aha', 'got it',
  'frustrating', 'annoying', 'tricky', 'remember'
];

const CODE_REFERENCE_PATTERNS = [
  /\b[A-Z][a-zA-Z]*\.[a-zA-Z]+\b/,
  /\b[a-z_][a-zA-Z0-9_]*\.(ts|js|py|go|rs)\b/,
  /`[^`]+`/,
  /\b(function|class|interface|type|const|let|var)\s+\w+/i,
  /\bline\s*\d+\b/i,
  /\b(src|lib|app|components?)\/\S+/,
];

function detectKeywords(text, keywords) {
  const lower = text.toLowerCase();
  return keywords.some(keyword => lower.includes(keyword.toLowerCase()));
}

function detectCodeReferences(content) {
  return CODE_REFERENCE_PATTERNS.some(pattern => pattern.test(content));
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
  return patterns.some(pattern => pattern.test(text));
}

function calculateSalience(text) {
  let score = 0.25; // Base score

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

function suggestCategory(text) {
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

function extractTags(text, extractorName = null) {
  const tags = new Set();

  // Extract hashtags
  const hashtagMatches = text.match(/#[a-zA-Z][a-zA-Z0-9_-]*/g);
  if (hashtagMatches) {
    hashtagMatches.forEach(tag => tags.add(tag.slice(1).toLowerCase()));
  }

  // Extract common tech terms
  const techTerms = [
    'react', 'vue', 'angular', 'node', 'python', 'typescript', 'javascript',
    'api', 'database', 'sql', 'mongodb', 'postgresql', 'mysql',
    'docker', 'kubernetes', 'aws', 'git', 'testing', 'auth', 'security'
  ];

  const lowerText = text.toLowerCase();
  techTerms.forEach(term => {
    if (lowerText.includes(term)) tags.add(term);
  });

  // Add auto-extracted tag
  tags.add('auto-extracted');

  // Add source extractor tag for tracking
  if (extractorName) {
    tags.add(`source:${extractorName}`);
  }

  return Array.from(tags).slice(0, 12);
}

/**
 * Calculate frequency boost based on how often key terms appear
 * across all extracted segments. Repeated topics are more important.
 */
function calculateFrequencyBoost(segment, allSegments) {
  // Extract key terms (words > 5 chars that aren't common)
  const commonWords = new Set([
    'about', 'after', 'before', 'being', 'between', 'could', 'during',
    'every', 'found', 'through', 'would', 'should', 'which', 'where',
    'there', 'these', 'their', 'other', 'using', 'because', 'without'
  ]);

  const words = segment.content.toLowerCase().split(/\s+/);
  const keyTerms = words.filter(w =>
    w.length > 5 &&
    !commonWords.has(w) &&
    /^[a-z]+$/.test(w)
  );

  let boost = 0;
  const seenTerms = new Set();

  for (const term of keyTerms) {
    if (seenTerms.has(term)) continue;
    seenTerms.add(term);

    // Count how many other segments mention this term
    const mentions = allSegments.filter(s =>
      s !== segment &&
      s.content.toLowerCase().includes(term)
    ).length;

    // Boost for repeated topics (cap at 5 mentions)
    if (mentions > 1) {
      boost += 0.03 * Math.min(mentions, 5);
    }
  }

  // Cap total frequency boost at 0.15
  return Math.min(0.15, boost);
}

// ==================== CONTENT EXTRACTION ====================

/**
 * Extract meaningful segments from conversation text
 * Looks for decisions, learnings, fixes, patterns, etc.
 */
function extractMemorableSegments(conversationText) {
  const segments = [];

  // Pattern matchers for different types of important content
  // Expanded patterns with lower minimum lengths for better capture
  const extractors = [
    {
      name: 'decision',
      patterns: [
        /(?:we\s+)?decided\s+(?:to\s+)?(.{15,200})/gi,
        /(?:going|went)\s+with\s+(.{15,150})/gi,
        /(?:chose|chosen|selected)\s+(.{15,150})/gi,
        /the\s+(?:approach|solution|fix)\s+(?:is|was)\s+(.{15,200})/gi,
        // New patterns
        /(?:using|will\s+use)\s+(.{15,150})/gi,
        /(?:opted\s+for|settled\s+on)\s+(.{15,150})/gi,
      ],
      titlePrefix: 'Decision: ',
    },
    {
      name: 'error-fix',
      patterns: [
        /(?:fixed|solved|resolved)\s+(?:by\s+)?(.{15,200})/gi,
        /the\s+(?:fix|solution|workaround)\s+(?:is|was)\s+(.{15,200})/gi,
        /(?:root\s+cause|issue)\s+(?:is|was)\s+(.{15,200})/gi,
        /(?:error|bug)\s+(?:was\s+)?caused\s+by\s+(.{15,200})/gi,
        // New patterns
        /(?:problem|issue)\s+was\s+(.{15,150})/gi,
        /(?:the\s+)?bug\s+(?:is|was)\s+(.{15,150})/gi,
        /(?:debugging|debugged)\s+(.{15,150})/gi,
      ],
      titlePrefix: 'Fix: ',
    },
    {
      name: 'learning',
      patterns: [
        /(?:learned|discovered|realized|found\s+out)\s+(?:that\s+)?(.{15,200})/gi,
        /turns\s+out\s+(?:that\s+)?(.{15,200})/gi,
        /(?:TIL|today\s+I\s+learned)[:\s]+(.{15,200})/gi,
        // New patterns
        /(?:now\s+)?(?:understand|know)\s+(?:that\s+)?(.{15,150})/gi,
        /(?:figured\s+out|worked\s+out)\s+(.{15,150})/gi,
      ],
      titlePrefix: 'Learned: ',
    },
    {
      name: 'architecture',
      patterns: [
        /the\s+architecture\s+(?:is|uses|consists\s+of)\s+(.{15,200})/gi,
        /(?:design|pattern)\s+(?:is|uses)\s+(.{15,200})/gi,
        /(?:system|api|database)\s+(?:structure|design)\s+(?:is|uses)\s+(.{15,200})/gi,
        // New patterns
        /(?:created|added|implemented|built)\s+(?:a\s+)?(.{15,200})/gi,
        /(?:refactored|updated|changed)\s+(?:the\s+)?(.{15,150})/gi,
      ],
      titlePrefix: 'Architecture: ',
    },
    {
      name: 'preference',
      patterns: [
        /(?:always|never)\s+(.{10,150})/gi,
        /(?:prefer|want)\s+to\s+(.{10,150})/gi,
        /(?:should|must)\s+(?:always\s+)?(.{10,150})/gi,
      ],
      titlePrefix: 'Preference: ',
    },
    {
      name: 'important-note',
      patterns: [
        /important[:\s]+(.{15,200})/gi,
        /(?:note|remember)[:\s]+(.{15,200})/gi,
        /(?:key|critical)\s+(?:point|thing)[:\s]+(.{15,200})/gi,
        // New patterns
        /(?:this\s+is\s+)?(?:crucial|essential)[:\s]+(.{15,150})/gi,
        /(?:don't\s+forget|keep\s+in\s+mind)[:\s]+(.{15,150})/gi,
      ],
      titlePrefix: 'Note: ',
    },
  ];

  for (const extractor of extractors) {
    for (const pattern of extractor.patterns) {
      let match;
      while ((match = pattern.exec(conversationText)) !== null) {
        const content = match[1].trim();
        if (content.length >= 20) {
          // Generate a title from first ~50 chars
          const titleContent = content.slice(0, 50).replace(/\s+/g, ' ').trim();
          const title = extractor.titlePrefix + (titleContent.length < 50 ? titleContent : titleContent + '...');

          segments.push({
            title,
            content: content.slice(0, 500), // Cap content length
            extractorType: extractor.name,
          });
        }
      }
    }
  }

  return segments;
}

/**
 * Deduplicate and score segments
 * @param {Array} segments - Raw extracted segments
 * @param {number} dynamicThreshold - Dynamic threshold based on memory fullness
 */
function processSegments(segments, dynamicThreshold = BASE_THRESHOLD) {
  // Remove near-duplicates (segments with >80% overlap)
  const unique = [];
  for (const seg of segments) {
    const isDupe = unique.some(existing => {
      const overlap = calculateOverlap(existing.content, seg.content);
      return overlap > 0.8;
    });
    if (!isDupe) {
      const text = seg.title + ' ' + seg.content;
      const baseSalience = calculateSalience(text);
      const category = suggestCategory(text);

      unique.push({
        ...seg,
        baseSalience,
        category,
        tags: extractTags(text, seg.extractorType),
      });
    }
  }

  // Calculate frequency boost after we have all unique segments
  for (const seg of unique) {
    const frequencyBoost = calculateFrequencyBoost(seg, unique);
    seg.salience = Math.min(1.0, seg.baseSalience + frequencyBoost);
    seg.frequencyBoost = frequencyBoost;
  }

  // Sort by salience (highest first)
  unique.sort((a, b) => b.salience - a.salience);

  // Filter by category-specific threshold (combined with dynamic threshold)
  const filtered = unique.filter(seg => {
    const threshold = getExtractionThreshold(seg.category, dynamicThreshold);
    return seg.salience >= threshold;
  });

  return filtered.slice(0, MAX_AUTO_MEMORIES);
}

/**
 * Simple overlap calculation (Jaccard similarity on words)
 */
function calculateOverlap(text1, text2) {
  const words1 = new Set(text1.toLowerCase().split(/\s+/));
  const words2 = new Set(text2.toLowerCase().split(/\s+/));

  const intersection = new Set([...words1].filter(w => words2.has(w)));
  const union = new Set([...words1, ...words2]);

  return intersection.size / union.size;
}

// ==================== DATABASE OPERATIONS ====================

// Thin wrapper to keep the existing call sites unchanged. The actual
// write lives in scripts/lib/save-memory.mjs so pre-compact and
// session-end share one code path (and one regression test).
function saveMemory(db, memory, project) {
  saveAutoExtractedMemory(db, memory, project);
}


// ==================== MAIN HOOK LOGIC ====================

let input = '';
process.stdin.setEncoding('utf8');

process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) {
    input += chunk;
  }
});

process.stdin.on('end', () => {
  const startedAt = Date.now();
  let db = null;
  let autoExtractedCount = 0;
  let bytesRead = 0;
  let exitCode = 0;
  let notes = null;
  try {
    const hookData = JSON.parse(input || '{}');

    const trigger = hookData.trigger || 'unknown';
    const project = extractProjectFromPath(hookData.cwd);
    const autoMemConfig = getAutoMemoryConfig();

    // Extract conversation text from hook data
    // Claude Code passes conversation in various formats
    const conversationOut = extractConversationText(hookData, autoMemConfig);
    const conversationText = conversationOut.text;
    bytesRead = conversationOut.bytesRead;

    // Ensure database directory exists
    if (!existsSync(DB_DIR)) {
      mkdirSync(DB_DIR, { recursive: true });
    }

    // Check if database exists
    if (!existsSync(DB_PATH)) {
      console.error('[pre-compact] Memory database not found, skipping auto-extraction');
      outputReminder(0, BASE_THRESHOLD);
      notes = 'no-database';
      process.exit(0);
    }

    // Connect to database with timeout to handle concurrent access
    // timeout: 5000ms prevents hook from hanging if DB is locked
    db = new Database(DB_PATH, { timeout: 5000 });

    // Get current memory stats for dynamic threshold calculation
    const stats = getMemoryStats(db);
    const totalMemories = stats.shortTerm + stats.longTerm;
    const maxMemories = MAX_SHORT_TERM_MEMORIES + MAX_LONG_TERM_MEMORIES;
    const dynamicThreshold = getDynamicThreshold(totalMemories, maxMemories);

    console.error(`[auto-extract] Memory status: ${totalMemories}/${maxMemories} (${(totalMemories/maxMemories*100).toFixed(0)}% full)`);
    console.error(`[auto-extract] Dynamic threshold: ${dynamicThreshold.toFixed(2)}`);

    // Only attempt extraction if we have conversation content
    if (conversationText && conversationText.length > 100) {
      // Extract memorable segments
      const segments = extractMemorableSegments(conversationText);
      const processedSegments = processSegments(segments, dynamicThreshold);

      // Save auto-extracted memories
      for (const memory of processedSegments) {
        try {
          saveMemory(db, memory, project);
          autoExtractedCount++;
          const boostInfo = memory.frequencyBoost > 0 ? ` +${memory.frequencyBoost.toFixed(2)} boost` : '';
          console.error(`[auto-extract] Saved: ${memory.title} (salience: ${memory.salience.toFixed(2)}${boostInfo}, category: ${memory.category})`);
        } catch (err) {
          console.error(`[auto-extract] Failed to save "${memory.title}": ${err.message}`);
        }
      }
    } else {
      notes = 'no-content';
    }

    console.error(`[shieldcortex] Pre-compact complete: ${autoExtractedCount} memories auto-extracted`);

    outputReminder(autoExtractedCount, dynamicThreshold);
  } catch (error) {
    console.error(`[pre-compact] Error: ${error.message}`);
    notes = `error: ${error.message}`;
    exitCode = 0; // Don't block compaction on errors
    outputReminder(0, BASE_THRESHOLD);
  } finally {
    if (db) {
      recordHookInvocation(db, {
        hookName: 'pre-compact',
        exitCode,
        durationMs: Date.now() - startedAt,
        memoriesExtracted: autoExtractedCount,
        transcriptBytes: bytesRead,
        notes,
      });
      try { db.close(); } catch { /* ignore */ }
    }
    process.exit(exitCode);
  }
});

/**
 * Resolve the most-recently-modified JSONL transcript for the given cwd
 * (Claude Code stores sessions under ~/.claude/projects/<encoded-cwd>/).
 */
function findLatestTranscriptForCwd(cwd) {
  if (!cwd) return null;
  const projectDir = join(homedir(), '.claude', 'projects', encodeClaudeProjectDir(cwd));
  if (!existsSync(projectDir)) return null;
  let files;
  try {
    files = readdirSync(projectDir)
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => ({ name: f, mtime: statSync(join(projectDir, f)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
  } catch {
    return null;
  }
  if (files.length === 0) return null;
  return join(projectDir, files[0].name);
}

/**
 * Extract conversation text from hook data, with three fallbacks:
 *   1. transcript_path supplied by Claude Code
 *   2. inline payload fields (conversation, messages, etc.)
 *   3. auto-detect latest JSONL under ~/.claude/projects/<encoded cwd>/
 *
 * Delegates JSONL parsing to scripts/lib/transcript-reader.mjs so the
 * byte-cap and slash-command rules are shared with session-end-hook.
 */
function extractConversationText(hookData, autoMemConfig) {
  const readerOpts = {
    maxBytes: autoMemConfig.maxTranscriptBytes,
    maxLines: autoMemConfig.maxTranscriptLines,
    keepSlashCommandProse: autoMemConfig.keepSlashCommandProse,
  };

  if (hookData.transcript_path) {
    const out = readTranscriptText(hookData.transcript_path, readerOpts);
    if (out.text) {
      console.error(`[auto-extract] Read ${out.messageCount} messages from transcript_path (${out.text.length} chars, ${out.bytesRead} bytes scanned)`);
      return { text: out.text, bytesRead: out.bytesRead };
    }
  }

  const sources = [
    hookData.conversation,
    hookData.messages,
    hookData.transcript,
    hookData.content,
    hookData.context,
    hookData.text,
  ];
  for (const source of sources) {
    if (typeof source === 'string' && source.length > 0) return { text: source, bytesRead: 0 };
    if (Array.isArray(source)) {
      const text = source
        .map((msg) => {
          if (typeof msg === 'string') return msg;
          if (msg.content) return msg.content;
          if (msg.text) return msg.text;
          return '';
        })
        .join('\n');
      return { text, bytesRead: 0 };
    }
  }

  const latest = findLatestTranscriptForCwd(hookData.cwd);
  if (!latest) {
    console.error('[auto-extract] No transcript located for cwd');
    return { text: '', bytesRead: 0 };
  }
  const out = readTranscriptText(latest, readerOpts);
  console.error(`[auto-extract] Read ${out.messageCount} messages from session JSONL (${out.text.length} chars, ${out.bytesRead} bytes scanned)`);
  return { text: out.text, bytesRead: out.bytesRead };
}

/**
 * Output reminder message to stdout.
 * v4.11.0: preamble instructions removed. The memories themselves are the
 * signal; repeating "use remember proactively" every compaction just eats
 * context. The one-line status note is kept for human visibility when the
 * hook runs interactively.
 */
function outputReminder(autoExtractedCount, dynamicThreshold) {
  if (autoExtractedCount > 0) {
    console.log(`\n🧠 AUTO-MEMORY: ${autoExtractedCount} item(s) saved before compaction.`);
  }
  // No stdout when nothing was extracted — silence is cheaper than chatter.
}
