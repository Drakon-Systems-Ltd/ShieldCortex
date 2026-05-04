#!/usr/bin/env node
/**
 * Session-end hook for ShieldCortex - Automatic Memory Extraction on Exit
 *
 * This script runs when a Claude Code session ends and:
 * 1. Reads the session transcript from the JSONL file
 * 2. Analyzes conversation content for important information
 * 3. Auto-extracts high-salience items (decisions, patterns, errors, etc.)
 * 4. Saves them to the memory database automatically
 *
 * NOTE: SessionEnd doesn't always fire reliably (e.g. terminal killed, SSH drops).
 * PreCompact remains the primary safety net for context preservation.
 *
 * Input (stdin JSON):
 * {
 *   "session_id": "abc123",
 *   "transcript_path": "~/.claude/projects/.../abc.jsonl",
 *   "cwd": "/path/to/project",
 *   "hook_event_name": "SessionEnd",
 *   "reason": "exit" | "clear" | "logout" | "prompt_input_exit" | "other"
 * }
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { saveAutoExtractedMemory } from './lib/save-memory.mjs';
import { readTranscriptText } from './lib/transcript-reader.mjs';
import { getAutoMemoryConfig } from './lib/auto-memory-config.mjs';
import { recordHookInvocation } from './lib/telemetry.mjs';

// Database paths (with legacy fallback)
const NEW_DB_DIR = join(homedir(), '.shieldcortex');
const LEGACY_DB_DIR = join(homedir(), '.claude-cortex');

function getDbPath() {
  const newPath = join(NEW_DB_DIR, 'memories.db');
  const legacyPath = join(LEGACY_DB_DIR, 'memories.db');
  if (existsSync(newPath) || !existsSync(legacyPath)) {
    return { dir: NEW_DB_DIR, path: newPath };
  }
  return { dir: LEGACY_DB_DIR, path: legacyPath };
}

const { dir: DB_DIR, path: DB_PATH } = getDbPath();

// Memory limits
const MAX_SHORT_TERM_MEMORIES = 100;
const MAX_LONG_TERM_MEMORIES = 1000;
const BASE_THRESHOLD = 0.35;
const MAX_AUTO_MEMORIES = 5;

const CATEGORY_EXTRACTION_THRESHOLDS = {
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

// ==================== PROJECT DETECTION ====================

const SKIP_DIRECTORIES = [
  'src', 'lib', 'dist', 'build', 'out',
  'node_modules', '.git', '.next', '.cache',
  'test', 'tests', '__tests__', 'spec',
  'bin', 'scripts', 'config', 'public', 'static',
];

function extractProjectFromPath(path) {
  if (!path) return null;
  const segments = path.split(/[/\\]/).filter(Boolean);
  if (segments.length === 0) return null;
  for (let i = segments.length - 1; i >= 0; i--) {
    const segment = segments[i];
    if (!SKIP_DIRECTORIES.includes(segment.toLowerCase())) {
      if (segment.startsWith('.')) continue;
      return segment;
    }
  }
  return null;
}

// ==================== DYNAMIC THRESHOLD ====================

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

function getDynamicThreshold(memoryCount, maxMemories) {
  const fullness = memoryCount / maxMemories;
  if (fullness > 0.8) return 0.50;
  if (fullness > 0.6) return 0.42;
  if (fullness > 0.4) return 0.35;
  if (fullness > 0.2) return 0.30;
  return 0.25;
}

function getExtractionThreshold(category, dynamicThreshold) {
  const categoryThreshold = CATEGORY_EXTRACTION_THRESHOLDS[category] || BASE_THRESHOLD;
  return Math.min(categoryThreshold, dynamicThreshold);
}

// ==================== SALIENCE DETECTION ====================

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
  const hashtagMatches = text.match(/#[a-zA-Z][a-zA-Z0-9_-]*/g);
  if (hashtagMatches) {
    hashtagMatches.forEach(tag => tags.add(tag.slice(1).toLowerCase()));
  }
  const techTerms = [
    'react', 'vue', 'angular', 'node', 'python', 'typescript', 'javascript',
    'api', 'database', 'sql', 'mongodb', 'postgresql', 'mysql',
    'docker', 'kubernetes', 'aws', 'git', 'testing', 'auth', 'security'
  ];
  const lowerText = text.toLowerCase();
  techTerms.forEach(term => {
    if (lowerText.includes(term)) tags.add(term);
  });
  tags.add('auto-extracted');
  tags.add('session-end');
  if (extractorName) {
    tags.add(`source:${extractorName}`);
  }
  return Array.from(tags).slice(0, 12);
}

function calculateFrequencyBoost(segment, allSegments) {
  const commonWords = new Set([
    'about', 'after', 'before', 'being', 'between', 'could', 'during',
    'every', 'found', 'through', 'would', 'should', 'which', 'where',
    'there', 'these', 'their', 'other', 'using', 'because', 'without'
  ]);
  const words = segment.content.toLowerCase().split(/\s+/);
  const keyTerms = words.filter(w =>
    w.length > 5 && !commonWords.has(w) && /^[a-z]+$/.test(w)
  );
  let boost = 0;
  const seenTerms = new Set();
  for (const term of keyTerms) {
    if (seenTerms.has(term)) continue;
    seenTerms.add(term);
    const mentions = allSegments.filter(s =>
      s !== segment && s.content.toLowerCase().includes(term)
    ).length;
    if (mentions > 1) {
      boost += 0.03 * Math.min(mentions, 5);
    }
  }
  return Math.min(0.15, boost);
}

// ==================== CONTENT EXTRACTION ====================

function extractMemorableSegments(conversationText) {
  const segments = [];
  const extractors = [
    {
      name: 'decision',
      patterns: [
        /(?:we\s+)?decided\s+(?:to\s+)?(.{15,200})/gi,
        /(?:going|went)\s+with\s+(.{15,150})/gi,
        /(?:chose|chosen|selected)\s+(.{15,150})/gi,
        /the\s+(?:approach|solution|fix)\s+(?:is|was)\s+(.{15,200})/gi,
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

function processSegments(segments, dynamicThreshold = BASE_THRESHOLD) {
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

  for (const seg of unique) {
    const frequencyBoost = calculateFrequencyBoost(seg, unique);
    seg.salience = Math.min(1.0, seg.baseSalience + frequencyBoost);
    seg.frequencyBoost = frequencyBoost;
  }

  unique.sort((a, b) => b.salience - a.salience);

  const filtered = unique.filter(seg => {
    const threshold = getExtractionThreshold(seg.category, dynamicThreshold);
    return seg.salience >= threshold;
  });

  return filtered.slice(0, MAX_AUTO_MEMORIES);
}

function calculateOverlap(text1, text2) {
  const words1 = new Set(text1.toLowerCase().split(/\s+/));
  const words2 = new Set(text2.toLowerCase().split(/\s+/));
  const intersection = new Set([...words1].filter(w => words2.has(w)));
  const union = new Set([...words1, ...words2]);
  return intersection.size / union.size;
}

// ==================== DATABASE OPERATIONS ====================

// Thin wrapper to keep the existing call sites unchanged.
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

function looksLikeOpenClawContext() {
  // OpenClaw spawns Claude Code agents as subprocesses. When SessionEnd fires
  // inside that subprocess, the OpenClaw runtime has often already torn down
  // shared state (lock files, IPC channels) — extracting from there has caused
  // fatal failures historically (settings-hooks.ts:23-25). Detect via env.
  if (process.env.OPENCLAW_AGENT_ID) return true;
  if (process.env.OPENCLAW_SESSION_ID) return true;
  if (process.env.OPENCLAW_PARENT_PID) return true;
  if (typeof process.env.OPENCLAW === 'string' && process.env.OPENCLAW.length > 0) return true;
  return false;
}

process.stdin.on('end', () => {
  const startedAt = Date.now();
  let db = null;
  let autoExtractedCount = 0;
  let bytesRead = 0;
  let notes = null;
  try {
    const hookData = JSON.parse(input || '{}');

    const reason = hookData.reason || 'unknown';
    const project = extractProjectFromPath(hookData.cwd);
    const autoMemConfig = getAutoMemoryConfig();

    // Config gate: opt-in (default off). Preserves the historical default
    // that protected OpenClaw users. We exit before touching the DB so a
    // disabled hook never opens better-sqlite3 — telemetry stays silent too.
    if (!autoMemConfig.enableSessionEnd) {
      console.error('[session-end] Disabled by config (autoMemory.enableSessionEnd=false)');
      process.exit(0);
    }

    // OpenClaw subprocess guard (extra defence on top of the config gate).
    if (looksLikeOpenClawContext()) {
      console.error('[session-end] OpenClaw context detected, skipping extraction');
      process.exit(0);
    }

    // Skip extraction on /clear — session is being intentionally wiped
    if (reason === 'clear') {
      console.error('[session-end] Session cleared, skipping extraction');
      notes = 'reason=clear';
      // fall through to telemetry record so 'fired but skipped' is visible
    } else {
      // Read conversation from transcript_path (provided by Claude Code)
      const transcriptOut = readTranscriptText(hookData.transcript_path, {
        maxBytes: autoMemConfig.maxTranscriptBytes,
        maxLines: autoMemConfig.maxTranscriptLines,
        keepSlashCommandProse: autoMemConfig.keepSlashCommandProse,
      });
      const conversationText = transcriptOut.text;
      bytesRead = transcriptOut.bytesRead;
      if (transcriptOut.messageCount > 0) {
        console.error(`[session-end] Read ${transcriptOut.messageCount} messages from transcript (${conversationText.length} chars, ${bytesRead} bytes scanned)`);
      }

      if (conversationText && conversationText.length >= 100) {
        // Ensure database directory exists
        if (!existsSync(DB_DIR)) {
          mkdirSync(DB_DIR, { recursive: true });
        }

        if (!existsSync(DB_PATH)) {
          console.error('[session-end] Memory database not found, skipping extraction');
          notes = 'no-database';
          process.exit(0);
        }

        db = new Database(DB_PATH, { timeout: 5000 });

        const stats = getMemoryStats(db);
        const totalMemories = stats.shortTerm + stats.longTerm;
        const maxMemories = MAX_SHORT_TERM_MEMORIES + MAX_LONG_TERM_MEMORIES;
        const dynamicThreshold = getDynamicThreshold(totalMemories, maxMemories);

        console.error(`[session-end] Memory status: ${totalMemories}/${maxMemories} (${(totalMemories/maxMemories*100).toFixed(0)}% full)`);
        console.error(`[session-end] Reason: ${reason}, Dynamic threshold: ${dynamicThreshold.toFixed(2)}`);

        // Extract memorable segments
        const segments = extractMemorableSegments(conversationText);
        const processedSegments = processSegments(segments, dynamicThreshold);

        for (const memory of processedSegments) {
          try {
            saveMemory(db, memory, project);
            autoExtractedCount++;
            const boostInfo = memory.frequencyBoost > 0 ? ` +${memory.frequencyBoost.toFixed(2)} boost` : '';
            console.error(`[session-end] Saved: ${memory.title} (salience: ${memory.salience.toFixed(2)}${boostInfo}, category: ${memory.category})`);
          } catch (err) {
            console.error(`[session-end] Failed to save "${memory.title}": ${err.message}`);
          }
        }

        console.error(`[session-end] Complete: ${autoExtractedCount} memories auto-extracted on session ${reason}`);
      } else {
        console.error('[session-end] Not enough conversation content to extract from');
        notes = 'no-content';
      }
    }
  } catch (error) {
    console.error(`[session-end] Error: ${error.message}`);
    notes = `error: ${error.message}`;
    // Don't block session exit on errors
  } finally {
    if (db) {
      recordHookInvocation(db, {
        hookName: 'session-end',
        exitCode: 0,
        durationMs: Date.now() - startedAt,
        memoriesExtracted: autoExtractedCount,
        transcriptBytes: bytesRead,
        notes,
      });
      try { db.close(); } catch { /* ignore */ }
    }
    process.exit(0);
  }
});
