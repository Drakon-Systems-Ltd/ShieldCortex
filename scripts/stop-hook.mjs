#!/usr/bin/env node

/**
 * Claude Cortex — Stop Hook
 *
 * Fires after each Claude response. Checks the last assistant message for
 * high-salience content (decisions, fixes, learnings) that should be saved
 * to memory via the `remember` tool.
 *
 * Loop prevention: If stop_hook_active is true, exits 0 immediately
 * (programmatic check, not LLM-dependent).
 *
 * Exit codes:
 *   0 = allow Claude to stop
 *   2 = block stop (stderr tells Claude to use `remember`)
 */

import { readFileSync, existsSync } from 'fs';
import { homedir } from 'os';

// ==================== SALIENCE DETECTION ====================

const DECISION_KEYWORDS = [
  'decided', 'decision', 'chose', 'chosen', 'selected', 'going with',
  'will use', 'opted for', 'settled on', 'agreed'
];

const ERROR_KEYWORDS = [
  'fixed by', 'the fix was', 'root cause', 'the bug was', 'the solution was',
  'resolved by', 'the issue was', 'workaround'
];

const LEARNING_KEYWORDS = [
  'learned that', 'discovered that', 'realized that', 'found out',
  'turns out', 'TIL', 'figured out'
];

const ARCHITECTURE_KEYWORDS = [
  'architecture uses', 'design decision', 'implemented', 'refactored to',
  'migrated from', 'created a new', 'built a'
];

const PREFERENCE_KEYWORDS = [
  'always use', 'never use', 'prefer to', 'convention is',
  'standard is', 'rule is'
];

const IMPORTANT_MARKERS = [
  'important:', 'remember:', 'key point', 'crucial:', 'note:'
];

function detectKeywords(text, keywords) {
  const lower = text.toLowerCase();
  return keywords.some(kw => lower.includes(kw.toLowerCase()));
}

/**
 * Check if text contains high-salience content worth remembering.
 * Returns a description string if yes, null if no.
 */
function detectNotableContent(text) {
  const lower = text.toLowerCase();

  if (detectKeywords(lower, DECISION_KEYWORDS)) {
    return 'A decision was made in the last response';
  }
  if (detectKeywords(lower, ERROR_KEYWORDS)) {
    return 'A bug fix or error resolution was described';
  }
  if (detectKeywords(lower, LEARNING_KEYWORDS)) {
    return 'Something new was learned or discovered';
  }
  if (detectKeywords(lower, ARCHITECTURE_KEYWORDS)) {
    return 'An architecture or design change was made';
  }
  if (detectKeywords(lower, PREFERENCE_KEYWORDS)) {
    return 'A preference or convention was stated';
  }
  if (detectKeywords(lower, IMPORTANT_MARKERS)) {
    return 'Something was marked as important';
  }

  return null;
}

/**
 * Read the last assistant message from the transcript JSONL.
 */
function getLastAssistantMessage(transcriptPath) {
  if (!transcriptPath) return '';

  const resolved = transcriptPath.replace(/^~/, homedir());
  if (!existsSync(resolved)) return '';

  try {
    const content = readFileSync(resolved, 'utf-8');
    const lines = content.trim().split('\n');

    // Read from the end to find the last assistant message
    for (let i = lines.length - 1; i >= Math.max(0, lines.length - 20); i--) {
      try {
        const entry = JSON.parse(lines[i]);
        const role = entry.type || entry.message?.role;
        if (role === 'assistant' && entry.message?.content) {
          const msgContent = entry.message.content;
          return Array.isArray(msgContent)
            ? msgContent.filter(c => c.type === 'text').map(c => c.text).join('\n')
            : msgContent;
        }
      } catch {
        // Skip invalid lines
      }
    }
    return '';
  } catch {
    return '';
  }
}

// ==================== MAIN ====================

async function main() {
  let hookData;
  try {
    const stdin = readFileSync(0, 'utf-8');
    hookData = JSON.parse(stdin);
  } catch {
    // No stdin or invalid JSON — allow stop
    process.exit(0);
  }

  // PROGRAMMATIC LOOP PREVENTION
  // If Claude is already continuing from a stop hook, always allow stop.
  if (hookData.stop_hook_active === true) {
    process.exit(0);
  }

  // Read the last assistant message
  const lastMessage = getLastAssistantMessage(hookData.transcript_path);
  if (!lastMessage || lastMessage.length < 50) {
    // Too short to contain anything notable
    process.exit(0);
  }

  // Check for notable content
  const description = detectNotableContent(lastMessage);
  if (description) {
    // Block stop — tell Claude to use remember
    process.stderr.write(
      `Use the remember tool to save what just happened: ${description}. ` +
      `Then continue with your response.`
    );
    process.exit(2);
  }

  // Nothing notable — allow stop
  process.exit(0);
}

main().catch(() => {
  // Never crash Claude Code
  process.exit(0);
});
