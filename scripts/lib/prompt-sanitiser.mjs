/**
 * Prompt sanitisation for ShieldCortex hooks.
 *
 * Strips framework-injected metadata wrappers from the start of a prompt so
 * downstream consumers (e.g. the FTS5 query builder in prompt-recall-hook.mjs)
 * search on the user's actual words, not on metadata terms like
 * "conversation", "info", "untrusted", "metadata", "json", "chat_id".
 *
 * The motivating case: OpenClaw's Telegram channel wraps every incoming
 * message with:
 *
 *     Conversation info (untrusted metadata):
 *     ```json
 *     { "chat_id": "telegram:…", "message_id": "…", … }
 *     ```
 *     <real user text>
 *
 * Without sanitisation the recall hook's first-6-words-of-prompt query never
 * sees the real user text and recall returns no relevant memories. The
 * resulting symptom is the agent (e.g. Edith) "forgetting" prior conversation
 * context and asking the user to clarify pronoun references.
 *
 * This sanitiser is conservative — it only strips wrappers we have verified
 * in the wild. New patterns require new branches and tests.
 */

// Header patterns that introduce a discardable metadata block at the top of
// a prompt. Each entry is matched case-insensitively against the start of
// the (trimmed) prompt. Order is irrelevant — at most one matches per call.
const HEADER_PATTERNS = [
  // OpenClaw Telegram channel wrapper. Header line ends with a colon, then
  // a fenced ``` (any language tag) JSON block, then the real user content.
  /^conversation info\s*\([^)]*\)\s*:\s*\n+/i,
  /^conversation info\s*:\s*\n+/i,
];

// Fenced code blocks at the start of a prompt that follow the header. We
// strip the entire fence (including its content) so metadata key names like
// "chat_id", "message_id", "sender_id" don't leak into the FTS query.
const LEADING_FENCE = /^```[a-zA-Z0-9_-]*\n[\s\S]*?\n```\s*\n*/;

/**
 * Strip framework metadata wrappers from a prompt.
 *
 * @param {string} prompt
 * @returns {string} sanitised prompt — may be empty if the entire prompt
 *   was metadata. Never null/undefined.
 */
export function sanitisePromptForRecall(prompt) {
  if (typeof prompt !== 'string' || prompt.length === 0) return '';

  let working = prompt;

  // 1) Strip a leading metadata header line (e.g. "Conversation info (untrusted metadata):").
  for (const pattern of HEADER_PATTERNS) {
    if (pattern.test(working)) {
      working = working.replace(pattern, '');
      break;
    }
  }

  // 2) If the next thing is a fenced code block, strip it as one unit.
  //    We only do this when a header was actually consumed in step 1 — a
  //    bare fenced block at the start of an unwrapped user prompt may be
  //    intentional content (e.g. a code snippet the user is asking about).
  if (working !== prompt && LEADING_FENCE.test(working)) {
    working = working.replace(LEADING_FENCE, '');
  }

  return working.trim();
}
