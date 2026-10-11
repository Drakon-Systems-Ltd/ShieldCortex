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
 * OpenClaw 2026.9.x (#717) replaced that wrapper with marker-keyed blocks —
 * `Conversation info: ⟦openclaw:ctx⟧` + a JSON fence, then a multi-KB
 * `Conversation context (chronological, selected for current message):
 * ⟦openclaw:ctx⟧` history block — with the current user message last. Left in
 * place, the history block made every recall query about the envelope and the
 * assistant's own previous replies rather than about what the user just said.
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

// ── OpenClaw 2026.9.x envelope (#717) ────────────────────────────────────
// Every OpenClaw-injected context header now ends with this provenance marker
// (OpenClaw's INBOUND_CONTEXT_MARKER — U+27E6 "openclaw:ctx" U+27E7). Keying
// on the marker rather than the label text is what OpenClaw's own stripper
// does, so new labels ("Thread starter:", "Reply target of current user
// message:", "Conversation context (chronological, selected for current
// message):", ...) are covered without a branch each.
const OPENCLAW_CTX_MARKER = '\u27E6openclaw:ctx\u27E7';
// Trailing channel-context suffix: from this line to the end is metadata.
const OPENCLAW_TRAILING_CONTEXT_HEADER = `Context: ${OPENCLAW_CTX_MARKER}`;
// Leading "[Fri 2026-10-10 12:48 UTC] " envelope timestamp.
const LEADING_TIMESTAMP_PREFIX = /^\[[A-Za-z]{3} \d{4}-\d{2}-\d{2} \d{2}:\d{2}[^\]]*\] */;
// Per-turn delivery hints OpenClaw prepends ("Delivery: ... `message` tool ...").
const DELIVERY_HINT_LINE = /^Delivery: .*`message` tool/;
// Session goal line OpenClaw adds between the context blocks and the message.
const ACTIVE_GOAL_LINE = /^Active goal: .* — advance; keep active until fully achieved;/;

// A marker header is a label line: "<Label>: ⟦openclaw:ctx⟧" and nothing else.
// Shape alone is not proof — an owner can type that line — so a header only
// counts once its block is also closed (see stripOpenClawEnvelope).
const OPENCLAW_HEADER_LINE = /^[A-Z][^:\n`\u27E6\u27E7]{0,120}:[ \t]*\u27E6openclaw:ctx\u27E7$/;
const FENCE_LINE = /^```/;

function isOpenClawHeaderLine(line) {
  return OPENCLAW_HEADER_LINE.test(line.trim());
}

function isJsonObjectText(text) {
  try {
    const parsed = JSON.parse(text);
    return parsed !== null && typeof parsed === 'object';
  } catch {
    return false;
  }
}

/**
 * Index of the trailing "Context: <marker>" suffix header in `lines`, or -1.
 * The owner's own code fences are opaque: a header inside one is quoted text,
 * not the channel suffix. Only called after a verified envelope was consumed,
 * so the header may open `lines` (an empty user message) or follow a blank
 * line — never sit glued to the end of an owner sentence.
 */
function findTrailingContextHeader(lines) {
  let inFence = false;
  for (let k = 0; k < lines.length; k += 1) {
    const trimmed = lines[k].trim();
    if (FENCE_LINE.test(trimmed)) {
      inFence = !inFence;
      continue;
    }
    if (inFence) continue;
    if (trimmed === OPENCLAW_TRAILING_CONTEXT_HEADER && (k === 0 || lines[k - 1].trim() === '')) return k;
  }
  return -1;
}

/**
 * Strip the leading run of OpenClaw-injected blocks and return the trailing
 * current user message. Mirrors OpenClaw's stripLeadingInboundMetadata:
 *   - a marker header followed by a ```json fence ends at the closing ```;
 *   - any other marker header (e.g. the multi-KB "Conversation context"
 *     history) ends at the first blank line — OpenClaw collapses every
 *     history body to a single line, so a blank line cannot occur inside it.
 *
 * #720 (Tars): only a COMPLETE, verified envelope is stripped. The leading
 * run must contain at least one marker block whose ```json fence closes and
 * parses as JSON (OpenClaw always opens with "Conversation info:"), and every
 * marker block in the run must be closed — a fence with no closer, or a
 * history block that runs to EOF, means the "envelope" is really the owner's
 * text, and the whole prompt is preserved. Returns null when nothing was
 * stripped (caller falls back to the legacy patterns).
 */
function stripOpenClawEnvelope(prompt) {
  if (!prompt.includes(OPENCLAW_CTX_MARKER)) return null;
  const lines = prompt.replace(/\r\n/g, '\n').split('\n');
  let i = 0;
  let verifiedJsonBlock = false;
  const skipBlank = () => { while (i < lines.length && lines[i].trim() === '') i += 1; };

  for (;;) {
    skipBlank();
    if (i >= lines.length) break;
    const line = lines[i];
    if (DELIVERY_HINT_LINE.test(line.trim()) || ACTIVE_GOAL_LINE.test(line.trim())) {
      i += 1;
      continue;
    }
    // The trailing suffix header ends the leading run; it is cut below.
    if (line.trim() === OPENCLAW_TRAILING_CONTEXT_HEADER || !isOpenClawHeaderLine(line)) break;
    i += 1;
    if (lines[i] !== undefined && /^```json\s*$/.test(lines[i].trim())) {
      const bodyStart = i + 1;
      let close = bodyStart;
      while (close < lines.length && lines[close].trim() !== '```') close += 1;
      if (close >= lines.length) return null; // unclosed fence: owner text
      if (!isJsonObjectText(lines.slice(bodyStart, close).join('\n'))) return null;
      verifiedJsonBlock = true;
      i = close + 1; // past the closing fence
    } else {
      const bodyStart = i;
      while (i < lines.length && lines[i].trim() !== '') i += 1;
      // Empty, or running to EOF with no blank terminator: not a closed block.
      if (i === bodyStart || i >= lines.length) return null;
    }
  }
  if (!verifiedJsonBlock) return null;

  let rest = lines.slice(i);
  // Trailing "Context: <marker>" suffix block runs to the end of the prompt.
  const suffixAt = findTrailingContextHeader(rest);
  if (suffixAt >= 0) rest = rest.slice(0, suffixAt);

  // Telegram reply turns: "Current message:\n[Replying to: \"…\"]\n#<id>: <text>".
  // The quoted text is someone else's words; only the text after "#<id>:" is
  // the user's.
  if (rest[0]?.trim() === 'Current message:') {
    rest = rest.slice(1);
    if (/^\[Replying to: /.test(rest[0] ?? '')) rest = rest.slice(1);
    if (rest.length > 0) rest[0] = rest[0].replace(/^#[^\s:]+:\s?/, '');
  }

  const out = rest.join('\n').replace(LEADING_TIMESTAMP_PREFIX, '');
  // A marker that only appears inside the user's own text (quoted, pasted)
  // consumes nothing — let the legacy patterns have their turn.
  return out === prompt ? null : out;
}

/**
 * Strip framework metadata wrappers from a prompt.
 *
 * @param {string} prompt
 * @returns {string} sanitised prompt — may be empty if the entire prompt
 *   was metadata. Never null/undefined.
 */
export function sanitisePromptForRecall(prompt) {
  if (typeof prompt !== 'string' || prompt.length === 0) return '';

  // 0) OpenClaw 2026.9.x marker-keyed envelope (#717). When it matches, the
  //    remainder is the current user message and the legacy patterns below
  //    have nothing left to do.
  const fromEnvelope = stripOpenClawEnvelope(prompt);
  if (fromEnvelope !== null) return fromEnvelope.trim();

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
