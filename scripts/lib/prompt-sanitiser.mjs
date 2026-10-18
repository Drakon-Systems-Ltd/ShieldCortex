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

// Verified OpenClaw envelope labels (#720 R2). Each label is taken from
// OpenClaw's own emitters — buildInboundUserContextPrefix (appendJsonContext,
// formatChatWindowStructuredContext) and selectInboundHistoryContext — and is
// consumed ONLY with the block grammar that emitter produces. Shape alone
// ("Capitalised label: ⟦openclaw:ctx⟧") is not proof: an owner can type that
// line, so an unlisted label is the owner's text and ends the envelope.
//
// JSON blocks: "<label> ⟦openclaw:ctx⟧" + a ```json fence that closes and
// parses as a JSON object/array.
const OPENCLAW_JSON_BLOCK_LABELS = new Set([
  'Conversation info:',
  'Thread starter:',
  'Reply target of current user message:',
  'Reply chain of current user message (nearest first):',
  'Forwarded message context:',
  'Location:',
  'Sender:',
  'Structured object:',
  'Image turn:',
]);
// Line-list blocks: "<label> ⟦openclaw:ctx⟧" + one line per history entry,
// terminated by a blank line (OpenClaw collapses every entry to one line).
const OPENCLAW_LINES_BLOCK_LABELS = new Set([
  'Conversation context (chronological, selected for current message):',
  'Chat history since last reply:',
  'Recent chat history:',
]);
// Chat-window structured context: "Chat window:" or "Chat window (<order>, <relation>):".
const OPENCLAW_CHAT_WINDOW_LABEL = /^Chat window(?: \([^()\n]{1,80}\))?:$/;

/**
 * Classify a line as a verified OpenClaw block header. Returns 'json',
 * 'lines' or null (not a framework header — owner text).
 */
function openClawBlockKind(line) {
  const trimmed = line.trim();
  if (!trimmed.endsWith(OPENCLAW_CTX_MARKER)) return null;
  const label = trimmed.slice(0, -OPENCLAW_CTX_MARKER.length).trimEnd();
  if (OPENCLAW_JSON_BLOCK_LABELS.has(label)) return 'json';
  if (OPENCLAW_LINES_BLOCK_LABELS.has(label) || OPENCLAW_CHAT_WINDOW_LABEL.test(label)) return 'lines';
  return null;
}

// Markdown fence delimiters (CommonMark): a run of 3+ backticks or 3+ tildes.
// A backtick fence's info string may not contain a backtick. A fence closes
// only on the SAME character with a run at least as long as the opener and
// nothing else on the line — so a ```` outer fence is not closed by a ```
// example inside it, and ~~~ fences are seen at all.
const FENCE_RUN = /^(`{3,}|~{3,})/;

function fenceOpener(trimmed) {
  const m = FENCE_RUN.exec(trimmed);
  if (!m) return null;
  const run = m[1];
  if (run[0] === '`' && trimmed.slice(run.length).includes('`')) return null;
  return { ch: run[0], len: run.length };
}

function closesFence(trimmed, open) {
  const m = FENCE_RUN.exec(trimmed);
  return m !== null && m[1][0] === open.ch && m[1].length >= open.len && trimmed.slice(m[1].length).trim() === '';
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
 * not the channel suffix. Fences are tracked by character and length (see
 * fenceOpener/closesFence); an owner fence that never closes keeps the rest
 * of the prompt opaque, i.e. we decline suffix removal rather than guess.
 * Only called after a verified envelope was consumed, so the header may open
 * `lines` (an empty user message) or follow a blank line — never sit glued to
 * the end of an owner sentence.
 */
function findTrailingContextHeader(lines) {
  let open = null;
  for (let k = 0; k < lines.length; k += 1) {
    const trimmed = lines[k].trim();
    if (open !== null) {
      if (closesFence(trimmed, open)) open = null;
      continue;
    }
    const opener = fenceOpener(trimmed);
    if (opener !== null) {
      open = opener;
      continue;
    }
    if (trimmed === OPENCLAW_TRAILING_CONTEXT_HEADER && (k === 0 || lines[k - 1].trim() === '')) return k;
  }
  return -1;
}

/**
 * Strip the leading run of OpenClaw-injected blocks and return the trailing
 * current user message. Mirrors OpenClaw's stripLeadingInboundMetadata, but
 * keyed on VERIFIED labels and their block grammar (#720 R2):
 *   - a JSON-label header must be followed by a ```json fence that closes and
 *     parses; the block ends at the closing ```;
 *   - a lines-label header (e.g. the multi-KB "Conversation context" history)
 *     ends at the first blank line — OpenClaw collapses every history body to
 *     a single line, so a blank line cannot occur inside it;
 *   - any other marker-ended line is the owner's own text and ENDS the run:
 *     it is preserved, never consumed as "another metadata block".
 *
 * #720 (Tars): only a COMPLETE, verified envelope is stripped. The leading
 * run must contain at least one JSON block whose fence closes and parses
 * (OpenClaw always opens with "Conversation info:"), and every verified block
 * in the run must be closed — a fence with no closer, or a history block that
 * runs to EOF, means the "envelope" is really the owner's text, and the whole
 * prompt is preserved. A JSON label NOT followed by a ```json fence is not
 * that block at all: it ends the run as owner text. Returns null when nothing
 * was stripped (caller falls back to the legacy patterns).
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
    // The trailing suffix header ends the leading run; it is cut below. So
    // does any line that is not a verified framework header (owner text).
    if (line.trim() === OPENCLAW_TRAILING_CONTEXT_HEADER) break;
    const kind = openClawBlockKind(line);
    if (kind === null) break;
    if (kind === 'json') {
      // Verified JSON label without its ```json fence: not this block — owner text.
      if (lines[i + 1] === undefined || !/^```json\s*$/.test(lines[i + 1].trim())) break;
      const bodyStart = i + 2;
      let close = bodyStart;
      while (close < lines.length && lines[close].trim() !== '```') close += 1;
      if (close >= lines.length) return null; // unclosed fence: owner text
      if (!isJsonObjectText(lines.slice(bodyStart, close).join('\n'))) return null;
      verifiedJsonBlock = true;
      i = close + 1; // past the closing fence
    } else {
      i += 1;
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
