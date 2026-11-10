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
  // The qualifier stays on that one line (#1045). [^)]* would cross newlines
  // and swallow a later lane marker or owner text up to a distant ")".
  // Whitespace before "(" and between ")" and ":" is horizontal only — the
  // s-class minus every JS line terminator (\n, \r, U+2028, U+2029). The
  // s-class there would let "conversation info" plus a line break plus
  // "(owner text):" consume that next line the same way.
  /^conversation info[^\S\n\r\u2028\u2029]*\([^)\n\r\u2028\u2029]*\)[^\S\n\r\u2028\u2029]*:\s*\n+/i,
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
const LEADING_TIMESTAMP_PREFIX = /^\[[A-Za-z]{3} \d{4}-\d{2}-\d{2} \d{2}:\d{2}[^\]\n\r\u2028\u2029]*\] */;
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

// ── OpenClaw 2026.10.x turn boilerplate (#992) ───────────────────────────
// A CLI-backend turn carries more than the #717 envelope. Taken from the
// 2026.10.9 emitters (RUNTIME_CONTEXT_* constants, labelRuntimeContextText,
// buildHarnessVisibleReplyGuidance, buildUiPresentationPrompt):
//   - closed `<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>` … `<<<END_…>>>` blocks;
//   - a trailing "OpenClaw runtime context:" … "End OpenClaw runtime context."
//     block (OpenClaw escapes the footer inside the body, so the first footer
//     line after the header ends it);
//   - trailing visible-reply guidance paragraphs;
//   - the leading "[Tue 2026-11-03 11:48 UTC] " envelope timestamp, which
//     #717 only removed after a ⟦openclaw:ctx⟧ envelope.
// The recall query is the first six distinct terms of the result, so the
// timestamp alone filled four slots on every turn and the guidance filled the
// rest of a short message: unrelated prompts recalled the same notes.
const RUNTIME_CONTEXT_BEGIN_MARKER = '<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>';
const RUNTIME_CONTEXT_END_MARKER = '<<<END_OPENCLAW_INTERNAL_CONTEXT>>>';
const RUNTIME_CONTEXT_HEADER = 'OpenClaw runtime context:';
const RUNTIME_CONTEXT_FOOTER = 'End OpenClaw runtime context.';
// Sentences of the guidance paragraphs OpenClaw appends after the user's
// message (2026.10.9 buildHarnessVisibleReplyGuidance / buildUiPresentationPrompt,
// plus the message_tool_only variants). A trailing paragraph is consumed
// sentence by sentence from its start: when every sentence is known the
// paragraph is boilerplate and goes; when owner text follows the known
// sentence(s) in the same paragraph (#993 review B1) only the known sentences
// go and the remainder stays. A guidance sentence quoted mid-paragraph, or in
// a paragraph that is not trailing, is owner text and is never touched.
const TRAILING_GUIDANCE_SENTENCES = [
  'You can participate in the conversation throughout your work.',
  'Use `message` when you have something worth saying; you don’t need to wait until you’re finished, and sending a message doesn’t end your task.',
  'OpenClaw delivers your final response automatically.',
  'Visible source replies are not automatically delivered for this run.',
  'Use `message(action=send)` for source output.',
  'For progress, set `final=false`.',
  'Set `final=true`, or omit it, for a completed reply to the current source.',
  'An added reaction to the current source message with `final=true` can also complete the reply.',
  'Do not repeat delivered content.',
  'No source-conversation reply can be sent from this turn.',
  'Final assistant text remains private and returns to the invoking workflow; it is not automatically delivered to the source conversation.',
  'For the current source conversation, reply normally in your final assistant message; OpenClaw will deliver it through the active source conversation.',
  '`send`: `target` + `message`; target required this turn.',
  '`send`: `message`; current source is default target.',
  'Set `target` only elsewhere.',
  'Commentary is optional progress and may be hidden.',
  'Answer user questions or status requests received during ongoing work with `message(action=send, final=false)`, then continue the task.',
  "Before finishing, deliver every still-pending answer through this turn's visible-reply route.",
  'Do not repeat answers already delivered.',
  'Include answers to every still-pending user question, including questions received during ongoing work, in your final response.',
  '## UI Presentation',
  '`dashboard`: layout/plugin widgets, not HTML authoring; never for opening a browser side panel.',
  'For a saved widget, use action="focus_tab" with its tabId.',
  'Custom authoring is unavailable this turn, not unsupported by dashboards.',
  'Inspect widgets in their chat/dashboard frame; do not open hosting URLs as browser pages.',
  'Verify the delivered interaction or say unverified.',
].sort((a, b) => b.length - a.length); // longest first: a sentence may prefix another

/**
 * Split a trailing paragraph into its known guidance prefix and the owner
 * remainder. Returns the remainder ('' when the whole paragraph is known), or
 * null when the paragraph does not start with a known sentence.
 */
function consumeGuidanceSentences(paragraph) {
  let rest = paragraph;
  let consumed = false;
  for (;;) {
    const hit = TRAILING_GUIDANCE_SENTENCES.find((sentence) => rest.startsWith(sentence)
      && (rest.length === sentence.length || /\s/.test(rest[sentence.length])));
    if (hit === undefined) break;
    consumed = true;
    rest = rest.slice(hit.length).replace(/^\s+/, '');
    if (rest === '') break;
  }
  return consumed ? rest : null;
}

/**
 * A BEGIN line is the exact marker, or the validated envelope timestamp
 * followed by the exact marker (#993 review round 3, R1). Any other text before
 * the marker makes the line owner text.
 */
function isInternalContextBegin(line) {
  const t = line.trim();
  if (t === RUNTIME_CONTEXT_BEGIN_MARKER) return true;
  const m = LEADING_TIMESTAMP_PREFIX.exec(t);
  return m !== null && t.slice(m[0].length) === RUNTIME_CONTEXT_BEGIN_MARKER;
}

/**
 * Strip the trailing run of 2026.10.x boilerplate, working backwards from the
 * end of the prompt one unit at a time (#993 review B2: a framework block is
 * removed only where the framework puts it). A unit is removed only while it
 * sits at the tail, i.e. is anchored to the end of the prompt through the
 * units already removed:
 *   - a closed "OpenClaw runtime context:" … "End OpenClaw runtime context."
 *     block whose footer is the last line;
 *   - a closed internal-context block whose END marker is the last line;
 *   - a guidance paragraph made of known sentences (see
 *     consumeGuidanceSentences); owner text after the known sentences in that
 *     paragraph ends the run and is kept.
 * Anything else ends the run: the owner's own text, including a quoted closed
 * pair with owner words after it, stays.
 *
 * Closed pairs are removed only when `framed` is true (#993 round 3, R2): the
 * prompt carries framework evidence independent of the pair itself. Guidance
 * paragraphs need no evidence.
 */
function stripTrailingTurnBoilerplate(lines, framed) {
  const out = lines.slice();
  const trimTail = () => { while (out.length > 0 && out[out.length - 1].trim() === '') out.pop(); };
  for (;;) {
    trimTail();
    if (out.length === 0) break;
    const last = out[out.length - 1].trim();
    if (last === RUNTIME_CONTEXT_FOOTER) {
      if (!framed) break;
      let start = out.length - 2;
      while (start >= 0 && out[start].trim() !== RUNTIME_CONTEXT_HEADER) start -= 1;
      if (start < 0) break; // footer without a header: owner text
      out.length = start;
      continue;
    }
    if (last === RUNTIME_CONTEXT_END_MARKER) {
      if (!framed) break;
      let start = out.length - 2;
      // The nearest BEGIN-looking line must be a valid BEGIN: another END, or a
      // marker with owner text before it, means this is not a framework block.
      while (start >= 0 && !isInternalContextBegin(out[start])
        && out[start].trim() !== RUNTIME_CONTEXT_END_MARKER
        && !out[start].includes(RUNTIME_CONTEXT_BEGIN_MARKER)) start -= 1;
      if (start < 0 || !isInternalContextBegin(out[start])) break; // owner text
      // Keep any text the BEGIN line carried before the marker (the timestamp).
      const before = out[start].trimEnd().slice(0, -RUNTIME_CONTEXT_BEGIN_MARKER.length).trimEnd();
      out.length = start;
      if (before !== '') out.push(before);
      continue;
    }
    // Last paragraph: back to the previous blank line.
    let pStart = out.length - 1;
    while (pStart > 0 && out[pStart - 1].trim() !== '') pStart -= 1;
    const remainder = consumeGuidanceSentences(out.slice(pStart).join('\n').trim());
    if (remainder === null) break; // owner paragraph
    out.length = pStart;
    if (remainder !== '') { out.push(remainder); break; } // owner text after the opener (B1)
  }
  return out;
}

/**
 * Strip internal-context blocks that open the prompt: the first non-blank
 * line is a BEGIN line (see isInternalContextBegin) and a closing END marker
 * follows. Only meaningful for a framed prompt (the caller checks). A forward
 * cursor walks the original array once, so N consecutive blocks cost O(N)
 * (#993 round 3, R3). The envelope timestamp the first BEGIN line carries is
 * kept once, for the final timestamp cut. An unclosed marker, or a block that
 * follows owner text, is left alone.
 */
function stripLeadingInternalContextBlocks(lines) {
  let pos = 0;
  let kept = '';
  for (;;) {
    let i = pos;
    while (i < lines.length && lines[i].trim() === '') i += 1;
    if (i >= lines.length || !isInternalContextBegin(lines[i])) break;
    let end = i + 1;
    while (end < lines.length && lines[end].trim() !== RUNTIME_CONTEXT_END_MARKER) end += 1;
    if (end >= lines.length) break; // unclosed: owner text
    if (pos === 0 && kept === '') {
      kept = lines[i].trimEnd().slice(0, -RUNTIME_CONTEXT_BEGIN_MARKER.length).trimEnd();
    }
    pos = end + 1;
  }
  if (pos === 0) return lines;
  return (kept !== '' ? [kept] : []).concat(lines.slice(pos));
}

/**
 * Strip OpenClaw 2026.10.x turn boilerplate around the owner's text (#992).
 * Never returns null; returns the input unchanged when nothing matched, and
 * also when stripping would leave nothing (an owner message that is itself a
 * complete framework pair must not gate as too short, #993 review B2).
 */
function stripOpenClawTurnBoilerplate(text, framework = false) {
  if (text.length === 0) return text;
  // R2 (#993 round 3): closed pairs go only with framework evidence that does
  // not come from the pair itself: a wrapper this call already consumed, or
  // the validated envelope timestamp opening the text. Otherwise keep.
  const framed = framework || LEADING_TIMESTAMP_PREFIX.test(text);
  let lines = text.replace(/\r\n/g, '\n').split('\n');
  lines = stripTrailingTurnBoilerplate(lines, framed);
  if (framed && text.includes(RUNTIME_CONTEXT_BEGIN_MARKER)) lines = stripLeadingInternalContextBlocks(lines);
  const out = lines.join('\n').trim().replace(LEADING_TIMESTAMP_PREFIX, '').trim();
  if (out === '') return text;
  return out === text.trim() ? text : out;
}

/**
 * Strip framework metadata wrappers from a prompt.
 *
 * @param {string} prompt
 * @returns {string} sanitised prompt — may be empty if the entire prompt
 *   was metadata. Never null/undefined.
 */
export function sanitisePromptForRecall(prompt) {
  return sanitise(prompt, true);
}

/**
 * The prompt lane detection reads (#718): the same as sanitisePromptForRecall
 * but WITHOUT the #992 turn-boilerplate step (only its leading-timestamp cut). OpenClaw puts lane markers such
 * as "[Subagent Context]" inside the internal-context blocks that step
 * removes, so detecting the lane on the recall text would turn a subagent
 * turn into an interactive one and widen what it may recall.
 *
 * @param {string} prompt
 * @returns {string}
 */
export function sanitisePromptForLaneDetection(prompt) {
  return sanitise(prompt, false);
}

function sanitise(prompt, stripTurnBoilerplate) {
  if (typeof prompt !== 'string' || prompt.length === 0) return '';
  // Lane text still loses the leading envelope timestamp: the lane markers are
  // line-anchored, so "[Tue … UTC] Automated liveness check …" otherwise read
  // as an interactive turn and fed the doctor's repetition sample (#992).
  // Removing it can only let a marker match, i.e. only narrow the lane.
  const finish = (text, framework = false) => (stripTurnBoilerplate
    ? stripOpenClawTurnBoilerplate(text.trim(), framework)
    : text.trim().replace(LEADING_TIMESTAMP_PREFIX, '')).trim();

  // 0) OpenClaw 2026.9.x marker-keyed envelope (#717). When it matches, the
  //    remainder is the current user message and the legacy patterns below
  //    have nothing left to do.
  const fromEnvelope = stripOpenClawEnvelope(prompt);
  if (fromEnvelope !== null) return finish(fromEnvelope, true);

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

  // 3) OpenClaw 2026.10.x turn boilerplate (#992).
  return finish(working, working !== prompt);
}
