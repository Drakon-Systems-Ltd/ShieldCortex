/**
 * Provenance labelling for the OpenClaw realtime `llm_input` hook.
 *
 * The hook used to hand every text to the scanner with no origin attached:
 * the operator's own prompt and a web page that arrived inside a tool result
 * were judged by the identical detector. That is the wall the L2 policy
 * exists to break — the same sentence is an instruction from the operator and
 * an injection from a fetched document, and only the ORIGIN separates them.
 *
 * Two rules govern everything here:
 *
 *   1. NEVER GUESS UPWARDS. A shape this file does not recognise is labelled
 *      `unknown`, which keeps exactly the pre-existing L1 path and is counted
 *      so an operator can see that their host's event shape is not being
 *      classified. Guessing `user` would silence L2 on real tool output;
 *      guessing `tool_result` would apply an aggressive policy to the
 *      operator's own words.
 *
 *   2. NEVER INVENT A DISTINCTION THE EVENT DOES NOT CARRY. The OpenClaw
 *      `llm_input` event exposes `prompt`, `systemPrompt`, `historyMessages`
 *      and counters — nothing in it says "this tool result was a fetched web
 *      page" or "this was a file read". So this file emits `tool_result` for
 *      all tool-origin content and never `web`/`document`. Those two labels
 *      remain reachable from ingresses that genuinely know (the `scan` CLI's
 *      --source), and adding them here later needs a host field to read, not
 *      a heuristic.
 *
 * Pure and synchronous: no I/O, no config read, no defence module. The plugin
 * calls it once per hook invocation before any scanning happens.
 *
 * The label vocabulary MIRRORS `ProvenanceLabel` in the main package
 * (src/defence/types.ts). It is spelled out rather than imported because this
 * plugin compiles against its own rootDir and must build without the package
 * source on disk. Only the subset this hook can honestly emit appears here —
 * a label this file cannot justify is a label it must not produce.
 */

export const PLUGIN_PROVENANCE_LABELS = ['user', 'tool_result', 'unknown'] as const;

export type PluginProvenanceLabel = (typeof PLUGIN_PROVENANCE_LABELS)[number];

export interface LabelledInput {
  text: string;
  label: PluginProvenanceLabel;
}

/**
 * The result of labelling one event: the texts to scan, and how many
 * tool-origin blocks carried no readable text.
 *
 * The second number exists because "dropped silently" is the one outcome a
 * provenance layer must not have. A host that wraps its tool results in a
 * shape this file cannot read produces no inputs AND no counter, so the
 * operator sees a clean plane that is in fact looking at nothing. The count
 * is of BLOCKS, never their content.
 */
export interface LabelledInputs {
  inputs: LabelledInput[];
  unreadableToolBlocks: number;
}

/**
 * How many history texts the hook looks at. Unchanged from the pre-provenance
 * behaviour (`extractUserContent(...).slice(-5)`): labelling widens WHICH
 * messages are eligible, not how many are scanned per turn.
 */
export const HISTORY_SCAN_LIMIT = 5;

/** Roles that carry tool output back to the model, across host encodings. */
const TOOL_ROLES = new Set(['tool', 'tool_result', 'function', 'tool-result']);
/** Roles that are the human speaking to the agent. */
const USER_ROLES = new Set(['user', 'human']);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function blockText(block: unknown): string | null {
  const b = asRecord(block);
  if (!b) return typeof block === 'string' ? block : null;
  if (typeof b.text === 'string') return b.text;
  if (typeof b.content === 'string') return b.content;
  return null;
}

/** A content block that IS a tool result, by any of the encodings in use. */
function isToolResultBlock(block: unknown): boolean {
  const b = asRecord(block);
  if (!b) return false;
  if (typeof b.type === 'string' && TOOL_ROLES.has(b.type)) return true;
  // Anthropic-shaped blocks correlate a result to its call; the presence of
  // that correlation id is the structural tell, independent of `type`.
  return typeof b.tool_use_id === 'string' || typeof b.toolUseId === 'string';
}

/** Nested tool-result content is flattened at most this deep. */
const MAX_NESTING = 3;

/**
 * Pull every readable text out of one tool-result block, however the host
 * nested it, and count the parts that carried none.
 *
 * Anthropic-shaped results are `{type:'tool_result', tool_use_id, content:[
 * {type:'text', text}]}` — a content ARRAY, which the r1 `blockText` could
 * not read, so the whole result was dropped before its tool-result structure
 * was ever examined and no counter moved either. The established provenance
 * is preserved through every child representation: once a block is
 * tool-origin, everything inside it is too.
 */
function flattenToolResult(block: unknown, depth: number, out: string[]): number {
  const direct = blockText(block);
  if (direct) {
    out.push(direct);
    return 0;
  }
  const b = asRecord(block);
  if (!b || depth >= MAX_NESTING) return 1;
  const inner = b.content ?? b.result ?? b.output;
  if (Array.isArray(inner)) {
    if (inner.length === 0) return 1;
    let unreadable = 0;
    for (const child of inner) unreadable += flattenToolResult(child, depth + 1, out);
    return unreadable;
  }
  if (inner && typeof inner === 'object') return flattenToolResult(inner, depth + 1, out);
  return 1;
}

/**
 * Label one history message.
 *
 * A user-role message is NOT automatically `user`: on Anthropic-shaped
 * histories a tool result is delivered as a user-role message whose content
 * blocks are tool results. That is precisely the indirect-injection path, so
 * the BLOCK decides, not the role.
 */
export function labelHistoryMessage(msg: unknown): LabelledInputs {
  const m = asRecord(msg);
  if (!m) return { inputs: [], unreadableToolBlocks: 0 };
  const role = typeof m.role === 'string' ? m.role.toLowerCase() : '';
  const roleLabel: PluginProvenanceLabel | null = TOOL_ROLES.has(role)
    ? 'tool_result'
    : USER_ROLES.has(role)
      ? 'user'
      : null;

  if (typeof m.content === 'string') {
    // A bare string carries no block structure. A TOOL role still decides —
    // the host declared the origin and inheriting it can only tighten. A USER
    // role does not: rule #1 forbids guessing upwards, and a host that
    // flattens tool results into user-role strings would otherwise turn L2
    // off by accident. `unknown` costs nothing here (both labels are L2-off)
    // and buys the honesty counter, so the operator sees that this host's
    // history shape is not being classified rather than being told it is.
    const label: PluginProvenanceLabel = roleLabel === 'tool_result' ? 'tool_result' : 'unknown';
    return {
      inputs: m.content ? [{ text: m.content, label }] : [],
      unreadableToolBlocks: 0,
    };
  }

  if (Array.isArray(m.content)) {
    const inputs: LabelledInput[] = [];
    let unreadableToolBlocks = 0;
    for (const block of m.content) {
      if (isToolResultBlock(block)) {
        const texts: string[] = [];
        unreadableToolBlocks += flattenToolResult(block, 0, texts);
        for (const text of texts) inputs.push({ text, label: 'tool_result' });
        continue;
      }
      const text = blockText(block);
      if (!text) {
        // Only tool-origin loss is counted: an image block in a user turn is
        // not a gap in this layer, it is a thing this layer never judged.
        if (roleLabel === 'tool_result') unreadableToolBlocks += 1;
        continue;
      }
      const b = asRecord(block);
      const isText = b && typeof b.type === 'string' && b.type === 'text';
      // Established untrusted provenance is INHERITED: a string (or any
      // shape) inside a tool-role message is tool output whatever its own
      // block type says. Under any other role only a text block may inherit;
      // anything else is a shape this file cannot account for.
      const label: PluginProvenanceLabel = roleLabel === 'tool_result'
        ? 'tool_result'
        : isText && roleLabel
          ? roleLabel
          : 'unknown';
      inputs.push({ text, label });
    }
    return { inputs, unreadableToolBlocks };
  }

  return { inputs: [], unreadableToolBlocks: 0 };
}

/**
 * Every text this hook will scan for one `llm_input` event, each with the
 * origin it was declared under.
 *
 * The live `prompt` is the turn the host attributes to the sender, so it is
 * `user` — the same judgement the conversation-trust layer already makes
 * about a turn. History is labelled per message and bounded to the last
 * {@link HISTORY_SCAN_LIMIT}, as before.
 */
export function labelLlmInput(event: {
  prompt?: unknown;
  historyMessages?: unknown;
}): LabelledInputs {
  const out: LabelledInput[] = [];
  if (typeof event?.prompt === 'string' && event.prompt) {
    out.push({ text: event.prompt, label: 'user' });
  }
  const history = Array.isArray(event?.historyMessages) ? event.historyMessages : [];
  const labelled: LabelledInput[] = [];
  let unreadableToolBlocks = 0;
  for (const msg of history) {
    const one = labelHistoryMessage(msg);
    labelled.push(...one.inputs);
    unreadableToolBlocks += one.unreadableToolBlocks;
  }
  out.push(...labelled.slice(-HISTORY_SCAN_LIMIT));
  return { inputs: out, unreadableToolBlocks };
}
