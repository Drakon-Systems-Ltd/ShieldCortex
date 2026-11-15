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

import { types } from 'node:util';

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
function flattenToolResult(block: unknown, depth: number, out: string[], opaque: OpaqueState): number {
  const direct = blockText(block);
  if (direct) {
    out.push(direct);
    return 0;
  }
  const b = asRecord(block);
  if (!b || depth >= MAX_NESTING) return 1;
  const inner = b.content ?? b.result ?? b.output;
  if (Array.isArray(inner)) {
    // A Proxy array may report any length or element. Scan what it yields,
    // and record that the yield cannot be trusted to be the whole result.
    if (isHostProxy(inner)) opaque.proxied = true;
    if (inner.length === 0) return 1;
    let unreadable = 0;
    for (const child of inner) unreadable += flattenToolResult(child, depth + 1, out, opaque);
    return unreadable;
  }
  if (inner && typeof inner === 'object') return flattenToolResult(inner, depth + 1, out, opaque);
  return 1;
}

/** Set when a container read during labelling was a Proxy. */
interface OpaqueState { proxied: boolean }

/**
 * True for a live or revoked Proxy. A Proxy array's `length` and index traps
 * may return values that differ from the target, so a scan of what they yield
 * is not proof the container was clean. Detection failure counts as a Proxy.
 */
export function isHostProxy(value: unknown): boolean {
  try { return types.isProxy(value); } catch { return true; }
}

/**
 * Read an array length once for an index loop. `incomplete` is set when the
 * read throws, yields a value that is not a safe non-negative integer, or the
 * array is a Proxy (whose reported length is not authoritative).
 */
export function readGateArrayLength(arr: unknown[]): { length: number; incomplete: boolean } {
  let raw: unknown;
  try { raw = arr.length; } catch { return { length: 0, incomplete: true }; }
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0) {
    return { length: 0, incomplete: true };
  }
  return { length: raw, incomplete: isHostProxy(arr) };
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
  return labelHistoryMessageTracked(msg, { proxied: false });
}

function labelHistoryMessageTracked(msg: unknown, opaque: OpaqueState): LabelledInputs {
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
        unreadableToolBlocks += flattenToolResult(block, 0, texts, opaque);
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

/** Gate-only extraction: keep readable siblings when a host getter is hostile.
 * `incomplete` is also set for any Proxy content array, including a nested
 * tool-result array: its traps may hide blocks while returning values, so the
 * yielded blocks are scanned but never accepted as the whole message. */
export function labelHistoryMessageForGate(msg: unknown): { inputs: LabelledInput[]; incomplete: boolean; userRole: boolean } {
  const inputs: LabelledInput[] = [];
  const opaque: OpaqueState = { proxied: false };
  let incomplete = false;
  let role: unknown;
  let content: unknown;
  try {
    const m = asRecord(msg);
    if (!m) return { inputs, incomplete: true, userRole: false };
    role = m.role;
  } catch { incomplete = true; }
  const userRole = typeof role === 'string' && USER_ROLES.has(role.toLowerCase());
  try { content = (msg as Record<string, unknown>).content; }
  catch { return { inputs, incomplete: true, userRole }; }

  let contentIsArray: boolean;
  try { contentIsArray = Array.isArray(content); }
  catch { return { inputs, incomplete: true, userRole }; }
  if (!contentIsArray) {
    try { inputs.push(...labelHistoryMessageTracked({ role, content }, opaque).inputs); }
    catch { incomplete = true; }
    return { inputs, incomplete: incomplete || opaque.proxied, userRole };
  }
  // Read by index: Array.prototype.slice, iteration, and species may all run
  // user-controlled code before the first readable block is returned. The
  // length is read once, so a trap cannot vary it between iterations.
  const blocks = content as unknown[];
  const read = readGateArrayLength(blocks);
  incomplete ||= read.incomplete;
  for (let i = 0; i < read.length; i++) {
    try { inputs.push(...labelHistoryMessageTracked({ role, content: [blocks[i]] }, opaque).inputs); }
    catch { incomplete = true; }
  }
  return { inputs, incomplete: incomplete || opaque.proxied, userRole };
}

/** Fields the labeller reads from a message or block, at any nesting. */
const SNAPSHOT_KEYS = ['role', 'content', 'type', 'text', 'tool_use_id', 'toolUseId', 'result', 'output'] as const;
/** Deeper than the labeller ever reads (message → blocks → MAX_NESTING tool-result levels). */
const SNAPSHOT_MAX_DEPTH = 4 + 2 * MAX_NESTING + 2;
/** Objects/arrays visited per event before the snapshot gives up (fail closed). */
const SNAPSHOT_NODE_BUDGET = 250_000;

interface SnapshotState { incomplete: boolean; nodes: { count: number }; alternateTexts: string[] }

/**
 * Read one property for the gate. Own data properties are taken without
 * running code. Anything else (own or inherited accessor, Proxy) is read
 * TWICE: a getter that answers differently on consecutive reads is not
 * telling the gate what the host will later see. Both values are returned so
 * the caller can scan both and record the read as unstable.
 */
function readGateProperty(obj: object, key: string, state: SnapshotState): { present: boolean; values: unknown[] } {
  const proxied = isHostProxy(obj);
  if (!proxied) {
    let desc: PropertyDescriptor | undefined;
    try { desc = Object.getOwnPropertyDescriptor(obj, key); }
    catch { state.incomplete = true; return { present: false, values: [] }; }
    if (desc && 'value' in desc) return { present: true, values: [desc.value] };
    if (!desc) {
      let has: boolean;
      try { has = key in obj; } catch { state.incomplete = true; return { present: false, values: [] }; }
      if (!has) return { present: false, values: [] };
    }
  }
  let first: unknown;
  let second: unknown;
  try { first = Reflect.get(obj, key); }
  catch { state.incomplete = true; return { present: false, values: [] }; }
  try { second = Reflect.get(obj, key); }
  catch { state.incomplete = true; return { present: true, values: [first] }; }
  return { present: true, values: Object.is(first, second) ? [first] : [first, second] };
}

function snapshotsEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    const bb = b as unknown[];
    return a.length === bb.length && a.every((v, i) => snapshotsEqual(v, bb[i]));
  }
  const ar = a as Record<string, unknown>;
  const br = b as Record<string, unknown>;
  const ak = Object.keys(ar);
  return ak.length === Object.keys(br).length && ak.every(k => Object.hasOwn(br, k) && snapshotsEqual(ar[k], br[k]));
}

/**
 * Snapshot the values one accessor read produced. Values that are equal as
 * plain data are one stable value (a getter returning a fresh but identical
 * copy is stable). Values that differ are all kept and the read is unstable.
 */
function snapshotReads(values: unknown[], depth: number, state: SnapshotState): unknown[] {
  const snaps = values.map(v => snapshotGateValue(v, depth, state));
  if (snaps.length > 1 && snapshotsEqual(snaps[0], snaps[1])) return [snaps[0]];
  if (snaps.length > 1) state.incomplete = true;
  return snaps;
}

function snapshotGateArray(arr: unknown[], depth: number, state: SnapshotState, lastN = 0): unknown[] {
  const read = readGateArrayLength(arr);
  if (read.incomplete) state.incomplete = true;
  const proxied = isHostProxy(arr);
  const out: unknown[] = [];
  const start = lastN > 0 ? Math.max(0, read.length - lastN) : 0;
  for (let i = start; i < read.length; i++) {
    if (state.nodes.count > SNAPSHOT_NODE_BUDGET) { state.incomplete = true; break; }
    const key = String(i);
    if (!proxied) {
      let desc: PropertyDescriptor | undefined;
      try { desc = Object.getOwnPropertyDescriptor(arr, key); }
      catch { state.incomplete = true; continue; }
      // A hole would be read through the prototype chain; ordinary host
      // history and content arrays are dense.
      if (!desc) { state.incomplete = true; continue; }
      if ('value' in desc) { out.push(snapshotGateValue(desc.value, depth, state)); continue; }
      // An accessor INDEX is never ordinary host data: plain, JSON-parsed and
      // cloned arrays all hold data elements. Scan whatever it yields, but it
      // can never be accepted as what the host will read next.
      state.incomplete = true;
    }
    const read2 = readGateProperty(arr, key, state);
    out.push(...snapshotReads(read2.values, depth, state));
  }
  return out;
}

function snapshotGateValue(value: unknown, depth: number, state: SnapshotState): unknown {
  if (value === null || typeof value !== 'object') return typeof value === 'function' ? undefined : value;
  if (depth > SNAPSHOT_MAX_DEPTH) return undefined;
  if (++state.nodes.count > SNAPSHOT_NODE_BUDGET) { state.incomplete = true; return undefined; }
  if (isHostProxy(value)) state.incomplete = true;
  let isArray: boolean;
  try { isArray = Array.isArray(value); } catch { state.incomplete = true; return undefined; }
  if (isArray) return snapshotGateArray(value as unknown[], depth + 1, state);
  const out: Record<string, unknown> = {};
  for (const key of SNAPSHOT_KEYS) {
    const read = readGateProperty(value, key, state);
    if (!read.present) continue;
    const snaps = snapshotReads(read.values, depth + 1, state);
    // Only one value can occupy the field. A differing value from a second
    // read is already recorded as unstable; its texts are kept for scanning
    // so a later-read attack still reaches the detector and the audit row.
    out[key] = snaps[0];
    for (const alt of snaps.slice(1)) collectSnapshotTexts(alt, state.alternateTexts);
  }
  return out;
}

function collectSnapshotTexts(snap: unknown, out: string[]): void {
  if (typeof snap === 'string') { if (snap) out.push(snap); return; }
  if (Array.isArray(snap)) { for (const v of snap) collectSnapshotTexts(v, out); return; }
  if (snap && typeof snap === 'object') {
    for (const v of Object.values(snap as Record<string, unknown>)) collectSnapshotTexts(v, out);
  }
}

/**
 * Plain-data copy of the selected (last `limit`) history messages for the
 * enforcing gate, read so that no host code runs again during labelling.
 *
 * `incomplete` is set when any read was opaque or unstable: a throwing read,
 * a Proxy, an array hole, an accessor array index, or a property getter that
 * returned different data on two consecutive reads (including the event's
 * own `messages`). Stable getters — identical value, or an equal fresh copy,
 * on both reads — are accepted. `alternateTexts` carries the texts of any
 * differing second read so they are scanned too, never silently discarded.
 */
export function snapshotGateHistory(event: unknown, limit: number): { messages: unknown[]; incomplete: boolean; alternateTexts: string[] } {
  const state: SnapshotState = { incomplete: false, nodes: { count: 0 }, alternateTexts: [] };
  const messages: unknown[] = [];
  if (!event || typeof event !== 'object') return { messages, incomplete: false, alternateTexts: [] };
  const read = readGateProperty(event, 'messages', state);
  const windows: unknown[][] = [];
  for (const value of read.values) {
    let isArray: boolean;
    try { isArray = Array.isArray(value); } catch { state.incomplete = true; continue; }
    windows.push(isArray ? snapshotGateArray(value as unknown[], 1, state, limit) : []);
  }
  // A getter returning an equal fresh array on both reads is stable; one
  // that answers differently is not, and both answers are scanned.
  if (windows.length > 1 && !snapshotsEqual(windows[0], windows[1])) {
    state.incomplete = true;
    for (const w of windows) messages.push(...w);
  } else if (windows.length > 0) {
    messages.push(...windows[0]);
  }
  return { messages, incomplete: state.incomplete, alternateTexts: state.alternateTexts };
}

/**
 * Every text this hook will scan for one `llm_input` event, each with the
 * origin it was declared under.
 *
 * A bare `prompt` can be a host-assembled bundle (including quoted history),
 * not just the sender's words. The hook exposes no attested origin for its
 * constituent spans, so retain `unknown`. Text markers MUST NOT grant trust
 * or change provenance. Structured history is labelled per message and bounded to the last
 * {@link HISTORY_SCAN_LIMIT}, as before. The prompt, when present, is always
 * the FIRST input: `scanLlmInput` relies on that to apply the #353 automation
 * session exemption to the prompt alone.
 */
export function labelLlmInput(event: {
  prompt?: unknown;
  historyMessages?: unknown;
}): LabelledInputs {
  const out: LabelledInput[] = [];
  if (typeof event?.prompt === 'string' && event.prompt) {
    out.push({ text: event.prompt, label: 'unknown' });
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
