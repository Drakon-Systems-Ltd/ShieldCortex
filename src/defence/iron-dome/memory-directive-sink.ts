/**
 * SCN-010 PR B (G1 + G2) — the Action Guard's memory sink.
 *
 * Durable agent memory is read back as context in every later session, so a
 * stored note that says "from now on, skip the confirmation prompt" is a
 * standing order, not a fact. The memory plane screens what reaches the
 * ShieldCortex store (PR A); this module lets the guard screen the same text
 * at the TOOL CALL, on every host that routes memory writes through it:
 *
 *   G1  a memory-family WRITE tool (`remember` in any namespace,
 *       `save_memory`, `memory_store`, a `memory` tool whose action or
 *       command stores text, and every storing op of an `operations` batch);
 *   G2  a Write / Edit / MultiEdit whose target is memory markdown
 *       (`isMemoryWritePath`), on the RAW written text.
 *
 * It only EXTRACTS and SCREENS. The screen itself is
 * `detectMemoryDirective` (firewall/memory-directive-policy.ts), reused as
 * shipped; the verdict is minted by the guard, which only ever turns an
 * `allow` into an approval card with this module's answer.
 *
 * Fail-safe by construction: an input this module cannot read in full
 * (too much text, too many fields) and a screen that throws both come back as
 * a HIT with their own reason, never as "nothing found", so an
 * attacker-shaped input cannot turn a gap into an allow.
 *
 * Output is pattern names and fixed reason codes only, never memory text.
 */

import { detectMemoryDirective, type MemoryDirectiveResult } from '../firewall/memory-directive-policy.js';

/** The one guard signal for this sink. */
export const MEMORY_DIRECTIVE_SIGNAL = 'memory-directive';

export type MemoryDirectiveScreen = (text: string) => MemoryDirectiveResult;

/**
 * Normalised tool names whose every call stores a memory:
 *   - `remember`: ShieldCortex MCP (`mcp__shieldcortex__remember`,
 *     `mcp__memory__remember`, bare `remember`);
 *   - `save_memory`: Gemini CLI (`{fact}`);
 *   - `memory_store`: OpenClaw memory-lancedb (`{text, importance, category}`).
 * `memory` (Hermes `{action, target, content, old_text}`, Anthropic's memory
 * tool `{command, path, file_text | new_str | insert_text}`) stores only for
 * some actions; see `NON_STORING_OPS`.
 */
const STORING_TOOLS: ReadonlySet<string> = new Set(['remember', 'save_memory', 'memory_store']);
const OP_TOOLS: ReadonlySet<string> = new Set(['memory']);

/** Action / command values that store no text: reads, removals, renames. An
 *  op carrying one of these is skipped whole (a removal names the text it
 *  removes, which is not a new standing order). Any OTHER value, including
 *  an unknown or misspelt one, is screened. */
const NON_STORING_OPS: ReadonlySet<string> = new Set([
  'remove', 'delete', 'read', 'view', 'list', 'get', 'search', 'recall', 'forget', 'rename',
]);
const OP_KEYS = ['action', 'op', 'operation', 'command'] as const;

/**
 * The keys whose string values are STORED text. The replacement side only:
 * `old_text`, `old_string` and `old_str` name text being replaced and are
 * never screened. A string under any other key (`target`, `category`,
 * `path`, ids) is not read.
 */
const TEXT_KEYS: ReadonlySet<string> = new Set([
  'title', 'content', 'contents', 'text', 'note', 'notes', 'memory', 'value', 'fact',
  'body', 'summary', 'new_string', 'new_text', 'new_str', 'new_source', 'file_text', 'insert_text',
]);

/** Containers are walked at most this many levels below the argument bag
 *  (args -> operations[] -> op -> content is two). */
export const MEMORY_SCREEN_MAX_DEPTH = 3;
/** Total stored text one call may carry and still be screened. The screen is
 *  linear (about 0.1 s per 200 KB); past this the call is carded unscreened
 *  rather than screened on a prefix an attacker could pad past. */
export const MEMORY_SCREEN_MAX_CHARS = 1_000_000;
/** Stored-text fields one call may carry (each is also screened alone). */
export const MEMORY_SCREEN_MAX_LEAVES = 256;
/** Objects and arrays visited per call, so a wide bag of non-text keys is bounded too. */
export const MEMORY_SCREEN_MAX_NODES = 10_000;

export type MemoryDirectiveSinkKind = 'memory-tool' | 'memory-markdown';

/** Why the sink holds the call. Fixed codes, never text. */
export type MemoryDirectiveHoldCause = 'directive' | 'too-large' | 'screen-unavailable';

export interface MemoryDirectiveHold {
  sink: MemoryDirectiveSinkKind;
  cause: MemoryDirectiveHoldCause;
  /** Pattern names (`memory_directive:<group>`) for `directive`; empty otherwise. */
  patterns: string[];
}

interface Collected {
  leaves: string[];
  overflow: boolean;
}

function opIsNonStoring(obj: Record<string, unknown>): boolean {
  for (const k of OP_KEYS) {
    const v = obj[k];
    if (typeof v === 'string' && NON_STORING_OPS.has(v.trim().toLowerCase())) return true;
  }
  return false;
}

/**
 * String leaves under `TEXT_KEYS`, depth-bounded, arrays included. An object
 * whose action/op/command is non-storing is skipped whole. Overflow (too much
 * text, too many leaves or nodes) is reported, never truncated silently.
 */
export function collectStoredText(args: unknown): Collected {
  const leaves: string[] = [];
  let chars = 0;
  let nodes = 0;
  let overflow = false;

  const take = (s: string): void => {
    if (s.length === 0) return;
    leaves.push(s);
    chars += s.length;
    if (leaves.length > MEMORY_SCREEN_MAX_LEAVES || chars > MEMORY_SCREEN_MAX_CHARS) overflow = true;
  };

  const walk = (value: unknown, depth: number, underTextKey: boolean): void => {
    if (overflow) return;
    if (typeof value === 'string') {
      if (underTextKey) take(value);
      return;
    }
    if (value === null || typeof value !== 'object') return;
    if (depth > MEMORY_SCREEN_MAX_DEPTH) return;
    nodes += 1;
    if (nodes > MEMORY_SCREEN_MAX_NODES) { overflow = true; return; }
    if (Array.isArray(value)) {
      for (const el of value) {
        walk(el, depth + 1, underTextKey);
        if (overflow) return;
      }
      return;
    }
    const obj = value as Record<string, unknown>;
    if (opIsNonStoring(obj)) return;
    for (const [k, v] of Object.entries(obj)) {
      walk(v, depth + 1, TEXT_KEYS.has(k.toLowerCase()));
      if (overflow) return;
    }
  };

  walk(args, 0, false);
  return { leaves, overflow };
}

/**
 * Which memory sink this call is, or null. `normalisedName` is the guard's
 * `normaliseToolName`; `family` its `classifyFamily`; `memoryPath` is
 * `isMemoryWritePath(extractPath(args))`. Read-side memory tools (`recall`,
 * `get_context`, `graph`, `forget`) are never a sink.
 */
export function memorySinkKind(
  normalisedName: string,
  family: string,
  memoryPath: boolean,
): MemoryDirectiveSinkKind | null {
  if (STORING_TOOLS.has(normalisedName) || OP_TOOLS.has(normalisedName)) return 'memory-tool';
  if (family === 'write' && memoryPath) return 'memory-markdown';
  return null;
}

/**
 * The reason prefix for a hold: the sink, then the pattern names or the fixed
 * cause. Never memory text. (Kept here, not in the guard module, whose
 * kebab-case literals the approval-card vocabulary test reads as signal ids.)
 */
export function memoryDirectiveHoldReason(hold: MemoryDirectiveHold): string {
  const where = hold.sink === 'memory-tool' ? 'memory write' : 'memory-markdown write';
  if (hold.cause === 'directive') return `${where} stores a standing directive (${hold.patterns.join(', ')})`;
  if (hold.cause === 'too-large') return `${where}: memory text too large to screen`;
  return `${where}: memory-directive screen unavailable`;
}

/**
 * Screen the text a memory write would store. Null when nothing would be
 * stored or the screen is quiet; otherwise the hold and its cause.
 *
 * The screen runs on every leaf joined by newlines (so a title and a body are
 * read together as separate clauses, as the memory plane joins them) and,
 * when that is quiet and there is more than one leaf, on each leaf alone, so
 * a fence opened in one field cannot mask a directive in the next.
 */
export function screenMemoryWrite(
  sink: MemoryDirectiveSinkKind,
  args: unknown,
  screen: MemoryDirectiveScreen = detectMemoryDirective,
): MemoryDirectiveHold | null {
  const { leaves, overflow } = collectStoredText(args);
  if (overflow) return { sink, cause: 'too-large', patterns: [] };
  if (leaves.length === 0) return null;
  try {
    const joined = screen(leaves.join('\n'));
    if (joined.detected) return { sink, cause: 'directive', patterns: [...joined.patterns] };
    if (leaves.length > 1) {
      const found = new Set<string>();
      for (const leaf of leaves) {
        const r = screen(leaf);
        if (r.detected) for (const p of r.patterns) found.add(p);
      }
      if (found.size > 0) return { sink, cause: 'directive', patterns: [...found].sort() };
    }
    return null;
  } catch {
    return { sink, cause: 'screen-unavailable', patterns: [] };
  }
}
