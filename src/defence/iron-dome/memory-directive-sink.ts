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
 *       command stores text, and every storing op of an `operations` batch):
 *       every string it would store, under any key;
 *   G2  a Write / Edit / MultiEdit whose target is memory markdown
 *       (`isMemoryWritePath`, or a `.md` file directly inside a Hermes
 *       memories directory), on the RAW written text.
 *
 * It only EXTRACTS and SCREENS. The screen itself is
 * `detectMemoryDirective` (firewall/memory-directive-policy.ts), reused as
 * shipped; the verdict is minted by the guard, which only ever turns an
 * `allow` into an approval card with this module's answer.
 *
 * Fail-safe by construction: an input this module cannot read in full
 * (too much text, too many fields, nested too deep) and a screen that throws
 * all come back as a HIT with their own reason, never as "nothing found", so
 * an attacker-shaped input cannot turn a gap into an allow.
 *
 * Output is pattern names and fixed reason codes only, never memory text.
 */

import { detectMemoryDirective, type MemoryDirectiveResult } from '../firewall/memory-directive-policy.js';

/** The one guard signal for this sink. */
export const MEMORY_DIRECTIVE_SIGNAL = 'memory-directive';

export type MemoryDirectiveScreen = (text: string) => MemoryDirectiveResult;

/**
 * Normalised tool names whose every call stores a memory, whatever op key
 * it carries (an `action` / `command` on these is not read at all):
 *   - `remember`: ShieldCortex MCP (`mcp__shieldcortex__remember`,
 *     `mcp__memory__remember`, bare `remember`);
 *   - `save_memory`: Gemini CLI (`{fact}`);
 *   - `memory_store`: OpenClaw memory-lancedb (`{text, importance, category}`).
 */
const STORING_TOOLS: ReadonlySet<string> = new Set(['remember', 'save_memory', 'memory_store']);
/**
 * Normalised tool names that store only for some ops: `memory` (Hermes
 * `{action, target, content, old_text}` or `{operations: [...]}`; Anthropic's
 * memory tool `{command, path, file_text | new_str | insert_text}`). See
 * `opIsNonStoring` for the one way an op is skipped.
 */
const OP_TOOLS: ReadonlySet<string> = new Set(['memory']);

/** Op values that store no text: reads, removals, renames. */
const NON_STORING_OPS: ReadonlySet<string> = new Set([
  'remove', 'delete', 'read', 'view', 'list', 'get', 'search', 'recall', 'forget', 'rename',
]);
const OP_KEYS = ['action', 'op', 'operation', 'command'] as const;

/**
 * Keys never read: the REPLACED side of an edit names text that is going
 * away, not a new standing order. Exact key names; every other string leaf,
 * under any key and in any array, is stored text.
 */
const REPLACED_SIDE_KEYS: ReadonlySet<string> = new Set(['old_text', 'old_string', 'old_str']);
/**
 * G2 also skips the keys that name WHERE a write goes. The screen would not
 * fire on a path, so this is precision only: a file name is not a clause of
 * the note and is kept out of the joined text.
 */
const MARKDOWN_SKIP_KEYS: ReadonlySet<string> = new Set([...REPLACED_SIDE_KEYS, 'file_path', 'path', 'notebook_path']);

/** Containers deeper than this below the argument bag (which is depth 0) are
 *  not walked; one is a hold (`too-deep`), never a silent skip. */
export const MEMORY_SCREEN_MAX_DEPTH = 8;
/** Total stored text one call may carry and still be screened. The screen is
 *  linear (about 0.1 s per 200 KB); past this the call is carded unscreened
 *  rather than screened on a prefix an attacker could pad past. */
export const MEMORY_SCREEN_MAX_CHARS = 1_000_000;
/** String leaves one call may carry (each is also screened alone). Every
 *  leaf counts, op values and targets included, so a Hermes batch entry is
 *  about three. */
export const MEMORY_SCREEN_MAX_LEAVES = 1024;
/** Objects and arrays visited per call, so a wide bag with few strings is bounded too. */
export const MEMORY_SCREEN_MAX_NODES = 10_000;

/** `memory-tool`: a storing tool; `memory-op-tool`: a tool whose op decides;
 *  `memory-markdown`: a write-family call to memory markdown. */
export type MemoryDirectiveSinkKind = 'memory-tool' | 'memory-op-tool' | 'memory-markdown';

/** Why the sink holds the call. Fixed codes, never text. */
export type MemoryDirectiveHoldCause = 'directive' | 'too-large' | 'too-deep' | 'screen-unavailable';

export interface MemoryDirectiveHold {
  sink: MemoryDirectiveSinkKind;
  cause: MemoryDirectiveHoldCause;
  /** Pattern names (`memory_directive:<group>`) for `directive`; empty otherwise. */
  patterns: string[];
}

interface Collected {
  leaves: string[];
  /** Set when the call could not be read in full; the leaves are then partial. */
  overflow: 'too-large' | 'too-deep' | null;
}

/**
 * An op object is non-storing ONLY when it carries at least one op key and
 * EVERY op key it carries holds a string that is exactly a non-storing op.
 * A storing, unknown, misspelt, non-string or conflicting value means the
 * object is screened: a host reads one of those keys, and the guard cannot
 * know which, so a decoy key must not be able to skip the op.
 */
function opIsNonStoring(obj: Record<string, unknown>): boolean {
  let seen = false;
  for (const k of OP_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
    seen = true;
    const v = obj[k];
    if (typeof v !== 'string' || !NON_STORING_OPS.has(v)) return false;
  }
  return seen;
}

/**
 * Every string leaf of the call that it would store, arrays included, down
 * to `MEMORY_SCREEN_MAX_DEPTH`, minus the keys `sink` never reads.
 *
 * Op keys are consulted for `memory-op-tool` only, and only in two places:
 * the argument bag itself and each entry of its top-level `operations`
 * array. A non-storing entry is skipped whole. A non-storing argument bag
 * skips its own fields but not `operations`: Hermes applies a batch whenever
 * one is present and ignores the top-level action.
 *
 * Overflow (too much text, too many leaves or nodes, a container too deep)
 * is reported, never truncated silently.
 */
export function collectStoredText(args: unknown, sink: MemoryDirectiveSinkKind = 'memory-tool'): Collected {
  const skipKeys = sink === 'memory-markdown' ? MARKDOWN_SKIP_KEYS : REPLACED_SIDE_KEYS;
  const leaves: string[] = [];
  let chars = 0;
  let nodes = 0;
  let overflow: Collected['overflow'] = null;

  const take = (s: string): void => {
    if (s.length === 0) return;
    leaves.push(s);
    chars += s.length;
    if (leaves.length > MEMORY_SCREEN_MAX_LEAVES || chars > MEMORY_SCREEN_MAX_CHARS) overflow = 'too-large';
  };

  /** Bounds a container; false when the walk must stop. */
  const enter = (depth: number): boolean => {
    if (depth > MEMORY_SCREEN_MAX_DEPTH) { overflow = 'too-deep'; return false; }
    nodes += 1;
    if (nodes > MEMORY_SCREEN_MAX_NODES) { overflow = 'too-large'; return false; }
    return true;
  };

  const walk = (value: unknown, depth: number, opPosition: boolean): void => {
    if (overflow) return;
    if (typeof value === 'string') { take(value); return; }
    if (value === null || typeof value !== 'object') return;
    if (!enter(depth)) return;
    if (Array.isArray(value)) {
      for (const el of value) {
        walk(el, depth + 1, false);
        if (overflow) return;
      }
      return;
    }
    const obj = value as Record<string, unknown>;
    const nonStoring = opPosition && opIsNonStoring(obj);
    for (const [k, v] of Object.entries(obj)) {
      if (skipKeys.has(k)) continue;
      if (depth === 0 && sink === 'memory-op-tool' && k === 'operations') {
        if (Array.isArray(v)) {
          if (!enter(1)) return;
          for (const op of v) {
            walk(op, 2, true);
            if (overflow) return;
          }
        } else {
          walk(v, 1, false);
        }
      } else if (!nonStoring) {
        walk(v, depth + 1, false);
      }
      if (overflow) return;
    }
  };

  walk(args, 0, sink === 'memory-op-tool');
  return { leaves, overflow };
}

/** A `.md` file directly inside a Hermes `memories/` directory (the default
 *  home or a profile), any case. */
const HERMES_MEMORIES_MD_RE = /(^|\/)\.hermes\/(profiles\/[^/]+\/)?memories\/[^/]+\.md$/i;

/**
 * Memory markdown for THIS sink: `isMemoryWritePath` (passed in, so the
 * guard's own predicate, which also drives the #93 write-content scan, is
 * unchanged) or a `.md` file directly inside a Hermes memories directory
 * (`USER.md` there is not a memory basename). NotebookEdit stays out of the
 * Hermes rule.
 */
export function isSinkMemoryMarkdown(normalisedName: string, path: string, memoryWritePath: boolean): boolean {
  if (memoryWritePath) return true;
  if (normalisedName.includes('notebook')) return false;
  return HERMES_MEMORIES_MD_RE.test(String(path || '').trim().replace(/\\/g, '/'));
}

/**
 * Which memory sink this call is, or null. `normalisedName` is the guard's
 * `normaliseToolName`; `family` its `classifyFamily`; `memoryPath` is
 * `isSinkMemoryMarkdown` of the call's path. Read-side memory tools
 * (`recall`, `get_context`, `graph`, `forget`) are never a sink.
 */
export function memorySinkKind(
  normalisedName: string,
  family: string,
  memoryPath: boolean,
): MemoryDirectiveSinkKind | null {
  if (STORING_TOOLS.has(normalisedName)) return 'memory-tool';
  if (OP_TOOLS.has(normalisedName)) return 'memory-op-tool';
  if (family === 'write' && memoryPath) return 'memory-markdown';
  return null;
}

/**
 * The reason prefix for a hold: the sink, then the pattern names or the fixed
 * cause. Never memory text. (Kept here, not in the guard module, whose
 * kebab-case literals the approval-card vocabulary test reads as signal ids.)
 */
export function memoryDirectiveHoldReason(hold: MemoryDirectiveHold): string {
  const where = hold.sink === 'memory-markdown' ? 'memory-markdown write' : 'memory write';
  if (hold.cause === 'directive') return `${where} stores a standing directive (${hold.patterns.join(', ')})`;
  if (hold.cause === 'too-large') return `${where}: memory text too large to screen`;
  if (hold.cause === 'too-deep') return `${where}: memory text too nested to screen`;
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
  const { leaves, overflow } = collectStoredText(args, sink);
  if (overflow) return { sink, cause: overflow, patterns: [] };
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
