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
 *   G2  a write-family call (or an unknown-family call carrying new-side
 *       text) where ANY path value it carries is memory markdown
 *       (`isMemoryWritePath`, or a `.md` file directly inside a Hermes
 *       memories directory), raw and lexically normalised spellings both, on
 *       the RAW written text; and an `apply_patch` whose file header names
 *       memory markdown, on the lines it adds there.
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

import { posix } from 'node:path';
import { detectMemoryDirective, type MemoryDirectiveResult } from '../firewall/memory-directive-policy.js';
import { foldForProvenance } from '../firewall/provenance-policy.js';
import { PATH_KEYS } from './tool-input-schema.js';

/** The one guard signal for this sink. */
export const MEMORY_DIRECTIVE_SIGNAL = 'memory-directive';

export type MemoryDirectiveScreen = (text: string) => MemoryDirectiveResult;

/**
 * Normalised tool names whose every call stores a memory, whatever op key
 * it carries (an `action` / `command` on these is not read at all):
 *   - `remember`: ShieldCortex MCP (`mcp__shieldcortex__remember`,
 *     `mcp__memory__remember`, bare `remember`);
 *   - `save_memory`: Gemini CLI (`{fact}`);
 *   - `memory_store`: OpenClaw memory-lancedb (`{text, importance, category}`);
 *   - `import_memories`: ShieldCortex MCP (`{data: <JSON text>}`; the JSON
 *     text is one stored string and is screened as such);
 *   - `create_entities` / `add_observations`: the official MCP memory
 *     server (`entities[].observations[]`, `observations[].contents[]`).
 */
const STORING_TOOLS: ReadonlySet<string> = new Set([
  'remember', 'save_memory', 'memory_store', 'import_memories', 'create_entities', 'add_observations',
]);
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
 * Keys not read at a REPLACEMENT position (the argument bag, each top-level
 * `operations[]` entry, each top-level `edits[]` entry): there the replaced
 * side names text that is going away, not a new standing order. Exact key
 * names. Anywhere else (a nested object, an array element) they are ordinary
 * stored text: nothing there establishes replacement semantics.
 */
const REPLACED_SIDE_KEYS: ReadonlySet<string> = new Set(['old_text', 'old_string', 'old_str']);
/**
 * G2 also skips, at the same positions, the keys that name WHERE a write
 * goes. The screen would not fire on a path, so this is precision only: a
 * file name is not a clause of the note and is kept out of the joined text.
 */
const MARKDOWN_SKIP_KEYS: ReadonlySet<string> = new Set([...REPLACED_SIDE_KEYS, 'file_path', 'path', 'notebook_path']);

/**
 * Batch keys on the argument bag, matched in ANY case: every array under
 * one is a batch whose entries are replacement positions (and, for an op
 * tool, op positions). A host's own casing is not the guard's to guess.
 */
const BATCH_KEYS: ReadonlySet<string> = new Set(['operations', 'edits']);

/**
 * Keys that name where a write goes, matched in ANY case: the guard's
 * `PATH_KEYS` plus `notebook_path`. G2 reads EVERY one of them on the
 * argument bag and in each top-level `edits[]` entry, not the first one, so
 * a decoy key cannot hide the file a host actually writes.
 */
const SINK_PATH_KEYS: ReadonlySet<string> = new Set([...PATH_KEYS, 'notebook_path'].map((k) => k.toLowerCase()));

/** Keys that carry the NEW side of an edit; an unknown-family call needs one
 *  (any case) to be a G2 write. */
const NEW_SIDE_KEYS: ReadonlySet<string> = new Set([
  'content', 'contents', 'new_string', 'new_str', 'new_text', 'file_text', 'insert_text', 'text',
]);

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
 * to `MEMORY_SCREEN_MAX_DEPTH`, minus the keys `sink` does not read at a
 * replacement position (the argument bag and each entry of a top-level
 * `operations` / `edits` array, either key in any case).
 *
 * Op keys are consulted for `memory-op-tool` only, and only in two places:
 * the argument bag itself and each entry of a top-level `operations`
 * array. A non-storing entry is skipped whole. A non-storing argument bag
 * skips its own fields but not a batch: Hermes applies `operations`
 * whenever one is present and ignores the top-level action.
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

  /**
   * `position`: `bag` (the argument bag), `op` (an entry of a top-level
   * `operations` batch), `edit` (an entry of a top-level `edits` batch) or
   * `plain` (anything else). The first three are replacement positions.
   */
  const walk = (value: unknown, depth: number, position: 'bag' | 'op' | 'edit' | 'plain'): void => {
    if (overflow) return;
    if (typeof value === 'string') { take(value); return; }
    if (value === null || typeof value !== 'object') return;
    if (!enter(depth)) return;
    if (Array.isArray(value)) {
      for (const el of value) {
        walk(el, depth + 1, 'plain');
        if (overflow) return;
      }
      return;
    }
    const obj = value as Record<string, unknown>;
    const nonStoring = sink === 'memory-op-tool' && (position === 'bag' || position === 'op') && opIsNonStoring(obj);
    for (const [k, v] of Object.entries(obj)) {
      if (position !== 'plain' && skipKeys.has(k)) continue;
      const batch = position === 'bag' ? k.toLowerCase() : '';
      if (BATCH_KEYS.has(batch)) {
        // A batch is read whatever the bag's own op says: Hermes applies
        // `operations` whenever present and ignores the top-level action.
        if (Array.isArray(v)) {
          if (!enter(1)) return;
          for (const entry of v) {
            walk(entry, 2, batch === 'operations' ? 'op' : 'edit');
            if (overflow) return;
          }
        } else {
          walk(v, 1, 'plain');
        }
      } else if (!nonStoring) {
        walk(v, depth + 1, 'plain');
      }
      if (overflow) return;
    }
  };

  walk(args, 0, 'bag');
  return { leaves, overflow };
}

/** A `.md` file directly inside a Hermes `memories/` directory (the default
 *  home or a profile), any case. */
const HERMES_MEMORIES_MD_RE = /(^|\/)\.hermes\/(profiles\/[^/]+\/)?memories\/[^/]+\.md$/i;

/**
 * A lexical spelling of `path` the host resolves to the same file:
 * backslashes as `/`, `//`, `/./` and `a/../` collapsed (no filesystem I/O,
 * no symlinks), a trailing `/` dropped, and the trailing dots and spaces
 * Windows drops from a file name dropped too.
 */
export function normaliseSinkPath(path: string): string {
  const slashed = String(path || '').trim().replace(/\\/g, '/');
  if (!slashed) return '';
  let out = posix.normalize(slashed);
  // Hand-rolled (linear) trims: a trailing `/`, then trailing dots/spaces
  // unless they are a whole `.` / `..` segment.
  while (out.length > 1 && out.endsWith('/')) out = out.slice(0, -1);
  let end = out.length;
  while (end > 0 && (out[end - 1] === '.' || out[end - 1] === ' ')) end -= 1;
  return end > 0 && out[end - 1] !== '/' ? out.slice(0, end) : out;
}

/**
 * Memory markdown for THIS sink, tested on the raw spelling AND on
 * `normaliseSinkPath` of it (either one is enough, so a path that is memory
 * markdown as written stays so): `isMemoryWritePath` (passed in, so the
 * guard's own predicate, which also drives the #93 write-content scan, is
 * unchanged) or a `.md` file directly inside a Hermes memories directory
 * (`USER.md` there is not a memory basename). NotebookEdit stays out of the
 * Hermes rule.
 */
export function isSinkMemoryMarkdown(
  normalisedName: string,
  path: string,
  isMemoryWritePath: (path: string) => boolean,
): boolean {
  const hermes = !normalisedName.includes('notebook');
  for (const p of [String(path || '').trim().replace(/\\/g, '/'), normaliseSinkPath(path)]) {
    if (!p) continue;
    if (isMemoryWritePath(p)) return true;
    if (hermes && HERMES_MEMORIES_MD_RE.test(p)) return true;
  }
  return false;
}

/** Own keys of `obj` (any case) that are in `keys`, with their values. */
function valuesUnder(obj: unknown, keys: ReadonlySet<string>): unknown[] {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return [];
  return Object.entries(obj as Record<string, unknown>)
    .filter(([k]) => keys.has(k.toLowerCase()))
    .map(([, v]) => v);
}

/** The objects G2 reads paths and new-side keys from: the bag and each
 *  entry of a top-level `edits` array (any case). */
function editPositions(args: Record<string, unknown>): unknown[] {
  const out: unknown[] = [args];
  for (const v of valuesUnder(args, new Set(['edits']))) if (Array.isArray(v)) out.push(...v);
  return out;
}

/** EVERY string path value of the call (`SINK_PATH_KEYS`, any case), on the
 *  bag and in each top-level `edits[]` entry. */
export function sinkPathValues(args: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const pos of editPositions(args)) {
    for (const v of valuesUnder(pos, SINK_PATH_KEYS)) if (typeof v === 'string' && v) out.push(v);
  }
  return out;
}

/** True when the call carries a new-side text key (any case) on the bag or
 *  in a top-level `edits[]` entry. */
function carriesNewSideText(args: Record<string, unknown>): boolean {
  return editPositions(args).some((pos) => valuesUnder(pos, NEW_SIDE_KEYS).length > 0);
}

/** Keys an `apply_patch` call carries its patch text in (any case). */
const PATCH_TEXT_KEYS: ReadonlySet<string> = new Set(['input', 'patch']);
/** Codex's patch markers (openai/codex `apply-patch/src/parser.rs`). */
const PATCH_END = '*** End Patch';
const PATCH_MOVE_TO = '*** Move to: ';
const PATCH_FILE_HEADERS: ReadonlyArray<readonly [marker: string, state: 'add' | 'delete' | 'update']> = [
  ['*** Add File: ', 'add'],
  ['*** Delete File: ', 'delete'],
  ['*** Update File: ', 'update'],
];

/** Rust's `char::is_whitespace` (Unicode White_Space), what `str::trim` and
 *  `str::trim_end` strip. JS `trim` is a different set: it lacks U+0085 and
 *  adds U+FEFF. */
function isRustWhiteSpace(c: number): boolean {
  return (c >= 0x09 && c <= 0x0d) || c === 0x20 || c === 0x85 || c === 0xa0 || c === 0x1680
    || (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 || c === 0x202f
    || c === 0x205f || c === 0x3000;
}
function rustTrimEnd(s: string): string {
  let end = s.length;
  while (end > 0 && isRustWhiteSpace(s.charCodeAt(end - 1))) end--;
  return s.slice(0, end);
}
function rustTrim(s: string): string {
  let start = 0;
  while (start < s.length && isRustWhiteSpace(s.charCodeAt(start))) start++;
  return rustTrimEnd(s.slice(start));
}

/**
 * The lines an `apply_patch` call adds to memory markdown (each `+` line of
 * a file section whose header, or `*** Move to:` destination, is memory
 * markdown, minus the `+`), all joined, or null when no header names memory
 * markdown. Removed and context lines are not read: they are not stored.
 * The sink screens `patchMemoryScreenUnits`, not this joined text.
 */
export function patchAddedMemoryText(
  normalisedName: string,
  args: Record<string, unknown>,
  isMemoryPath: (path: string) => boolean,
): string | null {
  const sections = patchMemorySections(normalisedName, args, isMemoryPath);
  return sections === null ? null : sections.flat(2).join('\n');
}

/**
 * The added memory lines grouped as Codex writes them: one entry per memory
 * file section, each a list of RUNS (consecutive `+` lines, which land as
 * consecutive lines of the file; any other line ends a run). Null when no
 * header names memory markdown.
 *
 * It follows the state of Codex's parser (openai/codex@21aa552e,
 * `streaming_parser.rs`), line by line (split on `\n`; the trailing `\r`
 * each of its two line splits strips is dropped):
 *   - outside a file section, and in an Add File or Delete File section, a
 *     file header or `*** End Patch` is matched on the line trimmed of
 *     Unicode White_Space at both ends (`rustTrim`, Rust's `str::trim`);
 *   - in an Update File section it is matched on the line trimmed at the END
 *     only (`rustTrimEnd`), so a line starting with a space there is a
 *     context line, whatever follows the space; `*** Move to:` is read the
 *     same way, once, and only before the section's first chunk line;
 *   - a `+` line is read raw, in an Add File or Update File section.
 * Invariant: for every patch Codex accepts, every line Codex writes into a
 * memory markdown file is in the returned sections. Codex rejects a patch with
 * any other line shape; for such input this is the guard's own reading
 * (Begin Patch changes no state, and headers are read again after End).
 */
function patchMemorySections(
  normalisedName: string,
  args: Record<string, unknown>,
  isMemoryPath: (path: string) => boolean,
): string[][][] | null {
  const isMemory = (path: string): boolean => isSinkMemoryMarkdown(normalisedName, path, isMemoryPath);
  let named = false;
  const sections: string[][][] = [];
  for (const text of valuesUnder(args, PATCH_TEXT_KEYS)) {
    if (typeof text !== 'string') continue;
    let state: 'outside' | 'add' | 'delete' | 'update' = 'outside';
    let inMemory = false;
    let chunkSeen = false;
    let moveSeen = false;
    let section: string[][] | null = null;
    let run: string[] | null = null;
    for (const split of text.split('\n')) {
      let line = split;
      for (let i = 0; i < 2 && line.endsWith('\r'); i++) line = line.slice(0, -1);
      const marker: string = state === 'update' ? rustTrimEnd(line) : rustTrim(line);
      const added = inMemory && (state === 'add' || state === 'update') && line.startsWith('+');
      if (!added) run = null;
      if (marker === PATCH_END) {
        state = 'outside';
        inMemory = false;
        section = null;
        continue;
      }
      const header: (typeof PATCH_FILE_HEADERS)[number] | undefined =
        PATCH_FILE_HEADERS.find(([prefix]) => marker.startsWith(prefix));
      if (header) {
        state = header[1];
        inMemory = state !== 'delete' && isMemory(marker.slice(header[0].length));
        named = named || inMemory;
        chunkSeen = false;
        moveSeen = false;
        section = null;
        continue;
      }
      if (state === 'update') {
        if (!chunkSeen && !moveSeen && marker.startsWith(PATCH_MOVE_TO)) {
          moveSeen = true;
          // A move keeps the section's memory-ness: either end is memory markdown.
          const memory = isMemory(marker.slice(PATCH_MOVE_TO.length));
          inMemory = inMemory || memory;
          named = named || memory;
          continue;
        }
        if (marker === '@@' || marker.startsWith('@@ ') || line === '' || /^[ +-]/.test(line)) chunkSeen = true;
      }
      if (!added) continue;
      if (section === null) sections.push(section = []);
      if (run === null) section.push(run = []);
      run.push(line.slice(1));
    }
  }
  return named ? sections : null;
}

/** A fence or a double quote, after the screen's own fold: the only wrappers
 *  of `detectMemoryDirective` that pair across a line break. */
const CROSS_LINE_FENCE = '```';
const CROSS_LINE_QUOTE = '"';

/**
 * What the sink screens for an `apply_patch` to memory markdown: a list of
 * texts, each screened on its own (null when no header names memory
 * markdown). A patch does not show the file around the lines it adds, and
 * the screen exempts a directive by its context (a closed fence or double
 * quote a cue introduces, a cue on the line above a fence), so no unit may
 * borrow context from text the file does not hold next to it:
 *   (a) each memory file section's added lines, on their own (never joined
 *       across sections or files);
 *   (b) each added line that carries a fence or a double quote, on its own,
 *       and again behind an open double quote or an open fence (the file
 *       above it may hold either, which pairs its delimiters the other way);
 *   (c) each stretch of the other lines of one run (lines Codex writes next
 *       to each other), split at every line of (b): no span the screen reads
 *       crosses such a stretch, so it holds no context the file lacks.
 * Screening more units can only add holds. Identical units are screened once.
 * Past the screen's bounds (`MEMORY_SCREEN_MAX_CHARS` of added text, or more
 * than `MEMORY_SCREEN_MAX_LEAVES` units) the list is cut short; the call is
 * then held as too large to screen, never allowed on part of it.
 */
export function patchMemoryScreenUnits(
  normalisedName: string,
  args: Record<string, unknown>,
  isMemoryPath: (path: string) => boolean,
): string[] | null {
  const sections = patchMemorySections(normalisedName, args, isMemoryPath);
  if (sections === null) return null;
  const units = new Set<string>();
  let chars = 0;
  const add = (unit: string): void => {
    if (unit.length === 0 || units.has(unit)) return;
    units.add(unit);
    chars += unit.length;
  };
  // Already past what `screenMemoryWrite` reads: it holds on these alone.
  const full = (): boolean => chars > MEMORY_SCREEN_MAX_CHARS || units.size > MEMORY_SCREEN_MAX_LEAVES;
  for (const runs of sections) add(runs.flat().join('\n'));
  for (const runs of sections) {
    for (const run of runs) {
      let stretch: string[] = [];
      for (const line of run) {
        if (full()) return [...units];
        const folded = foldForProvenance(line);
        const fence = folded.includes(CROSS_LINE_FENCE);
        const quote = folded.includes(CROSS_LINE_QUOTE);
        if (!fence && !quote) { stretch.push(line); continue; }
        add(stretch.join('\n'));
        stretch = [];
        add(line);
        if (quote) add(`${CROSS_LINE_QUOTE}${line}`);
        if (fence) add(`${CROSS_LINE_FENCE}\n${line}`);
      }
      add(stretch.join('\n'));
    }
  }
  return [...units];
}

/** What the sink screens for this call: its kind and the value to collect
 *  stored text from. */
export interface MemorySinkTarget {
  kind: MemoryDirectiveSinkKind;
  stored: unknown;
}

/**
 * Which memory sink this call is, and what it stores, or null.
 * `normalisedName` is the guard's `normaliseToolName`; `family` its
 * `classifyFamily`. Read-side memory tools (`recall`, `get_context`,
 * `graph`, `forget`) are never a sink; read- and exec-family calls are never
 * a G2 sink.
 *
 *   - a storing tool / an op tool: the whole argument bag;
 *   - G2: a `write`-family call, or an `unknown`-family call carrying a
 *     new-side text key (`str_replace`, `search_replace`), where ANY path
 *     value is memory markdown: the whole argument bag;
 *   - otherwise an `apply_patch` whose header names memory markdown: the
 *     lines it adds there, as `patchMemoryScreenUnits`.
 */
export function memorySinkTarget(
  normalisedName: string,
  family: string,
  args: Record<string, unknown>,
  isMemoryWritePath: (path: string) => boolean,
): MemorySinkTarget | null {
  if (STORING_TOOLS.has(normalisedName)) return { kind: 'memory-tool', stored: args };
  if (OP_TOOLS.has(normalisedName)) return { kind: 'memory-op-tool', stored: args };
  if (family !== 'write' && family !== 'unknown') return null;
  if (family === 'write' || carriesNewSideText(args)) {
    if (sinkPathValues(args).some((p) => isSinkMemoryMarkdown(normalisedName, p, isMemoryWritePath))) {
      return { kind: 'memory-markdown', stored: args };
    }
  }
  if (normalisedName === 'apply_patch') {
    const units = patchMemoryScreenUnits(normalisedName, args, isMemoryWritePath);
    if (units !== null) return { kind: 'memory-markdown', stored: units };
  }
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
