/**
 * #412 — closed tool-input schemas on the enforcement path.
 *
 * Downstream extractors (extractCommand/path/url) used to read an open bag.
 * Unknown nested keys or smuggled shapes could carry security-relevant data
 * that was never intended for the guard. This module:
 *   1. Accepts only plain objects
 *   2. For known tool families, allows a closed key set (+ optional nested
 *      objects validated recursively)
 *   3. Rejects unknown keys (fail closed) when `mode: 'enforce'`
 *   4. In `mode: 'annotate'` (default for hash/approve stability), strips
 *      unknown keys but never invents values — EXCEPT the extractor keys
 *      (see EXTRACTOR_KEYS), which always survive so annotate cannot blind
 *      the guard on non-exec surfaces such as `Workflow.script`
 *
 * ── Native contract drift ──────────────────────────────────────────────────
 *
 * The closed bag was doing two jobs at once. Job A — evidence discipline: make
 * sure a command-bearing key on a delegation tool gets SCANNED rather than
 * read-short-circuited. Load-bearing, kept. Job B — novelty rejection: deny any
 * key not enumerated when the contract was last measured. Job B is a staleness
 * alarm wired to the deny path, and it caused a card storm on ordinary work
 * every time a host shipped a field (13 of `sessions_spawn`'s 28 live fields
 * denied; three hand-widenings in a row: #436, #445, and this one).
 *
 * For EXACT-SPECIAL native contracts only, the unknown-key verdict is now split
 * by SCANNABILITY rather than by membership:
 *
 *   - unknown key IN `GUARD_EVIDENCE_KEYS` → unchanged. `UNKNOWN_KEYS`, fail
 *     closed, raw-evidence rescan; a spawn that grows a `command` or `argv` is
 *     precisely the smuggle this module exists to catch, and an `argv` wipe
 *     stays catastrophic and doorless.
 *   - unknown key OUTSIDE it → dropped BEFORE nested validation and before any
 *     extractor, the call proceeds, and the key NAME (never its value) is
 *     returned in `strippedKeys` as a bounded contract-drift observation.
 *
 * Inertness is decided by ShieldCortex's OWN reader lists, so a caller cannot
 * nominate its key as inert. A dropped key is never forwarded, never granted
 * semantics, and can never widen a verdict — it just stops minting cards.
 */

export type ToolInputMode = 'enforce' | 'annotate';

export interface ToolInputValidationOk {
  ok: true;
  args: Record<string, unknown>;
  strippedKeys: string[];
}

export interface ToolInputValidationErr {
  ok: false;
  reason: string;
  code: 'NOT_OBJECT' | 'UNKNOWN_KEYS' | 'NESTED_INVALID' | 'TYPE_COERCION' | 'MISSING_HANDLE';
  unknownKeys?: string[];
}

export type ToolInputValidation = ToolInputValidationOk | ToolInputValidationErr;

/**
 * ── Canonical extractor/evidence key lists ─────────────────────────────────
 *
 * ShieldCortex's OWN readers, in one place. `tool-action-guard.ts` imports
 * these arrays rather than restating them, so "which keys does a scanner
 * actually read?" has exactly one answer and a contract fold cannot be built
 * against a stale copy. ORDER IS LOAD-BEARING: `pickString` is first-wins.
 *
 * Nothing here is caller-supplied. A tool cannot nominate its key into (or out
 * of) these lists — that is what keeps the drift fold below from becoming
 * "trust the payload's own idea of what is inert".
 */
export const COMMAND_KEYS = [
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
] as const;

export const PATH_KEYS = [
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
] as const;

export const URL_KEYS = ['url', 'uri', 'endpoint', 'href', 'host', 'to', 'cc', 'bcc'] as const;

/**
 * Recipient keys whose LIVE contract is `string | string[]`. Gmail's
 * `send_message`/`reply`/`forward` all declare `to`/`cc`/`bcc` as arrays of
 * addresses, and `to` sits in `URL_KEYS` (it is an egress destination), so the
 * blanket "a scanned key must be a string" rule below denied every real
 * multi-recipient send as `NESTED_INVALID`.
 *
 * This is a per-KEY relaxation, not a per-TYPE one: `url`/`uri`/`endpoint`/
 * `href`/`host` stay string-only, so "URL evidence may be an array" remains
 * false everywhere except the three recipient spellings. The array itself is
 * still shape-checked — every element must be a string and the list is bounded
 * — and the elements are still read by `extractUrl`, so a smuggled exfil
 * destination is weighed exactly as the single-string spelling is.
 */
export const RECIPIENT_LIST_KEYS: ReadonlySet<string> = new Set(['to', 'cc', 'bcc']);

/** Longest recipient list accepted. Beyond this the shape is not a live send. */
export const RECIPIENT_LIST_MAX = 256;

export const WRITE_CONTENT_KEYS = [
  'new_string', 'content', 'contents', 'file_text', 'body', 'text',
] as const;

/** Command-bearing aliases the schema-failure recovery pass must union-scan. */
export const COMMAND_EVIDENCE_KEYS = [...COMMAND_KEYS, 'args', 'argv'] as const;

/** Keys `hasOutboundData` consults to decide a network call carries a payload. */
export const OUTBOUND_DATA_KEYS = [
  'body', 'data', 'json', 'form', 'payload', 'formData', 'files',
] as const;

/** Keys `hasOutboundData` consults for the HTTP verb. */
export const OUTBOUND_METHOD_KEYS = ['method', 'httpMethod', 'verb'] as const;

/** Process-stream keys carried into the exec bag and scanned as strings. */
export const STREAM_KEYS = ['stdin', 'stdout', 'stderr', 'env'] as const;

/**
 * EVERY key any ShieldCortex reader consults by name — the union of the lists
 * above. This is the fail-closed floor for the exact-special contract fold:
 * an UNDECLARED key in this set is never inert, because a scanner would have
 * read it. `command`/`cmd`/`script`/`run`/`args`/`argv`/`path`/`url` and every
 * other extractor alias therefore keep the pre-fold behaviour byte for byte —
 * `UNKNOWN_KEYS`, raw-evidence rescan, catastrophic stays terminal.
 */
export const GUARD_EVIDENCE_KEYS: ReadonlySet<string> = new Set<string>([
  ...COMMAND_KEYS,
  ...PATH_KEYS,
  ...URL_KEYS,
  ...WRITE_CONTENT_KEYS,
  ...COMMAND_EVIDENCE_KEYS,
  ...OUTBOUND_DATA_KEYS,
  ...OUTBOUND_METHOD_KEYS,
  ...STREAM_KEYS,
  'old_string',
]);

const EXEC_KEYS = new Set<string>([
  ...COMMAND_KEYS,
  'description', 'timeout', 'run_in_background', 'dangerouslyDisableSandbox',
  'cwd', 'working_directory', 'env',
  'stdin', 'stdout', 'stderr', 'args', 'argv',
]);

const WRITE_KEYS = new Set<string>([
  ...PATH_KEYS,
  'old_string', ...WRITE_CONTENT_KEYS,
  'description',
  // Non-exec tools may still carry these keys; extractors + field discipline decide weight.
  ...COMMAND_KEYS,
]);

const READ_KEYS = new Set([
  'path', 'file_path', 'filePath', 'file', 'target', 'offset', 'limit', 'description',
]);

const NETWORK_KEYS = new Set<string>([
  ...URL_KEYS, 'method', 'headers', 'body',
  'query', 'description', 'timeout',
]);

const MEMORY_KEYS = new Set([
  'title', 'content', 'query', 'category', 'type', 'project', 'tags', 'limit',
  'importance', 'scope', 'transferable', 'memoryPurpose', 'memoryScope',
  'source', 'sourceType', 'sourceIdentifier', 'sessionId', 'agentId', 'workspaceDir',
  'includeDecayed', 'includeGlobal', 'mode', 'id', 'memoryId',
]);

/**
 * Keys the downstream extractors (extractCommand / extractPath / extractUrl /
 * extractWriteContent) actually read. Stripping one of these in annotate mode
 * blinds the guard: `Workflow.script` carrying a force-push scanned clean and
 * returned `allow`. These survive annotate for EVERY family, and must be
 * strings — a smuggled object/array here is fail-closed, not silently ignored.
 */
const EXTRACTOR_KEYS = new Set<string>([
  ...COMMAND_KEYS, ...PATH_KEYS, ...URL_KEYS,
  'stdin', 'old_string', ...WRITE_CONTENT_KEYS,
]);

/** Command/path/url keys the scanners actually read as strings. Object/array here is fail-closed. Messaging `content`/`body`/`text` are NOT in this set — Block Kit payloads must not trip the guard. */
const STRING_SCAN_KEYS = new Set<string>([
  ...COMMAND_KEYS, 'stdin', ...PATH_KEYS, ...URL_KEYS,
]);

const UNKNOWN_FAMILY_KEYS = new Set<string>([
  'description', 'timeout', 'title', 'name', 'id',
  // Messaging / notification tools: free-form body is data, not shell (field discipline).
  'content', 'message', 'text', 'body', 'channel', 'to', 'cc', 'bcc', 'subject',
  // Extractor keys may appear on unknown tools; keep for scan, do not invent semantics.
  ...COMMAND_KEYS,
  'path', 'file_path', 'filePath', 'file', 'url', 'uri',
]);

/**
 * #436 — Claude Code's own background-shell CONTROL plane. `BashOutput` reads
 * an already-running shell's buffered output; `KillShell`/`KillBash` stop it.
 * Neither starts an OS process: the originating `Bash` call was scanned when it
 * was made. Their handle keys (`bash_id`/`shell_id`/`task_id`) are absent from
 * EXEC_KEYS, so the substring `bash`/`shell` match sent every live control call
 * to `invalid_tool_input` — a hard block on the guard's own read-and-stop path.
 *
 * The schema stays CLOSED and deliberately omits every exec key: a control tool
 * must not be able to smuggle a command through this bag. Nothing here is added
 * to EXEC_KEYS, so real `Bash` enforcement is untouched.
 */
interface ShellControlSchema {
  /** Closed allowed-key set. */
  allowed: Set<string>;
  /** At least one of these must carry a non-empty string, else fail closed. */
  handles: string[];
  /**
   * Per-field primitive type; absent means `'string'`. The live host
   * contract for `TaskOutput` requires `block: boolean` and `timeout: number`
   * beside `task_id`, so the blanket string rule below denied every real call.
   * Types stay EXACT: an array, an object, or a coerced `'true'` in one of
   * these fields fails closed exactly as a non-string handle does.
   */
  fieldTypes?: Record<string, 'string' | 'boolean' | 'number'>;
  /**
   * Inclusive numeric bounds for a `'number'` field, copied from the host's own
   * JSON Schema. `Number.isFinite` alone accepted `-1` and `600001`, neither of
   * which the host will ever send: the contract is a RANGE, and a bag that
   * claims to be the live contract has to enforce the whole of it. Out of range
   * fails closed like any other shape the host cannot produce.
   */
  numericRanges?: Record<string, { min: number; max: number }>;
}

/**
 * P0 reviewed host contracts. These are exact spellings, not suffix/pattern
 * matches: an unrelated third-party `*_spawn` / `*run*` tool must retain the
 * old fail-closed family behaviour.
 *
 * NATIVE SPELLINGS ONLY. The `mcp__web__run` / `mcp__openclaw__sessions_spawn`
 * / `mcp__collaboration__spawn_agent` spellings used to sit here, which handed
 * any MCP server that chose one of those names a reviewed contract on the
 * strength of caller-supplied identity. They are gone. After this exact lookup,
 * every syntactically MCP-fronted name resolves to the `unknown` schema family:
 * harmless structured host fields are stripped from the guard view, while the
 * shared raw-evidence pass still scans command/cmd/script/run/args/argv before
 * schema handling. That is neither trusted identity nor an open schema.
 */
interface ExactSpecialSchema {
  /** Closed set of DECLARED host fields. */
  allowed: Set<string>;
  /**
   * Declared fields whose VALUE no ShieldCortex reader ever consults, and whose
   * live shape `validateNested` cannot express. `sessions_spawn.outputSchema`
   * is an arbitrary caller-authored JSON Schema (`Type.Record(String, Unknown)`)
   * — nested two deep, so it tripped `NESTED_INVALID` even once its key was
   * allowed. These are DROPPED before nested validation and before any
   * extractor: deleted, not judged. Declared, so this is not drift.
   */
  inert?: Set<string>;
  family: 'read' | 'network' | 'exec';
  /** Stable label for the contract-drift observation. Never a payload value. */
  contract: string;
}

const WEB_RUN_KEYS = new Set<string>([
  'search_query', 'open', 'click', 'find', 'image_query', 'calculator',
  'weather', 'finance', 'sports', 'time', 'response_length',
]);

/**
 * The LIVE OpenClaw `sessions_spawn` contract — all 28 declared top-level
 * fields of `createSessionsSpawnToolSchema` (`sessions-spawn-tool.ts`) with
 * every capability flag on, including the swarm block
 * (`collect`/`outputSchema`/`fastMode`/`groupId`), the visible-session family
 * (`VISIBLE_SESSIONS_SPAWN_SCHEMA`: `visible`/`category`/`worktree`/
 * `worktreeName`/`worktreeBaseRef`) and the ACP block
 * (`resumeSessionId`/`streamTo`).
 *
 * The February bag carried 16 of these; the other 13 hard-denied every modern
 * spawn — `{task, runtime, visible, worktree}` blocked on `visible`. Measured,
 * not guessed. Not one of these keys is a GUARD_EVIDENCE_KEY, which is the
 * invariant that makes the whole contract inert to the scanners
 * (`native-contract-drift.test.ts` pins it).
 */
const OPENCLAW_SPAWN_KEYS = new Set<string>([
  'task', 'taskName', 'label', 'runtime', 'agentId', 'model',
  'runTimeoutSeconds', 'thinking', 'cwd', 'thread', 'mode', 'cleanup',
  'sandbox', 'context', 'lightContext',
  // swarm block (config-gated upstream)
  'collect', 'outputSchema', 'fastMode', 'groupId',
  // visible-session family
  'visible', 'category', 'worktree', 'worktreeName', 'worktreeBaseRef',
  'attachments', 'attachAs',
  // ACP block (config-gated upstream)
  'resumeSessionId', 'streamTo',
  // Back-compat: the shipped pre-visible schema still accepts timeoutSeconds.
  'timeoutSeconds',
]);

/**
 * Collaboration `spawn_agent` is a SEPARATE contract, not a synonym. No
 * upstream schema source is reachable from here, so this is exactly the
 * measured live field set and nothing invented alongside it — folding it into
 * the OpenClaw bag would have granted each host the other's fields on no
 * evidence. Anything beyond these is undeclared: inert-dropped and reported as
 * drift, never denied.
 */
const COLLABORATION_SPAWN_KEYS = new Set<string>([
  'task_name', 'fork_turns', 'model', 'reasoning_effort', 'message',
]);

const WEB_RUN_ALIASES = new Set(['webrun', 'web.run', 'web__run']);

const OPENCLAW_SPAWN_ALIASES = new Set([
  'sessions_spawn', 'openclawsessions_spawn',
  'openclaw.sessions_spawn', 'openclaw__sessions_spawn',
]);

const COLLABORATION_SPAWN_ALIASES = new Set([
  'collaborationspawn_agent', 'collaboration.spawn_agent', 'collaboration__spawn_agent',
]);

/**
 * Live OpenClaw 2026.8.1 `exec` bag (`bash-tools.schemas.ts` `execSchema`).
 * Extra host fields are typed control, not Claude `cwd`/`timeout` spellings.
 * `host` here is auto|sandbox|gateway|node — not a URL.
 */
const OPENCLAW_EXEC_KEYS = new Set<string>([
  ...COMMAND_KEYS,
  'workdir', 'env', 'yieldMs', 'background', 'timeoutSeconds',
  'pty', 'elevated', 'host', 'security', 'ask', 'node',
  'description', 'timeout', 'run_in_background', 'cwd', 'working_directory',
  'stdin', 'stdout', 'stderr', 'args', 'argv',
]);

const OPENCLAW_EXEC_ALIASES = new Set(['exec']);

const OPENCLAW_SPAWN_INERT = new Set<string>(['outputSchema']);

function exactSpecialSchemaFor(toolName: string): ExactSpecialSchema | null {
  const exact = String(toolName ?? '').trim().toLowerCase();
  if (WEB_RUN_ALIASES.has(exact)) {
    return { allowed: WEB_RUN_KEYS, family: 'network', contract: 'web.run' };
  }
  if (OPENCLAW_SPAWN_ALIASES.has(exact)) {
    return {
      allowed: OPENCLAW_SPAWN_KEYS,
      inert: OPENCLAW_SPAWN_INERT,
      family: 'read',
      contract: 'openclaw.sessions_spawn',
    };
  }
  if (COLLABORATION_SPAWN_ALIASES.has(exact)) {
    return {
      allowed: COLLABORATION_SPAWN_KEYS,
      family: 'read',
      contract: 'collaboration.spawn_agent',
    };
  }
  if (OPENCLAW_EXEC_ALIASES.has(exact)) {
    return {
      allowed: OPENCLAW_EXEC_KEYS,
      family: 'exec',
      contract: 'openclaw.exec',
    };
  }
  return null;
}

/** The contract label an exact-special tool name resolves to, or null. */
export function exactSpecialContractName(toolName: string): string | null {
  return exactSpecialSchemaFor(toolName)?.contract ?? null;
}

/** Special contracts are enforced closed even though their effects are read/network. */
export function hasExactSpecialToolSchema(toolName: string): boolean {
  return exactSpecialSchemaFor(toolName) !== null;
}

/**
 * `BashOutput` reads `bash_id ?? task_id ?? agentId`; `filter` is an output
 * regex — data, not a command. All four are strings. Legacy shape, unchanged.
 */
const SHELL_CONTROL_BASH_OUTPUT: ShellControlSchema = {
  allowed: new Set(['bash_id', 'task_id', 'agentId', 'filter']),
  handles: ['bash_id', 'task_id', 'agentId'],
};

/**
 * TaskOutput live-contract fix (regression from #445). The LIVE native
 * `TaskOutput` contract is
 * `{task_id: string, block: boolean, timeout: number}`: all three REQUIRED,
 * `additionalProperties: false`. #445 pointed `TaskOutput` at the BashOutput
 * bag, so `block` and `timeout` were UNKNOWN_KEYS and every real call — the
 * host's own background read path, one of the highest-frequency tools an
 * unattended operator runs — was denied.
 *
 * The legacy handle/`filter` keys stay allowed so a host still on the older
 * shape keeps working, so what this bag accepts is the UNION of the live shape
 * and those older spellings rather than the live required triple alone. The bag
 * is still CLOSED and still carries no exec key: a control tool cannot smuggle
 * a command through it.
 *
 * `timeout` carries the host's own bounds — `{"type":"number","minimum":0,
 * "maximum":600000}` — not merely `Number.isFinite`. A negative or
 * over-maximum wait is a value the host rejects, so ShieldCortex rejects it
 * too instead of forwarding a call that cannot succeed.
 */
const SHELL_CONTROL_TASK_OUTPUT: ShellControlSchema = {
  allowed: new Set(['bash_id', 'task_id', 'agentId', 'filter', 'block', 'timeout']),
  handles: ['bash_id', 'task_id', 'agentId'],
  fieldTypes: { block: 'boolean', timeout: 'number' },
  numericRanges: { timeout: { min: 0, max: 600_000 } },
};

/** TaskStop reads `task_id ?? shell_id` — the live contract adds nothing, so neither does this. */
const SHELL_CONTROL_STOP: ShellControlSchema = {
  allowed: new Set(['shell_id', 'task_id']),
  handles: ['shell_id', 'task_id'],
};

/**
 * EXACT native tool names only — the WHOLE name, case-insensitively. A
 * namespaced `mcp__thirdparty__BashOutput` merely borrowed the name and gets no
 * native shell-control contract: like every syntactically MCP-fronted tool it
 * uses the generic unknown schema family, while raw command evidence is scanned
 * independently with execution semantics.
 */
function shellControlSchemaFor(toolName: string): ShellControlSchema | null {
  switch (String(toolName ?? '').trim().toLowerCase()) {
    case 'bashoutput': return SHELL_CONTROL_BASH_OUTPUT;
    case 'taskoutput': return SHELL_CONTROL_TASK_OUTPUT;
    case 'killshell':
    case 'killbash':
    case 'taskstop': return SHELL_CONTROL_STOP;
    default: return null;
  }
}

/** #439: native control tools are not exec-family by name, but their bag is still closed. */
export function isNativeShellControlTool(toolName: string): boolean {
  return shellControlSchemaFor(toolName) != null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

/**
 * Exec vocabulary as WORDS. A name built entirely out of these — in any
 * separator style — is an exec tool: `run_command`, `runCommand`, `RunCmd`,
 * `execute_command`, `shell`, `run`. A name that merely CONTAINS one of the
 * weak words is not: `workflow_run` runs nothing, `get_command` reads one,
 * `slash_command` names one, `command_center` is a noun.
 *
 * The strong words below keep their own segment-anchored rule as well, because
 * `vendor_bash` / `sessions_spawn` are exec whatever the other words are.
 */
const EXEC_WORDS: ReadonlySet<string> = new Set([
  'bash', 'shell', 'sh', 'zsh', 'powershell', 'cmd', 'command', 'commands',
  'exec', 'execute', 'run', 'runs', 'terminal', 'script', 'eval', 'spawn',
  'process', 'system',
]);

/**
 * Words strong enough to pick the closed EXEC bag from ANY segment position.
 * `run` and `command` are deliberately ABSENT: as a bare segment token they
 * matched `workflow_run`, `get_command`, `slash_command` and `command_center`,
 * and forced the live GitHub-Actions / slash-command bags into EXEC_KEYS where
 * every real field was an UNKNOWN_KEY — a hard deny on tools that execute
 * nothing. They are reachable only through the whole-name word rule above.
 */
const EXEC_ANCHORED_WORD =
  /(^|_)(bash|shell|exec|terminal|powershell|cmd|script|eval|spawn|process|system|sh|zsh)(_|$)/;

/** Longest single token this module will try to split into glued exec words. */
const EXEC_GLUE_MAX_LEN = 32;
/** Most words a glued token may decompose into (`runcommand` = 2). */
const EXEC_GLUE_MAX_WORDS = 3;

/**
 * Split a tool-name segment into lowercase words. camelCase IS a separator:
 * `runCommand` is the same name as `run_command`, and lowercasing the whole
 * segment first (which this module used to do before asking) destroyed the
 * only boundary that made them the same — so `runCommand` fell to the unknown
 * bag while `run_command` stayed closed.
 */
function nameWords(segment: string): string[] {
  return String(segment || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toLowerCase());
}

/**
 * A single token that is a run of exec words glued together with no separator
 * at all (`runcommand`, `shellexec`). Bounded in both length and word count so
 * this stays a lookup, not a search. `runbook` does not decompose (`book` is
 * not exec vocabulary) and neither do `preprocess`, `systemctl`, `evaluate` or
 * `subscription` — the substring false positives this whole fold is about.
 */
function isGluedExecWords(word: string, budget = EXEC_GLUE_MAX_WORDS): boolean {
  if (EXEC_WORDS.has(word)) return true;
  if (budget <= 1 || word.length > EXEC_GLUE_MAX_LEN) return false;
  for (let i = 2; i < word.length; i++) {
    if (EXEC_WORDS.has(word.slice(0, i)) && isGluedExecWords(word.slice(i), budget - 1)) return true;
  }
  return false;
}

/** Every word of the name is exec vocabulary — the whole name IS the verb. */
function isAllExecWords(segment: string): boolean {
  const words = nameWords(segment);
  if (words.length === 0) return false;
  if (words.length === 1) return isGluedExecWords(words[0]);
  return words.every((w) => EXEC_WORDS.has(w));
}

/**
 * True only for the host spelling `mcp__<server>__<tool>` (case-insensitive).
 * Server names may contain single underscores; an empty server or tool is not
 * syntactically MCP-fronted. This is a routing boundary, not provenance.
 */
export function isMcpFrontedToolName(toolName: string): boolean {
  const raw = String(toolName || '').trim();
  return /^mcp__(?!_)(?:(?!__).)+__(?=.)[\s\S]+$/i.test(raw);
}

/** Pick the closed schema family, with exact native and MCP routing first. */
export function schemaFamilyForTool(
  toolName: string,
): 'exec' | 'write' | 'read' | 'network' | 'memory' | 'git' | 'unknown' {
  const raw = String(toolName || '').trim();
  const n = raw.toLowerCase();
  const special = exactSpecialSchemaFor(n);
  if (special) return special.family;
  // MCP spelling carries no trustworthy native identity. Keep its guard view
  // on the closed annotate path instead of guessing a contract from the final
  // segment (`sessions_spawn`, `bash`, etc.). Raw command evidence was already
  // scanned before schema handling by commandEvidencePass.
  if (isMcpFrontedToolName(raw)) return 'unknown';
  // Keep the ORIGINAL case of the segment: camelCase is a word boundary.
  const rawSeg = raw.split(/__|\.|:|\//).filter(Boolean).pop() ?? raw;
  const seg = n.split(/__|\.|:|\//).filter(Boolean).pop() ?? n;
  if (/(remember|recall|forget|memory|get_context|getcontext)/.test(seg) || /(remember|recall|forget|memory)/.test(n)) {
    return 'memory';
  }
  // Three questions, narrowest first:
  //   1. does a STRONG exec word occupy a whole segment token (`vendor_bash`,
  //      `sessions_spawn`)?
  //   2. is the name built ENTIRELY out of exec words, in any separator style
  //      (`run_command`, `runCommand`, `runcommand`, `execute_command`, `run`)?
  //   3. does the name contain an unambiguous exec substring anywhere?
  //
  // #454 anchored `run`/`command` at segment boundaries, which was still too
  // wide: `(^|_)run(_|$)` matched the live `get_workflow_run` /
  // `list_workflow_runs` GitHub bags and `(^|_)command(_|$)` matched
  // `get_command` / `slash_command` / `command_center`, forcing all of them
  // into EXEC_KEYS where every declared field is an UNKNOWN_KEY — a hard deny
  // on read-only host tools. Both weak words now need the WHOLE name to be
  // exec vocabulary, which is exactly the class that can actually run
  // something. Nothing here removes a SCAN: a command payload on any of these
  // names is still weighed by `classifyFamily`'s substring net and by the
  // shared command-evidence pass in `evaluateToolCall`.
  if (
    EXEC_ANCHORED_WORD.test(seg)
    || isAllExecWords(rawSeg)
    || /(bash|shell|exec|terminal)/.test(n)
  ) {
    return 'exec';
  }
  // Real git CLIs only. Do not substring-match `_git` inside `_github`.
  if (/(^git$|^git_|_git$|_git_)/.test(seg) || seg === 'git') return 'git';
  if (/(^read|read_file|cat$|view_file|get_file|search_files|grep|glob)/.test(seg)) return 'read';
  if (/(write|edit|create_file|apply_patch|strreplace|mkdir|save|copy|remove_file|delete_file)/.test(seg)) return 'write';
  if (/(http|fetch|curl|wget|web_request|browser|web_fetch|web_search|email)/.test(seg) || /(web_fetch|web_search|fetch)/.test(n)) {
    return 'network';
  }
  return 'unknown';
}

function allowedKeysFor(toolName: string): Set<string> {
  const special = exactSpecialSchemaFor(toolName);
  if (special) return special.allowed;
  // #436: the native control plane is narrower than its exec family, not wider.
  const control = shellControlSchemaFor(toolName);
  if (control) return control.allowed;
  const fam = schemaFamilyForTool(toolName);
  switch (fam) {
    case 'exec':
    case 'git':
      return EXEC_KEYS;
    case 'write':
      return WRITE_KEYS;
    case 'read':
      return READ_KEYS;
    case 'network':
      return NETWORK_KEYS;
    case 'memory':
      return MEMORY_KEYS;
    default:
      return UNKNOWN_FAMILY_KEYS;
  }
}

function validateNested(value: unknown, path: string, depth = 0): ToolInputValidationErr | null {
  if (value === null || value === undefined) return null;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') return null;
  if (depth > 3) {
    return { ok: false, code: 'NESTED_INVALID', reason: `Nesting too deep at ${path}` };
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const err = validateNested(value[i], `${path}[${i}]`, depth + 1);
      if (err) return err;
    }
    return null;
  }
  if (!isPlainObject(value)) {
    return {
      ok: false,
      code: 'NESTED_INVALID',
      reason: `Unsupported nested type at ${path}`,
    };
  }
  for (const [k, v] of Object.entries(value)) {
    if (!k) {
      return { ok: false, code: 'NESTED_INVALID', reason: `Invalid nested key at ${path}` };
    }
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
      return { ok: false, code: 'NESTED_INVALID', reason: `Forbidden key ${k} at ${path}` };
    }
    // env/headers maps: one level of primitives only — no nested objects.
    if (isPlainObject(v)) {
      return { ok: false, code: 'NESTED_INVALID', reason: `Nested object not allowed at ${path}.${k}` };
    }
    const err = validateNested(v, `${path}.${k}`, depth + 1);
    if (err) return err;
  }
  return null;
}

/**
 * Validate / normalise tool input for enforcement.
 * - enforce: unknown keys → fail closed
 * - annotate: unknown keys stripped (returned in strippedKeys)
 */
export function validateToolInput(
  toolName: string,
  raw: unknown,
  mode: ToolInputMode = 'enforce',
): ToolInputValidation {
  if (raw === undefined || raw === null) {
    return { ok: true, args: {}, strippedKeys: [] };
  }
  if (typeof raw === 'string') {
    // Only box raw strings as command for exec/git families.
    const fam = schemaFamilyForTool(toolName);
    if (fam === 'exec' || fam === 'git') {
      return { ok: true, args: { command: raw }, strippedKeys: [] };
    }
    return { ok: false, code: 'NOT_OBJECT', reason: 'tool input must be a plain object' };
  }
  if (!isPlainObject(raw)) {
    return { ok: false, code: 'NOT_OBJECT', reason: 'tool input must be a plain object' };
  }

  // Reject pollution at top level
  for (const bad of ['__proto__', 'constructor', 'prototype']) {
    if (Object.prototype.hasOwnProperty.call(raw, bad)) {
      return { ok: false, code: 'NESTED_INVALID', reason: `Forbidden key ${bad}` };
    }
  }

  const control = shellControlSchemaFor(toolName);
  const special = exactSpecialSchemaFor(toolName);
  const allowed = allowedKeysFor(toolName);
  const strippedKeys: string[] = [];
  const out: Record<string, unknown> = {};
  const unknown: string[] = [];

  for (const [key, value] of Object.entries(raw)) {
    const isAbsent = value === '' || value === null || value === undefined;

    // A DECLARED field the guard never reads and cannot shape-check
    // (`sessions_spawn.outputSchema` is caller-authored JSON Schema). Deleted
    // before nested validation, so its nesting never reaches validateNested.
    // Declared → not drift, so it is not reported in strippedKeys.
    if (special?.inert?.has(key)) continue;

    if (!allowed.has(key)) {
      // An empty value does NOT excuse an unknown key: skipping it here would
      // let `{command:'ok', evil:''}` fail open on the enforcement path.
      if (mode === 'enforce') {
        // Contract drift on a reviewed native contract: the host grew a field
        // no ShieldCortex reader consults. Drop it before nested validation
        // and before the extractors, and record the NAME for the observation.
        // Anything a scanner WOULD have read stays fail-closed below.
        if (special && !GUARD_EVIDENCE_KEYS.has(key)) {
          strippedKeys.push(key);
          continue;
        }
        unknown.push(key);
        continue;
      }
      // annotate: keep extractor-critical keys so unknown tool names are not blinded
      const specialArgvEvidence = exactSpecialSchemaFor(toolName) && (key === 'args' || key === 'argv');
      if (!EXTRACTOR_KEYS.has(key) && !specialArgvEvidence) {
        strippedKeys.push(key);
        continue;
      }
    }

    // Allowed (or retained extractor) key with no payload: absent, not invalid.
    // Hosts routinely send `command: ''` alongside the field they actually used.
    if (isAbsent) continue;

    // Command/path/url scanners only accept strings. Object/array/number/boolean
    // cannot be scanned (extractors are pickString) so they must not fail open.
    // `content`/`body`/`text` stay out of STRING_SCAN_KEYS (structured messages).
    // #436: a control tool's fields are typed by its live host contract —
    // handles and `filter` are strings, TaskOutput's `block` is a boolean and
    // its `timeout` a number. Anything else is not a shape the host ever sends,
    // so it fails closed rather than reaching the extractors. Widening the bag
    // must never widen the shapes it accepts.
    const expected = control ? (control.fieldTypes?.[key] ?? 'string') : null;
    if (expected !== null && typeof value !== expected) {
      return {
        ok: false,
        code: typeof value === 'object' ? 'NESTED_INVALID' : 'TYPE_COERCION',
        reason: `Field "${key}" must be a ${expected}, got ${Array.isArray(value) ? 'array' : typeof value}`,
      };
    }
    if (expected === 'number' && !Number.isFinite(value)) {
      return {
        ok: false,
        code: 'TYPE_COERCION',
        reason: `Field "${key}" must be a finite number`,
      };
    }
    const range = control?.numericRanges?.[key];
    if (range && typeof value === 'number' && (value < range.min || value > range.max)) {
      return {
        ok: false,
        code: 'TYPE_COERCION',
        reason: `Field "${key}" must be between ${range.min} and ${range.max}`,
      };
    }
    if (expected === null && STRING_SCAN_KEYS.has(key) && typeof value !== 'string') {
      // The recipient exception: `to`/`cc`/`bcc` may be a LIST of addresses,
      // because that is the live Gmail contract. Everything else about the
      // rule holds — the list must be flat strings, non-empty, and bounded.
      // A nested/typed element is the shape a scanner cannot read, so it fails
      // closed exactly as a smuggled object in `url` does.
      const list = RECIPIENT_LIST_KEYS.has(key) && Array.isArray(value) ? value : null;
      if (!list) {
        return {
          ok: false,
          code: typeof value === 'object' ? 'NESTED_INVALID' : 'TYPE_COERCION',
          reason: `Field "${key}" must be a string, got ${Array.isArray(value) ? 'array' : typeof value}`,
        };
      }
      if (list.length > RECIPIENT_LIST_MAX) {
        return {
          ok: false,
          code: 'NESTED_INVALID',
          reason: `Field "${key}" list exceeds ${RECIPIENT_LIST_MAX} entries`,
        };
      }
      for (const el of list) {
        // An empty element is ABSENT, not invalid — the same rule the top-level
        // keys use (`command: ''` beside the field the host actually filled).
        // A non-string element is a shape no reader can consult: fail closed.
        if (el === '' || el === null || el === undefined) continue;
        if (typeof el !== 'string') {
          return {
            ok: false,
            code: typeof el === 'object' ? 'NESTED_INVALID' : 'TYPE_COERCION',
            reason: `Field "${key}" list entries must be strings, got ${Array.isArray(el) ? 'array' : typeof el}`,
          };
        }
      }
    }

    const nestedErr = validateNested(value, key);
    if (nestedErr) return nestedErr;

    out[key] = value;
  }

  if (unknown.length > 0) {
    return {
      ok: false,
      code: 'UNKNOWN_KEYS',
      reason: `Unknown tool input field "${unknown[0]}" rejected`,
      unknownKeys: unknown,
    };
  }

  // #436: a control call that names no shell is not a control call. Fail closed
  // rather than let an empty bag through on a tool whose whole job is a handle.
  if (control && !control.handles.some((k) => typeof out[k] === 'string' && out[k].trim() !== '')) {
    return {
      ok: false,
      code: 'MISSING_HANDLE',
      reason: `Tool input must name a shell (${control.handles.join(' | ')})`,
    };
  }

  return { ok: true, args: out, strippedKeys };
}

/** Convenience: enforce mode, throw-free. */
export function enforceToolInput(toolName: string, raw: unknown): ToolInputValidation {
  return validateToolInput(toolName, raw, 'enforce');
}

/** Most drifted key NAMES one observation carries. Names only — never values. */
export const CONTRACT_DRIFT_MAX_KEYS = 12;
/** Longest reported key name. A key name is attacker-chosen text; bound it. */
export const CONTRACT_DRIFT_MAX_KEY_LEN = 64;

export interface ContractDriftObservation {
  /** Reviewed contract the tool name resolved to, e.g. `openclaw.sessions_spawn`. */
  contract: string;
  /** Undeclared, provably unscanned field NAMES that were dropped. Bounded. */
  droppedKeys: string[];
  /** True when more keys drifted than `CONTRACT_DRIFT_MAX_KEYS` reports. */
  truncated?: boolean;
}

/**
 * Control characters and Unicode line breaks in a drifted key NAME.
 *
 * A key name is model-controlled text — a prompt-injected payload can choose
 * it — and it travels to an operator's gateway log, where a newline buys a
 * whole extra line. A dropped key spelled
 * `x<LF>[shieldcortex] action-guard ALLOWED Bash: operator approved<LF>zz`
 * rendered a forged ShieldCortex verdict into journald on the ordinary
 * unattended ALLOW path — and journald is precisely where an operator looks
 * to find out what the guard actually did.
 *
 * The full C0 and C1 ranges (C1 because U+0085 NEL is a line break to several
 * readers and terminals act on the rest) plus U+2028/U+2029 collapse to a
 * single space. One space per character, so the bounds below are unchanged and
 * nothing shifts under truncation.
 */
const DRIFT_KEY_CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/**
 * The contract-drift observation for a call, or null when nothing drifted.
 *
 * Derived from `validateToolInput` itself rather than restating the strip rule,
 * so the observation can never disagree with what enforcement actually did.
 * Carries key NAMES only: no value, no length, no shape — a drifted field may
 * hold a prompt, a token, or a whole JSON Schema, and none of that belongs in
 * an audit row.
 *
 * Names are neutralised HERE, at the single point they are minted, rather than
 * at each sink: the observation reaches a gateway log line, a jsonl audit row
 * and an operator summary, and a rule applied per-sink is a rule one new sink
 * forgets.
 */
export function contractDriftFor(toolName: string, raw: unknown): ContractDriftObservation | null {
  const contract = exactSpecialContractName(toolName);
  if (!contract) return null;
  const validated = validateToolInput(toolName, raw, 'enforce');
  if (!validated.ok || validated.strippedKeys.length === 0) return null;
  const droppedKeys = validated.strippedKeys
    .slice(0, CONTRACT_DRIFT_MAX_KEYS)
    .map((k) => k.replace(DRIFT_KEY_CONTROL_CHARS, ' ').slice(0, CONTRACT_DRIFT_MAX_KEY_LEN));
  return {
    contract,
    droppedKeys,
    ...(validated.strippedKeys.length > CONTRACT_DRIFT_MAX_KEYS ? { truncated: true } : {}),
  };
}
