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

const EXEC_KEYS = new Set([
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
  'description', 'timeout', 'run_in_background', 'dangerouslyDisableSandbox',
  'cwd', 'working_directory', 'env',
  'stdin', 'stdout', 'stderr', 'args', 'argv',
]);

const WRITE_KEYS = new Set([
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
  'new_string', 'old_string', 'content', 'contents', 'file_text', 'body', 'text',
  'description',
  // Non-exec tools may still carry these keys; extractors + field discipline decide weight.
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
]);

const READ_KEYS = new Set([
  'path', 'file_path', 'filePath', 'file', 'target', 'offset', 'limit', 'description',
]);

const NETWORK_KEYS = new Set([
  'url', 'uri', 'endpoint', 'href', 'host', 'to', 'method', 'headers', 'body',
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
const EXTRACTOR_KEYS = new Set([
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
  'url', 'uri', 'endpoint', 'href', 'host', 'to',
  'stdin', 'new_string', 'old_string', 'content', 'contents', 'file_text', 'body', 'text',
]);

/** Command/path/url keys the scanners actually read as strings. Object/array here is fail-closed. Messaging `content`/`body`/`text` are NOT in this set — Block Kit payloads must not trip the guard. */
const STRING_SCAN_KEYS = new Set([
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run', 'stdin',
  'path', 'file_path', 'filePath', 'file', 'target', 'destination', 'dir', 'directory',
  'url', 'uri', 'endpoint', 'href', 'host', 'to',
]);

const UNKNOWN_FAMILY_KEYS = new Set([
  'description', 'timeout', 'title', 'name', 'id',
  // Messaging / notification tools: free-form body is data, not shell (field discipline).
  'content', 'message', 'text', 'body', 'channel', 'to', 'subject',
  // Extractor keys may appear on unknown tools; keep for scan, do not invent semantics.
  'command', 'cmd', 'script', 'code', 'input', 'shell', 'run',
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
}

/**
 * P0 reviewed host contracts. These are exact spellings, not suffix/pattern
 * matches: an unrelated third-party `*_spawn` / `*run*` tool must retain the
 * old fail-closed family behaviour.
 */
interface ExactSpecialSchema {
  allowed: Set<string>;
  family: 'read' | 'network';
}

const WEB_RUN_KEYS = new Set([
  'search_query', 'open', 'click', 'find', 'image_query', 'calculator',
  'weather', 'finance', 'sports', 'time', 'response_length',
]);

const DELEGATION_KEYS = new Set([
  'task', 'label', 'runtime', 'agentId', 'model', 'thinking', 'cwd',
  'runTimeoutSeconds', 'timeoutSeconds', 'thread', 'mode', 'cleanup',
  'sandbox', 'attachments', 'context', 'taskName',
  'task_name', 'fork_turns', 'reasoning_effort', 'message',
]);

const WEB_RUN_ALIASES = new Set([
  'webrun', 'web.run', 'web__run', 'mcp__web__run',
]);

const DELEGATION_ALIASES = new Set([
  'sessions_spawn', 'openclawsessions_spawn',
  'openclaw.sessions_spawn', 'openclaw__sessions_spawn', 'mcp__openclaw__sessions_spawn',
  'collaborationspawn_agent', 'collaboration.spawn_agent', 'collaboration__spawn_agent',
  'mcp__collaboration__spawn_agent',
]);

function exactSpecialSchemaFor(toolName: string): ExactSpecialSchema | null {
  const exact = String(toolName ?? '').trim().toLowerCase();
  if (WEB_RUN_ALIASES.has(exact)) return { allowed: WEB_RUN_KEYS, family: 'network' };
  if (DELEGATION_ALIASES.has(exact)) return { allowed: DELEGATION_KEYS, family: 'read' };
  return null;
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
 * shape keeps working. The bag is still CLOSED and still carries no exec key:
 * a control tool cannot smuggle a command through it.
 */
const SHELL_CONTROL_TASK_OUTPUT: ShellControlSchema = {
  allowed: new Set(['bash_id', 'task_id', 'agentId', 'filter', 'block', 'timeout']),
  handles: ['bash_id', 'task_id', 'agentId'],
  fieldTypes: { block: 'boolean', timeout: 'number' },
};

/** TaskStop reads `task_id ?? shell_id` — the live contract adds nothing, so neither does this. */
const SHELL_CONTROL_STOP: ShellControlSchema = {
  allowed: new Set(['shell_id', 'task_id']),
  handles: ['shell_id', 'task_id'],
};

/**
 * EXACT native tool names only — the WHOLE name, case-insensitively. A
 * namespaced `mcp__thirdparty__BashOutput` is a third-party tool that merely
 * borrowed the name, so it keeps EXEC_KEYS and still fails closed on `bash_id`.
 * That is stricter than the last-segment matching used elsewhere, on purpose.
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

/** Align with classifyFamily so exec-class tools never use the unknown bag. */
export function schemaFamilyForTool(
  toolName: string,
): 'exec' | 'write' | 'read' | 'network' | 'memory' | 'git' | 'unknown' {
  const n = String(toolName || '').toLowerCase().trim();
  const special = exactSpecialSchemaFor(n);
  if (special) return special.family;
  const seg = n.split(/__|\.|:|\//).filter(Boolean).pop() ?? n;
  if (/(remember|recall|forget|memory|get_context|getcontext)/.test(seg) || /(remember|recall|forget|memory)/.test(n)) {
    return 'memory';
  }
  if (
    /(^|_)(bash|shell|exec|terminal|run_terminal|powershell|cmd|run_command|script|eval|spawn|process|system|sh|zsh)(_|$)/.test(seg)
    || /^(bash|shell|sh|zsh|exec|cmd|powershell|run|command)$/.test(seg)
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
  const allowed = allowedKeysFor(toolName);
  const strippedKeys: string[] = [];
  const out: Record<string, unknown> = {};
  const unknown: string[] = [];

  for (const [key, value] of Object.entries(raw)) {
    const isAbsent = value === '' || value === null || value === undefined;

    if (!allowed.has(key)) {
      // An empty value does NOT excuse an unknown key: skipping it here would
      // let `{command:'ok', evil:''}` fail open on the enforcement path.
      if (mode === 'enforce') {
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
    if (expected === null && STRING_SCAN_KEYS.has(key) && typeof value !== 'string') {
      return {
        ok: false,
        code: typeof value === 'object' ? 'NESTED_INVALID' : 'TYPE_COERCION',
        reason: `Field "${key}" must be a string, got ${Array.isArray(value) ? 'array' : typeof value}`,
      };
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
