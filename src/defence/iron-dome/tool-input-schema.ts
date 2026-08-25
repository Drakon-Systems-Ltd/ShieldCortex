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
 *      unknown keys but never invents values
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
  code: 'NOT_OBJECT' | 'UNKNOWN_KEYS' | 'NESTED_INVALID' | 'TYPE_COERCION';
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

const UNKNOWN_FAMILY_KEYS = new Set([
  'description', 'timeout', 'title', 'name', 'id',
]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

/** Align with classifyFamily so exec-class tools never use the unknown bag. */
export function schemaFamilyForTool(
  toolName: string,
): 'exec' | 'write' | 'read' | 'network' | 'memory' | 'git' | 'unknown' {
  const n = String(toolName || '').toLowerCase().trim();
  const seg = n.split(/__|\.|:|\//).filter(Boolean).pop() ?? n;
  if (/(remember|recall|forget|memory|get_context|getcontext)/.test(seg) || /(remember|recall|forget|memory)/.test(n)) {
    return 'memory';
  }
  if (
    /(^|_)(bash|shell|exec|terminal|run_terminal|powershell|cmd|run_command|script|eval|spawn|process|system|sh|zsh)(_|$)/.test(seg)
    || /^(bash|shell|sh|zsh|exec|cmd|powershell)$/.test(seg)
    || /(bash|shell|exec|terminal)/.test(n)
  ) {
    return 'exec';
  }
  if (/(^git$|git_|_git|github)/.test(seg) || seg === 'git') return 'git';
  if (/(^read|read_file|cat$|view_file|get_file|search_files|grep|glob)/.test(seg)) return 'read';
  if (/(write|edit|create_file|apply_patch|strreplace|mkdir|save|copy)/.test(seg)) return 'write';
  if (/(http|fetch|curl|wget|web_request|browser|web_fetch|web_search|email)/.test(seg) || /(web_fetch|web_search|fetch)/.test(n)) {
    return 'network';
  }
  return 'unknown';
}

function allowedKeysFor(toolName: string): Set<string> {
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

  const allowed = allowedKeysFor(toolName);
  const strippedKeys: string[] = [];
  const out: Record<string, unknown> = {};
  const unknown: string[] = [];

  for (const [key, value] of Object.entries(raw)) {
    // Empty strings are absent payload (hosts/tests often send command:'' alongside
    // url/query). Drop them before unknown-key checks so they do not fail closed.
    if (value === '' || value === null || value === undefined) {
      continue;
    }
    if (!allowed.has(key)) {
      if (mode === 'enforce') unknown.push(key);
      else strippedKeys.push(key);
      continue;
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

  return { ok: true, args: out, strippedKeys };
}

/** Convenience: enforce mode, throw-free. */
export function enforceToolInput(toolName: string, raw: unknown): ToolInputValidation {
  return validateToolInput(toolName, raw, 'enforce');
}
