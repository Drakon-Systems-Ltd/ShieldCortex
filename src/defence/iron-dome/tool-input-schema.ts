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
  'description', 'timeout',
]);

const MEMORY_KEYS = new Set([
  'title', 'content', 'query', 'category', 'type', 'project', 'tags', 'limit',
  'importance', 'scope', 'transferable', 'memoryPurpose', 'memoryScope',
  'source', 'sourceType', 'sourceIdentifier', 'sessionId', 'agentId', 'workspaceDir',
  'includeDecayed', 'includeGlobal', 'mode', 'id', 'memoryId',
]);

const GENERIC_SAFE_KEYS = new Set([
  'description', 'timeout', 'title', 'name', 'id',
]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

function familyForTool(toolName: string): 'exec' | 'write' | 'read' | 'network' | 'memory' | 'generic' {
  const n = String(toolName || '').toLowerCase();
  if (/(^|_)(bash|shell|exec|terminal|run_terminal|powershell|cmd)(_|$)/.test(n) || n === 'bash') return 'exec';
  if (/(write|edit|create_file|apply_patch|strreplace)/.test(n)) return 'write';
  if (/(^read|read_file|cat$|view_file|get_file)/.test(n)) return 'read';
  if (/(http|fetch|curl|wget|web_request|browser)/.test(n)) return 'network';
  if (/(remember|recall|forget|memory|get_context)/.test(n)) return 'memory';
  return 'generic';
}

function allowedKeysFor(toolName: string): Set<string> | null {
  const fam = familyForTool(toolName);
  switch (fam) {
    case 'exec': return EXEC_KEYS;
    case 'write': return WRITE_KEYS;
    case 'read': return READ_KEYS;
    case 'network': return NETWORK_KEYS;
    case 'memory': return MEMORY_KEYS;
    default: return null; // unknown family — only generic-safe + no nested smuggle
  }
}

function validateNested(value: unknown, path: string): ToolInputValidationErr | null {
  if (value === null || value === undefined) return null;
  const t = typeof value;
  if (t === 'string' || t === 'number' || t === 'boolean') return null;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      const err = validateNested(value[i], `${path}[${i}]`);
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
  // Nested plain objects: only string/number/boolean/array-of-primitives leaves.
  for (const [k, v] of Object.entries(value)) {
    if (typeof k !== 'string' || !k) {
      return { ok: false, code: 'NESTED_INVALID', reason: `Invalid nested key at ${path}` };
    }
    // Reject prototype pollution keys always
    if (k === '__proto__' || k === 'constructor' || k === 'prototype') {
      return { ok: false, code: 'NESTED_INVALID', reason: `Forbidden key ${k} at ${path}` };
    }
    const err = validateNested(v, `${path}.${k}`);
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
    // Some hosts pass a raw command string for Bash — box it.
    return { ok: true, args: { command: raw }, strippedKeys: [] };
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

  for (const [key, value] of Object.entries(raw)) {
    const permitted = allowed
      ? allowed.has(key)
      : GENERIC_SAFE_KEYS.has(key) || typeof value !== 'object' || value === null;

    if (!permitted) {
      if (mode === 'enforce') {
        return {
          ok: false,
          code: 'UNKNOWN_KEYS',
          reason: `Unknown tool input field "${key}" rejected`,
          unknownKeys: [key],
        };
      }
      strippedKeys.push(key);
      continue;
    }

    const nestedErr = validateNested(value, key);
    if (nestedErr) return nestedErr;

    // No type coercion: numbers must be numbers, etc. (leave as-is if already correct)
    out[key] = value;
  }

  return { ok: true, args: out, strippedKeys };
}

/** Convenience: enforce mode, throw-free. */
export function enforceToolInput(toolName: string, raw: unknown): ToolInputValidation {
  return validateToolInput(toolName, raw, 'enforce');
}
