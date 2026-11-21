/**
 * #970 r3 mixed-version fixture: the closed-schema gate of a CLI from BEFORE
 * #970 — copied from `parseSelfReport` at 277e88f4 (the branch base), not
 * imported, so it cannot drift with the code under test. Only the checks that
 * decide whether a newer writer's report is even read: schema id, version,
 * closed top-level keys, closed `instance` keys. Not a test file itself.
 */

const TOP_KEYS = [
  'schema', 'version', 'runtime', 'profile', 'plane', 'instance', 'runtime_version', 'plugin',
  'heartbeat_at', 'loaded', 'configured_posture', 'scanner', 'policy_hash', 'degraded_intervals', 'denials',
] as const;

function exactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(o);
  return own.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));
}

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** `null` when a pre-#970 CLI would go on to read the report, else its rejection reason. */
export function legacyGateRejects(text: string): string | null {
  let o: unknown;
  try {
    o = JSON.parse(text);
  } catch {
    return 'not JSON';
  }
  if (!isObj(o)) return 'not a JSON object';
  if (o.schema !== 'shieldcortex.posture.self-report') return 'unrecognised schema id';
  if (o.version !== 1) return `version ${typeof o.version === 'number' ? o.version : '?'} is not supported`;
  if (Object.keys(o).some((k) => !(TOP_KEYS as readonly string[]).includes(k))) return 'unknown keys';
  const missing = TOP_KEYS.filter((k) => !(k in o));
  if (missing.length > 0) return `missing keys: ${missing.join(', ')}`;
  const inst = o.instance;
  if (!isObj(inst) || !exactKeys(inst, ['key', 'pid', 'process_start', 'started_at', 'liveness'])) return 'invalid instance';
  return null;
}
