/**
 * #970 mixed-version fixture: how a CLI from BEFORE #970 finds and gates
 * self-reports — copied from `reportingProfiles` (src/posture/collect.ts
 * :208-240) and `parseSelfReport` (src/posture/posture-record.ts :303-330) at
 * 277e88f4, the branch base, not imported, so it cannot drift with the code
 * under test. collect.ts is byte-identical at 277e88f4, v5.20.2 and
 * origin/main. Only what decides whether a newer writer's file is even read:
 * the directory enumeration, then schema id, version, closed top-level keys,
 * closed `instance` keys. Not a test file itself.
 */
import fs from 'fs';
import path from 'path';

const TOP_KEYS = [
  'schema', 'version', 'runtime', 'profile', 'plane', 'instance', 'runtime_version', 'plugin',
  'heartbeat_at', 'loaded', 'configured_posture', 'scanner', 'policy_hash', 'degraded_intervals', 'denials',
] as const;

const INSTANCE_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

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

/**
 * The instance names a pre-#970 CLI lists in one profile directory, before
 * its cap: `*.json` names whose stem is a valid instance key. Every listed
 * name becomes a record (read, or rejected); anything else in the directory is
 * never opened, counted or reported.
 */
export function legacyListInstances(profileDir: string): string[] {
  let names: string[];
  try {
    names = fs.readdirSync(profileDir).sort();
  } catch {
    return [];
  }
  return names
    .filter((n) => n.endsWith('.json'))
    .map((n) => n.slice(0, -'.json'.length))
    .filter((n) => INSTANCE_RE.test(n));
}

/** What a pre-#970 CLI does with each file it lists in `profileDir`: read it (`null`) or reject it (reason). */
export function legacyReadProfile(profileDir: string): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const instance of legacyListInstances(profileDir)) {
    out[instance] = legacyGateRejects(fs.readFileSync(path.join(profileDir, `${instance}.json`), 'utf8'));
  }
  return out;
}
