/**
 * Per-runtime posture record (#613).
 *
 * One record per `(runtime, profile, plane, instance)`. `plane` is
 * `tool-gate` or `memory`; `instance` is the start identity of the runtime
 * process that reported (null when nothing reported). Two live processes
 * sharing a profile are two records, never last-writer-wins.
 *
 * Every field carries its OWN evidence: value, how and when it was observed,
 * how long that observation stays good, the path it tested, and the
 * process / plugin / effective-policy identity it was observed against. There
 * is no record-level probe that could make one field look fresher than it is.
 *
 * This replaces the overloaded `HostRuntimeEvidence.bound` boolean for
 * anything that describes gating. `bound` means "installed or SC-integrated",
 * stays for backwards-compatible display only, and is never an input here.
 *
 * Rules this module holds (design r2.1 §5.6, Tars r2.1 §1):
 *
 *  - **Explicit unknown.** A process-side value older than `max_age`, dated in
 *    the future, or from a process that cannot be shown to still be the one
 *    that wrote it is `unknown`/`unobserved`, never green.
 *  - **Membership is explicit.** A record is `current`, `ended` or
 *    `unobserved`. Records are what was FOUND; nothing here claims the host has
 *    no other runtime processes.
 *  - **A heartbeat never refreshes a denial.** Denial evidence carries its own
 *    timestamp and the identity it was observed against, and becomes
 *    `obsolete` on process restart, plugin change, effective-policy change,
 *    posture change, stale or future timestamps, or scanner degradation.
 *  - **A denial is narrow.** It shows that one tested path denied at that
 *    moment, nothing wider. It never feeds the posture level: an advisory or
 *    intentionally-off process is never shown as enforcing because it once
 *    denied something.
 *  - **Synthetic probes are not incidents.** `kind` separates
 *    `synthetic-probe` from `blocked-action`; only blocked actions are counted.
 *  - **Memory-only is never a tool gate.**
 *  - **No host-wide rollup to green.** A summary is its weakest record.
 *  - **The self-report is untrusted.** It is size-capped and validated
 *    against a closed schema, never executed or interpolated; an unknown
 *    version is `unknown`, not guessed forward.
 *
 * Host-integrity limitation: a self-report is a host-local file. Anything
 * running as the same user can write one. It is bounded local evidence of what
 * a process said about itself, not attestation, and not liveness on its own.
 *
 * This file is pure. `collect.ts` does the (read-only) disk and process work.
 */

export const POSTURE_RECORD_VERSION = 1;

export const SELF_REPORT_SCHEMA = 'shieldcortex.posture.self-report';
export const SELF_REPORT_VERSION = 1;
/** Hard cap on a self-report file. Anything bigger is rejected unread. */
export const SELF_REPORT_MAX_BYTES = 8192;
/** A self-report heartbeat older than this is stale, and stale is unknown. */
export const DEFAULT_MAX_AGE_MS = 24 * 60 * 60 * 1000;
/** A timestamp further ahead than this is not trusted. */
export const FUTURE_SKEW_MS = 5 * 60 * 1000;
export const MAX_DEGRADED_INTERVALS = 8;
export const MAX_REASON_CHARS = 120;
/** Most instances the collector reads per (runtime, profile). */
export const MAX_INSTANCES_PER_PROFILE = 16;

export const HOST_INTEGRITY_LIMITATION =
  'Self-reports are host-local files written by runtime processes on this host. Anything running ' +
  'as the same user can write one. They are bounded local evidence of what a process said about ' +
  'itself, not attestation, and not liveness on their own.';
export const COMPLETENESS_LIMITATION =
  'Records are the runtimes and processes found on this host. Nothing here claims there are no others.';

/** Runtimes whose process can gate a tool call and self-report. */
export const GATE_RUNTIMES = ['claude_code', 'openclaw', 'hermes'] as const;
export type GateRuntimeId = (typeof GATE_RUNTIMES)[number];
/** Runtimes ShieldCortex serves memory to but cannot gate. */
export const MEMORY_ONLY_RUNTIMES = ['codex', 'copilot'] as const;
export type MemoryOnlyRuntimeId = (typeof MEMORY_ONLY_RUNTIMES)[number];
export type PostureRuntimeId = GateRuntimeId | MemoryOnlyRuntimeId;

export type PosturePlane = 'tool-gate' | 'memory';
export type Capability = 'tool-gate' | 'memory-only' | 'none' | 'unknown';
export type Installed = 'yes' | 'no' | 'unknown';
export type RuntimeLoaded = 'yes' | 'no' | 'unobserved' | 'unknown';
export type ConfiguredPosture = 'enforce' | 'advisory' | 'intentionally-off' | 'unavailable' | 'unknown';
export type ObservedDenial = 'observed' | 'not-observed' | 'obsolete' | 'degraded' | 'unknown';
export type ScannerState = 'available' | 'degraded' | 'unknown';
export type DenialKind = 'blocked-action' | 'synthetic-probe';
export type Membership = 'current' | 'ended' | 'unobserved';
/**
 * `alive`: the host confirmed the reporting pid is running with the reported
 * start identity. `ended`: the pid is gone or now belongs to another process
 * (restart / PID reuse). `unverified`: the report named a resident process but
 * this host cannot check it. `per-call`: the reporter is a per-call hook with
 * no resident process; recency within max_age is the only evidence.
 */
export type Liveness = 'alive' | 'ended' | 'unverified' | 'per-call' | 'not-applicable';
/** How the reporter's process can be checked. */
export type LivenessMode = 'process' | 'per-call';

const CONFIGURED_POSTURES: readonly ConfiguredPosture[] = ['enforce', 'advisory', 'intentionally-off', 'unavailable', 'unknown'];
const SCANNER_STATES: readonly ScannerState[] = ['available', 'degraded', 'unknown'];

export interface DegradedInterval {
  from: string;
  /** null while the interval is still open. */
  to: string | null;
  reason: string;
}

export interface ProcessIdentity {
  runtime: PostureRuntimeId;
  runtime_version: string | null;
  /** Start identity of the reporting process; also the record key's `instance`. */
  instance: string;
  pid: number | null;
  /** Host-specific start token (Linux: /proc/<pid>/stat starttime). */
  process_start: string | null;
  started_at: string;
  liveness_mode: LivenessMode;
}

export interface PluginIdentity {
  id: string;
  version: string | null;
  hash: string | null;
}

export type EvidenceMethod =
  | 'static'
  | 'file-probe'
  | 'process-self-report'
  | 'process-liveness'
  | 'none';

/** One field's value and the evidence behind it. */
export interface FieldEvidence<V> {
  value: V;
  method: EvidenceMethod;
  /** Provenance, always `sc://...`. */
  source: string;
  observed_at: string | null;
  max_age_ms: number | null;
  /** The gate path the observation exercised, when it exercised one. */
  tested_path: string | null;
  process_identity: ProcessIdentity | null;
  plugin_identity: PluginIdentity | null;
  effective_policy_hash: string | null;
  /** Plain-English reason for an unknown / obsolete / unobserved value. */
  note: string | null;
}

export interface DenialEvidence extends FieldEvidence<ObservedDenial> {
  kind: DenialKind | null;
}

export type ObsoleteReason =
  | 'process-restart'
  | 'plugin-change'
  | 'policy-change'
  | 'posture-change'
  | 'stale'
  | 'future-dated'
  | 'scanner-degraded';

export interface PostureRecord {
  record_version: typeof POSTURE_RECORD_VERSION;
  /** `sc://posture/<runtime>/<profile>/<plane>/<instance|none>`. */
  source: string;
  key: { runtime: PostureRuntimeId; profile: string; plane: PosturePlane; instance: string | null };
  runtime: PostureRuntimeId;
  profile: string;
  plane: PosturePlane;
  membership: Membership;
  liveness: FieldEvidence<Liveness>;
  collected_at: string;
  capability: FieldEvidence<Capability>;
  installed: FieldEvidence<Installed>;
  runtime_loaded: FieldEvidence<RuntimeLoaded>;
  configured_posture: FieldEvidence<ConfiguredPosture>;
  scanner: FieldEvidence<ScannerState>;
  effective_policy_hash: FieldEvidence<string | null>;
  /** The strongest still-valid denial evidence, else why there is none. */
  observed_denial: DenialEvidence;
  /** Both kinds, separately, so a probe can never be read as an incident. */
  denials: { blocked_action: DenialEvidence | null; synthetic_probe: DenialEvidence | null };
  /** Real blocked actions this process reported. Synthetic probes are never counted. */
  incidents: FieldEvidence<number | null>;
  degraded_intervals: DegradedInterval[];
  notes: string[];
}

export interface SelfReportDenial {
  at: string;
  tested_path: string;
  instance: string;
  plugin_hash: string | null;
  policy_hash: string | null;
  configured_posture: ConfiguredPosture;
}

export interface SelfReport {
  schema: typeof SELF_REPORT_SCHEMA;
  version: typeof SELF_REPORT_VERSION;
  runtime: GateRuntimeId;
  profile: string;
  plane: 'tool-gate';
  instance: {
    key: string;
    pid: number | null;
    process_start: string | null;
    started_at: string;
    liveness: LivenessMode;
  };
  runtime_version: string | null;
  plugin: PluginIdentity;
  /** Heartbeat: when the process last wrote its CURRENT state. */
  heartbeat_at: string;
  loaded: boolean;
  configured_posture: ConfiguredPosture;
  scanner: ScannerState;
  policy_hash: string | null;
  degraded_intervals: DegradedInterval[];
  denials: {
    blocked_action: SelfReportDenial | null;
    synthetic_probe: SelfReportDenial | null;
    blocked_action_count: number;
  };
}

export type SelfReportRead =
  | { kind: 'absent' }
  | { kind: 'invalid'; reason: string; instance?: string }
  | { kind: 'valid'; report: SelfReport };

// ── Validation ──────────────────────────────────────────────────────────────

const PROFILE_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
/** Instance keys double as file names: closed, lower-case, no dots. */
const INSTANCE_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
/** Identifier-ish text: no whitespace, no control characters, no shell metacharacters. */
const IDENT_RE = /^[A-Za-z0-9@/._:+-]{1,64}$/;
const START_RE = /^[0-9]{1,20}$/;
/** Free text: printable ASCII only. */
const REASON_RE = new RegExp(`^[\\x20-\\x7e]{1,${MAX_REASON_CHARS}}$`);
const MAX_COUNT = 1_000_000_000;

function exactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(o);
  return own.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));
}

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export function isGateRuntime(v: unknown): v is GateRuntimeId {
  return typeof v === 'string' && (GATE_RUNTIMES as readonly string[]).includes(v);
}

export function isValidProfileId(v: unknown): v is string {
  return typeof v === 'string' && PROFILE_RE.test(v);
}

export function isValidInstanceKey(v: unknown): v is string {
  return typeof v === 'string' && INSTANCE_RE.test(v);
}

function isIso(v: unknown): v is string {
  return typeof v === 'string' && ISO_RE.test(v) && !Number.isNaN(Date.parse(v));
}

function nullable<T>(v: unknown, check: (x: unknown) => x is T): v is T | null {
  return v === null || check(v);
}

const isHash = (v: unknown): v is string => typeof v === 'string' && HASH_RE.test(v);
const isIdent = (v: unknown): v is string => typeof v === 'string' && IDENT_RE.test(v);
const isStart = (v: unknown): v is string => typeof v === 'string' && START_RE.test(v);
const isPid = (v: unknown): v is number => Number.isInteger(v) && (v as number) > 0 && (v as number) < 2 ** 31;
const isPosture = (v: unknown): v is ConfiguredPosture => CONFIGURED_POSTURES.includes(v as ConfiguredPosture);

function validInterval(v: unknown): v is DegradedInterval {
  if (!isObj(v) || !exactKeys(v, ['from', 'to', 'reason'])) return false;
  return isIso(v.from) && nullable(v.to, isIso) && typeof v.reason === 'string' && REASON_RE.test(v.reason);
}

function validDenial(v: unknown): v is SelfReportDenial {
  if (!isObj(v) || !exactKeys(v, ['at', 'tested_path', 'instance', 'plugin_hash', 'policy_hash', 'configured_posture'])) return false;
  return isIso(v.at) && isIdent(v.tested_path) && isValidInstanceKey(v.instance)
    && nullable(v.plugin_hash, isHash) && nullable(v.policy_hash, isHash) && isPosture(v.configured_posture);
}

const TOP_KEYS = [
  'schema', 'version', 'runtime', 'profile', 'plane', 'instance', 'runtime_version', 'plugin',
  'heartbeat_at', 'loaded', 'configured_posture', 'scanner', 'policy_hash', 'degraded_intervals', 'denials',
] as const;

/**
 * Validate a self-report. `sizeBytes` is the on-disk size; anything over the
 * cap is rejected before it is parsed.
 */
export function parseSelfReport(text: string, sizeBytes: number): SelfReportRead {
  if (!Number.isFinite(sizeBytes) || sizeBytes > SELF_REPORT_MAX_BYTES) {
    return { kind: 'invalid', reason: `size ${sizeBytes} bytes exceeds the ${SELF_REPORT_MAX_BYTES}-byte cap` };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return { kind: 'invalid', reason: 'not JSON' };
  }
  if (!isObj(raw)) return { kind: 'invalid', reason: 'not a JSON object' };
  const o = raw;
  if (o.schema !== SELF_REPORT_SCHEMA) return { kind: 'invalid', reason: 'unrecognised schema id' };
  if (o.version !== SELF_REPORT_VERSION) {
    return { kind: 'invalid', reason: `version ${typeof o.version === 'number' ? o.version : '?'} is not supported` };
  }
  const extra = Object.keys(o).filter((k) => !(TOP_KEYS as readonly string[]).includes(k));
  if (extra.length > 0) return { kind: 'invalid', reason: 'unknown keys' };
  const missing = TOP_KEYS.filter((k) => !(k in o));
  if (missing.length > 0) return { kind: 'invalid', reason: `missing keys: ${missing.join(', ')}` };

  const bad = (field: string): SelfReportRead => ({ kind: 'invalid', reason: `invalid ${field}` });
  if (!isGateRuntime(o.runtime)) return bad('runtime');
  if (!isValidProfileId(o.profile)) return bad('profile');
  if (o.plane !== 'tool-gate') return bad('plane');

  const inst = o.instance;
  if (!isObj(inst) || !exactKeys(inst, ['key', 'pid', 'process_start', 'started_at', 'liveness'])) return bad('instance');
  if (!isValidInstanceKey(inst.key) || !nullable(inst.pid, isPid) || !nullable(inst.process_start, isStart)
    || !isIso(inst.started_at) || (inst.liveness !== 'process' && inst.liveness !== 'per-call')) return bad('instance');

  if (!nullable(o.runtime_version, isIdent)) return bad('runtime_version');
  const plugin = o.plugin;
  if (!isObj(plugin) || !exactKeys(plugin, ['id', 'version', 'hash'])
    || !isIdent(plugin.id) || !nullable(plugin.version, isIdent) || !nullable(plugin.hash, isHash)) return bad('plugin');
  if (!isIso(o.heartbeat_at)) return bad('heartbeat_at');
  if (typeof o.loaded !== 'boolean') return bad('loaded');
  if (!isPosture(o.configured_posture)) return bad('configured_posture');
  if (!SCANNER_STATES.includes(o.scanner as ScannerState)) return bad('scanner');
  if (!nullable(o.policy_hash, isHash)) return bad('policy_hash');
  if (!Array.isArray(o.degraded_intervals) || o.degraded_intervals.length > MAX_DEGRADED_INTERVALS
    || !o.degraded_intervals.every(validInterval)) return bad('degraded_intervals');
  const d = o.denials;
  if (!isObj(d) || !exactKeys(d, ['blocked_action', 'synthetic_probe', 'blocked_action_count'])
    || !nullable(d.blocked_action, validDenial) || !nullable(d.synthetic_probe, validDenial)
    || !Number.isInteger(d.blocked_action_count) || (d.blocked_action_count as number) < 0
    || (d.blocked_action_count as number) > MAX_COUNT) return bad('denials');

  const copyDenial = (x: SelfReportDenial | null): SelfReportDenial | null => (x === null ? null : {
    at: x.at, tested_path: x.tested_path, instance: x.instance,
    plugin_hash: x.plugin_hash, policy_hash: x.policy_hash, configured_posture: x.configured_posture,
  });
  return {
    kind: 'valid',
    report: {
      schema: SELF_REPORT_SCHEMA,
      version: SELF_REPORT_VERSION,
      runtime: o.runtime,
      profile: o.profile,
      plane: 'tool-gate',
      instance: {
        key: inst.key,
        pid: inst.pid as number | null,
        process_start: inst.process_start as string | null,
        started_at: inst.started_at,
        liveness: inst.liveness,
      },
      runtime_version: o.runtime_version as string | null,
      plugin: { id: plugin.id, version: plugin.version as string | null, hash: plugin.hash as string | null },
      heartbeat_at: o.heartbeat_at,
      loaded: o.loaded,
      configured_posture: o.configured_posture,
      scanner: o.scanner as ScannerState,
      policy_hash: o.policy_hash as string | null,
      degraded_intervals: (o.degraded_intervals as DegradedInterval[]).map((x) => ({ from: x.from, to: x.to, reason: x.reason })),
      denials: {
        blocked_action: copyDenial(d.blocked_action as SelfReportDenial | null),
        synthetic_probe: copyDenial(d.synthetic_probe as SelfReportDenial | null),
        blocked_action_count: d.blocked_action_count as number,
      },
    },
  };
}

// ── Provenance ──────────────────────────────────────────────────────────────

export function recordSource(runtime: PostureRuntimeId, profile: string, plane: PosturePlane, instance: string | null): string {
  return `sc://posture/${runtime}/${profile}/${plane}/${instance ?? 'none'}`;
}

function reportSource(runtime: GateRuntimeId, profile: string, instance: string, field: string): string {
  return `sc://posture/self-report/${runtime}/${profile}/${instance}#${field}`;
}

function artefactSource(runtime: PostureRuntimeId, profile: string): string {
  return `sc://probe/artefact/${runtime}/${profile}`;
}

function capabilitySource(runtime: PostureRuntimeId): string {
  return `sc://posture/capability/${runtime}`;
}

function livenessSource(runtime: GateRuntimeId, profile: string, instance: string): string {
  return `sc://probe/process/${runtime}/${profile}/${instance}`;
}

// ── Derivation ──────────────────────────────────────────────────────────────

function evidence<V>(value: V, method: EvidenceMethod, source: string, over: Partial<FieldEvidence<V>> = {}): FieldEvidence<V> {
  return {
    value,
    method,
    source,
    observed_at: null,
    max_age_ms: null,
    tested_path: null,
    process_identity: null,
    plugin_identity: null,
    effective_policy_hash: null,
    note: null,
    ...over,
  };
}

/**
 * What the host could say about the reporting process.
 * `alive` / `ended` only from a real check; `unsupported` when this host
 * exposes no start identity (or the report named no pid).
 */
export type LivenessCheck = 'alive' | 'ended' | 'unsupported';

export interface ToolGateInput {
  runtime: GateRuntimeId;
  profile: string;
  /** Artefact probe for this runtime/profile: are ShieldCortex's gate files on disk? */
  installed: Installed;
  installedNote?: string | null;
  read: SelfReportRead;
  /** Result of the host's process-start check for this report (ignored for per-call reporters). */
  liveness?: LivenessCheck;
  nowMs: number;
  maxAgeMs?: number;
}

function denialObsolete(
  d: SelfReportDenial,
  r: SelfReport,
  nowMs: number,
  maxAgeMs: number,
): ObsoleteReason | null {
  const at = Date.parse(d.at);
  if (at > nowMs + FUTURE_SKEW_MS || at > Date.parse(r.heartbeat_at) + FUTURE_SKEW_MS) return 'future-dated';
  if (d.instance !== r.instance.key || at + FUTURE_SKEW_MS < Date.parse(r.instance.started_at)) return 'process-restart';
  if (d.plugin_hash !== r.plugin.hash) return 'plugin-change';
  if (d.policy_hash !== r.policy_hash) return 'policy-change';
  if (d.configured_posture !== r.configured_posture) return 'posture-change';
  if (nowMs - at > maxAgeMs) return 'stale';
  if (r.scanner !== 'available') return 'scanner-degraded';
  // Any degradation that was still running at, or began after, the denial:
  // the path it tested is not the path in effect now.
  if (r.degraded_intervals.some((i) => i.to === null || Date.parse(i.to) >= at)) return 'scanner-degraded';
  return null;
}

const OBSOLETE_TEXT: Record<ObsoleteReason, string> = {
  'process-restart': 'the process restarted since',
  'plugin-change': 'the plugin changed since',
  'policy-change': 'the effective policy changed since',
  'posture-change': 'the configured posture changed since',
  stale: 'older than max_age',
  'future-dated': 'dated in the future',
  'scanner-degraded': 'the scanner degraded since',
};

export function deriveToolGateRecord(input: ToolGateInput): PostureRecord {
  const { runtime, profile, installed, read, nowMs } = input;
  const maxAgeMs = input.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
  const nowIso = new Date(nowMs).toISOString();
  const notes: string[] = [];
  const instance = read.kind === 'valid' ? read.report.instance.key : read.kind === 'invalid' ? read.instance ?? null : null;
  const inst = instance ?? 'none';
  const src = (field: string) => reportSource(runtime, profile, inst, field);
  const unknown = <V>(value: V, field: string, note: string | null): FieldEvidence<V> =>
    evidence(value, 'none', src(field), { max_age_ms: maxAgeMs, note });

  const rec: PostureRecord = {
    record_version: POSTURE_RECORD_VERSION,
    source: recordSource(runtime, profile, 'tool-gate', instance),
    key: { runtime, profile, plane: 'tool-gate', instance },
    runtime,
    profile,
    plane: 'tool-gate',
    membership: 'unobserved',
    liveness: evidence<Liveness>('not-applicable', 'none', livenessSource(runtime, profile, inst)),
    collected_at: nowIso,
    capability: evidence<Capability>('tool-gate', 'static', capabilitySource(runtime)),
    installed: evidence(installed, 'file-probe', artefactSource(runtime, profile), {
      observed_at: nowIso,
      note: input.installedNote ?? (installed === 'unknown' ? 'the ShieldCortex gate artefacts could not be confirmed' : null),
    }),
    runtime_loaded: unknown<RuntimeLoaded>('unknown', 'loaded', null),
    configured_posture: unknown<ConfiguredPosture>('unknown', 'configured_posture', null),
    scanner: unknown<ScannerState>('unknown', 'scanner', null),
    effective_policy_hash: unknown<string | null>(null, 'policy_hash', null),
    observed_denial: { ...unknown<ObservedDenial>('unknown', 'denials', null), kind: null },
    denials: { blocked_action: null, synthetic_probe: null },
    incidents: unknown<number | null>(null, 'denials.blocked_action_count', 'synthetic probes are never counted'),
    degraded_intervals: [],
    notes,
  };

  if (read.kind === 'absent') {
    rec.runtime_loaded = unknown<RuntimeLoaded>('unobserved', 'loaded', 'no self-report from any runtime process');
    notes.push('no self-report from the runtime process');
    if (installed === 'no') {
      rec.configured_posture = evidence<ConfiguredPosture>('unavailable', 'file-probe', artefactSource(runtime, profile), {
        observed_at: nowIso,
        note: 'no ShieldCortex gate artefacts for this runtime',
      });
    }
    return rec;
  }

  if (read.kind === 'invalid') {
    const why = `self-report rejected: ${read.reason}`;
    rec.runtime_loaded = unknown<RuntimeLoaded>('unknown', 'loaded', why);
    notes.push(why);
    return rec;
  }

  const r = read.report;
  const heartbeatMs = Date.parse(r.heartbeat_at);
  const identity: ProcessIdentity = {
    runtime,
    runtime_version: r.runtime_version,
    instance: r.instance.key,
    pid: r.instance.pid,
    process_start: r.instance.process_start,
    started_at: r.instance.started_at,
    liveness_mode: r.instance.liveness,
  };
  const plugin: PluginIdentity = { ...r.plugin };
  const tested = `${r.plugin.id}`;
  const fromReport = <V>(value: V, field: string, note: string | null = null): FieldEvidence<V> =>
    evidence(value, 'process-self-report', src(field), {
      observed_at: r.heartbeat_at,
      max_age_ms: maxAgeMs,
      tested_path: tested,
      process_identity: identity,
      plugin_identity: plugin,
      effective_policy_hash: r.policy_hash,
      note,
    });

  // Liveness first: a report cannot vouch for a process that is gone.
  const check = input.liveness ?? 'unsupported';
  let liveness: Liveness;
  let livenessNote: string | null = null;
  if (r.instance.liveness === 'per-call') {
    liveness = 'per-call';
    livenessNote = 'per-call hook: no resident process to check; the last call within max_age is the evidence';
  } else if (check === 'alive') {
    liveness = 'alive';
  } else if (check === 'ended') {
    liveness = 'ended';
    livenessNote = 'the reporting process has exited, or its pid now belongs to a different process';
  } else {
    liveness = 'unverified';
    livenessNote = 'this host cannot confirm the reporting process is still running';
  }
  rec.liveness = evidence(liveness, liveness === 'per-call' ? 'process-self-report' : 'process-liveness',
    livenessSource(runtime, profile, r.instance.key), {
      observed_at: liveness === 'per-call' ? r.heartbeat_at : nowIso,
      max_age_ms: liveness === 'per-call' ? maxAgeMs : null,
      process_identity: identity,
      plugin_identity: plugin,
      note: livenessNote,
    });

  if (heartbeatMs > nowMs + FUTURE_SKEW_MS) {
    const why = `self-report heartbeat is dated in the future (${r.heartbeat_at})`;
    rec.runtime_loaded = unknown<RuntimeLoaded>('unknown', 'loaded', why);
    rec.observed_denial = { ...unknown<ObservedDenial>('unknown', 'denials', why), kind: null };
    notes.push(why);
    return rec;
  }
  if (nowMs - heartbeatMs > maxAgeMs) {
    const why = `self-report is stale (heartbeat ${r.heartbeat_at})`;
    rec.runtime_loaded = unknown<RuntimeLoaded>('unknown', 'loaded', why);
    rec.observed_denial = { ...unknown<ObservedDenial>('unknown', 'denials', why), kind: null };
    notes.push(why);
    return rec;
  }
  if (liveness === 'ended') {
    rec.membership = 'ended';
    rec.runtime_loaded = evidence<RuntimeLoaded>('unobserved', 'process-liveness', livenessSource(runtime, profile, r.instance.key), {
      observed_at: nowIso,
      process_identity: identity,
      note: livenessNote,
    });
    rec.observed_denial = { ...unknown<ObservedDenial>('obsolete', 'denials', 'the process that reported it has ended'), kind: null };
    notes.push('reporting process has ended');
    return rec;
  }

  // Current values, each with the heartbeat's own evidence.
  rec.configured_posture = fromReport(r.configured_posture, 'configured_posture',
    r.configured_posture === 'unknown' ? 'the runtime process has not resolved its posture yet' : null);
  rec.scanner = fromReport(r.scanner, 'scanner', r.scanner === 'unknown' ? 'the runtime process did not report its scanner state' : null);
  rec.effective_policy_hash = fromReport(r.policy_hash, 'policy_hash');
  rec.degraded_intervals = r.degraded_intervals;
  rec.incidents = fromReport<number | null>(r.denials.blocked_action_count, 'denials.blocked_action_count',
    'real blocked actions this process reported; synthetic probes are never counted');

  if (liveness === 'unverified') {
    rec.membership = 'unobserved';
    rec.runtime_loaded = evidence<RuntimeLoaded>('unknown', 'process-liveness', livenessSource(runtime, profile, r.instance.key), {
      observed_at: nowIso,
      process_identity: identity,
      note: livenessNote,
    });
    notes.push('reporting process could not be checked on this host');
  } else {
    rec.membership = 'current';
    rec.runtime_loaded = fromReport<RuntimeLoaded>(r.loaded ? 'yes' : 'no', 'loaded');
  }

  // Denials: each judged against the CURRENT identity, never refreshed by the heartbeat.
  const judge = (kind: DenialKind, d: SelfReportDenial | null): DenialEvidence | null => {
    if (!d) return null;
    const obsolete = denialObsolete(d, r, nowMs, maxAgeMs);
    return {
      ...evidence<ObservedDenial>(obsolete ? 'obsolete' : 'observed', 'process-self-report',
        src(kind === 'blocked-action' ? 'denials.blocked_action' : 'denials.synthetic_probe'), {
          observed_at: d.at,
          max_age_ms: maxAgeMs,
          tested_path: d.tested_path,
          process_identity: { ...identity, instance: d.instance },
          plugin_identity: { ...plugin, hash: d.plugin_hash },
          effective_policy_hash: d.policy_hash,
          note: obsolete
            ? `obsolete: ${OBSOLETE_TEXT[obsolete]}`
            : kind === 'synthetic-probe'
              ? 'synthetic probe: the tested path denied at that moment; not an incident, nothing wider'
              : 'blocked action: the tested path denied at that moment, nothing wider',
        }),
      kind,
    };
  };
  const blocked = judge('blocked-action', r.denials.blocked_action);
  const probe = judge('synthetic-probe', r.denials.synthetic_probe);
  rec.denials = { blocked_action: blocked, synthetic_probe: probe };

  if (r.scanner === 'degraded') {
    rec.observed_denial = { ...fromReport<ObservedDenial>('degraded', 'scanner', 'scanner degraded: fallback scan only'), kind: null };
  } else if (r.scanner === 'unknown') {
    rec.observed_denial = { ...fromReport<ObservedDenial>('unknown', 'scanner', 'scanner state not reported'), kind: null };
  } else {
    const valid = [blocked, probe].filter((x): x is DenialEvidence => !!x && x.value === 'observed');
    const any = [blocked, probe].filter((x): x is DenialEvidence => !!x);
    const latest = (xs: DenialEvidence[]) => xs.sort((a, b) => Date.parse(b.observed_at!) - Date.parse(a.observed_at!))[0];
    if (valid.length > 0) rec.observed_denial = latest(valid);
    else if (any.length > 0) rec.observed_denial = latest(any);
    else rec.observed_denial = { ...fromReport<ObservedDenial>('not-observed', 'denials', 'no denial reported by this process'), kind: null };
  }
  return rec;
}

export interface MemoryOnlyInput {
  runtime: MemoryOnlyRuntimeId;
  profile: string;
  installed: Installed;
  nowMs: number;
}

export function deriveMemoryOnlyRecord(input: MemoryOnlyInput): PostureRecord {
  const { runtime, profile, installed, nowMs } = input;
  const nowIso = new Date(nowMs).toISOString();
  const cap = capabilitySource(runtime);
  const stat = <V>(value: V, note: string): FieldEvidence<V> => evidence(value, 'static', cap, { note });
  return {
    record_version: POSTURE_RECORD_VERSION,
    source: recordSource(runtime, profile, 'memory', null),
    key: { runtime, profile, plane: 'memory', instance: null },
    runtime,
    profile,
    plane: 'memory',
    membership: 'unobserved',
    liveness: stat<Liveness>('not-applicable', 'no ShieldCortex process runs inside this host'),
    collected_at: nowIso,
    capability: stat<Capability>('memory-only', 'ShieldCortex serves memory here and cannot gate tool calls'),
    installed: evidence(installed, 'file-probe', artefactSource(runtime, profile), { observed_at: nowIso }),
    runtime_loaded: stat<RuntimeLoaded>('unobserved', 'no ShieldCortex process runs inside this host, so nothing reports'),
    configured_posture: stat<ConfiguredPosture>('unavailable', 'there is no tool gate to configure on a memory-only host'),
    scanner: stat<ScannerState>('unknown', 'not a tool gate'),
    effective_policy_hash: stat<string | null>(null, 'not a tool gate'),
    observed_denial: { ...stat<ObservedDenial>('unknown', 'not a tool gate'), kind: null },
    denials: { blocked_action: null, synthetic_probe: null },
    incidents: stat<number | null>(null, 'not a tool gate'),
    degraded_intervals: [],
    notes: ['memory-only host: ShieldCortex serves memory here and cannot gate tool calls'],
  };
}

// ── Levels, rollup, rendering ───────────────────────────────────────────────

export type PostureLevel =
  | 'unknown'
  | 'unobserved'
  | 'unavailable'
  | 'off'
  | 'not-a-gate'
  | 'degraded'
  | 'advisory'
  | 'loaded-enforce';

/** Lower is weaker. Only `loaded-enforce` is green. */
const LEVEL_RANK: Record<PostureLevel, number> = {
  unknown: 0,
  unobserved: 1,
  unavailable: 2,
  off: 2,
  'not-a-gate': 2,
  degraded: 3,
  advisory: 4,
  'loaded-enforce': 5,
};

/**
 * The record's level. Denial evidence never raises it: a process is judged by
 * what it is configured and loaded to do NOW, not by what it once denied.
 */
export function postureLevel(r: PostureRecord): PostureLevel {
  const cap = r.capability.value;
  if (cap !== 'tool-gate') return cap === 'memory-only' || cap === 'none' ? 'not-a-gate' : 'unknown';
  if (r.membership === 'ended') return 'unobserved';
  if (r.installed.value === 'unknown' || r.runtime_loaded.value === 'unknown') return 'unknown';
  if (r.installed.value === 'no' && r.runtime_loaded.value !== 'yes') return 'unavailable';
  if (r.runtime_loaded.value === 'unobserved') return 'unobserved';
  if (r.runtime_loaded.value === 'no') return 'off';
  if (r.membership !== 'current') return 'unknown';
  switch (r.configured_posture.value) {
    case 'unknown': return 'unknown';
    case 'intentionally-off': return 'off';
    case 'unavailable': return 'unavailable';
    default: break;
  }
  if (r.scanner.value === 'unknown') return 'unknown';
  if (r.scanner.value === 'degraded') return 'degraded';
  if (r.configured_posture.value === 'advisory') return 'advisory';
  return 'loaded-enforce';
}

export interface PostureSummary {
  level: PostureLevel;
  green: boolean;
  /** `source` of the weakest record, or null when there are none. */
  weakest: string | null;
  record_count: number;
  /** Records in the rollup; the rest are listed but have no evidence of still running. */
  rollup_count: number;
  completeness: 'not-claimed';
}

function groupKey(r: PostureRecord): string {
  return `${r.runtime}/${r.profile}/${r.plane}`;
}

/**
 * Which records the rollup judges. Every `current` record counts, and every
 * record whose process the host says is alive counts. A (runtime, profile,
 * plane) with no current record contributes its records as-is, so an
 * all-ended or all-stale group can never be green. Ended or unverifiable
 * leftovers BESIDE a current member are listed but not rolled up: nothing
 * shows they are still running.
 */
export function rollupRecords(records: readonly PostureRecord[]): PostureRecord[] {
  const hasCurrent = new Set(records.filter((r) => r.membership === 'current').map(groupKey));
  return records.filter((r) =>
    r.membership === 'current'
    || r.liveness.value === 'alive'
    || !hasCurrent.has(groupKey(r)));
}

export function summarisePosture(records: readonly PostureRecord[]): PostureSummary {
  const judged = rollupRecords(records);
  if (judged.length === 0) {
    return { level: 'unknown', green: false, weakest: null, record_count: records.length, rollup_count: 0, completeness: 'not-claimed' };
  }
  let weakest = judged[0];
  let level = postureLevel(weakest);
  for (const r of judged.slice(1)) {
    const l = postureLevel(r);
    if (LEVEL_RANK[l] < LEVEL_RANK[level]) {
      weakest = r;
      level = l;
    }
  }
  return {
    level,
    green: level === 'loaded-enforce',
    weakest: weakest.source,
    record_count: records.length,
    rollup_count: judged.length,
    completeness: 'not-claimed',
  };
}

const POSTURE_TEXT: Record<ConfiguredPosture, string> = {
  enforce: 'posture enforce (self-reported)',
  advisory: 'posture advisory — warns, does not block',
  'intentionally-off': 'posture intentionally off by configuration',
  unavailable: 'posture unavailable — no gate can run here',
  unknown: 'posture unknown',
};

const LOADED_TEXT: Record<RuntimeLoaded, string> = {
  yes: 'loaded yes (self-reported by the runtime process)',
  no: 'loaded no (the runtime process reports the gate is not loaded)',
  unobserved: 'loaded unobserved — no current self-report from a runtime process',
  unknown: 'loaded unknown',
};

const SCANNER_TEXT: Record<ScannerState, string> = {
  available: 'scanner available',
  degraded: 'scanner degraded (fallback scan only)',
  unknown: 'scanner unknown',
};

function denialText(d: DenialEvidence): string {
  const what = d.kind === 'synthetic-probe' ? 'synthetic probe denied' : 'blocked action';
  switch (d.value) {
    case 'observed':
      return `${what} at ${d.observed_at} on ${d.tested_path} (that path, that moment)`;
    case 'obsolete':
      return d.kind ? `earlier ${d.kind === 'synthetic-probe' ? 'probe denial' : 'blocked action'} is ${d.note ?? 'obsolete'}` : `denial evidence ${d.note ?? 'obsolete'}`;
    case 'not-observed':
      return 'no denial observed';
    case 'degraded':
      return 'no current denial evidence (scanner degraded)';
    case 'unknown':
      return 'denials unknown';
  }
}

/**
 * One operator-readable line. Never says "enforced", "protected" or
 * "proves": the strongest thing this can say is what the process reported.
 */
export function renderPostureLine(r: PostureRecord): string {
  if (r.capability.value !== 'tool-gate') {
    return `memory only — not a tool gate; ShieldCortex memory installed ${r.installed.value}`;
  }
  const parts = [
    'tool gate',
    r.key.instance ? `instance ${r.key.instance} (${r.membership})` : `no reporting instance (${r.membership})`,
    `installed ${r.installed.value}`,
    LOADED_TEXT[r.runtime_loaded.value],
  ];
  if (r.membership === 'current') {
    parts.push(POSTURE_TEXT[r.configured_posture.value], SCANNER_TEXT[r.scanner.value], denialText(r.observed_denial));
    if (r.liveness.value === 'per-call') parts.push('per-call hook, last call within max_age');
  } else {
    parts.push(POSTURE_TEXT[r.configured_posture.value]);
  }
  const why = r.runtime_loaded.note ?? (r.membership !== 'current' ? r.liveness.note : null);
  if (why && r.runtime_loaded.value !== 'yes') parts.push(why);
  return parts.join(' · ');
}

export function runtimeLabel(runtime: PostureRuntimeId): string {
  switch (runtime) {
    case 'claude_code': return 'Claude Code';
    case 'openclaw': return 'OpenClaw';
    case 'hermes': return 'Hermes';
    case 'codex': return 'Codex';
    case 'copilot': return 'Cursor / VS Code';
  }
}
