/**
 * Policy lock — an OS-owned floor under the security-critical config (#501).
 *
 * ## The defect this closes
 *
 * Every security switch ShieldCortex has lives in `~/.shieldcortex/config.json`,
 * a file owned by the same uid as the agent. The embedded `_sig` HMAC does not
 * change that: `.integrity-key` is co-located and equally same-UID, so a process
 * that can disable the guard can also re-sign the file it disabled it in. Worse,
 * neither enforcement surface consulted the signature at all — the Claude Code
 * hook did a bare `JSON.parse`, and the OpenClaw plugin read a different
 * unsigned file (`openclaw.json`). A same-user process could switch the Action
 * Guard off with a one-line edit and nothing anywhere would notice.
 *
 * ## The shape
 *
 * A human, once, with sudo, runs `shieldcortex protect`. That writes the
 * security-critical SUBSET of config to a path the agent uid cannot write —
 * `/etc/shieldcortex/policy.json`, root-owned `0644`, in a root-owned `0755`
 * directory. Agent-READABLE is fine and intended; agent-WRITABLE is the thing
 * being removed. There is no cryptography, so there is no key to steal and no
 * second same-UID file to forge.
 *
 * Precedence: **the lock wins for the keys it covers, and `config.json` may
 * only tighten.** An operator who locks `enforce: false` has not forbidden a
 * stricter local config; they have forbidden a looser one.
 *
 * ## Failing closed, precisely
 *
 * A lock that EXISTS but does not verify (wrong owner, writable directory,
 * symlink, unparseable, schema mismatch) is the interesting case: we cannot
 * tell an operator's policy from one the agent wrote for itself. That forces
 * the strict posture in {@link STRICT_FAILCLOSED_POSTURE}, audits
 * `policy_unverifiable`, and prints one line to stderr.
 *
 * It does NOT deny every tool call. Bricking the agent on a policy read failure
 * teaches operators to delete the lock, which is the opposite of the outcome
 * this exists for.
 */
import {
  DEFAULT_PROTECTED_ROOT,
  POLICY_LOCK_FILENAME,
  defaultProtectedFsSeam,
  describeProtectedFailure,
  emitProtectedAudit,
  resolveProtectedRoot,
  verifyProtectedFile,
  type ProtectedFsSeam,
  type ProtectedRootUnsupportedReason,
} from './protected-root.js';

// ── The protected key set (v1) ────────────────────────

/**
 * The keys a v1 lock may cover, as dotted config paths.
 *
 * Deliberately small: every entry is a switch whose wrong value is the
 * difference between a guarded host and an unguarded one. Growing this set is a
 * decision, not a convenience — anything listed here becomes something an
 * operator can no longer change without sudo.
 */
export const PROTECTED_POLICY_KEYS_V1 = [
  'actionGuard.enabled',
  'actionGuard.enforce',
  'actionGuard.autoApprove',
  'actionGuard.broker.enabled',
  'defenceMode',
  'memory.hostContract.posture',
  'memory.inject.mode',
] as const;

export type ProtectedPolicyKey = (typeof PROTECTED_POLICY_KEYS_V1)[number];

/** The subset of the Action Guard config a lock covers. */
export interface LockedActionGuard {
  enabled?: boolean;
  enforce?: boolean;
  autoApprove?: string[];
  broker?: { enabled?: boolean };
}

export interface LockedPolicy {
  /** Schema version. Absent is read as 1. */
  version?: number;
  actionGuard?: LockedActionGuard;
  defenceMode?: LockedDefenceMode;
  memory?: {
    hostContract?: { posture?: string };
    inject?: { mode?: string };
  };
}

export type LockedDefenceMode = 'strict' | 'balanced' | 'permissive';

/**
 * The one way to change a lock, quoted in every message that has to say so.
 *
 * Phrased as "run X as root" rather than as a copy-pasteable privileged command
 * line on purpose: `protect` rewrites the file that decides whether the guard
 * can be switched off, and a message an agent can lift verbatim into a shell is
 * a message that invites exactly the automated privilege escalation the lock
 * exists to make impossible. A human who needs it knows how to become root.
 */
export const PROTECT_HINT = 'Run `shieldcortex protect` as root';

/** Strictness order for the `defenceMode` FLOOR. Higher wins. */
const DEFENCE_MODE_RANK: Record<LockedDefenceMode, number> = {
  permissive: 0,
  balanced: 1,
  strict: 2,
};

const DEFAULT_DEFENCE_MODE: LockedDefenceMode = 'balanced';

/**
 * The exact posture an unverifiable lock (or a tampered config) forces.
 *
 * Stated as data, in one place, because three call sites have to produce
 * BYTE-IDENTICAL behaviour: `readRawConfigState`, the Claude Code hook's
 * inline probe, and the OpenClaw plugin. A posture that drifts between
 * surfaces is the bug class this whole issue is about.
 */
export const STRICT_FAILCLOSED_POSTURE = {
  actionGuard: {
    enabled: true,
    enforce: true,
    autoApprove: [] as string[],
    broker: { enabled: false },
  },
  defenceMode: 'strict' as LockedDefenceMode,
} as const;

// ── Lock state ────────────────────────────────────────

export type PolicyLockState =
  | { status: 'locked'; path: string; policy: LockedPolicy }
  | { status: 'unverifiable'; path: string; reason: string; detail: string }
  | { status: 'absent'; path: string }
  | { status: 'unsupported'; path: null; reason: ProtectedRootUnsupportedReason; detail: string };

export interface PolicyLockOptions {
  seam?: ProtectedFsSeam;
  /**
   * Emit the `policy_unverifiable` audit row. OFF by default: the audit logger
   * is SQLite-backed, and this reader is on the PreToolUse hook's path, where
   * opening a database on every tool call is a cost and a new failure mode.
   * The src-side config reader turns it on.
   */
  audit?: boolean;
  /** Emit the one-shot stderr line on an unverifiable lock. Default true. */
  warn?: boolean;
}

/**
 * Once-per-process-per-state suppression for the stderr line and the audit row.
 *
 * Not a cache of the STATE: `readPolicyLock` deliberately re-stats on every
 * call (four `lstat`s on an unlocked host) so an operator who has just run
 * `shieldcortex protect` is obeyed by the already-running agent rather than at
 * the next restart. A stale security policy is a worse trade than four syscalls.
 */
let lastReportedSignature: string | null = null;

/** Test hook: forget the once-per-process report suppression. */
export function clearPolicyLockReportState(): void {
  lastReportedSignature = null;
}

/** Where the lock file would live, whether or not it exists. */
export function policyLockPath(seam: ProtectedFsSeam = defaultProtectedFsSeam()): string | null {
  const root = resolveProtectedRoot(seam);
  if (!root.supported) return null;
  return `${root.root}/${POLICY_LOCK_FILENAME}`;
}

/**
 * Read the policy lock and say, exactly, what it is.
 *
 * Never throws: a reader that throws is a reader that takes the guard down with
 * it, and this one runs inside both enforcement surfaces.
 */
export function readPolicyLock(options: PolicyLockOptions = {}): PolicyLockState {
  const seam = options.seam ?? defaultProtectedFsSeam();
  let state: PolicyLockState;
  try {
    state = readPolicyLockInner(seam);
  } catch (err) {
    // Belt and braces. An unexpected throw is treated as "a lock might be
    // there and we cannot read it" — the fail-closed side, never the open one.
    state = {
      status: 'unverifiable',
      path: `${DEFAULT_PROTECTED_ROOT}/${POLICY_LOCK_FILENAME}`,
      reason: 'read-threw',
      detail: `reading the policy lock threw (${err instanceof Error ? err.message : String(err)}).`,
    };
  }
  if (state.status === 'unverifiable') reportUnverifiable(state, options);
  return state;
}

function readPolicyLockInner(seam: ProtectedFsSeam): PolicyLockState {
  const root = resolveProtectedRoot(seam);
  if (!root.supported) {
    return { status: 'unsupported', path: null, reason: root.reason, detail: root.detail };
  }
  const path = `${root.root}/${POLICY_LOCK_FILENAME}`;

  const verdict = verifyProtectedFile(path, seam);
  if (!verdict.ok) {
    // `missing` is the ONE failure that is not a failure: no lock means this
    // host is simply unlocked, which is today's behaviour and is reported as
    // such (loudly, by doctor) rather than treated as an attack.
    if (verdict.reason === 'missing') return { status: 'absent', path };
    return {
      status: 'unverifiable',
      path,
      reason: verdict.reason ?? 'unknown',
      detail: verdict.detail,
    };
  }

  const contents = seam.readFile(path);
  if (contents === null) {
    return { status: 'unverifiable', path, reason: 'unreadable', detail: `${path} verified but could not be read.` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch {
    return { status: 'unverifiable', path, reason: 'parse-failed', detail: `${path} is not valid JSON.` };
  }
  const schema = validateLockedPolicy(parsed);
  if (!schema.ok) {
    return { status: 'unverifiable', path, reason: 'schema-failed', detail: `${path}: ${schema.problem}` };
  }
  return { status: 'locked', path, policy: schema.policy };
}

function reportUnverifiable(state: Extract<PolicyLockState, { status: 'unverifiable' }>, options: PolicyLockOptions): void {
  const signature = `${state.path}|${state.reason}`;
  if (lastReportedSignature === signature) return;
  lastReportedSignature = signature;
  if (options.warn !== false) {
    // console.error, not process.stderr.write: it is the stderr channel every
    // other warning in src/ uses (including the integrity-check warning this
    // sits beside), so a host that redirects one redirects both.
    console.error(
      `[ShieldCortex] policy lock at ${state.path} is present but UNVERIFIABLE (${state.reason}: ${state.detail}) — ` +
      'falling back to the strict fail-closed posture (Action Guard on + enforcing, no auto-approve, broker off, ' +
      `defence mode strict). ${PROTECT_HINT} to write a valid lock, or remove the file to run unlocked.`,
    );
  }
  if (options.audit) {
    emitProtectedAudit({
      outcome: 'policy_unverifiable',
      path: state.path,
      reason: state.reason,
      detail: 'forcing the strict fail-closed posture',
    });
  }
}

// ── Schema ────────────────────────────────────────────

type SchemaResult = { ok: true; policy: LockedPolicy } | { ok: false; problem: string };

function isBlock(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Validate a parsed lock.
 *
 * Unknown keys are IGNORED, so a newer `protect` can add a key without every
 * older install on the fleet falling into the fail-closed posture. A known key
 * with the wrong TYPE is a schema failure: that is a malformed policy, and a
 * malformed policy is exactly the case we must not guess at.
 *
 * An unrecognised `version` is also a failure, and deliberately so — a v2
 * policy may mean something a v1 reader would get wrong, and getting a security
 * policy wrong quietly is the thing this module exists to stop.
 */
function validateLockedPolicy(raw: unknown): SchemaResult {
  if (!isBlock(raw)) return { ok: false, problem: 'top level is not a JSON object' };
  const policy: LockedPolicy = {};

  if (raw.version !== undefined) {
    if (typeof raw.version !== 'number' || !Number.isInteger(raw.version)) {
      return { ok: false, problem: '`version` must be an integer' };
    }
    if (raw.version !== 1) {
      return { ok: false, problem: `unsupported policy version ${raw.version} (this build understands 1)` };
    }
    policy.version = raw.version;
  }

  if (raw.actionGuard !== undefined) {
    if (!isBlock(raw.actionGuard)) return { ok: false, problem: '`actionGuard` must be an object' };
    const src = raw.actionGuard;
    const guard: LockedActionGuard = {};
    if (src.enabled !== undefined) {
      if (typeof src.enabled !== 'boolean') return { ok: false, problem: '`actionGuard.enabled` must be a boolean' };
      guard.enabled = src.enabled;
    }
    if (src.enforce !== undefined) {
      if (typeof src.enforce !== 'boolean') return { ok: false, problem: '`actionGuard.enforce` must be a boolean' };
      guard.enforce = src.enforce;
    }
    if (src.autoApprove !== undefined) {
      if (!Array.isArray(src.autoApprove) || src.autoApprove.some((e) => typeof e !== 'string')) {
        return { ok: false, problem: '`actionGuard.autoApprove` must be an array of strings' };
      }
      guard.autoApprove = src.autoApprove as string[];
    }
    if (src.broker !== undefined) {
      if (!isBlock(src.broker)) return { ok: false, problem: '`actionGuard.broker` must be an object' };
      if (src.broker.enabled !== undefined) {
        if (typeof src.broker.enabled !== 'boolean') {
          return { ok: false, problem: '`actionGuard.broker.enabled` must be a boolean' };
        }
        guard.broker = { enabled: src.broker.enabled };
      }
    }
    if (Object.keys(guard).length > 0) policy.actionGuard = guard;
  }

  if (raw.defenceMode !== undefined) {
    if (typeof raw.defenceMode !== 'string' || !(raw.defenceMode in DEFENCE_MODE_RANK)) {
      return { ok: false, problem: '`defenceMode` must be one of strict | balanced | permissive' };
    }
    policy.defenceMode = raw.defenceMode as LockedDefenceMode;
  }

  if (raw.memory !== undefined) {
    if (!isBlock(raw.memory)) return { ok: false, problem: '`memory` must be an object' };
    const memory: NonNullable<LockedPolicy['memory']> = {};
    if (raw.memory.hostContract !== undefined) {
      if (!isBlock(raw.memory.hostContract)) return { ok: false, problem: '`memory.hostContract` must be an object' };
      const posture = raw.memory.hostContract.posture;
      if (posture !== undefined) {
        if (typeof posture !== 'string') return { ok: false, problem: '`memory.hostContract.posture` must be a string' };
        memory.hostContract = { posture };
      }
    }
    if (raw.memory.inject !== undefined) {
      if (!isBlock(raw.memory.inject)) return { ok: false, problem: '`memory.inject` must be an object' };
      const mode = raw.memory.inject.mode;
      if (mode !== undefined) {
        if (typeof mode !== 'string') return { ok: false, problem: '`memory.inject.mode` must be a string' };
        memory.inject = { mode };
      }
    }
    if (Object.keys(memory).length > 0) policy.memory = memory;
  }

  return { ok: true, policy };
}

// ── Coverage ──────────────────────────────────────────

/**
 * Which protected keys this lock actually covers, and with what value.
 *
 * A lock does not have to mention every key. `protect` writes the whole set by
 * default, but a hand-written lock that pins only `actionGuard.enabled` leaves
 * every other key to `config.json`, which is the honest reading of the file.
 */
export function policyLockCoverage(state: PolicyLockState): Map<ProtectedPolicyKey, unknown> {
  const out = new Map<ProtectedPolicyKey, unknown>();
  if (state.status === 'unverifiable') {
    // An unverifiable lock covers the whole Action Guard posture — that IS the
    // fail-closed posture, and it must be as binding as a verified one, or
    // corrupting the lock would become the way to escape it.
    out.set('actionGuard.enabled', STRICT_FAILCLOSED_POSTURE.actionGuard.enabled);
    out.set('actionGuard.enforce', STRICT_FAILCLOSED_POSTURE.actionGuard.enforce);
    out.set('actionGuard.autoApprove', []);
    out.set('actionGuard.broker.enabled', STRICT_FAILCLOSED_POSTURE.actionGuard.broker.enabled);
    out.set('defenceMode', STRICT_FAILCLOSED_POSTURE.defenceMode);
    return out;
  }
  if (state.status !== 'locked') return out;
  const p = state.policy;
  if (p.actionGuard?.enabled !== undefined) out.set('actionGuard.enabled', p.actionGuard.enabled);
  if (p.actionGuard?.enforce !== undefined) out.set('actionGuard.enforce', p.actionGuard.enforce);
  if (p.actionGuard?.autoApprove !== undefined) out.set('actionGuard.autoApprove', p.actionGuard.autoApprove);
  if (p.actionGuard?.broker?.enabled !== undefined) out.set('actionGuard.broker.enabled', p.actionGuard.broker.enabled);
  if (p.defenceMode !== undefined) out.set('defenceMode', p.defenceMode);
  if (p.memory?.hostContract?.posture !== undefined) out.set('memory.hostContract.posture', p.memory.hostContract.posture);
  if (p.memory?.inject?.mode !== undefined) out.set('memory.inject.mode', p.memory.inject.mode);
  return out;
}

/** True when this lock has anything at all to say about `key`. */
export function isPolicyKeyLocked(state: PolicyLockState, key: ProtectedPolicyKey): boolean {
  return policyLockCoverage(state).has(key);
}

// ── Applying the lock ─────────────────────────────────

function guardBlockOf(raw: Record<string, unknown>): Record<string, unknown> {
  return isBlock(raw.actionGuard) ? { ...raw.actionGuard } : {};
}

/**
 * Force the exact strict fail-closed posture onto a raw config object.
 *
 * Used for BOTH an unverifiable lock and a `tampered` HMAC verdict. Before
 * #501 a tampered verdict set `defenceMode: 'strict'` and nothing else, so the
 * Action Guard's own switches were still read straight out of the bytes the
 * integrity check had just called untrustworthy — the guard stayed off in the
 * exact scenario the check exists to catch.
 */
export function applyStrictFailClosedPosture(raw: Record<string, unknown>): Record<string, unknown> {
  const out = { ...raw };
  const guard = guardBlockOf(out);
  guard.enabled = STRICT_FAILCLOSED_POSTURE.actionGuard.enabled;
  guard.enforce = STRICT_FAILCLOSED_POSTURE.actionGuard.enforce;
  guard.autoApprove = [];
  guard.broker = { ...(isBlock(guard.broker) ? guard.broker : {}), enabled: false };
  out.actionGuard = guard;
  out.defenceMode = STRICT_FAILCLOSED_POSTURE.defenceMode;
  // The deprecated `interceptor.actionGuard` alias gap-fills per key on both
  // enforcement surfaces (#209), so leaving it untouched here would let an
  // alias `enabled: false`… not win (top-level wins), but an alias
  // `autoApprove` WOULD survive as a gap-fill for a key we mean to empty.
  // Strip the alias's covered keys rather than reason about the merge twice.
  if (isBlock(out.interceptor) && isBlock(out.interceptor.actionGuard)) {
    const interceptor = { ...out.interceptor };
    const alias = { ...(interceptor.actionGuard as Record<string, unknown>) };
    delete alias.enabled;
    delete alias.enforce;
    delete alias.autoApprove;
    delete alias.broker;
    interceptor.actionGuard = alias;
    out.interceptor = interceptor;
  }
  return out;
}

/**
 * Apply lock precedence to a raw config object, returning a new object.
 *
 * The rule, for every covered key: **take whichever of the lock and the config
 * is TIGHTER.** That is what "the lock wins; config may only tighten" means
 * when written as one operation rather than as seven special cases.
 *
 *   - `actionGuard.enabled` / `enforce` — tighter is `true`.
 *   - `actionGuard.broker.enabled` — tighter is `false`. A broker can pre-clear
 *     reversible actions; enabling one widens, it never narrows.
 *   - `actionGuard.autoApprove` — a CEILING, so the effective list is the
 *     intersection. A config may drop entries the lock permits; it may not add.
 *   - `defenceMode` — a FLOOR, so the effective mode is the stricter rank.
 *   - the two memory sidecar-posture keys — no tightness order exists for a
 *     posture NAME, so the lock's value is authoritative outright.
 *
 * `absent` and `unsupported` return the config untouched: an unlocked host
 * behaves exactly as it did before #501.
 */
export function applyPolicyLock(raw: Record<string, unknown>, state: PolicyLockState): Record<string, unknown> {
  if (state.status === 'unverifiable') return applyStrictFailClosedPosture(raw);
  if (state.status !== 'locked') return raw;

  const out = { ...raw };
  const p = state.policy;
  const guard = guardBlockOf(out);
  let guardTouched = false;

  if (p.actionGuard?.enabled === true) { guard.enabled = true; guardTouched = true; }
  if (p.actionGuard?.enforce === true) { guard.enforce = true; guardTouched = true; }
  if (p.actionGuard?.broker?.enabled === false) {
    guard.broker = { ...(isBlock(guard.broker) ? guard.broker : {}), enabled: false };
    guardTouched = true;
  }
  if (p.actionGuard?.autoApprove !== undefined) {
    const ceiling = new Set(p.actionGuard.autoApprove);
    const configured = Array.isArray(guard.autoApprove)
      ? (guard.autoApprove as unknown[]).filter((e): e is string => typeof e === 'string')
      : [];
    guard.autoApprove = configured.filter((e) => ceiling.has(e));
    guardTouched = true;
  }
  if (guardTouched) out.actionGuard = guard;

  if (p.defenceMode !== undefined) {
    const configured = typeof out.defenceMode === 'string' && out.defenceMode in DEFENCE_MODE_RANK
      ? (out.defenceMode as LockedDefenceMode)
      : DEFAULT_DEFENCE_MODE;
    out.defenceMode = DEFENCE_MODE_RANK[p.defenceMode] >= DEFENCE_MODE_RANK[configured] ? p.defenceMode : configured;
  }

  if (p.memory?.hostContract?.posture !== undefined || p.memory?.inject?.mode !== undefined) {
    const memory = isBlock(out.memory) ? { ...out.memory } : {};
    if (p.memory.hostContract?.posture !== undefined) {
      memory.hostContract = {
        ...(isBlock(memory.hostContract) ? memory.hostContract : {}),
        posture: p.memory.hostContract.posture,
      };
    }
    if (p.memory.inject?.mode !== undefined) {
      memory.inject = {
        ...(isBlock(memory.inject) ? memory.inject : {}),
        mode: p.memory.inject.mode,
      };
    }
    out.memory = memory;
  }

  return out;
}

// ── Refusing a loosening write ────────────────────────

/** Thrown by a setter asked to loosen a key the lock covers. */
export class PolicyLockRefusal extends Error {
  readonly key: ProtectedPolicyKey;
  readonly lockPath: string;
  readonly lockedValue: unknown;
  constructor(key: ProtectedPolicyKey, lockPath: string, lockedValue: unknown, message: string) {
    super(message);
    this.name = 'PolicyLockRefusal';
    this.key = key;
    this.lockPath = lockPath;
    this.lockedValue = lockedValue;
  }
}

/**
 * Would writing `value` to `key` LOOSEN what the lock guarantees?
 *
 * The same tightness order {@link applyPolicyLock} uses, asked as a question.
 * Anything at or tighter than the lock is allowed through — an operator may
 * still turn the guard UP locally.
 */
export function wouldLoosen(key: ProtectedPolicyKey, value: unknown, lockedValue: unknown): boolean {
  switch (key) {
    case 'actionGuard.enabled':
    case 'actionGuard.enforce':
      return lockedValue === true && value === false;
    case 'actionGuard.broker.enabled':
      return lockedValue === false && value === true;
    case 'actionGuard.autoApprove': {
      if (!Array.isArray(value)) return false;
      const ceiling = new Set(Array.isArray(lockedValue) ? (lockedValue as unknown[]) : []);
      return (value as unknown[]).some((e) => !ceiling.has(e));
    }
    case 'defenceMode': {
      const locked = typeof lockedValue === 'string' && lockedValue in DEFENCE_MODE_RANK
        ? DEFENCE_MODE_RANK[lockedValue as LockedDefenceMode] : -1;
      const next = typeof value === 'string' && value in DEFENCE_MODE_RANK
        ? DEFENCE_MODE_RANK[value as LockedDefenceMode] : -1;
      return next < locked;
    }
    case 'memory.hostContract.posture':
    case 'memory.inject.mode':
      // No tightness order for a posture name: any change away from the locked
      // value is a change the lock forbids.
      return value !== lockedValue;
  }
}

/**
 * Throw {@link PolicyLockRefusal} if this write would loosen a locked key.
 *
 * Callers should audit `policy_refused` and print the message; the message
 * names the lock file so the operator knows exactly which machine-owned file
 * is saying no, and how to change it (with sudo, deliberately).
 */
export function assertPolicyLockAllows(
  state: PolicyLockState,
  updates: Array<{ key: ProtectedPolicyKey; value: unknown }>,
): void {
  const coverage = policyLockCoverage(state);
  if (coverage.size === 0) return;
  const lockPath = state.path ?? `${DEFAULT_PROTECTED_ROOT}/${POLICY_LOCK_FILENAME}`;
  for (const { key, value } of updates) {
    if (!coverage.has(key)) continue;
    const lockedValue = coverage.get(key);
    if (!wouldLoosen(key, value, lockedValue)) continue;
    const why = state.status === 'unverifiable'
      ? `the policy lock at ${lockPath} is present but unverifiable, so the strict fail-closed posture is in force`
      : `the policy lock at ${lockPath} pins it`;
    throw new PolicyLockRefusal(
      key,
      lockPath,
      lockedValue,
      `Refusing to loosen \`${key}\`: ${why} (locked value: ${JSON.stringify(lockedValue)}). ` +
      'The lock is owned by root and this process is not; that is the point. ' +
      `${PROTECT_HINT} to change it, then retry.`,
    );
  }
}

// ── Operator-facing summary ───────────────────────────

export interface PolicyLockSummary {
  status: PolicyLockState['status'];
  path: string | null;
  /** One sentence, safe to print. */
  headline: string;
  /** Covered keys with their locked values, for `config --policy-status`. */
  covered: Array<{ key: ProtectedPolicyKey; value: unknown }>;
  reason?: string;
}

export function describePolicyLock(state: PolicyLockState): PolicyLockSummary {
  const covered = [...policyLockCoverage(state)].map(([key, value]) => ({ key, value }));
  switch (state.status) {
    case 'locked':
      return {
        status: 'locked',
        path: state.path,
        headline: `policy locked by ${state.path} (root-owned) — ${covered.length} key${covered.length === 1 ? '' : 's'} pinned; config.json may only tighten them`,
        covered,
      };
    case 'unverifiable':
      return {
        status: 'unverifiable',
        path: state.path,
        reason: state.reason,
        headline:
          `policy lock at ${state.path} is present but UNVERIFIABLE (${describeProtectedFailure2(state.reason)}) — ` +
          'the strict fail-closed posture is in force',
        covered,
      };
    case 'absent':
      return {
        status: 'absent',
        path: state.path,
        headline: 'policy unlocked: a same-user process can disable the guard',
        covered,
      };
    case 'unsupported':
      return {
        status: 'unsupported',
        path: null,
        reason: state.reason,
        headline: `no policy lock is possible on this host — ${state.detail}`,
        covered,
      };
  }
}

/** Reason strings here are a superset of ProtectedFileFailure (parse/schema too). */
function describeProtectedFailure2(reason: string): string {
  switch (reason) {
    case 'parse-failed': return 'not valid JSON';
    case 'schema-failed': return 'does not match the policy schema';
    case 'unreadable': return 'unreadable';
    case 'read-threw': return 'the read threw';
    default:
      return describeProtectedFailure(reason);
  }
}

export { POLICY_LOCK_FILENAME, DEFAULT_PROTECTED_ROOT };
