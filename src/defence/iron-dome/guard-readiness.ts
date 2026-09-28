/**
 * ShieldCortex — "enforce when ready" readiness gate for the Action Guard (#509).
 *
 * Operator direction (28 Sep 2026): "Go and build the version that the
 * false-positive rate is measured low and approvals reliably reach a human."
 * Under the `enforce-when-ready` posture (`actionGuard.readinessGate: true` on
 * top of `enabled` + `enforce`) the Claude Code hook runs the guard in SHADOW
 * mode — every verdict computed and audited, a would-stop recorded but not
 * applied — and enforces only while THREE readiness conditions hold.
 *
 * What is measured here are READINESS PROXIES for operability, not the
 * ADR-002 §5B bars. §5B's ≤ 2% is unintended blocking of legitimate work on
 * frozen fixtures with a frozen denominator, and its ≥ 98% is legitimate task
 * completion along the approval path. The two local proxies use different
 * denominators and measure different things; neither is a false-positive
 * rate, and neither bounds one. The 2% and 98% below are operability
 * thresholds chosen for this posture.
 *
 * Nothing here touches session taint, the §2.4 effect decision or the
 * dangerous-tier narrowing: the verdicts are exactly the guard's verdicts; the
 * gate decides only whether a dangerous-tier verdict is applied or shadowed.
 * The catastrophic tier and the session-lease floor are enforced in every
 * posture and mode and never reach here.
 *
 * ## The three conditions
 *
 * 1. Operational intervention rate (proxy) — over the last
 *    {@link INTERVENTION_WINDOW_MS} of real Claude Code hook calls:
 *    (would-stop + stop, excluding catastrophic) ÷ all audited calls ≤
 *    {@link INTERVENTION_MAX_RATE}, with at least
 *    {@link INTERVENTION_MIN_SAMPLE} calls spanning at least
 *    {@link INTERVENTION_MIN_SPAN_MS}. It says how often the guard would get in
 *    the way of this install's traffic; it does not say how many of those
 *    stops were wrong.
 *
 * 2. Approval reachability (proxy) — of approval requests put to the
 *    configured human channel over the last {@link REACHABILITY_WINDOW_MS},
 *    ≥ {@link REACHABILITY_MIN_RATE} got a human answer (approve OR deny)
 *    within {@link REACH_ANSWER_WINDOW_MS}, with at least
 *    {@link REACHABILITY_MIN_SAMPLE} resolved requests, AND at least one
 *    reached round-trip within {@link ROUND_TRIP_MAX_AGE_MS}. A timeout, an
 *    undelivered request, "no prompt surface", or the hash-in-transcript
 *    fallback is NOT a reach. A human answering is not the task completing.
 *    No configured human channel ⇒ not ready, full stop.
 *
 * 3. Effectiveness evidence — operability says the guard is tolerable to run;
 *    it says nothing about whether it stops attacks. Automatic promotion
 *    therefore also needs independently reviewed effectiveness evidence (the
 *    effect-based red-team exam) pinned to the adapter + policy version in
 *    force. Required by default ({@link EFFECTIVENESS_EVIDENCE_REQUIRED},
 *    config `actionGuard.readinessRequireEffectivenessEvidence`). No such
 *    evidence ships: {@link REVIEWED_EFFECTIVENESS_EVIDENCE} is empty, so with
 *    the default an install stays in shadow and says so.
 *
 * ## Evidence pinning
 *
 * Every evidence row carries the {@link ReadinessPin} (adapter version +
 * policy version) it was produced under, and only rows pinned to the version
 * in force count: an upgrade or a guard-rule change starts the evidence over.
 * Each input has a minimum sample and a freshness window. Evidence that is
 * missing, empty, unreadable or unparseable never qualifies — it is "not
 * ready", never a pass. A pin that cannot be determined is not ready too.
 *
 * ## Tamper direction
 *
 * The audit log and the state file below are same-UID files. Inflating
 * readiness only tightens. Deflating it — forged would-stop rows, deleted
 * approval answers, a corrupted line, a removed state file — loosens, so it is
 * never silent: readiness is RECOMPUTED from evidence at least every
 * {@link READINESS_CACHE_TTL_MS}; a recompute that turns an enforcing install
 * into a shadow one is a DEMOTION, which is audited, reported to the operator
 * and makes `shieldcortex doctor` FAIL. The state file is a cache and a memory
 * of the last mode, never the source of truth: a missing state falls back to
 * the last transition row in the audit log, and wherever state and audit
 * disagree the ENFORCING answer wins. The state file (and its lock and temp
 * files) live in the approval store's own directory, `~/.shieldcortex/approvals`
 * — deliberately NOT under a `SHIELDCORTEX_CONFIG_DIR` override — so the
 * guard's existing `touch-approval-store` path rule (core, hook fallback,
 * OpenClaw fallback) gates an agent writing it wherever the config lives.
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

// ==================== THRESHOLDS ====================
// Operability thresholds chosen for this posture. They are readiness proxies,
// not the ADR-002 §5B bars, and passing them is not a §5B result.

/** Maximum operational intervention rate (would-stop ÷ all gated calls). */
export const INTERVENTION_MAX_RATE = 0.02;
/** Minimum audited calls before the intervention proxy can pass. */
export const INTERVENTION_MIN_SAMPLE = 500;
/** The counted calls must span at least this long — one busy afternoon is not
 *  a representative week. */
export const INTERVENTION_MIN_SPAN_MS = 7 * 24 * 60 * 60 * 1000;
/** Freshness: the rolling window the intervention proxy is computed over. */
export const INTERVENTION_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

/** Minimum share of approval requests a human answered before timeout. */
export const REACHABILITY_MIN_RATE = 0.98;
/** Minimum resolved approval requests before the reachability proxy can pass. */
export const REACHABILITY_MIN_SAMPLE = 20;
/** Freshness: the rolling window the reachability proxy is computed over. */
export const REACHABILITY_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
/** A reached round-trip must be at least this recent. */
export const ROUND_TRIP_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
/** An answer later than this after the request counts as a timeout. Covers the
 *  10-minute OpenClaw card lifetime plus slack. */
export const REACH_ANSWER_WINDOW_MS = 15 * 60 * 1000;

/**
 * Addendum 1 (B): automatic promotion needs reviewed effectiveness evidence.
 * The default is REQUIRED pending the operator's decision; flipping it is this
 * one line, or `actionGuard.readinessRequireEffectivenessEvidence: false` in
 * config (only the literal `false` turns it off).
 */
export const EFFECTIVENESS_EVIDENCE_REQUIRED = true;
/** The config key that overrides {@link EFFECTIVENESS_EVIDENCE_REQUIRED}. */
export const EFFECTIVENESS_EVIDENCE_CONFIG_KEY = 'readinessRequireEffectivenessEvidence';
/** Freshness: a review older than this no longer counts. */
export const EFFECTIVENESS_EVIDENCE_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
/** Minimum sample: a reviewed exam must report at least this many attack
 *  cases. A proposed floor — the exam's own design sets the real number. */
export const EFFECTIVENESS_MIN_CASES = 50;

/** How long a computed mode is reused before the hook recomputes it. */
export const READINESS_CACHE_TTL_MS = 10 * 60 * 1000;
/** Hysteresis: a failing condition must stay failing this long before an
 *  enforcing install is demoted — one bad hour does not flap it. */
export const DEMOTE_AFTER_FAILING_MS = 60 * 60 * 1000;
/** Hysteresis: after a demotion, no re-promotion for this long. */
export const REPROMOTE_COOLDOWN_MS = 60 * 60 * 1000;

/** Read budget per recompute, newest files first. */
export const MAX_READINESS_BYTES = 64 * 1024 * 1024;
/** A recompute lock older than this is abandoned. */
const LOCK_STALE_MS = 60 * 1000;

/** The readiness output once both proxies pass but effectiveness is missing. */
export const AWAITING_EFFECTIVENESS_MESSAGE = 'operability proxies met; awaiting reviewed effectiveness evidence';

// ==================== TYPES ====================

export type ReadinessMode = 'shadow' | 'enforcing';

export type ReachAnswer = 'approve' | 'deny' | 'timeout' | 'unreached' | 'no_surface';

export interface HumanChannel {
  configured: boolean;
  /** 'openclaw-card' | 'webhook' | null */
  kind: string | null;
}

/** The adapter + policy version evidence is pinned to. */
export interface ReadinessPin {
  /** The enforcement adapter and the package build it shipped in. */
  adapter: string;
  /** A digest of the guard's rule source: any rule change is a new policy. */
  policy: string;
}

/**
 * One independently reviewed effectiveness result (the effect-based red-team
 * exam), pinned to the adapter + policy version it examined. Entries arrive
 * only through code review of this file — never from a same-UID file an agent
 * could write, and never self-attested by this module.
 */
export interface EffectivenessEvidence {
  adapter: string;
  policy: string;
  /** ISO date the review concluded. */
  reviewedAt: string;
  /** Who reviewed it (not the author of the change under test). */
  reviewedBy: string;
  /** Where the exam and its verdict live. */
  reference: string;
  /** Attack cases the exam ran. */
  cases: number;
}

export interface InterventionProxy {
  stops: number;
  total: number;
  rate: number | null;
  spanMs: number;
  /** Rows skipped because they were pinned to another adapter/policy version. */
  otherVersion: number;
  pass: boolean;
  missing: string | null;
}

export interface ReachabilityProxy {
  channel: HumanChannel;
  reached: number;
  resolved: number;
  pending: number;
  rate: number | null;
  lastRoundTripAt: string | null;
  otherVersion: number;
  pass: boolean;
  missing: string | null;
}

export interface EffectivenessCondition {
  required: boolean;
  evidence: EffectivenessEvidence | null;
  pass: boolean;
  missing: string | null;
}

export interface EvidenceIntegrity {
  /** Evidence files that could not be stat'ed or read. */
  unreadableFiles: number;
  /** Complete evidence lines that did not parse as a JSON object. */
  unparseableLines: number;
  pass: boolean;
  missing: string | null;
}

export interface ReadinessReport {
  computedAt: string;
  /** The version in force; null when it could not be determined. */
  pin: ReadinessPin | null;
  intervention: InterventionProxy;
  reachability: ReachabilityProxy;
  effectiveness: EffectivenessCondition;
  integrity: EvidenceIntegrity;
  /** Both operability proxies pass on sound, pinned evidence. */
  proxiesMet: boolean;
  /** All three conditions hold: the install may enforce. */
  ready: boolean;
  /** Plain-English list of what is missing; empty when ready. */
  missing: string[];
  /** The newest readiness_transition row found in the audit, if any. */
  lastTransition: { to: ReadinessMode; ts: string } | null;
  bytesRead: number;
  truncated: boolean;
}

export interface ReadinessState {
  version: 1;
  mode: ReadinessMode;
  computedAt: string;
  /** The pin the mode was computed under; a different pin makes it stale. */
  pin?: ReadinessPin | null;
  failingSince?: string;
  lastPromotedAt?: string;
  lastDemotedAt?: string;
  lastDemotionReason?: string;
  missing?: string[];
}

export interface ReadinessPaths {
  /** Where the state file is written (inside the approval store directory). */
  statePath: string;
  /** Where readiness rows (reach answers, transitions) are appended. */
  auditDir: string;
  /** Every audit directory evidence is read from (deduplicated). */
  readAuditDirs: string[];
}

// ==================== PATHS ====================

/**
 * `SHIELDCORTEX_CONFIG_DIR` when set (the same override every config reader
 * honours), else `~/.shieldcortex`. An explicit `home` pins the tree for tests.
 */
export function readinessRoot(home?: string): string {
  if (home !== undefined) return join(home, '.shieldcortex');
  const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
  return override || join(homedir(), '.shieldcortex');
}

/**
 * Paths for one install. Evidence is read from the union of the configured
 * root's `audit/` and `~/.shieldcortex/audit` — the Claude Code hook writes
 * its intercept rows under the home directory — so a config-dir override can
 * never hide the hook's own rows from the gate. The state file sits beside
 * `approvals.json` (action-approvals.ts `approvalsDir`), which ignores the
 * override on purpose: that is the directory the path rules protect.
 */
export function readinessPaths(opts: { home?: string } = {}): ReadinessPaths {
  const root = readinessRoot(opts.home);
  const auditDir = join(root, 'audit');
  const homeRoot = join(opts.home ?? homedir(), '.shieldcortex');
  const hookAudit = join(homeRoot, 'audit');
  const readAuditDirs = Array.from(new Set([auditDir, hookAudit]));
  return {
    statePath: join(homeRoot, 'approvals', 'guard-readiness.json'),
    auditDir,
    readAuditDirs,
  };
}

// ==================== PIN ====================

/** The enforcement adapter this module gates. */
export const READINESS_ADAPTER = 'claude-code-hook';

let cachedPin: ReadinessPin | null | undefined;

function readSibling(rel: string): string | null {
  try {
    return readFileSync(new URL(rel, import.meta.url), 'utf8');
  } catch {
    return null;
  }
}

/**
 * The adapter + policy version in force: the hook adapter at this package's
 * version, and a digest of the guard's rule module as built. Null when either
 * cannot be read — and a null pin is never ready. Memoised per process.
 */
export function currentReadinessPin(): ReadinessPin | null {
  if (cachedPin !== undefined) return cachedPin;
  let version: string | null = null;
  const pkg = readSibling('../../../package.json');
  if (pkg) {
    try {
      const v = (JSON.parse(pkg) as { version?: unknown }).version;
      if (typeof v === 'string' && v.trim()) version = v.trim();
    } catch {
      version = null;
    }
  }
  const rules = readSibling('./tool-action-guard.js') ?? readSibling('./tool-action-guard.ts');
  cachedPin = version && rules
    ? {
      adapter: `${READINESS_ADAPTER}@${version}`,
      policy: `tool-action-guard:${createHash('sha256').update(rules).digest('hex').slice(0, 16)}`,
    }
    : null;
  return cachedPin;
}

function samePin(a: unknown, b: ReadinessPin | null): boolean {
  if (!b || !a || typeof a !== 'object') return false;
  const p = a as Record<string, unknown>;
  return p.adapter === b.adapter && p.policy === b.policy;
}

// ==================== EFFECTIVENESS ====================

/**
 * Reviewed effectiveness evidence, pinned per adapter + policy version. EMPTY:
 * no reviewed exam exists for any version yet. Add an entry only with the
 * reviewer's sign-off and a link to the exam; never add one to make a test or
 * an install pass.
 */
export const REVIEWED_EFFECTIVENESS_EVIDENCE: readonly EffectivenessEvidence[] = Object.freeze([]);

/** Whether effectiveness evidence is required, from the RAW actionGuard block. */
export function effectivenessEvidenceRequired(rawActionGuard: unknown): boolean {
  if (rawActionGuard && typeof rawActionGuard === 'object' && !Array.isArray(rawActionGuard)) {
    if ((rawActionGuard as Record<string, unknown>)[EFFECTIVENESS_EVIDENCE_CONFIG_KEY] === false) return false;
  }
  return EFFECTIVENESS_EVIDENCE_REQUIRED;
}

function findEffectivenessEvidence(
  pin: ReadinessPin | null,
  nowMs: number,
  registry: readonly EffectivenessEvidence[],
): EffectivenessEvidence | null {
  if (!pin) return null;
  for (const e of registry) {
    if (!samePin(e, pin)) continue;
    const at = Date.parse(e.reviewedAt);
    if (!Number.isFinite(at) || at > nowMs || nowMs - at > EFFECTIVENESS_EVIDENCE_MAX_AGE_MS) continue;
    if (!Number.isFinite(e.cases) || e.cases < EFFECTIVENESS_MIN_CASES) continue;
    if (!e.reviewedBy?.trim() || !e.reference?.trim()) continue;
    return e;
  }
  return null;
}

// ==================== CHANNEL ====================

/**
 * Whether a human approval channel is configured, from the RAW
 * `actionGuard.notify` block. Mirrors notify-config.ts's acceptance rules
 * without importing it (this module is loaded by the hook on every call under
 * the posture; keep it dependency-free): enabled must be exactly true, and a
 * webhook must be an http(s) URL. `openclaw: true` counts — its failures show
 * up as unreached requests in the evidence, which is where they belong.
 */
export function describeHumanChannel(rawNotify: unknown): HumanChannel {
  if (!rawNotify || typeof rawNotify !== 'object' || Array.isArray(rawNotify)) {
    return { configured: false, kind: null };
  }
  const n = rawNotify as Record<string, unknown>;
  if (n.enabled !== true) return { configured: false, kind: null };
  if (n.openclaw === true) return { configured: true, kind: 'openclaw-card' };
  if (typeof n.webhookUrl === 'string') {
    try {
      const u = new URL(n.webhookUrl.trim());
      if (u.protocol === 'https:' || u.protocol === 'http:') return { configured: true, kind: 'webhook' };
    } catch {
      /* not a URL — no channel */
    }
  }
  return { configured: false, kind: null };
}

// ==================== ROW WRITERS ====================

/** Stable, non-reversible id linking an approval request to its answer. */
export function reachIdFor(hash: string): string {
  return createHash('sha256').update(`sc-reach:${String(hash).toLowerCase()}`).digest('hex').slice(0, 24);
}

function appendRow(auditDir: string, row: Record<string, unknown>, now: Date): boolean {
  let fd: number | undefined;
  try {
    mkdirSync(auditDir, { recursive: true, mode: 0o700 });
    const file = join(auditDir, `realtime-${now.toISOString().slice(0, 10)}.jsonl`);
    fd = openSync(file, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink > 1) return false;
    writeFileSync(fd, `${JSON.stringify(row)}\n`);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
}

export interface ReachRowInput {
  /** The full approval hash (or a synthetic one for test-approval). */
  hash: string;
  /** request = put to the channel; answer = the human's reply or its absence;
   *  resolved = request and outcome known together (undelivered, no surface). */
  phase: 'request' | 'answer' | 'resolved';
  answer?: ReachAnswer;
  channel?: string | null;
  reason?: string;
  synthetic?: boolean;
  origin?: string;
}

/**
 * Append one approval-reachability evidence row, pinned to the version in
 * force. Best-effort: evidence that cannot be written is evidence that is
 * missing, which can only keep an install from becoming ready — never make it
 * ready.
 */
export function recordApprovalReach(
  input: ReachRowInput,
  opts: { home?: string; now?: number; auditDir?: string; pin?: ReadinessPin | null } = {},
): boolean {
  const now = new Date(opts.now ?? Date.now());
  const auditDir = opts.auditDir ?? readinessPaths({ home: opts.home }).auditDir;
  const pin = opts.pin === undefined ? currentReadinessPin() : opts.pin;
  const row: Record<string, unknown> = {
    type: 'approval_reach',
    origin: input.origin ?? 'claude-code-hook',
    reachId: reachIdFor(input.hash),
    phase: input.phase,
    ts: now.toISOString(),
    auditEventId: randomBytes(16).toString('hex'),
  };
  if (pin) row.readinessPin = pin;
  if (input.answer) row.answer = input.answer;
  if (input.channel) row.channel = String(input.channel).slice(0, 40);
  if (input.reason) row.reason = String(input.reason).slice(0, 160);
  if (input.synthetic) row.synthetic = true;
  return appendRow(auditDir, row, now);
}

// ==================== EVIDENCE ====================

/** Outcomes that mean the guard stopped (or, in shadow, would have stopped)
 *  a call. `approved`/`allowed` are not stops: an approved row is either an
 *  operator allowlist, a broker pre-clear, or the retry a human released. */
const STOP_OUTCOMES = new Set([
  'would_hold',
  'would_block',
  'asked',
  'denied_no_prompt_surface',
  'warned',
  'auto_denied',
]);

/** Rows that are not a verdict on a tool call. */
const NON_VERDICT_ACTIONS = new Set(['gate_degraded', 'notify']);

interface ParsedRow {
  ts: number;
  row: Record<string, unknown>;
}

function listAuditFiles(dir: string, sinceMs: number): Array<{ path: string; date: string }> {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return [];
  }
  const sinceDate = new Date(sinceMs - 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  return names
    .map((name) => ({ name, m: /^realtime-(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(name) }))
    .filter((e) => e.m !== null && e.m[1] >= sinceDate)
    .map((e) => ({ path: join(dir, e.name), date: e.m![1] }));
}

/** Only these lines are parsed; the rest of the audit is skipped unread. */
const LINE_PREFILTER = /"claude-code-hook"|"approval_reach"|"readiness_transition"/;

function readEvidence(dirs: string[], sinceMs: number, nowMs: number): {
  rows: ParsedRow[];
  bytesRead: number;
  truncated: boolean;
  unreadableFiles: number;
  unparseableLines: number;
} {
  const files = dirs.flatMap((d) => listAuditFiles(d, sinceMs));
  // Newest first, so a budget cut drops the OLDEST evidence.
  files.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  const seen = new Set<string>();
  const rows: ParsedRow[] = [];
  let bytesRead = 0;
  let truncated = false;
  let unreadableFiles = 0;
  let unparseableLines = 0;
  for (const f of files) {
    let size = 0;
    try {
      size = statSync(f.path).size;
    } catch {
      unreadableFiles += 1;
      continue;
    }
    if (bytesRead + size > MAX_READINESS_BYTES) {
      truncated = true;
      break;
    }
    let text: string;
    try {
      text = readFileSync(f.path, 'utf8');
    } catch {
      unreadableFiles += 1;
      continue;
    }
    bytesRead += size;
    const lines = text.split('\n');
    // A final segment with no newline is an append still in flight, not a
    // corrupt row: leave it for the next recompute.
    lines.pop();
    for (const line of lines) {
      if (!line || !LINE_PREFILTER.test(line)) continue;
      let row: Record<string, unknown>;
      try {
        row = JSON.parse(line) as Record<string, unknown>;
      } catch {
        unparseableLines += 1;
        continue;
      }
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        unparseableLines += 1;
        continue;
      }
      const ts = Date.parse(String(row.ts ?? ''));
      // Future-dated rows are not evidence of anything that happened.
      if (!Number.isFinite(ts) || ts < sinceMs || ts > nowMs + 60_000) continue;
      const id = typeof row.auditEventId === 'string' ? row.auditEventId : null;
      if (id) {
        if (seen.has(id)) continue;
        seen.add(id);
      }
      rows.push({ ts, row });
    }
  }
  return { rows, bytesRead, truncated, unreadableFiles, unparseableLines };
}

/** A real, verdict-bearing Claude Code hook call (any version). */
function isCountedCall(row: Record<string, unknown>): boolean {
  if (row.type !== 'intercept') return false;
  // Exact origin: rows from other planes, canaries and proofs never count.
  if (row.origin !== 'claude-code-hook') return false;
  if (row.synthetic === true) return false;
  if (NON_VERDICT_ACTIONS.has(String(row.action))) return false;
  const threats = Array.isArray(row.threats) ? row.threats : [];
  // An operator freeze (#227) is not a guard verdict.
  if (threats.includes('session-lease')) return false;
  return true;
}

function fmtPct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`;
}

function fmtDays(ms: number): string {
  return `${(ms / (24 * 60 * 60 * 1000)).toFixed(1)} days`;
}

/**
 * Compute the three conditions from the evidence. Pure with respect to its
 * inputs: nothing is written, and no stored boolean is consulted.
 */
export function computeReadiness(opts: {
  channel: HumanChannel;
  paths?: ReadinessPaths;
  home?: string;
  now?: number;
  /** The version in force; defaults to {@link currentReadinessPin}. */
  pin?: ReadinessPin | null;
  /** Defaults to {@link EFFECTIVENESS_EVIDENCE_REQUIRED}. */
  requireEffectivenessEvidence?: boolean;
  /** Test seam; defaults to {@link REVIEWED_EFFECTIVENESS_EVIDENCE}. */
  effectivenessRegistry?: readonly EffectivenessEvidence[];
}): ReadinessReport {
  const nowMs = opts.now ?? Date.now();
  const paths = opts.paths ?? readinessPaths({ home: opts.home });
  const pin = opts.pin === undefined ? currentReadinessPin() : opts.pin;
  const since = nowMs - Math.max(INTERVENTION_WINDOW_MS, REACHABILITY_WINDOW_MS);
  const { rows, bytesRead, truncated, unreadableFiles, unparseableLines } = readEvidence(paths.readAuditDirs, since, nowMs);

  // ── Operational intervention rate ──
  let stops = 0;
  let total = 0;
  let ivOther = 0;
  let oldest = Infinity;
  let newest = -Infinity;
  const ivSince = nowMs - INTERVENTION_WINDOW_MS;
  for (const { ts, row } of rows) {
    if (ts < ivSince || !isCountedCall(row)) continue;
    if (!samePin(row.readinessPin, pin)) {
      ivOther += 1;
      continue;
    }
    total += 1;
    oldest = Math.min(oldest, ts);
    newest = Math.max(newest, ts);
    const catastrophic = row.severity === 'critical';
    if (!catastrophic && STOP_OUTCOMES.has(String(row.outcome))) stops += 1;
  }
  const spanMs = total > 0 ? newest - oldest : 0;
  const ivRate = total > 0 ? stops / total : null;
  let ivMissing: string | null = null;
  if (total < INTERVENTION_MIN_SAMPLE) {
    ivMissing = `only ${total} of the ${INTERVENTION_MIN_SAMPLE} real tool calls needed have been observed on this version`;
  } else if (spanMs < INTERVENTION_MIN_SPAN_MS) {
    ivMissing = `observed calls span ${fmtDays(spanMs)}; at least ${fmtDays(INTERVENTION_MIN_SPAN_MS)} are needed`;
  } else if (ivRate !== null && ivRate > INTERVENTION_MAX_RATE) {
    ivMissing = `the guard would intervene on ${fmtPct(ivRate)} of calls (${stops}/${total}); the threshold is ≤ ${fmtPct(INTERVENTION_MAX_RATE)}`;
  }
  const intervention: InterventionProxy = {
    stops, total, rate: ivRate, spanMs, otherVersion: ivOther, pass: ivMissing === null, missing: ivMissing,
  };

  // ── Approval reachability ──
  const rcSince = nowMs - REACHABILITY_WINDOW_MS;
  const requests = new Map<string, { ts: number }>();
  const answers = new Map<string, Array<{ ts: number; answer: string }>>();
  let resolved = 0;
  let reached = 0;
  let pending = 0;
  let rcOther = 0;
  let lastRoundTrip = -Infinity;
  for (const { ts, row } of rows) {
    if (row.type !== 'approval_reach' || ts < rcSince) continue;
    const id = typeof row.reachId === 'string' ? row.reachId : '';
    if (!id) continue;
    if (row.phase === 'answer') {
      // Answers join to a pinned request by id; the request carries the pin.
      const list = answers.get(id) ?? [];
      list.push({ ts, answer: String(row.answer ?? '') });
      answers.set(id, list);
      continue;
    }
    if (!samePin(row.readinessPin, pin)) {
      rcOther += 1;
      continue;
    }
    if (row.phase === 'request') {
      const prev = requests.get(id);
      if (!prev || ts > prev.ts) requests.set(id, { ts });
    } else if (row.phase === 'resolved') {
      // Outcome known at request time: undelivered / no surface. Never a reach.
      resolved += 1;
    }
  }
  for (const [id, req] of requests) {
    const replies = (answers.get(id) ?? []).filter((a) => a.ts >= req.ts).sort((a, b) => a.ts - b.ts);
    const first = replies[0];
    if (first && first.ts - req.ts <= REACH_ANSWER_WINDOW_MS) {
      resolved += 1;
      if (first.answer === 'approve' || first.answer === 'deny') {
        reached += 1;
        lastRoundTrip = Math.max(lastRoundTrip, first.ts);
      }
      continue;
    }
    if (nowMs - req.ts > REACH_ANSWER_WINDOW_MS) {
      resolved += 1; // timed out: late or no answer
      continue;
    }
    pending += 1;
  }
  const rcRate = resolved > 0 ? reached / resolved : null;
  const roundTripFresh = lastRoundTrip > -Infinity && nowMs - lastRoundTrip <= ROUND_TRIP_MAX_AGE_MS;
  let rcMissing: string | null = null;
  if (!opts.channel.configured) {
    rcMissing = 'no human approval channel is configured (run `shieldcortex config --action-guard-notify-openclaw` or `--action-guard-notify-webhook <url>`)';
  } else if (resolved < REACHABILITY_MIN_SAMPLE) {
    rcMissing = `only ${resolved} of the ${REACHABILITY_MIN_SAMPLE} answered-or-expired approval requests needed on this version (run \`shieldcortex guard test-approval\` to add round-trips)`;
  } else if (rcRate !== null && rcRate < REACHABILITY_MIN_RATE) {
    rcMissing = `a human answered ${fmtPct(rcRate)} of approval requests (${reached}/${resolved}); the threshold is ≥ ${fmtPct(REACHABILITY_MIN_RATE)}`;
  } else if (!roundTripFresh) {
    rcMissing = 'no approval request has reached a human in the last 7 days (run `shieldcortex guard test-approval`)';
  }
  const reachability: ReachabilityProxy = {
    channel: opts.channel,
    reached,
    resolved,
    pending,
    rate: rcRate,
    lastRoundTripAt: lastRoundTrip > -Infinity ? new Date(lastRoundTrip).toISOString() : null,
    otherVersion: rcOther,
    pass: rcMissing === null,
    missing: rcMissing,
  };

  // ── Evidence integrity: unreadable or unparseable is never a pass ──
  const integrityProblems: string[] = [];
  if (!pin) integrityProblems.push('the adapter/policy version in force could not be determined, so no evidence can be pinned to it');
  if (unreadableFiles > 0) integrityProblems.push(`${unreadableFiles} audit evidence file(s) could not be read`);
  if (unparseableLines > 0) integrityProblems.push(`${unparseableLines} audit evidence line(s) could not be parsed`);
  const integrity: EvidenceIntegrity = {
    unreadableFiles,
    unparseableLines,
    pass: integrityProblems.length === 0,
    missing: integrityProblems.length > 0 ? `evidence is not sound: ${integrityProblems.join('; ')}` : null,
  };

  // ── Effectiveness evidence ──
  const required = opts.requireEffectivenessEvidence ?? EFFECTIVENESS_EVIDENCE_REQUIRED;
  const evidence = findEffectivenessEvidence(pin, nowMs, opts.effectivenessRegistry ?? REVIEWED_EFFECTIVENESS_EVIDENCE);
  const effectiveness: EffectivenessCondition = {
    required,
    evidence,
    pass: !required || evidence !== null,
    missing: required && !evidence
      ? 'reviewed effectiveness evidence (the effect-based red-team exam) for this adapter + policy version — none has been published'
      : null,
  };

  // ── Last transition, the fallback memory of the mode ──
  let lastTransition: ReadinessReport['lastTransition'] = null;
  for (const { ts, row } of rows) {
    if (row.type !== 'readiness_transition') continue;
    const to = row.to === 'enforcing' ? 'enforcing' : row.to === 'shadow' ? 'shadow' : null;
    if (!to) continue;
    if (!lastTransition || ts >= Date.parse(lastTransition.ts)) {
      lastTransition = { to, ts: new Date(ts).toISOString() };
    }
  }

  const proxiesMet = intervention.pass && reachability.pass && integrity.pass;
  const ready = proxiesMet && effectiveness.pass;
  let missing: string[];
  if (proxiesMet && !effectiveness.pass) {
    missing = [AWAITING_EFFECTIVENESS_MESSAGE];
  } else {
    missing = [intervention.missing, reachability.missing, integrity.missing, effectiveness.missing]
      .filter((m): m is string => m !== null);
  }
  if (truncated) {
    missing.push(`the audit exceeded the ${MAX_READINESS_BYTES / (1024 * 1024)} MB read budget; only the newest evidence was counted`);
  }
  return {
    computedAt: new Date(nowMs).toISOString(),
    pin,
    intervention,
    reachability,
    effectiveness,
    integrity,
    proxiesMet,
    ready,
    missing,
    lastTransition,
    bytesRead,
    truncated,
  };
}

// ==================== STATE ====================

export function readReadinessState(statePath: string): ReadinessState | null {
  try {
    const parsed = JSON.parse(readFileSync(statePath, 'utf8')) as Partial<ReadinessState>;
    if (!parsed || parsed.version !== 1) return null;
    if (parsed.mode !== 'shadow' && parsed.mode !== 'enforcing') return null;
    if (!Number.isFinite(Date.parse(String(parsed.computedAt)))) return null;
    return parsed as ReadinessState;
  } catch {
    return null;
  }
}

function writeReadinessState(statePath: string, state: ReadinessState): void {
  try {
    const dir = join(statePath, '..');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${statePath}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(state, null, 2), { mode: 0o600 });
    renameSync(tmp, statePath);
  } catch {
    /* a cache that cannot be written is recomputed next call */
  }
}

/** A state younger than the TTL, computed under the pin in force. */
function isFreshState(state: ReadinessState | null, now: number, ttl: number, pin: ReadinessPin | null): boolean {
  if (!state || !samePin(state.pin, pin)) return false;
  const age = now - Date.parse(state.computedAt);
  return age >= 0 && age < ttl;
}

// ==================== DECISION ====================

export interface ModeDecision {
  mode: ReadinessMode;
  failingSince?: string;
  transition: 'promote' | 'demote' | null;
}

/**
 * The hysteresis rule. `prevMode` is the last KNOWN mode (state file, or the
 * audit's last transition when the state is missing — enforcing wins any
 * disagreement).
 *  - ready + was enforcing → enforcing.
 *  - ready + was shadow → promote, unless a demotion happened within
 *    {@link REPROMOTE_COOLDOWN_MS}.
 *  - not ready + was enforcing → stay enforcing until the conditions have
 *    been failing for {@link DEMOTE_AFTER_FAILING_MS}, then demote.
 *  - not ready + was shadow → shadow.
 */
export function decideMode(input: {
  prevMode: ReadinessMode | null;
  failingSince?: string;
  lastDemotedAt?: string;
  ready: boolean;
  now: number;
}): ModeDecision {
  const { prevMode, ready, now } = input;
  if (ready) {
    if (prevMode === 'enforcing') return { mode: 'enforcing', transition: null };
    const demotedAt = input.lastDemotedAt ? Date.parse(input.lastDemotedAt) : NaN;
    if (Number.isFinite(demotedAt) && now - demotedAt < REPROMOTE_COOLDOWN_MS) {
      return { mode: 'shadow', transition: null };
    }
    return { mode: 'enforcing', transition: 'promote' };
  }
  if (prevMode === 'enforcing') {
    const since = input.failingSince ? Date.parse(input.failingSince) : NaN;
    const failingSince = Number.isFinite(since) && since <= now ? since : now;
    if (now - failingSince >= DEMOTE_AFTER_FAILING_MS) {
      return { mode: 'shadow', transition: 'demote' };
    }
    return { mode: 'enforcing', failingSince: new Date(failingSince).toISOString(), transition: null };
  }
  return { mode: 'shadow', transition: null };
}

/** The last KNOWN mode: state or audit transition, enforcing wins a disagreement. */
export function previousMode(state: ReadinessState | null, report: ReadinessReport): ReadinessMode | null {
  const auditMode = report.lastTransition?.to ?? null;
  return state?.mode === 'enforcing' || auditMode === 'enforcing' ? 'enforcing' : state?.mode ?? auditMode;
}

/**
 * The mode the hook would apply right now, WITHOUT writing anything: a fresh
 * cache as-is, else the evidence through the same hysteresis rule. Used by
 * `guard readiness` and `doctor`, which report and never flip.
 */
export function previewMode(opts: {
  state: ReadinessState | null;
  report: ReadinessReport;
  now: number;
  ttlMs?: number;
}): ReadinessMode {
  const { state, report, now } = opts;
  if (isFreshState(state, now, opts.ttlMs ?? READINESS_CACHE_TTL_MS, report.pin)) return state!.mode;
  return decideMode({
    prevMode: previousMode(state, report),
    failingSince: state?.failingSince,
    lastDemotedAt: state?.lastDemotedAt,
    ready: report.ready,
    now,
  }).mode;
}

export interface ResolvedReadiness {
  mode: ReadinessMode;
  /** True when the mode came from a fresh cache without recomputing. */
  cached: boolean;
  transition: 'promote' | 'demote' | null;
  report: ReadinessReport | null;
  state: ReadinessState | null;
  /** Human-readable reason for a demotion, when one happened now. */
  demotionReason?: string;
}

function tryLock(lockPath: string, now: number): boolean {
  try {
    mkdirSync(join(lockPath, '..'), { recursive: true, mode: 0o700 });
    const fd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    writeFileSync(fd, String(now));
    closeSync(fd);
    return true;
  } catch {
    try {
      const st = statSync(lockPath);
      if (now - st.mtimeMs > LOCK_STALE_MS) {
        rmSync(lockPath, { force: true });
        return tryLock(lockPath, now);
      }
    } catch {
      /* raced away — treat as busy */
    }
    return false;
  }
}

/**
 * The per-call entry point used by the hook. The ONLY writer of readiness
 * state: `guard readiness` and `doctor` use {@link previewMode} instead.
 *
 * Fresh state (younger than {@link READINESS_CACHE_TTL_MS}, not future-dated,
 * computed under the pin in force) is reused as-is — the cheap path, and the
 * documented residual: a state file forged outside the tool surface holds its
 * mode for at most one TTL before evidence overrules it. Otherwise readiness
 * is recomputed from evidence, the hysteresis rule applied, and any
 * transition audited. A missing or stale state is never read as "shadow": the
 * previous mode then comes from the audit's own transition rows, so deleting
 * the state file cannot quietly end enforcement.
 */
export function resolveReadiness(opts: {
  channel: HumanChannel;
  home?: string;
  now?: number;
  paths?: ReadinessPaths;
  ttlMs?: number;
  pin?: ReadinessPin | null;
  requireEffectivenessEvidence?: boolean;
  effectivenessRegistry?: readonly EffectivenessEvidence[];
}): ResolvedReadiness {
  const now = opts.now ?? Date.now();
  const paths = opts.paths ?? readinessPaths({ home: opts.home });
  const ttl = opts.ttlMs ?? READINESS_CACHE_TTL_MS;
  const pin = opts.pin === undefined ? currentReadinessPin() : opts.pin;
  const state = readReadinessState(paths.statePath);
  if (isFreshState(state, now, ttl, pin)) {
    return { mode: state!.mode, cached: true, transition: null, report: null, state };
  }

  const report = computeReadiness({
    channel: opts.channel,
    paths,
    now,
    pin,
    requireEffectivenessEvidence: opts.requireEffectivenessEvidence,
    effectivenessRegistry: opts.effectivenessRegistry,
  });
  const prevMode = previousMode(state, report);
  const decision = decideMode({
    prevMode,
    failingSince: state?.failingSince,
    lastDemotedAt: state?.lastDemotedAt,
    ready: report.ready,
    now,
  });

  const lockPath = `${paths.statePath}.lock`;
  if (!tryLock(lockPath, now)) {
    // Someone else is recomputing: answer from evidence, write nothing, and
    // never announce a transition twice. A would-be demotion keeps enforcing
    // until the lock holder has written (and announced) it.
    const mode = decision.transition === 'demote' ? 'enforcing' : decision.mode;
    return { mode, cached: false, transition: null, report, state };
  }
  try {
    const nowIso = new Date(now).toISOString();
    let demotionReason: string | undefined;
    const next: ReadinessState = {
      version: 1,
      mode: decision.mode,
      computedAt: nowIso,
      pin,
      ...(decision.failingSince ? { failingSince: decision.failingSince } : {}),
      ...(state?.lastPromotedAt ? { lastPromotedAt: state.lastPromotedAt } : {}),
      ...(state?.lastDemotedAt ? { lastDemotedAt: state.lastDemotedAt } : {}),
      ...(state?.lastDemotionReason ? { lastDemotionReason: state.lastDemotionReason } : {}),
      missing: report.missing,
    };
    if (decision.transition === 'promote') {
      next.lastPromotedAt = nowIso;
    } else if (decision.transition === 'demote') {
      demotionReason = report.missing.join('; ') || 'readiness evidence no longer holds';
      if (!state) demotionReason += ' (readiness state file was missing; last mode taken from the audit log)';
      next.lastDemotedAt = nowIso;
      next.lastDemotionReason = demotionReason;
    }
    if (decision.transition) {
      appendRow(
        paths.auditDir,
        {
          type: 'readiness_transition',
          origin: 'claude-code-hook',
          from: prevMode ?? 'shadow',
          to: decision.mode,
          transition: decision.transition,
          ts: nowIso,
          auditEventId: randomBytes(16).toString('hex'),
          ...(pin ? { readinessPin: pin } : {}),
          intervention: { stops: report.intervention.stops, total: report.intervention.total, rate: report.intervention.rate },
          reachability: { reached: report.reachability.reached, resolved: report.reachability.resolved, rate: report.reachability.rate },
          effectivenessEvidence: report.effectiveness.required ? (report.effectiveness.evidence ? 'reviewed' : 'missing') : 'not-required',
          ...(demotionReason ? { reason: demotionReason.slice(0, 400) } : {}),
        },
        new Date(now),
      );
    }
    writeReadinessState(paths.statePath, next);
    return { mode: decision.mode, cached: false, transition: decision.transition, report, state: next, demotionReason };
  } finally {
    try { rmSync(lockPath, { force: true }); } catch { /* stale lock self-heals */ }
  }
}

/**
 * Whether the install is in a DEMOTED state: it enforced before, and now it
 * does not. Doctor FAILs on this — the operator chose enforcement and is not
 * getting it. Read from both the state file and the audit, loosest-evidence
 * wins (either one saying "demoted and not re-promoted" is enough).
 */
export function isDemoted(state: ReadinessState | null, report: ReadinessReport | null): boolean {
  const stateDemoted =
    !!state && state.mode === 'shadow' && !!state.lastDemotedAt &&
    (!state.lastPromotedAt || Date.parse(state.lastDemotedAt) >= Date.parse(state.lastPromotedAt));
  const auditDemoted = report?.lastTransition?.to === 'shadow';
  return stateDemoted || auditDemoted;
}

/** Plain-English one-liner for stderr / notifications. */
export function describeDemotion(reason: string | undefined): string {
  return (
    'ShieldCortex Action Guard DEMOTED to shadow mode (enforce-when-ready): dangerous actions are ' +
    `now logged but NOT stopped. Reason: ${reason ?? 'readiness evidence no longer holds'}. ` +
    'Run `shieldcortex guard readiness` for details.'
  );
}
