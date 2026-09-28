/**
 * ShieldCortex — "enforce when ready" readiness gate for the Action Guard (#509).
 *
 * Operator direction (28 Sep 2026): "build the version that the false-positive
 * rate is measured low and approvals reliably reach a human." Those are two of
 * the ADR-002 §5B pre-registered bars — ≤ 2% unintended blocking of legitimate
 * work and ≥ 98% completion along the approval path. Under the
 * `enforce-when-ready` posture (`actionGuard.readinessGate: true` on top of
 * `enabled` + `enforce`) the Claude Code hook runs the guard in SHADOW mode —
 * every verdict computed and audited, a would-stop recorded but not applied —
 * and enforces only while THIS install's own audit log shows both bars hold.
 *
 * Nothing here touches session taint, the §2.4 effect decision or the
 * dangerous-tier narrowing: the verdicts are exactly the guard's verdicts; the
 * gate decides only whether a dangerous-tier verdict is applied or shadowed.
 * The catastrophic tier is enforced in every posture and never reaches here.
 *
 * ## The two bars, measured from evidence
 *
 * FP bar — over the last {@link FP_WINDOW_MS} of real Claude Code hook calls:
 * (would-stop + stop, excluding catastrophic) ÷ all audited calls ≤
 * {@link FP_MAX_RATE}, with at least {@link FP_MIN_SAMPLE} calls spanning at
 * least {@link FP_MIN_SPAN_MS}. Every would-stop counts as a potential false
 * positive — deliberately conservative: the measured rate is an UPPER bound on
 * unintended blocking, because some of those stops were right.
 *
 * Approval-reach bar — of approval requests put to the configured human channel
 * over the last {@link APPROVAL_WINDOW_MS}, ≥ {@link APPROVAL_MIN_RATE} got a
 * human answer (approve OR deny) within {@link REACH_ANSWER_WINDOW_MS}, with at
 * least {@link APPROVAL_MIN_SAMPLE} resolved requests, AND at least one reached
 * round-trip within {@link ROUND_TRIP_MAX_AGE_MS}. A timeout, an undelivered
 * request, "no prompt surface", or the hash-in-transcript fallback is NOT a
 * reach. No configured human channel ⇒ not ready, full stop.
 *
 * ## Tamper direction
 *
 * The audit log and the state file below are same-UID files. Inflating
 * readiness only tightens. Deflating it — forged would-stop rows, deleted
 * approval answers, a removed state file — loosens, so it is never silent:
 * readiness is RECOMPUTED from evidence at least every
 * {@link READINESS_CACHE_TTL_MS}; a recompute that turns an enforcing install
 * into a shadow one is a DEMOTION, which is audited, reported to the operator
 * and makes `shieldcortex doctor` FAIL. The state file is a cache and a memory
 * of the last mode, never the source of truth: a missing state falls back to
 * the last transition row in the audit log, and wherever state and audit
 * disagree the ENFORCING answer wins. The state file lives inside the approvals
 * directory, so the guard's existing `touch-approval-store` path rule (core,
 * hook fallback, OpenClaw fallback) already gates an agent writing it.
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
// ADR-002 §5B bars, applied per install. Change them only with the ADR.

/** Maximum would-stop rate (conservative upper bound on false positives). */
export const FP_MAX_RATE = 0.02;
/** Minimum audited calls before the FP bar can pass. */
export const FP_MIN_SAMPLE = 500;
/** The counted calls must span at least this long — one busy afternoon is not
 *  a representative week. */
export const FP_MIN_SPAN_MS = 7 * 24 * 60 * 60 * 1000;
/** Rolling window the FP bar is computed over. */
export const FP_WINDOW_MS = 14 * 24 * 60 * 60 * 1000;

/** Minimum share of approval requests a human answered before timeout. */
export const APPROVAL_MIN_RATE = 0.98;
/** Minimum resolved approval requests before the approval bar can pass. */
export const APPROVAL_MIN_SAMPLE = 20;
/** Rolling window the approval bar is computed over. */
export const APPROVAL_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
/** A reached round-trip must be at least this recent. */
export const ROUND_TRIP_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
/** An answer later than this after the request counts as a timeout. Covers the
 *  10-minute OpenClaw card lifetime plus slack. */
export const REACH_ANSWER_WINDOW_MS = 15 * 60 * 1000;

/** How long a computed mode is reused before the hook recomputes it. */
export const READINESS_CACHE_TTL_MS = 10 * 60 * 1000;
/** Hysteresis: a failing bar must stay failing this long before an enforcing
 *  install is demoted — one bad hour does not flap it. */
export const DEMOTE_AFTER_FAILING_MS = 60 * 60 * 1000;
/** Hysteresis: after a demotion, no re-promotion for this long. */
export const REPROMOTE_COOLDOWN_MS = 60 * 60 * 1000;

/** Read budget per recompute, newest files first. */
export const MAX_READINESS_BYTES = 64 * 1024 * 1024;
/** A recompute lock older than this is abandoned. */
const LOCK_STALE_MS = 60 * 1000;

// ==================== TYPES ====================

export type ReadinessMode = 'shadow' | 'enforcing';

export type ReachAnswer = 'approve' | 'deny' | 'timeout' | 'unreached' | 'no_surface';

export interface HumanChannel {
  configured: boolean;
  /** 'openclaw-card' | 'webhook' | null */
  kind: string | null;
}

export interface FpBar {
  stops: number;
  total: number;
  rate: number | null;
  spanMs: number;
  pass: boolean;
  missing: string | null;
}

export interface ApprovalBar {
  channel: HumanChannel;
  reached: number;
  resolved: number;
  pending: number;
  rate: number | null;
  lastRoundTripAt: string | null;
  pass: boolean;
  missing: string | null;
}

export interface ReadinessReport {
  computedAt: string;
  fp: FpBar;
  approval: ApprovalBar;
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
  failingSince?: string;
  lastPromotedAt?: string;
  lastDemotedAt?: string;
  lastDemotionReason?: string;
  missing?: string[];
}

export interface ReadinessPaths {
  /** Where the state file is written (inside the approvals dir). */
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
 * never hide the hook's own rows from the gate.
 */
export function readinessPaths(opts: { home?: string } = {}): ReadinessPaths {
  const root = readinessRoot(opts.home);
  const auditDir = join(root, 'audit');
  const hookAudit = join(opts.home ?? homedir(), '.shieldcortex', 'audit');
  const readAuditDirs = Array.from(new Set([auditDir, hookAudit]));
  return {
    statePath: join(root, 'approvals', 'guard-readiness.json'),
    auditDir,
    readAuditDirs,
  };
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
 * Append one approval-reach evidence row. Best-effort: evidence that cannot be
 * written is evidence that is missing, which can only keep an install from
 * becoming ready — never make it ready.
 */
export function recordApprovalReach(
  input: ReachRowInput,
  opts: { home?: string; now?: number; auditDir?: string } = {},
): boolean {
  const now = new Date(opts.now ?? Date.now());
  const auditDir = opts.auditDir ?? readinessPaths({ home: opts.home }).auditDir;
  const row: Record<string, unknown> = {
    type: 'approval_reach',
    origin: input.origin ?? 'claude-code-hook',
    reachId: reachIdFor(input.hash),
    phase: input.phase,
    ts: now.toISOString(),
    auditEventId: randomBytes(16).toString('hex'),
  };
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
} {
  const files = dirs.flatMap((d) => listAuditFiles(d, sinceMs));
  // Newest first, so a budget cut drops the OLDEST evidence.
  files.sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));
  const seen = new Set<string>();
  const rows: ParsedRow[] = [];
  let bytesRead = 0;
  let truncated = false;
  for (const f of files) {
    let size = 0;
    try {
      size = statSync(f.path).size;
    } catch {
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
      continue;
    }
    bytesRead += size;
    for (const line of text.split('\n')) {
      if (!line || !LINE_PREFILTER.test(line)) continue;
      let row: Record<string, unknown>;
      try {
        row = JSON.parse(line) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (!row || typeof row !== 'object') continue;
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
  return { rows, bytesRead, truncated };
}

/** A real, verdict-bearing Claude Code hook call. */
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
 * Compute both bars from the audit evidence. Pure with respect to its inputs:
 * nothing is written, and no stored boolean is consulted.
 */
export function computeReadiness(opts: {
  channel: HumanChannel;
  paths?: ReadinessPaths;
  home?: string;
  now?: number;
}): ReadinessReport {
  const nowMs = opts.now ?? Date.now();
  const paths = opts.paths ?? readinessPaths({ home: opts.home });
  const since = nowMs - Math.max(FP_WINDOW_MS, APPROVAL_WINDOW_MS);
  const { rows, bytesRead, truncated } = readEvidence(paths.readAuditDirs, since, nowMs);

  // ── FP bar ──
  let stops = 0;
  let total = 0;
  let oldest = Infinity;
  let newest = -Infinity;
  const fpSince = nowMs - FP_WINDOW_MS;
  for (const { ts, row } of rows) {
    if (ts < fpSince || !isCountedCall(row)) continue;
    total += 1;
    oldest = Math.min(oldest, ts);
    newest = Math.max(newest, ts);
    const catastrophic = row.severity === 'critical';
    if (!catastrophic && STOP_OUTCOMES.has(String(row.outcome))) stops += 1;
  }
  const spanMs = total > 0 ? newest - oldest : 0;
  const fpRate = total > 0 ? stops / total : null;
  let fpMissing: string | null = null;
  if (total < FP_MIN_SAMPLE) {
    fpMissing = `only ${total} of the ${FP_MIN_SAMPLE} real tool calls needed have been observed`;
  } else if (spanMs < FP_MIN_SPAN_MS) {
    fpMissing = `observed calls span ${fmtDays(spanMs)}; at least ${fmtDays(FP_MIN_SPAN_MS)} are needed`;
  } else if (fpRate !== null && fpRate > FP_MAX_RATE) {
    fpMissing = `the guard would stop ${fmtPct(fpRate)} of calls (${stops}/${total}); the bar is ≤ ${fmtPct(FP_MAX_RATE)}`;
  }
  const fp: FpBar = { stops, total, rate: fpRate, spanMs, pass: fpMissing === null, missing: fpMissing };

  // ── Approval-reach bar ──
  const apSince = nowMs - APPROVAL_WINDOW_MS;
  const requests = new Map<string, { ts: number; synthetic: boolean }>();
  const answers = new Map<string, Array<{ ts: number; answer: string }>>();
  let resolved = 0;
  let reached = 0;
  let pending = 0;
  let lastRoundTrip = -Infinity;
  for (const { ts, row } of rows) {
    if (row.type !== 'approval_reach' || ts < apSince) continue;
    const id = typeof row.reachId === 'string' ? row.reachId : '';
    if (!id) continue;
    if (row.phase === 'request') {
      const prev = requests.get(id);
      if (!prev || ts > prev.ts) requests.set(id, { ts, synthetic: row.synthetic === true });
    } else if (row.phase === 'answer') {
      const list = answers.get(id) ?? [];
      list.push({ ts, answer: String(row.answer ?? '') });
      answers.set(id, list);
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
  const apRate = resolved > 0 ? reached / resolved : null;
  const roundTripFresh = lastRoundTrip > -Infinity && nowMs - lastRoundTrip <= ROUND_TRIP_MAX_AGE_MS;
  let apMissing: string | null = null;
  if (!opts.channel.configured) {
    apMissing = 'no human approval channel is configured (run `shieldcortex config --action-guard-notify-openclaw` or `--action-guard-notify-webhook <url>`)';
  } else if (resolved < APPROVAL_MIN_SAMPLE) {
    apMissing = `only ${resolved} of the ${APPROVAL_MIN_SAMPLE} answered-or-expired approval requests needed (run \`shieldcortex guard test-approval\` to add round-trips)`;
  } else if (apRate !== null && apRate < APPROVAL_MIN_RATE) {
    apMissing = `a human answered ${fmtPct(apRate)} of approval requests (${reached}/${resolved}); the bar is ≥ ${fmtPct(APPROVAL_MIN_RATE)}`;
  } else if (!roundTripFresh) {
    apMissing = 'no approval request has reached a human in the last 7 days (run `shieldcortex guard test-approval`)';
  }
  const approval: ApprovalBar = {
    channel: opts.channel,
    reached,
    resolved,
    pending,
    rate: apRate,
    lastRoundTripAt: lastRoundTrip > -Infinity ? new Date(lastRoundTrip).toISOString() : null,
    pass: apMissing === null,
    missing: apMissing,
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

  const missing = [fp.missing, approval.missing].filter((m): m is string => m !== null);
  if (truncated) {
    missing.push(`the audit exceeded the ${MAX_READINESS_BYTES / (1024 * 1024)} MB read budget; only the newest evidence was counted`);
  }
  return {
    computedAt: new Date(nowMs).toISOString(),
    fp,
    approval,
    ready: fp.pass && approval.pass,
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
 *  - not ready + was enforcing → stay enforcing until the bars have been
 *    failing for {@link DEMOTE_AFTER_FAILING_MS}, then demote.
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
 * The per-call entry point used by the hook.
 *
 * Fresh state (younger than {@link READINESS_CACHE_TTL_MS}, not future-dated)
 * is reused as-is — the cheap path, and the documented residual: a state file
 * forged outside the tool surface holds its mode for at most one TTL before
 * evidence overrules it. Otherwise readiness is recomputed from evidence, the
 * hysteresis rule applied, and any transition audited. A missing or stale
 * state is never read as "shadow": the previous mode then comes from the
 * audit's own transition rows, so deleting the state file cannot quietly end
 * enforcement.
 */
export function resolveReadiness(opts: {
  channel: HumanChannel;
  home?: string;
  now?: number;
  paths?: ReadinessPaths;
  ttlMs?: number;
}): ResolvedReadiness {
  const now = opts.now ?? Date.now();
  const paths = opts.paths ?? readinessPaths({ home: opts.home });
  const ttl = opts.ttlMs ?? READINESS_CACHE_TTL_MS;
  const state = readReadinessState(paths.statePath);
  if (state) {
    const age = now - Date.parse(state.computedAt);
    if (age >= 0 && age < ttl) {
      return { mode: state.mode, cached: true, transition: null, report: null, state };
    }
  }

  const report = computeReadiness({ channel: opts.channel, paths, now });
  const auditMode = report.lastTransition?.to ?? null;
  const prevMode: ReadinessMode | null =
    state?.mode === 'enforcing' || auditMode === 'enforcing'
      ? 'enforcing'
      : state?.mode ?? auditMode;
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
          fp: { stops: report.fp.stops, total: report.fp.total, rate: report.fp.rate },
          approval: { reached: report.approval.reached, resolved: report.approval.resolved, rate: report.approval.rate },
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

