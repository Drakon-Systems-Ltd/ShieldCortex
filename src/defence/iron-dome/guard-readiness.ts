/**
 * ShieldCortex — "enforce when ready" readiness gate for the Action Guard (#509).
 *
 * Operator direction (28 Sep 2026): "Go and build the version that the
 * false-positive rate is measured low and approvals reliably reach a human."
 * Under the `enforce-when-ready` posture (`actionGuard.readinessGate: true` on
 * top of `enabled` + `enforce`) each gated adapter — the Claude Code hook and
 * (r7) the OpenClaw interceptor, see READINESS_ADAPTERS — runs the guard in
 * SHADOW mode — every verdict computed and audited, a would-stop recorded but
 * not applied — and enforces only while THREE readiness conditions hold for
 * THAT adapter. The Hermes plugin does not implement the gate.
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
 *    {@link INTERVENTION_WINDOW_MS} of real calls through the adapter:
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
 *    force. ALWAYS required — the operator's decision of 29 Sep 2026 (#509
 *    option A); there is no setting that drops it, and an old
 *    `readinessRequireEffectivenessEvidence` key in config is ignored. No such
 *    evidence ships: {@link REVIEWED_EFFECTIVENESS_EVIDENCE} is empty, so an
 *    install stays in shadow and says so.
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
 * The audit log, the state file and the transition record are same-UID
 * files. Inflating readiness only tightens. Deflating it — forged would-stop
 * rows, deleted approval answers, a corrupted line, a removed or forged state
 * file, a lost transition record — loosens, so it is never silent:
 *  - readiness is RECOMPUTED from evidence at least every
 *    {@link READINESS_CACHE_TTL_MS}, and every complete audit line is parsed
 *    and validated first: one malformed record invalidates the measurement;
 *  - a recompute that turns an enforcing install into a shadow one is a
 *    DEMOTION: audited, announced to the operator, `shieldcortex doctor` FAIL;
 *  - the durable transition record (see TRANSITION RECORD) is the authority
 *    for "was this install enforcing". The state file is a cache that may only
 *    TIGHTEN: a cached mode that disagrees with the record is a tamper signal
 *    and is recomputed, and a missing or unreadable record is UNKNOWN, treated
 *    as potentially demoted — never as never-ready;
 *  - promotion needs a channel that can push notices, and every promotion
 *    and demotion is announced on it when it happens, with the outcome
 *    journalled (TRANSITION NOTICES) — the detection control for a forged
 *    journal, which the floor does not make impossible.
 * The state file, the record (and their lock and temp files) live in the
 * approval store's own directory, `~/.shieldcortex/approvals` — deliberately
 * NOT under a `SHIELDCORTEX_CONFIG_DIR` override — so the guard's existing
 * `touch-approval-store` path rule (core, hook fallback, OpenClaw fallback)
 * gates an agent writing them wherever the config lives.
 */

import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { normaliseNotifyConfig } from './notify-config.js';

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

// Addendum 1 (B), decided 29 Sep 2026 (option A): automatic promotion ALWAYS
// needs reviewed effectiveness evidence. There is deliberately no constant,
// config key or option that turns the condition off.

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
  /** A channel that can PUSH a plain notice (a demotion) to the operator, not
   *  only carry an approval card: today, the webhook. The OpenClaw card
   *  channel is approval-only (openclaw-approval-channel.ts refuses anything
   *  with no live decision behind it), so an OpenClaw-only install has none. */
  pushesNotices: boolean;
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

export interface NoticeChannelCondition {
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
  /** A configured channel can push a demotion notice (precondition). */
  noticeChannel: NoticeChannelCondition;
  /** Both operability proxies pass on sound, pinned evidence, and a demotion
   *  notice could reach the operator. */
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
  /** The durable, append-only transition record. Defaults to
   *  `guard-readiness-transitions.jsonl` beside the state file. */
  transitionsPath?: string;
}

// ==================== PATHS ====================

/**
 * `SHIELDCORTEX_CONFIG_DIR` when set (the same override every config reader
 * honours), else `~/.shieldcortex`. An explicit `home` pins the tree for tests.
 */
export function readinessRoot(home?: string): string {
  if (home !== undefined) return join(home, '.shieldcortex');
  const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
  return override || join(userHome(), '.shieldcortex');
}

/**
 * `$HOME` when set, else `os.homedir()`. On POSIX these are the same value
 * (libuv reads `$HOME` first); reading the variable directly also keeps a
 * test runner that sandboxes `process.env` (Jest) from resolving the real
 * home and writing into the operator's live store.
 */
function userHome(): string {
  return process.env.HOME?.trim() || homedir();
}

/**
 * Paths for one install. Evidence is read from the union of the configured
 * root's `audit/` and `~/.shieldcortex/audit` — the Claude Code hook writes
 * its intercept rows under the home directory — so a config-dir override can
 * never hide the hook's own rows from the gate. The state file sits beside
 * `approvals.json` (action-approvals.ts `approvalsDir`), which ignores the
 * override on purpose: that is the directory the path rules protect.
 */
export function readinessPaths(opts: { home?: string; adapter?: ReadinessAdapter } = {}): ReadinessPaths {
  const root = readinessRoot(opts.home);
  const auditDir = join(root, 'audit');
  const homeRoot = join(opts.home ?? userHome(), '.shieldcortex');
  const hookAudit = join(homeRoot, 'audit');
  // r7: the OpenClaw interceptor writes its rows to SHIELDCORTEX_AUDIT_DIR
  // when the gateway sets it (interceptor.ts auditDir), so that directory is
  // read too — never when a test pins `home`.
  const interceptorAudit = opts.home === undefined ? process.env.SHIELDCORTEX_AUDIT_DIR?.trim() : undefined;
  const readAuditDirs = Array.from(new Set([auditDir, hookAudit, ...(interceptorAudit ? [interceptorAudit] : [])]));
  const suffix = adapterFileSuffix(opts.adapter ?? READINESS_ADAPTER);
  return {
    statePath: join(homeRoot, 'approvals', `guard-readiness${suffix}.json`),
    auditDir,
    readAuditDirs,
    transitionsPath: join(homeRoot, 'approvals', `guard-readiness-transitions${suffix}.jsonl`),
  };
}

/** The Claude Code hook keeps the original file names (an install that
 *  already has a journal keeps it); every other adapter has its own. */
function adapterFileSuffix(adapter: ReadinessAdapter): string {
  return adapter === 'claude-code-hook' ? '' : `.${adapter}`;
}

/** The durable transition record's file name (inside the approval store). */
export const TRANSITIONS_FILE = 'guard-readiness-transitions.jsonl';

export function transitionsPathFor(paths: ReadinessPaths): string {
  return paths.transitionsPath ?? join(dirname(paths.statePath), TRANSITIONS_FILE);
}

// ==================== PIN ====================

/**
 * The enforcement adapters that implement the gate (#509 r7). Each is its own
 * readiness subject: its evidence rows (by audit `origin` AND pin), its state
 * file, its transition journal and its promotion are separate, so the Claude
 * Code hook's evidence never promotes the OpenClaw interceptor and the
 * reverse. The adapter id is the `origin` each writes on its audit rows.
 * Hermes does not implement the gate; it ignores it and enforces.
 */
export const READINESS_ADAPTERS = ['claude-code-hook', 'openclaw-interceptor'] as const;
export type ReadinessAdapter = (typeof READINESS_ADAPTERS)[number];

/** The default adapter (the Claude Code hook) — every caller that names none. */
export const READINESS_ADAPTER: ReadinessAdapter = 'claude-code-hook';

export function isReadinessAdapter(v: unknown): v is ReadinessAdapter {
  return typeof v === 'string' && (READINESS_ADAPTERS as readonly string[]).includes(v);
}

const cachedPins = new Map<ReadinessAdapter, ReadinessPin | null>();

function readSibling(rel: string): string | null {
  try {
    return readFileSync(new URL(rel, import.meta.url), 'utf8');
  } catch {
    return null;
  }
}

/**
 * The adapter + policy version in force: the given adapter (default the hook)
 * at this package's version, and a digest of the guard's rule module as
 * built. Null when either cannot be read — and a null pin is never ready.
 * Memoised per process and adapter.
 */
export function currentReadinessPin(adapter: ReadinessAdapter = READINESS_ADAPTER): ReadinessPin | null {
  if (!isReadinessAdapter(adapter)) return null;
  if (cachedPins.has(adapter)) return cachedPins.get(adapter)!;
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
  const pin = version && rules
    ? {
      adapter: `${adapter}@${version}`,
      policy: `tool-action-guard:${createHash('sha256').update(rules).digest('hex').slice(0, 16)}`,
    }
    : null;
  cachedPins.set(adapter, pin);
  return pin;
}

function samePin(a: unknown, b: ReadinessPin | null): boolean {
  if (!b || !a || typeof a !== 'object') return false;
  const p = a as Record<string, unknown>;
  return p.adapter === b.adapter && p.policy === b.policy;
}

/**
 * #509 r7: whether an evidence row counts for THIS adapter at the version in
 * force. The pin names the adapter (`openclaw-interceptor@x.y.z`), so a row
 * pinned by another adapter never matches; a verdict row must also carry this
 * adapter's audit origin. The hook promoting must not promote OpenClaw, nor
 * the reverse. The one place that decides it.
 */
function isAdapterEvidence(row: Record<string, unknown>, pin: ReadinessPin | null, adapter: ReadinessAdapter): boolean {
  if (row.type === 'intercept' && row.origin !== adapter) return false;
  return samePin(row.readinessPin, pin);
}

// ==================== EFFECTIVENESS ====================

/**
 * Reviewed effectiveness evidence, pinned per adapter + policy version. EMPTY:
 * no reviewed exam exists for any version yet. Add an entry only with the
 * reviewer's sign-off and a link to the exam; never add one to make a test or
 * an install pass.
 */
export const REVIEWED_EFFECTIVENESS_EVIDENCE: readonly EffectivenessEvidence[] = Object.freeze([]);

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
 * `actionGuard.notify` block, decided by the transport's OWN validator
 * (`normaliseNotifyConfig`, the function the hook's `loadNotify` builds its
 * channels from). #509 R4-3: a private copy of the rules drifted — a
 * 2,074-character URL the transport drops passed here, so promotion could rest
 * on a notice channel that did not exist. `openclaw: true` counts as an
 * approval channel — its failures show up as unreached requests in the
 * evidence, which is where they belong — but only a webhook the transport
 * will actually build pushes demotion notices.
 */
export function describeHumanChannel(rawNotify: unknown): HumanChannel {
  const none: HumanChannel = { configured: false, kind: null, pushesNotices: false };
  let n: ReturnType<typeof normaliseNotifyConfig>;
  try {
    n = normaliseNotifyConfig(rawNotify);
  } catch {
    return none;
  }
  if (n.enabled !== true) return none;
  const webhook = typeof n.webhookUrl === 'string' && n.webhookUrl.length > 0;
  if (n.openclaw === true) return { configured: true, kind: 'openclaw-card', pushesNotices: webhook };
  if (webhook) return { configured: true, kind: 'webhook', pushesNotices: true };
  return none;
}

/** Why an install without a notice-pushing channel cannot be promoted. */
export const NO_NOTICE_CHANNEL_MESSAGE =
  'no channel can push a demotion notice: the OpenClaw card channel carries approvals only, so promotion also needs ' +
  '`shieldcortex config --action-guard-notify-webhook <url>` — without it the install stays in shadow, because a later ' +
  'demotion could not reach you';

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

/** A fresh correlation id for ONE delivered approval attempt. */
export function newReachAttemptId(): string {
  return randomBytes(12).toString('hex');
}

export interface ReachRowInput {
  /** The full approval hash (or a synthetic one for test-approval). */
  hash: string;
  /**
   * The correlation id of the ONE delivery attempt this row is about. A
   * request row carries it (one is minted when absent); an answer counts only
   * when it names the attempt it answers. The hash alone is not enough: the
   * same command asked ten times is ten attempts, and one answer must not
   * erase the nine that expired.
   */
  attemptId?: string;
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
  opts: { home?: string; now?: number; auditDir?: string; pin?: ReadinessPin | null; adapter?: ReadinessAdapter } = {},
): boolean {
  const now = new Date(opts.now ?? Date.now());
  const adapter = opts.adapter ?? READINESS_ADAPTER;
  const auditDir = opts.auditDir ?? readinessPaths({ home: opts.home, adapter }).auditDir;
  const pin = opts.pin === undefined ? currentReadinessPin(adapter) : opts.pin;
  const row: Record<string, unknown> = {
    type: 'approval_reach',
    origin: input.origin ?? adapter,
    reachId: reachIdFor(input.hash),
    phase: input.phase,
    ts: now.toISOString(),
    auditEventId: randomBytes(16).toString('hex'),
  };
  const attemptId = input.attemptId ?? (input.phase === 'answer' ? undefined : newReachAttemptId());
  if (attemptId) row.attemptId = String(attemptId).slice(0, 64);
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

/** #509 r7: the OpenClaw interceptor's own words for a stop. A card hold
 *  writes no row until the operator answers (#372), so every card outcome —
 *  including an approval — is the row for a call the guard held; a denial on
 *  the failure policy (no approver) or by the operator is a stop too. */
const OPENCLAW_STOP_OUTCOMES = new Set([
  ...STOP_OUTCOMES,
  'failure_denied',
  'denied',
  'approved_once',
  'card_denied',
  'card_timeout',
  'card_cancelled',
]);

function stopOutcomes(adapter: ReadinessAdapter): ReadonlySet<string> {
  return adapter === 'openclaw-interceptor' ? OPENCLAW_STOP_OUTCOMES : STOP_OUTCOMES;
}

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

const REACH_PHASES = new Set(['request', 'answer', 'resolved']);

/**
 * Whether a parsed record is well-formed. EVERY complete line is parsed and
 * checked before any origin/type filter — a prefilter on raw text would let a
 * corrupted would-stop row drop out of the count unnoticed, which improves
 * the measured rate instead of invalidating it. Any JSON object is a valid
 * audit record; the evidence types this module counts must also have the
 * fields it reads, with the right types.
 */
function isWellFormedRecord(row: unknown): row is Record<string, unknown> {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return false;
  const r = row as Record<string, unknown>;
  const evidence =
    (r.type === 'intercept' && isReadinessAdapter(r.origin)) ||
    r.type === 'approval_reach' ||
    r.type === 'readiness_transition';
  if (!evidence) return true;
  if (typeof r.ts !== 'string' || !Number.isFinite(Date.parse(r.ts))) return false;
  if (r.type === 'intercept') return typeof r.outcome === 'string' && typeof r.action === 'string';
  if (r.type === 'approval_reach') {
    return typeof r.reachId === 'string' && typeof r.phase === 'string' && REACH_PHASES.has(r.phase);
  }
  return r.to === 'enforcing' || r.to === 'shadow';
}

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
    // Only the LAST segment, and only when it has no trailing newline, is an
    // append still in flight rather than a corrupt row: leave it for the next
    // recompute. (With a trailing newline the last segment is empty.) Every
    // other line is complete and must parse.
    lines.pop();
    for (const line of lines) {
      if (!line) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        unparseableLines += 1;
        continue;
      }
      if (!isWellFormedRecord(parsed)) {
        unparseableLines += 1;
        continue;
      }
      const row = parsed;
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

/** A real, verdict-bearing call through a gated adapter (any adapter, any
 *  version — {@link isAdapterEvidence} then decides whose it is). */
function isCountedCall(row: Record<string, unknown>): boolean {
  if (row.type !== 'intercept') return false;
  // Exact origin: rows from other planes, canaries and proofs never count.
  if (!isReadinessAdapter(row.origin)) return false;
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
  /** In-process test seam, standing for a build that ships reviewed
   *  evidence; defaults to {@link REVIEWED_EFFECTIVENESS_EVIDENCE}. Never fed
   *  from config or any file. */
  effectivenessRegistry?: readonly EffectivenessEvidence[];
  /** #509 r7: whose readiness this is (default the Claude Code hook). */
  adapter?: ReadinessAdapter;
}): ReadinessReport {
  const nowMs = opts.now ?? Date.now();
  const adapter = opts.adapter ?? READINESS_ADAPTER;
  const paths = opts.paths ?? readinessPaths({ home: opts.home, adapter });
  const pin = opts.pin === undefined ? currentReadinessPin(adapter) : opts.pin;
  const since = nowMs - Math.max(INTERVENTION_WINDOW_MS, REACHABILITY_WINDOW_MS);
  const { rows, bytesRead, truncated, unreadableFiles, unparseableLines } = readEvidence(paths.readAuditDirs, since, nowMs);
  const stopSet = stopOutcomes(adapter);

  // ── Operational intervention rate ──
  let stops = 0;
  let total = 0;
  let ivOther = 0;
  let oldest = Infinity;
  let newest = -Infinity;
  const ivSince = nowMs - INTERVENTION_WINDOW_MS;
  for (const { ts, row } of rows) {
    if (ts < ivSince || !isCountedCall(row)) continue;
    if (!isAdapterEvidence(row, pin, adapter)) {
      ivOther += 1;
      continue;
    }
    total += 1;
    oldest = Math.min(oldest, ts);
    newest = Math.max(newest, ts);
    const catastrophic = row.severity === 'critical';
    if (!catastrophic && stopSet.has(String(row.outcome))) stops += 1;
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
  // One entry per delivered ATTEMPT, keyed by its correlation id — never by
  // the command hash: the same command asked ten times is ten attempts, and a
  // later answer must not erase the earlier ones that expired. An answer
  // counts only for the attempt it names; one with no attempt id binds to
  // nothing (it can only leave its attempt looking unanswered — tighter).
  const requests = new Map<string, { ts: number }>();
  const answers = new Map<string, Array<{ ts: number; answer: string }>>();
  let resolved = 0;
  let reached = 0;
  let pending = 0;
  let rcOther = 0;
  let lastRoundTrip = -Infinity;
  for (const { ts, row } of rows) {
    if (row.type !== 'approval_reach' || ts < rcSince) continue;
    const attempt = typeof row.attemptId === 'string' && row.attemptId ? row.attemptId : null;
    if (row.phase === 'answer') {
      // Answers join to a pinned request by attempt id; the request carries the pin.
      if (!attempt) continue;
      const list = answers.get(attempt) ?? [];
      list.push({ ts, answer: String(row.answer ?? '') });
      answers.set(attempt, list);
      continue;
    }
    if (!isAdapterEvidence(row, pin, adapter)) {
      rcOther += 1;
      continue;
    }
    if (row.phase === 'request') {
      // A request row without an attempt id is still an attempt: it stays in
      // the denominator, and no answer can bind to it.
      const key = attempt ?? `unbound:${String(row.auditEventId ?? '')}:${ts}:${requests.size}`;
      if (!requests.has(key)) requests.set(key, { ts });
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

  // ── A demotion must be able to reach the operator ──
  // Promotion is refused where a later demotion could not be pushed: a
  // loosening nobody hears about is the one outcome this posture forbids.
  const noticeChannel: NoticeChannelCondition = opts.channel.configured && !opts.channel.pushesNotices
    ? { pass: false, missing: NO_NOTICE_CHANNEL_MESSAGE }
    : { pass: opts.channel.configured, missing: null };

  // ── Evidence integrity: unreadable or unparseable is never a pass ──
  const integrityProblems: string[] = [];
  if (!pin) integrityProblems.push('the adapter/policy version in force could not be determined, so no evidence can be pinned to it');
  if (unreadableFiles > 0) integrityProblems.push(`${unreadableFiles} audit evidence file(s) could not be read`);
  if (unparseableLines > 0) {
    integrityProblems.push(`${unparseableLines} malformed audit record(s) inside the evidence window (a line that is not a well-formed record)`);
  }
  const integrity: EvidenceIntegrity = {
    unreadableFiles,
    unparseableLines,
    pass: integrityProblems.length === 0,
    missing: integrityProblems.length > 0 ? `evidence is not sound: ${integrityProblems.join('; ')}` : null,
  };

  // ── Effectiveness evidence ──
  // Always required (#509 option A). A caller passing a legacy
  // `requireEffectivenessEvidence: false` is not read.
  const evidence = findEffectivenessEvidence(pin, nowMs, opts.effectivenessRegistry ?? REVIEWED_EFFECTIVENESS_EVIDENCE);
  const effectiveness: EffectivenessCondition = {
    evidence,
    pass: evidence !== null,
    missing: evidence
      ? null
      : 'reviewed effectiveness evidence (the effect-based red-team exam) for this adapter + policy version — none has been published',
  };

  // ── Last transition, the fallback memory of the mode ──
  let lastTransition: ReadinessReport['lastTransition'] = null;
  for (const { ts, row } of rows) {
    if (row.type !== 'readiness_transition') continue;
    // r7: another adapter's transition is not this adapter's mode (a row
    // with no origin predates r7 and was written by the hook).
    if ((row.origin ?? READINESS_ADAPTER) !== adapter) continue;
    const to = row.to === 'enforcing' ? 'enforcing' : row.to === 'shadow' ? 'shadow' : null;
    if (!to) continue;
    if (!lastTransition || ts >= Date.parse(lastTransition.ts)) {
      lastTransition = { to, ts: new Date(ts).toISOString() };
    }
  }

  const proxiesMet = intervention.pass && reachability.pass && integrity.pass && noticeChannel.pass;
  const ready = proxiesMet && effectiveness.pass;
  let missing: string[];
  if (proxiesMet && !effectiveness.pass) {
    missing = [AWAITING_EFFECTIVENESS_MESSAGE];
  } else {
    missing = [intervention.missing, reachability.missing, noticeChannel.missing, integrity.missing, effectiveness.missing]
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
    noticeChannel,
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

// ==================== TRANSITION RECORD ====================

/**
 * The durable, append-only record of this install's mode transitions:
 * `guard-readiness-transitions.jsonl` beside the state file, inside the
 * approval store, so the same `touch-approval-store` path rule gates an agent
 * writing it. Unlike the audit it is never rotated, never windowed and never
 * cut by a read budget, so a promotion made months ago is still remembered.
 * It is the AUTHORITY for "was this install enforcing": the state file is only
 * a cache that may TIGHTEN (a cached `enforcing` is applied as-is) and is
 * never trusted to loosen (a cached `shadow` that disagrees with the record is
 * recomputed, and reported as tampering).
 *
 * A missing, unreadable or malformed record while the posture is on is
 * UNKNOWN, never "never ready": unknown is treated as potentially demoted —
 * announced, audited, and a doctor FAIL.
 */
export type TransitionEvent = 'init' | 'promote' | 'demote' | 'recover' | 'tamper' | 'checkpoint' | 'notice';

export interface TransitionEntry {
  ts: string;
  event: TransitionEvent;
  /** The mode after this entry; absent on a tamper report. */
  to?: ReadinessMode;
  pin?: ReadinessPin | null;
  reason?: string;
  /** On a `checkpoint`: how many entries compaction dropped. */
  compacted?: number;
  /** On a `notice`: which transition was announced. */
  of?: 'promote' | 'demote';
  /** On a `notice`: the `ts` of the transition entry it announces. */
  transitionTs?: string;
  /** On a `notice`: whether a channel accepted it. */
  delivered?: boolean;
  /** On a `notice`: the channel that accepted it (or was tried). */
  channel?: string;
}

export interface TransitionRecord {
  status: 'ok' | 'missing' | 'unreadable';
  entries: TransitionEntry[];
  /** Bytes read (0 when missing/unreadable) — the compaction trigger. */
  bytes?: number;
  /** The newest entry that sets a mode. */
  last: TransitionEntry | null;
  /** The newest tamper report. */
  lastTamper: TransitionEntry | null;
}

const TRANSITION_EVENTS = new Set<string>(['init', 'promote', 'demote', 'recover', 'tamper', 'checkpoint', 'notice']);

// ── #509 R4-4: a bounded journal ──
// The record is read on every hook call under the posture, so it must stay
// small. It is compacted (atomically rewritten) once it passes either bound:
// a `checkpoint` entry saying how much was dropped, then — in their original
// order — the newest promote, demote, init, recover and tamper entries, plus
// the most recent JOURNAL_KEEP_RECENT. The newest mode-setting entry is
// always among them, so compaction never changes what the record says.
/** Entries at which the journal is compacted. */
export const JOURNAL_MAX_ENTRIES = 256;
/** Bytes at which the journal is compacted (a compacted one is far smaller). */
export const JOURNAL_MAX_BYTES = 128 * 1024;
/** #509 r6 (N4): the most the journal read takes into memory; anything
 *  larger is unreadable (unknown — the loud path). Far above the compaction
 *  bound (the hook compacts past JOURNAL_MAX_BYTES), and above the R4-4
 *  100,000-entry flood (~16 MiB), which is still compacted, not quarantined. */
export const JOURNAL_READ_MAX_BYTES = 32 * 1024 * 1024;
/** Most recent entries kept verbatim by compaction. */
export const JOURNAL_KEEP_RECENT = 32;
/** A tamper report identical to the newest one within this window is not
 *  journalled again (the audit row and stderr still happen): a forged cache
 *  refreshed on every call must not grow the journal on every call. */
export const TAMPER_JOURNAL_DEDUP_MS = 60 * 60 * 1000;
/** #509 r5 (finding 8): every retained field is bounded, so the byte bound
 *  holds for what compaction keeps, not only for what the hook writes. */
export const JOURNAL_REASON_MAX = 400;
const JOURNAL_SHORT_FIELD_MAX = 120;
/** An ISO timestamp is 24 characters; anything far longer is not one. */
const JOURNAL_TS_MAX = 40;

function isTransitionEntry(e: unknown): e is TransitionEntry {
  if (!e || typeof e !== 'object' || Array.isArray(e)) return false;
  const r = e as Record<string, unknown>;
  if (typeof r.ts !== 'string' || r.ts.length > JOURNAL_TS_MAX || !Number.isFinite(Date.parse(r.ts))) return false;
  if (typeof r.event !== 'string' || !TRANSITION_EVENTS.has(r.event)) return false;
  if (r.event === 'tamper') return true;
  if (r.event === 'checkpoint') return r.compacted === undefined || (typeof r.compacted === 'number' && Number.isFinite(r.compacted));
  if (r.event === 'notice') {
    return (r.of === 'promote' || r.of === 'demote') && typeof r.delivered === 'boolean'
      && typeof r.transitionTs === 'string' && r.transitionTs.length <= JOURNAL_TS_MAX;
  }
  return r.to === 'enforcing' || r.to === 'shadow';
}

function clipText(v: unknown, max: number): string | undefined {
  return typeof v === 'string' ? v.slice(0, max) : undefined;
}

/**
 * The bounded form of a valid entry: known fields only, every string clipped.
 * Applied on read, so compaction — which re-serialises what was read — can
 * never carry an oversized field (a 2,000,000-character `reason`, or an
 * unknown key) forward, and the journal's byte bound holds after compaction.
 */
function boundedEntry(e: TransitionEntry): TransitionEntry {
  const out: TransitionEntry = { ts: e.ts, event: e.event };
  if (e.to === 'enforcing' || e.to === 'shadow') out.to = e.to;
  if (e.pin && typeof e.pin === 'object') {
    const adapter = clipText((e.pin as unknown as Record<string, unknown>).adapter, JOURNAL_SHORT_FIELD_MAX);
    const policy = clipText((e.pin as unknown as Record<string, unknown>).policy, JOURNAL_SHORT_FIELD_MAX);
    if (adapter !== undefined && policy !== undefined) out.pin = { adapter, policy };
  }
  const reason = clipText(e.reason, JOURNAL_REASON_MAX);
  if (reason !== undefined) out.reason = reason;
  if (typeof e.compacted === 'number' && Number.isFinite(e.compacted)) out.compacted = e.compacted;
  if (e.event === 'notice') {
    out.of = e.of;
    out.transitionTs = e.transitionTs;
    out.delivered = e.delivered;
    const channel = clipText(e.channel, 40);
    if (channel !== undefined) out.channel = channel;
  }
  return out;
}

/** Read the record. Any malformed complete line makes the whole record
 *  unreadable; a final line with no newline is an append in flight. */
export function readTransitionRecord(path: string): TransitionRecord {
  const fail = (status: 'missing' | 'unreadable'): TransitionRecord => ({ status, entries: [], last: null, lastTamper: null });
  let text: string;
  let fd: number | undefined;
  try {
    // #509 r6 (N4): never more than the cap into memory. A journal over it
    // is unreadable — unknown, the loud path — not something to parse.
    fd = openSync(path, 'r');
    const size = fstatSync(fd).size;
    if (size > JOURNAL_READ_MAX_BYTES) return fail('unreadable');
    const buf = Buffer.alloc(Math.min(size, JOURNAL_READ_MAX_BYTES) + 1);
    let got = 0;
    for (let n = 1; n > 0 && got < buf.length; got += n) n = readSync(fd, buf, got, buf.length - got, got);
    if (got > JOURNAL_READ_MAX_BYTES) return fail('unreadable');
    text = buf.toString('utf8', 0, got);
  } catch (err) {
    return fail((err as NodeJS.ErrnoException)?.code === 'ENOENT' ? 'missing' : 'unreadable');
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
  const lines = text.split('\n');
  lines.pop();
  const entries: TransitionEntry[] = [];
  for (const line of lines) {
    if (!line) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return fail('unreadable');
    }
    if (!isTransitionEntry(parsed)) return fail('unreadable');
    entries.push(boundedEntry(parsed));
  }
  let last: TransitionEntry | null = null;
  let lastTamper: TransitionEntry | null = null;
  for (const e of entries) {
    if (e.event === 'tamper') lastTamper = e;
    else if (e.event !== 'checkpoint' && e.event !== 'notice') last = e;
  }
  return { status: 'ok', entries, last, lastTamper, bytes: Buffer.byteLength(text) };
}

/** Whether a readable record has outgrown its bounds. */
export function needsCompaction(record: TransitionRecord): boolean {
  return record.status === 'ok'
    && (record.entries.length > JOURNAL_MAX_ENTRIES || (record.bytes ?? 0) > JOURNAL_MAX_BYTES);
}

/**
 * Compact the journal in place (see JOURNAL_MAX_ENTRIES). Atomic: the new
 * record is written to a fresh private file and renamed over the old one, so
 * a crash leaves either the old record or the new one, never half of each.
 * A record that is not readable is left alone (the caller quarantines it).
 * Returns whether a compaction was written.
 *
 * #509 r5 (finding 7): the record compacted is ALWAYS the one read here, and
 * the caller must hold the writer lock (`<state>.lock`) — never a snapshot
 * taken before the lock. Compacting a pre-lock snapshot rewrote the journal
 * without a promotion another process had appended in between.
 */
export function compactTransitionRecord(path: string, now: number): boolean {
  const record = readTransitionRecord(path);
  if (record.status !== 'ok' || !needsCompaction(record)) return false;
  const entries = record.entries;
  const keep = new Set<number>();
  for (let i = Math.max(0, entries.length - JOURNAL_KEEP_RECENT); i < entries.length; i += 1) keep.add(i);
  const newestOf = new Map<string, number>();
  entries.forEach((e, i) => newestOf.set(e.event === 'notice' ? `notice:${e.of}` : e.event, i));
  for (const ev of ['promote', 'demote', 'init', 'recover', 'tamper', 'notice:promote', 'notice:demote']) {
    const i = newestOf.get(ev);
    if (i !== undefined) keep.add(i);
  }
  const kept = [...keep].sort((a, b) => a - b).map((i) => entries[i]).filter((e) => e.event !== 'checkpoint');
  const previouslyDropped = entries.reduce((n, e) => n + (e.event === 'checkpoint' && typeof e.compacted === 'number' ? e.compacted : 0), 0);
  const checkpoint: TransitionEntry = {
    ts: new Date(now).toISOString(),
    event: 'checkpoint',
    compacted: previouslyDropped + (entries.length - kept.length - entries.filter((e) => e.event === 'checkpoint').length),
    ...(record.last ? { reason: `last ${record.last.event} → ${record.last.to} at ${record.last.ts}`.slice(0, JOURNAL_REASON_MAX) } : {}),
  };
  const body = [checkpoint, ...kept].map((e) => JSON.stringify(e)).join('\n') + '\n';
  const tmp = `${path}.compact-${process.pid}-${randomBytes(4).toString('hex')}`;
  let fd: number | undefined;
  try {
    fd = openSync(tmp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    writeFileSync(fd, body);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, path);
    return true;
  } catch {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
    try { rmSync(tmp, { force: true }); } catch { /* ignore */ }
    return false;
  }
}

/** Whether this tamper report repeats the newest journalled one inside the
 *  dedup window (then it is not journalled again). */
function isRepeatTamper(record: TransitionRecord, reason: string, now: number): boolean {
  const t = record.lastTamper;
  if (!t || t.reason !== reason.slice(0, 400)) return false;
  const at = Date.parse(t.ts);
  return Number.isFinite(at) && now - at >= 0 && now - at < TAMPER_JOURNAL_DEDUP_MS;
}

/** The mode the record says this install is in; `unknown` when it cannot say. */
export function durableMode(record: TransitionRecord): ReadinessMode | 'unknown' {
  return record.status === 'ok' && record.last?.to ? record.last.to : 'unknown';
}

/**
 * #509 r6 (S1): a demotion nobody announced. The hook only ever leaves
 * enforcing through a `demote` entry (announced, audited, a doctor FAIL), and
 * re-choosing the posture records one too. So a newest mode entry that is an
 * `init` or `recover` to shadow, after a `promote` with no `demote` between
 * them, was written by something else — the same-UID forgery that keeps the
 * real promotion in place and quietly drops to shadow. Returns that entry.
 */
export function unexplainedDemotion(record: TransitionRecord): TransitionEntry | null {
  const last = record.status === 'ok' ? record.last : null;
  if (!last || (last.event !== 'init' && last.event !== 'recover') || last.to !== 'shadow') return null;
  for (let i = record.entries.lastIndexOf(last) - 1; i >= 0; i -= 1) {
    const e = record.entries[i]!;
    if (e.event === 'demote') return null;
    if (e.event === 'promote') return last;
  }
  return null;
}

/** The mode the record is TRUSTED for: an unexplained demotion is not
 *  trusted, so the promotion before it stands (fail toward enforcing). */
export function trustedDurableMode(record: TransitionRecord): ReadinessMode | 'unknown' {
  return unexplainedDemotion(record) ? 'enforcing' : durableMode(record);
}

function appendTransition(path: string, entry: TransitionEntry): boolean {
  let fd: number | undefined;
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    fd = openSync(path, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink > 1) return false;
    writeFileSync(fd, `${JSON.stringify(entry)}\n`);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
}

/** A corrupt record is kept for inspection, never appended to. */
function quarantineRecord(path: string, now: number): void {
  try {
    renameSync(path, `${path}.corrupt-${now}`);
  } catch {
    /* a record that cannot be moved stays unreadable, i.e. unknown */
  }
}

/**
 * Start the record for a newly chosen enforce-when-ready posture (config and
 * setup call this). Appends an `init` (shadow) entry only when the posture
 * was not already enforce-when-ready, or when no record exists — re-running
 * the command on an install that already has a record changes nothing, so it
 * cannot clear a recorded demotion.
 *
 * r7: with neither `adapter` nor `paths`, every gated adapter's record is
 * started (the posture is one config key; each adapter keeps its own
 * journal). The return value is the default adapter's (the hook's).
 */
export function initReadinessTransitions(opts: {
  postureChanged: boolean;
  reason: string;
  home?: string;
  paths?: ReadinessPaths;
  now?: number;
  adapter?: ReadinessAdapter;
}): boolean {
  if (!opts.paths && !opts.adapter) {
    let result = false;
    for (const adapter of READINESS_ADAPTERS) {
      const r = initReadinessTransitions({ ...opts, adapter });
      if (adapter === READINESS_ADAPTER) result = r;
    }
    return result;
  }
  const now = opts.now ?? Date.now();
  const paths = opts.paths ?? readinessPaths({ home: opts.home, adapter: opts.adapter });
  const path = transitionsPathFor(paths);
  return withWriterLock(paths, now, () => {
    const record = readTransitionRecord(path);
    if (record.status === 'ok' && record.last && !opts.postureChanged) return false;
    if (record.status === 'unreadable') quarantineRecord(path, now);
    const ts = new Date(now).toISOString();
    // #509 r6 (S1): re-choosing the posture on an install the record says is
    // enforcing restarts it in shadow — a real demotion, recorded as one, so
    // the `init` after it is not read as an unexplained (forged) demotion.
    if (durableMode(record) === 'enforcing') {
      appendTransition(path, { ts, event: 'demote', to: 'shadow', reason: `posture re-selected: ${opts.reason}`.slice(0, 200) });
    }
    return appendTransition(path, { ts, event: 'init', to: 'shadow', reason: opts.reason.slice(0, 200) });
  });
}

/** How often, and how far apart, a journal writer retries a busy lock. */
const WRITER_LOCK_RETRIES = 10;
const WRITER_LOCK_RETRY_MS = 20;

/**
 * #509 r6 (N3): run a journal append under the writer lock (`<state>.lock`)
 * that resolveReadiness and compaction hold, so an append can never land
 * between compaction's read and its rename and be lost. Retries briefly; a
 * lock it cannot get means no append (false) — for a notice, the louder
 * "no notice attempt recorded".
 */
function withWriterLock(paths: ReadinessPaths, now: number, fn: () => boolean): boolean {
  const lockPath = `${paths.statePath}.lock`;
  for (let i = 0; !tryLock(lockPath, now); i += 1) {
    if (i >= WRITER_LOCK_RETRIES) return false;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, WRITER_LOCK_RETRY_MS);
  }
  try {
    return fn();
  } finally {
    try { rmSync(lockPath, { force: true }); } catch { /* stale lock self-heals */ }
  }
}

// ==================== TRANSITION NOTICES ====================
//
// #509 r5 (finding 1). The floor stops the agent's ordinary tool calls from
// editing guard state; it does not stop a same-UID process that deliberately
// evades the command classifier (a symlink, an interpreter, a moved parent
// directory). So forging a promotion is made LOUD rather than impossible:
// every promotion is announced through the push notice channel at the moment
// it happens, and whether that notice was delivered is journalled next to
// it. Doctor reports the newest promotion from the journal; the operator
// holds it against the notices they actually received. A promotion nobody
// was told about — no notice entry, or one that failed — is shown as such.

/** Journal whether the notice for a transition made at `transitionAt` was
 *  delivered. Best-effort: a notice entry that cannot be written leaves the
 *  promotion reading as "no notice attempt recorded" — the louder answer. */
export function recordTransitionNotice(opts: {
  of: 'promote' | 'demote';
  transitionAt: string;
  delivered: boolean;
  channel?: string | null;
  reason?: string;
  home?: string;
  paths?: ReadinessPaths;
  now?: number;
  /** r7: whose transition this notice announces (default the hook). */
  adapter?: ReadinessAdapter;
}): boolean {
  const now = opts.now ?? Date.now();
  const paths = opts.paths ?? readinessPaths({ home: opts.home, adapter: opts.adapter });
  return withWriterLock(paths, now, () => appendTransition(transitionsPathFor(paths), {
    ts: new Date(now).toISOString(),
    event: 'notice',
    of: opts.of,
    transitionTs: String(opts.transitionAt).slice(0, JOURNAL_TS_MAX),
    delivered: opts.delivered === true,
    ...(opts.channel ? { channel: String(opts.channel).slice(0, 40) } : {}),
    ...(opts.reason ? { reason: String(opts.reason).slice(0, JOURNAL_REASON_MAX) } : {}),
  }));
}

export interface PromotionNotice {
  /** The newest `promote` entry's timestamp. */
  promotedAt: string;
  /** delivered = a channel accepted the notice; failed = every attempt
   *  failed; none = no notice attempt is recorded for this promotion. */
  notice: 'delivered' | 'failed' | 'none';
  channel?: string;
  reason?: string;
}

/** The newest promotion the journal records, and what became of its notice. */
export function lastPromotion(record: TransitionRecord): PromotionNotice | null {
  if (record.status !== 'ok') return null;
  let promote: TransitionEntry | null = null;
  for (const e of record.entries) if (e.event === 'promote') promote = e;
  if (!promote) return null;
  const notices = record.entries.filter((e) => e.event === 'notice' && e.of === 'promote' && e.transitionTs === promote!.ts);
  const delivered = notices.find((e) => e.delivered === true);
  if (delivered) return { promotedAt: promote.ts, notice: 'delivered', ...(delivered.channel ? { channel: delivered.channel } : {}) };
  const failed = notices[notices.length - 1];
  if (failed) return { promotedAt: promote.ts, notice: 'failed', ...(failed.reason ? { reason: failed.reason } : {}) };
  return { promotedAt: promote.ts, notice: 'none' };
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

/**
 * The last KNOWN mode. The durable record is the authority; the state file
 * and the audit's transition rows can only RAISE it to enforcing (enforcing
 * wins any disagreement). With no durable answer, the state/audit answer.
 */
export function previousMode(
  state: ReadinessState | null,
  report: ReadinessReport,
  durable: ReadinessMode | 'unknown' = 'unknown',
): ReadinessMode | null {
  const auditMode = report.lastTransition?.to ?? null;
  if (durable === 'enforcing' || state?.mode === 'enforcing' || auditMode === 'enforcing') return 'enforcing';
  if (durable === 'shadow') return 'shadow';
  return state?.mode ?? auditMode;
}

/** The unknown-record reason, shared by the announcement and doctor. */
export const UNKNOWN_RECORD_REASON =
  'the durable readiness transition record is missing or unreadable, so whether this install was enforcing is ' +
  'unknown — treated as potentially demoted';

export interface EvidenceDecision extends ModeDecision {
  /** The decision was forced by an unknown record. */
  unknown?: boolean;
}

/**
 * The hysteresis rule applied with the durable record. An UNKNOWN record is
 * treated as potentially demoted: unless the evidence promotes, or the state
 * or audit still say enforcing (then the normal grace applies), the answer is
 * shadow WITH a demotion — announced, never silent, never "never ready".
 */
export function decideFromEvidence(input: {
  state: ReadinessState | null;
  report: ReadinessReport;
  durable: ReadinessMode | 'unknown';
  now: number;
  /** The cache disagreed with the durable record on this call. */
  tampered?: boolean;
}): EvidenceDecision {
  const { state, report, durable, now } = input;
  const prevMode = previousMode(state, report, durable);
  // A tampered cache cannot be trusted for the grace clock either (its
  // failingSince is the forger's): if the evidence says not ready, the
  // demotion protocol runs now — announced, never silent.
  if (input.tampered && prevMode === 'enforcing' && !report.ready) {
    return { mode: 'shadow', transition: 'demote' };
  }
  const base = { failingSince: state?.failingSince, lastDemotedAt: state?.lastDemotedAt, ready: report.ready, now };
  if (durable === 'unknown') {
    if (prevMode === 'enforcing') return decideMode({ ...base, prevMode });
    const d = decideMode({ ...base, prevMode: null });
    if (d.transition === 'promote') return d;
    return { mode: 'shadow', transition: 'demote', unknown: true };
  }
  return decideMode({ ...base, prevMode });
}

/**
 * The mode the hook would apply right now, WITHOUT writing anything: a fresh
 * cache that agrees with the durable record (or a fresh `enforcing`, which
 * can only tighten), else the evidence through the same rule. Used by
 * `guard readiness` and `doctor`, which report and never flip. Without a
 * record (legacy callers) the fresh cache is taken as-is.
 */
export function previewMode(opts: {
  state: ReadinessState | null;
  report: ReadinessReport;
  now: number;
  ttlMs?: number;
  record?: TransitionRecord;
}): ReadinessMode {
  const { state, report, now } = opts;
  const durable = opts.record ? trustedDurableMode(opts.record) : null;
  // r6 (S1): an unexplained demotion is a tamper signal, as the hook treats it.
  let tampered = !!opts.record && unexplainedDemotion(opts.record) !== null;
  if (isFreshState(state, now, opts.ttlMs ?? READINESS_CACHE_TTL_MS, report.pin)) {
    if (durable === null || (!tampered && state!.mode === durable)) return state!.mode;
    tampered = durable !== 'unknown';
  }
  if (durable === null) {
    return decideMode({
      prevMode: previousMode(state, report),
      failingSince: state?.failingSince,
      lastDemotedAt: state?.lastDemotedAt,
      ready: report.ready,
      now,
    }).mode;
  }
  return decideFromEvidence({ state, report, durable, now, tampered }).mode;
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
  /** Set when a tamper signal was recorded on this call. */
  tamper?: string;
  /** The journal `ts` of the transition made on this call, for its notice. */
  transitionAt?: string;
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
 * state and of the transition record's promote/demote entries: `guard
 * readiness` and `doctor` use {@link previewMode} instead.
 *
 * The cache may only TIGHTEN. A fresh state (younger than
 * {@link READINESS_CACHE_TTL_MS}, not future-dated, computed under the pin in
 * force) is reused only when its mode matches the durable transition record.
 * A cached mode that disagrees — above all a cached `shadow` on an install
 * the record says was promoted — is a tamper signal: it is recorded (in the
 * record and the audit) and readiness is recomputed from evidence. If the
 * evidence then says shadow, that is a demotion with the full protocol
 * (announced by the hook, audited, doctor FAIL). Refreshing `computedAt`
 * therefore buys nothing. A missing or unreadable record is UNKNOWN and is
 * treated as potentially demoted (see {@link decideFromEvidence}).
 */
export function resolveReadiness(opts: {
  channel: HumanChannel;
  home?: string;
  now?: number;
  paths?: ReadinessPaths;
  ttlMs?: number;
  pin?: ReadinessPin | null;
  effectivenessRegistry?: readonly EffectivenessEvidence[];
  /** Test seam: runs between the pre-lock journal read and taking the
   *  writer lock — where another process's write can interleave. */
  beforeLock?: () => void;
  /** #509 r7: which adapter is asking (default the Claude Code hook). Its own
   *  evidence, state file, journal and lock — see READINESS_ADAPTERS. */
  adapter?: ReadinessAdapter;
}): ResolvedReadiness {
  const now = opts.now ?? Date.now();
  const adapter = opts.adapter ?? READINESS_ADAPTER;
  if (!isReadinessAdapter(adapter)) throw new Error(`unknown readiness adapter: ${String(adapter).slice(0, 40)}`);
  const paths = opts.paths ?? readinessPaths({ home: opts.home, adapter });
  const ttl = opts.ttlMs ?? READINESS_CACHE_TTL_MS;
  const pin = opts.pin === undefined ? currentReadinessPin(adapter) : opts.pin;
  const recordPath = transitionsPathFor(paths);
  const record = readTransitionRecord(recordPath);
  const recorded = durableMode(record);
  // r6 (S1): an unexplained demotion is not trusted — the promotion before it
  // stands, and the entry is a tamper signal like a forged cache.
  const forged = unexplainedDemotion(record);
  const durable = forged ? 'enforcing' : recorded;
  const state = readReadinessState(paths.statePath);
  let tamper: string | undefined = forged
    ? `the transition record's newest entry is an unexplained demotion (${forged.event} → shadow at ${forged.ts} after a promotion, ` +
      'with no demote between); it was not trusted'
    : undefined;
  if (isFreshState(state, now, ttl, pin)) {
    if (!forged && state!.mode === durable) {
      // R4-4: an oversized journal is compacted here too, so the cheap path
      // stays cheap from the next call on. r5 (finding 7): the pre-lock read
      // above only decides whether to try; compaction re-reads the journal
      // under the lock, so a promotion appended in between is kept.
      if (needsCompaction(record)) {
        const lock = `${paths.statePath}.lock`;
        opts.beforeLock?.();
        if (tryLock(lock, now)) {
          try { compactTransitionRecord(recordPath, now); } finally {
            try { rmSync(lock, { force: true }); } catch { /* stale lock self-heals */ }
          }
        }
      }
      return { mode: state!.mode, cached: true, transition: null, report: null, state };
    }
    if (!tamper && durable !== 'unknown') {
      tamper = `the readiness cache said ${state!.mode} while the durable transition record says ${durable}; the cache was not trusted`;
    }
  }

  const report = computeReadiness({
    channel: opts.channel,
    paths,
    now,
    pin,
    effectivenessRegistry: opts.effectivenessRegistry,
    adapter,
  });
  const prevMode = previousMode(state, report, durable);
  const decision = decideFromEvidence({ state, report, durable, now, tampered: tamper !== undefined });
  // No transition, but the record does not say this mode: re-anchor it with a
  // `recover` entry so the record and the applied mode agree again.
  const anchor = !decision.transition && decision.mode !== recorded;
  if (anchor && durable === 'unknown') {
    tamper = `the durable transition record was ${record.status === 'missing' ? 'missing' : 'unreadable'}; ` +
      'enforcing carried over from the readiness state / audit log';
  }

  const lockPath = `${paths.statePath}.lock`;
  opts.beforeLock?.();
  if (!tryLock(lockPath, now)) {
    // Someone else is recomputing: answer from evidence, write nothing, and
    // never announce a transition twice. A would-be demotion keeps enforcing
    // until the lock holder has written (and announced) it.
    const mode = decision.transition === 'demote' ? 'enforcing' : decision.mode;
    return { mode, cached: false, transition: null, report, state };
  }
  try {
    // r5 (finding 7): the decision above was made from a pre-lock read. If
    // another process changed the journal's mode since, that decision is
    // stale: write nothing, and answer with the tighter of the two modes —
    // the next call decides from the journal as it now is.
    const underLock = readTransitionRecord(recordPath);
    if (underLock.status !== record.status || underLock.last?.ts !== record.last?.ts) {
      const mode = decision.mode === 'enforcing' || durableMode(underLock) === 'enforcing' ? 'enforcing' : 'shadow';
      return { mode, cached: false, transition: null, report, state };
    }
    const nowIso = new Date(now).toISOString();
    if (record.status === 'unreadable') quarantineRecord(recordPath, now);
    const repeatTamper = tamper !== undefined && record.status === 'ok' && isRepeatTamper(record, tamper, now);
    if (tamper && !repeatTamper) {
      appendTransition(recordPath, { ts: nowIso, event: 'tamper', pin, reason: tamper.slice(0, 400) });
      appendRow(
        paths.auditDir,
        {
          type: 'readiness_tamper',
          origin: adapter,
          ts: nowIso,
          auditEventId: randomBytes(16).toString('hex'),
          ...(pin ? { readinessPin: pin } : {}),
          reason: tamper.slice(0, 400),
        },
        new Date(now),
      );
    }
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
      demotionReason = decision.unknown
        ? `${UNKNOWN_RECORD_REASON}${report.missing.length > 0 ? `; ${report.missing.join('; ')}` : ''}`
        : report.missing.join('; ') || 'readiness evidence no longer holds';
      if (!state && !decision.unknown) demotionReason += ' (readiness state file was missing; last mode taken from the transition record)';
      if (tamper) demotionReason += ` (${tamper})`;
      next.lastDemotedAt = nowIso;
      next.lastDemotionReason = demotionReason;
    }
    if (decision.transition || anchor) {
      // The durable record first: if this process dies before the state is
      // written, the next call sees the record, distrusts the stale cache and
      // recomputes — it never loses the transition.
      appendTransition(recordPath, {
        ts: nowIso,
        event: decision.transition ?? 'recover',
        to: decision.mode,
        pin,
        ...(demotionReason ? { reason: demotionReason.slice(0, 400) } : {}),
      });
    }
    if (decision.transition) {
      appendRow(
        paths.auditDir,
        {
          type: 'readiness_transition',
          origin: adapter,
          from: decision.unknown ? 'unknown' : prevMode ?? 'shadow',
          to: decision.mode,
          transition: decision.transition,
          ts: nowIso,
          auditEventId: randomBytes(16).toString('hex'),
          ...(pin ? { readinessPin: pin } : {}),
          intervention: { stops: report.intervention.stops, total: report.intervention.total, rate: report.intervention.rate },
          reachability: { reached: report.reachability.reached, resolved: report.reachability.resolved, rate: report.reachability.rate },
          effectivenessEvidence: report.effectiveness.evidence ? 'reviewed' : 'missing',
          ...(demotionReason ? { reason: demotionReason.slice(0, 400) } : {}),
        },
        new Date(now),
      );
    }
    // R4-4: keep the journal bounded (re-read: this call may have appended).
    if (record.status !== 'missing' && (needsCompaction(record) || record.entries.length + 3 > JOURNAL_MAX_ENTRIES)) {
      compactTransitionRecord(recordPath, now);
    }
    writeReadinessState(paths.statePath, next);
    return {
      mode: decision.mode,
      cached: false,
      transition: decision.transition,
      report,
      state: next,
      demotionReason,
      tamper,
      ...(decision.transition ? { transitionAt: nowIso } : {}),
    };
  } finally {
    try { rmSync(lockPath, { force: true }); } catch { /* stale lock self-heals */ }
  }
}

/**
 * Whether the install is in a DEMOTED state: it enforced before, and now it
 * does not. Doctor FAILs on this — the operator chose enforcement and is not
 * getting it. With the durable record: its newest mode entry is a demotion,
 * or the record is unknown (treated as potentially demoted). Without one
 * (legacy callers): the state file or the audit, either saying so is enough.
 */
export function isDemoted(state: ReadinessState | null, report: ReadinessReport | null, record?: TransitionRecord): boolean {
  if (record) {
    if (durableMode(record) === 'unknown') return true;
    return record.last?.event === 'demote';
  }
  const stateDemoted =
    !!state && state.mode === 'shadow' && !!state.lastDemotedAt &&
    (!state.lastPromotedAt || Date.parse(state.lastDemotedAt) >= Date.parse(state.lastPromotedAt));
  const auditDemoted = report?.lastTransition?.to === 'shadow';
  return stateDemoted || auditDemoted;
}

/** How recent a tamper report doctor still shows. */
export const TAMPER_REPORT_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** Plain-English one-liner for stderr / notifications. */
export function describeDemotion(reason: string | undefined): string {
  return (
    'ShieldCortex Action Guard DEMOTED to shadow mode (enforce-when-ready): dangerous actions are ' +
    `now logged but NOT stopped. Reason: ${reason ?? 'readiness evidence no longer holds'}. ` +
    'Run `shieldcortex guard readiness` for details.'
  );
}
