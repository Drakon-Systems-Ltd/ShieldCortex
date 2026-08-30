/**
 * ShieldCortex — AI-assisted approval broker, decision core (#143).
 *
 * Design: docs/design/2026-07-31-ai-approval-broker.md
 *
 * This module is the *policy*, not the plumbing. It is pure and synchronous:
 * given a guard verdict and (optionally) a judge model's assessment, it decides
 * whether to harden, hold for a human, or pre-clear. Calling the model, ringing
 * the operator's phone and waiting for a tap all live in the transport layers;
 * they consult this to know what they are allowed to do.
 *
 * Keeping the policy pure is deliberate. It is the part that must never be
 * wrong, so it must be exhaustively testable without a model, a network or a
 * clock — see __tests__/approval-broker.test.ts, where every invariant below is
 * pinned by a test that fails loudly if the broker ever becomes a bypass.
 *
 * The invariants, in the order they are enforced:
 *
 *   1. Catastrophic is never brokered. It never reaches here from the guard, and
 *      if it does, the answer is `not_brokerable` regardless of everything else.
 *   2. The judge escalates toward caution ONLY. It can harden a gate or leave it
 *      alone; a benign verdict is never sufficient on its own to release. If the
 *      model's "yes" could open a gate by itself, the lock's key becomes
 *      "convince the AI" — which is exactly what prompt injection does for a
 *      living.
 *   3. Pre-clear requires ALL of: every signal reversible, in-context, confident,
 *      injection-free. Missing any one holds for the human.
 *   4. No judge (unreachable, errored, malformed) → hold. Never pre-clear.
 *   5. Timeout is asymmetric: only a pre-cleared request may auto-approve when
 *      nobody answers. Everything else auto-denies. Silence never means yes on
 *      anything that matters.
 *   6. Config may TIGHTEN any of the above and can never loosen them.
 */

/** Structural shape of the guard verdict the broker consumes. */
export interface BrokerVerdictLike {
  decision: 'allow' | 'require_approval' | 'block';
  severity: 'benign' | 'sensitive' | 'dangerous' | 'catastrophic' | string;
  family: string;
  action: string;
  reason: string;
  signals: string[];
}

/** What the judge model returns. Deliberately small — a classifier, not an agent. */
export interface JudgeResult {
  /** The model's read of the request. Anything but 'benign' blocks pre-clear. */
  assessment: 'benign' | 'uncertain' | 'malicious';
  /** 0..1. Outside that range is treated as untrustworthy, not clamped. */
  confidence: number;
  /** Does this action fit what the session was already doing? */
  inContext: boolean;
  /** Did the model see an injection attempt in or around the request? */
  injectionSuspected: boolean;
  /** Short human-readable justification, carried into the audit row. */
  rationale?: string;
}

export interface BrokerPolicy {
  /** Master switch for the pre-clear path. `false` = every gate goes to a human. */
  allowPreClear: boolean;
  /** Minimum judge confidence for a pre-clear. Raising it tightens; it cannot loosen
   *  the reversibility or injection checks, which are not configurable. */
  preClearConfidence: number;
}

/**
 * Conservative by construction, and deliberately small.
 *
 * A dangerous-tier signal earns a place here only if it is BOTH reversible AND
 * stays on the host. That rules out anything that deletes, anything that
 * escalates privilege, anything that sends bytes off the box (data leaving is
 * irreversible by definition — you cannot un-send it), anything that touches
 * scheduling, services, firewalls or the guard's own state, and anything that
 * executes code fetched from a registry or the network.
 *
 * What remains is the boring, reversible middle of the dangerous tier — the
 * stuff that dominated the false-positive corpus and that a confident,
 * in-context judge can safely release when the operator is asleep.
 *
 * Growing this set is a security change: it needs corpus evidence, a review,
 * and its own test. An unknown signal is never pre-clearable (fail closed).
 */
export const PRE_CLEARABLE_SIGNALS: ReadonlySet<string> = new Set([
  // Workspace/project-scoped dependency installs. NOT install-package-global —
  // that mutates the host toolchain and has its own signal.
  'local-package-install',
  'install-package',
  // Reversible filesystem shuffling within the workspace. Deletion is excluded.
  'move-or-copy',
  // Mode/owner changes. The destructive recursive-system-dir variants are
  // separate signals and are excluded.
  'change-permissions',
  // Ordinary git mutation (commit/checkout/merge/reset). git-force-push is a
  // separate signal and stays out — it rewrites shared history.
  'git-mutate',
]);

export const DEFAULT_BROKER_POLICY: BrokerPolicy = {
  allowPreClear: true,
  // Deliberately high. A pre-clear happens with nobody watching, so the bar is
  // "the model is nearly certain", not "the model leans yes". Calibrate against
  // the real-stop corpus before moving it.
  preClearConfidence: 0.9,
};

/**
 * Why there is no judge result, for the audit row (#143 residual).
 *
 * Every value means exactly the same thing to the policy — no usable judge,
 * hold for a human. It exists so an operator can tell "the judge never
 * answered" from "the judge said hold", which were the same null until now: a
 * judge that times out on every call used to be indistinguishable from a
 * cautious one, and that is how a silently-broken judge stays broken.
 */
export type JudgeUnavailableReason = 'timeout' | 'unreachable' | 'parse' | 'thrown' | 'disabled';

const JUDGE_UNAVAILABLE_REASONS: ReadonlySet<string> = new Set<JudgeUnavailableReason>([
  'timeout', 'unreachable', 'parse', 'thrown', 'disabled',
]);

export interface BrokerInput {
  tool: string;
  toolInput: unknown;
  verdict: BrokerVerdictLike;
  /** null when no judge ran: model unreachable, disabled, or out of budget. */
  judge: JudgeResult | null;
  /** Optional availability metadata from the transport, for the audit row only.
   *  It can add a WORD to the reason; it can never add an outcome. */
  judgeMeta?: { timedOut?: boolean; error?: string | null };
  policy?: BrokerPolicy;
}

export type BrokerOutcome =
  /** The verdict is outside the broker's remit (catastrophic). Guard's answer stands. */
  | 'not_brokerable'
  /** The judge found something worse than the rules did — deny outright. */
  | 'harden'
  /** Ask the human. The default, and the only path for anything irreversible. */
  | 'hold'
  /** Reversible + in-context + confident + injection-free: may proceed without waiting. */
  | 'pre_clear';

export interface BrokerAudit {
  outcome: BrokerOutcome;
  tool: string;
  action: string;
  severity: string;
  signals: string[];
  judgeAssessment: JudgeResult['assessment'] | 'unavailable';
  judgeConfidence: number | null;
  injectionSuspected: boolean;
  inContext: boolean | null;
  /** True only when the transport reported a deadline AND no judge came back.
   *  Never true alongside a usable judge — a judge that answered did not time out. */
  judgeTimedOut?: boolean;
  /** Why the judge is 'unavailable', or null when one was actually used. */
  judgeUnavailableReason?: JudgeUnavailableReason | null;
  reason: string;
}

export interface BrokerDecision {
  outcome: BrokerOutcome;
  /** Why, in words, for the operator and the audit row. */
  reason: string;
  /** The ONLY thing the timeout path is allowed to consult. True iff pre-cleared. */
  canAutoApproveOnTimeout: boolean;
  audit: BrokerAudit;
}

/** True only if EVERY signal is on the reversible allowlist, and there is at least one. */
export function isPreClearable(signals: readonly string[]): boolean {
  if (!Array.isArray(signals) || signals.length === 0) return false;
  return signals.every(s => PRE_CLEARABLE_SIGNALS.has(s));
}

/** A judge result we are willing to act on at all. Anything malformed is discarded. */
function judgeIsUsable(j: JudgeResult | null): j is JudgeResult {
  if (!j || typeof j !== 'object') return false;
  if (j.assessment !== 'benign' && j.assessment !== 'uncertain' && j.assessment !== 'malicious') return false;
  if (typeof j.confidence !== 'number' || !Number.isFinite(j.confidence)) return false;
  // Out of range means the producer is not speaking our protocol. Do not clamp
  // an unknown number up into "confident" — distrust it.
  if (j.confidence < 0 || j.confidence > 1) return false;
  if (typeof j.inContext !== 'boolean') return false;
  if (typeof j.injectionSuspected !== 'boolean') return false;
  return true;
}

/**
 * Normalise the transport's availability metadata (#143 residual).
 *
 * A usable judge always reports "did not time out, no reason" regardless of
 * what the transport claimed — a judge that answered did not time out, and a
 * caller cannot mark a live verdict as an outage. Unrecognised reason strings
 * are dropped rather than carried, so a hostile or stale transport cannot write
 * free text into the audit row.
 */
function judgeAvailability(
  meta: BrokerInput['judgeMeta'],
  usable: boolean,
): { timedOut: boolean; reason: JudgeUnavailableReason | null } {
  if (usable) return { timedOut: false, reason: null };
  const raw = typeof meta?.error === 'string' ? meta.error : '';
  const reason = JUDGE_UNAVAILABLE_REASONS.has(raw) ? (raw as JudgeUnavailableReason) : null;
  return { timedOut: meta?.timedOut === true || reason === 'timeout', reason };
}

function decide(input: BrokerInput): { outcome: BrokerOutcome; reason: string } {
  const policy = input.policy ?? DEFAULT_BROKER_POLICY;
  const { verdict, judge } = input;

  // (1) Catastrophic is not ours. No judge verdict and no config reaches this.
  //
  // A bag the #412 schema rejected, or one whose command evidence exceeded the
  // scan budget, is out of remit for the same reason even though the core now
  // answers it `require_approval` so every plane says one word about it: the
  // guard never read the call, so there is nothing for a judge to assess and
  // nothing its confidence could be about. Keyed off the guard's own reason
  // code, not the decision tier — the same derivation the two enforcement
  // planes use for `unscannedBlock`.
  const schemaInvalid = verdict.action === 'invalid_tool_input'
    || (Array.isArray(verdict.signals) && verdict.signals.includes('invalid-tool-input'));
  if (verdict.severity === 'catastrophic' || verdict.decision === 'block' || schemaInvalid) {
    return {
      outcome: 'not_brokerable',
      reason: schemaInvalid && verdict.severity !== 'catastrophic'
        ? 'tool input the guard could not read in full — never brokered'
        : 'catastrophic-tier action — blocked by rule, never brokered',
    };
  }

  // (4) No usable judge → the human is the only path. A timeout is named
  // explicitly: same outcome, but the operator can see that the judge never
  // answered rather than assuming it looked and hesitated.
  if (!judgeIsUsable(judge)) {
    return {
      outcome: 'hold',
      reason: judgeAvailability(input.judgeMeta, false).timedOut
        ? 'judge timed out — holding for operator approval'
        : 'no usable judge assessment — holding for operator approval',
    };
  }

  // (2) The judge may only escalate. Injection first: it is the reason the judge
  // exists, and it overrides every other consideration including confidence.
  if (judge.injectionSuspected) {
    return { outcome: 'harden', reason: `judge flagged possible prompt injection — denying${judge.rationale ? `: ${judge.rationale}` : ''}` };
  }
  if (judge.assessment === 'malicious') {
    return { outcome: 'harden', reason: `judge assessed the request as malicious — denying${judge.rationale ? `: ${judge.rationale}` : ''}` };
  }

  // (3) + (6) Pre-clear: every condition must hold. Policy may switch it off or
  // raise the bar; it cannot reach the reversibility or injection checks.
  if (!policy.allowPreClear) {
    return { outcome: 'hold', reason: 'pre-clear disabled by policy — holding for operator approval' };
  }
  if (!isPreClearable(verdict.signals)) {
    return {
      outcome: 'hold',
      reason: `action is not reversible on-host (${verdict.signals.join(', ') || 'no signals'}) — holding for operator approval`,
    };
  }
  if (!judge.inContext) {
    return { outcome: 'hold', reason: 'judge found the request out of context for this session — holding for operator approval' };
  }
  if (judge.assessment !== 'benign') {
    return { outcome: 'hold', reason: 'judge was not confident the request is benign — holding for operator approval' };
  }
  if (judge.confidence < policy.preClearConfidence) {
    return {
      outcome: 'hold',
      reason: `judge confidence ${judge.confidence.toFixed(2)} below pre-clear threshold ${policy.preClearConfidence} — holding for operator approval`,
    };
  }

  return {
    outcome: 'pre_clear',
    reason: `reversible on-host action, in context, judge benign at ${judge.confidence.toFixed(2)} — pre-cleared`,
  };
}

/** The whole policy, in one pure call. */
export function brokerDecision(input: BrokerInput): BrokerDecision {
  const { outcome, reason } = decide(input);
  const usable = judgeIsUsable(input.judge);
  const availability = judgeAvailability(input.judgeMeta, usable);

  return {
    outcome,
    reason,
    // (5) The timeout path reads THIS and nothing else. Keeping it a single
    // derived boolean means a future transport cannot reconstruct its own,
    // more generous, idea of what is safe to auto-approve.
    canAutoApproveOnTimeout: outcome === 'pre_clear',
    audit: {
      outcome,
      tool: input.tool,
      action: input.verdict.action,
      severity: input.verdict.severity,
      signals: [...(input.verdict.signals ?? [])],
      judgeAssessment: usable ? (input.judge as JudgeResult).assessment : 'unavailable',
      judgeConfidence: usable ? (input.judge as JudgeResult).confidence : null,
      injectionSuspected: usable ? (input.judge as JudgeResult).injectionSuspected : false,
      inContext: usable ? (input.judge as JudgeResult).inContext : null,
      // Audit only. Neither field is read by any decision above, and
      // canAutoApproveOnTimeout stays derived from the outcome alone.
      judgeTimedOut: availability.timedOut,
      judgeUnavailableReason: availability.reason,
      reason,
    },
  };
}

/**
 * What happens when the operator never answers.
 *
 * Asymmetric on purpose. An attacker fires at 3am precisely BECAUSE nobody is
 * watching, so "nobody answered" must not be a route to yes for anything that
 * matters. Only a request the broker already pre-cleared — reversible, on-host,
 * in-context, judge-confident — may proceed on silence.
 */
export function timeoutOutcome(decision: BrokerDecision): 'approve' | 'deny' {
  return decision.canAutoApproveOnTimeout ? 'approve' : 'deny';
}
