/**
 * `shieldcortex guard readiness` and `shieldcortex guard test-approval` (#509).
 *
 * `readiness` shows what the enforce-when-ready gate sees: the posture, the
 * mode the hook is in, each bar's measured value against its threshold and
 * sample size, the last live round-trip, and in plain English what is
 * missing. It recomputes from the audit evidence and writes nothing.
 *
 * `test-approval` puts a clearly labelled SYNTHETIC approval request through
 * the configured human channel and records whether a human answered — the
 * way a quiet box earns approval-reach evidence. It never approves anything
 * real: it does not import the approval store, its hash is 256 random bits no
 * pending request can share, and the card's answer is only ever written as a
 * `synthetic` reach row. TTY-only, like `approve`: an agent with piped stdio
 * must not be able to spam unanswerable cards (each one would count against
 * the bar and force a demotion).
 */

import { execFile } from 'node:child_process';
import { randomBytes, randomInt } from 'node:crypto';
import readline from 'node:readline/promises';

import { actionGuardPosture, getActionGuardCoreConfig, readRawConfig, type ActionGuardPosture } from '../cloud/config.js';
import { readPolicyLock } from '../defence/iron-dome/policy-lock.js';
import {
  APPROVAL_MIN_RATE,
  APPROVAL_MIN_SAMPLE,
  FP_MAX_RATE,
  FP_MIN_SAMPLE,
  FP_MIN_SPAN_MS,
  REACH_ANSWER_WINDOW_MS,
  computeReadiness,
  decideMode,
  describeHumanChannel,
  isDemoted,
  readReadinessState,
  readinessPaths,
  recordApprovalReach,
  type HumanChannel,
  type ReadinessMode,
  type ReadinessReport,
  type ReadinessState,
  type ReachAnswer,
  READINESS_CACHE_TTL_MS,
} from '../defence/iron-dome/guard-readiness.js';
import type { OperatorNotification, NotifyChannel } from '../defence/iron-dome/operator-notify.js';
import { isInteractive } from './approve.js';

// ==================== SUMMARY (shared with doctor) ====================

export interface ReadinessSummary {
  posture: ActionGuardPosture;
  /** A policy lock pins enforcement; the readiness gate is then ignored. */
  lockOverrides: boolean;
  /** What the Claude Code hook applies to dangerous-tier verdicts right now. */
  mode: 'off' | 'watch-only' | ReadinessMode;
  channel: HumanChannel;
  report: ReadinessReport;
  state: ReadinessState | null;
  demoted: boolean;
}

function rawActionGuard(): Record<string, unknown> {
  try {
    const raw = readRawConfig();
    const g = raw.actionGuard;
    return g && typeof g === 'object' && !Array.isArray(g) ? (g as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function lockPresent(): boolean {
  try {
    const s = readPolicyLock({ audit: false, warn: false }).status;
    return s === 'locked' || s === 'unverifiable';
  } catch {
    return false;
  }
}

export function buildReadinessSummary(opts: { now?: number; home?: string } = {}): ReadinessSummary {
  const now = opts.now ?? Date.now();
  const core = getActionGuardCoreConfig();
  const lockOverrides = core.readinessGate && lockPresent();
  const posture = lockOverrides ? 'enforce' : actionGuardPosture(core);
  const channel = describeHumanChannel(rawActionGuard().notify);
  // `home` pins the evidence tree (tests); production reads the configured
  // root plus the hook's home-directory audit.
  const paths = readinessPaths({ home: opts.home });
  const report = computeReadiness({ channel, paths, now });
  const state = readReadinessState(paths.statePath);

  let mode: ReadinessSummary['mode'];
  if (posture === 'off') mode = 'off';
  else if (posture === 'watch-only') mode = 'watch-only';
  else if (posture === 'enforce') mode = 'enforcing';
  else {
    // What the hook would apply: a fresh cache as-is, else the evidence
    // through the same hysteresis rule (without writing anything).
    const age = state ? now - Date.parse(state.computedAt) : Infinity;
    if (state && age >= 0 && age < READINESS_CACHE_TTL_MS) {
      mode = state.mode;
    } else {
      const auditMode = report.lastTransition?.to ?? null;
      const prevMode = state?.mode === 'enforcing' || auditMode === 'enforcing' ? 'enforcing' : state?.mode ?? auditMode;
      mode = decideMode({
        prevMode,
        failingSince: state?.failingSince,
        lastDemotedAt: state?.lastDemotedAt,
        ready: report.ready,
        now,
      }).mode;
    }
  }
  const demoted = posture === 'enforce-when-ready' && mode === 'shadow' && isDemoted(state, report);
  return { posture, lockOverrides, mode, channel, report, state, demoted };
}

function pct(rate: number | null): string {
  return rate === null ? 'n/a' : `${(rate * 100).toFixed(1)}%`;
}

const POSTURE_TEXT: Record<ActionGuardPosture, string> = {
  off: 'off — tool calls are not gated',
  'watch-only': 'watch only — dangerous ops are logged, not stopped (catastrophic still blocks)',
  enforce: 'enforce — dangerous ops need approval or are blocked',
  'enforce-when-ready': 'enforce when ready — shadow until this install proves both readiness bars',
};

const MODE_TEXT: Record<ReadinessSummary['mode'], string> = {
  off: 'not gating',
  'watch-only': 'watch only (advisory)',
  shadow: 'SHADOW — dangerous ops logged as would-stop, NOT stopped',
  enforcing: 'ENFORCING — dangerous ops need approval or are blocked',
};

export function formatReadinessLines(s: ReadinessSummary): string[] {
  const { report } = s;
  const fp = report.fp;
  const ap = report.approval;
  const lines = [
    `Posture:       ${POSTURE_TEXT[s.posture]}${s.lockOverrides ? ' (policy lock pins enforcement; readiness gate ignored)' : ''}`,
    `Current mode:  ${MODE_TEXT[s.mode]}${s.demoted ? ' — DEMOTED from enforcing' : ''}`,
    `FP bar:        ${pct(fp.rate)} would-stop (${fp.stops}/${fp.total} calls over ${(fp.spanMs / 86_400_000).toFixed(1)} days) ` +
      `— need ≤ ${pct(FP_MAX_RATE)} over ≥ ${FP_MIN_SAMPLE} calls and ≥ ${FP_MIN_SPAN_MS / 86_400_000} days  ${fp.pass ? 'PASS' : 'not met'}`,
    `Approval bar:  ${pct(ap.rate)} answered by a human (${ap.reached}/${ap.resolved}${ap.pending ? `, ${ap.pending} pending` : ''}) ` +
      `via ${ap.channel.configured ? ap.channel.kind : 'NO CHANNEL'} — need ≥ ${pct(APPROVAL_MIN_RATE)} over ≥ ${APPROVAL_MIN_SAMPLE}  ${ap.pass ? 'PASS' : 'not met'}`,
    `Last live round-trip: ${ap.lastRoundTripAt ?? 'never'}`,
  ];
  if (s.state?.lastDemotedAt) {
    lines.push(`Last demotion: ${s.state.lastDemotedAt}${s.state.lastDemotionReason ? ` — ${s.state.lastDemotionReason}` : ''}`);
  }
  if (report.missing.length > 0) {
    lines.push('Missing:');
    for (const m of report.missing) lines.push(`  - ${m}`);
  } else {
    lines.push('Missing: nothing — both bars hold.');
  }
  lines.push(
    'Note: every would-stop counts as a possible false positive, so the FP figure is an upper bound.',
  );
  return lines;
}

// ==================== test-approval ====================

export interface TestApprovalDeps {
  isTTY?: boolean;
  now?: () => number;
  /** Returns the raw decision for a card, as the gateway reports it. */
  cardRoundTrip?: (paramsJson: string, timeoutMs: number) => Promise<{ ok: true; decision: unknown } | { ok: false; reason: string }>;
  /** Builds the webhook channel (injectable for tests). */
  webhookChannel?: () => Promise<NotifyChannel | null>;
  /** Reads the code the operator typed; null on timeout/empty. */
  askCode?: (prompt: string, timeoutMs: number) => Promise<string | null>;
  log?: (line: string) => void;
  error?: (line: string) => void;
  openclawBin?: () => Promise<string | null>;
}

function syntheticNotification(hash: string, code: string | null): OperatorNotification {
  return {
    event: 'approval_requested',
    hash,
    shortHash: hash.slice(0, 12),
    tool: 'TEST-no-real-action',
    command:
      'SYNTHETIC ROUND-TRIP TEST from `shieldcortex guard test-approval`. Nothing will run. ' +
      (code
        ? `Type this confirmation code in the terminal that started the test: ${code}`
        : 'Approve or Deny — either answer only proves this channel reaches you.'),
    signals: ['approval-round-trip-test'],
    severity: 'dangerous',
    reason: 'Readiness test for enforce-when-ready (#509). No tool call is waiting on this.',
    judge: null,
    fallbackHint: 'No action needed — this is a test.',
  };
}

async function defaultCardRoundTrip(bin: string, paramsJson: string, timeoutMs: number) {
  const { callApprovalGateway } = await import('../defence/iron-dome/openclaw-approval-waiter.js');
  return callApprovalGateway(execFile, bin, paramsJson, timeoutMs);
}

async function defaultAskCode(prompt: string, timeoutMs: number): Promise<string | null> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const answer = (await rl.question(prompt, { signal: ac.signal })).trim();
    return answer || null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    rl.close();
  }
}

/**
 * One synthetic round-trip. Returns the recorded answer. Exported for tests;
 * the only side effects are the two synthetic reach rows and the channel send.
 */
export async function runTestApproval(deps: TestApprovalDeps = {}): Promise<{ code: number; answer?: ReachAnswer }> {
  const log = deps.log ?? ((l: string) => console.log(l));
  const error = deps.error ?? ((l: string) => console.error(l));
  const now = deps.now ?? Date.now;
  if (!(deps.isTTY ?? isInteractive())) {
    error('shieldcortex guard test-approval must be run by a human in a real terminal (stdin and stdout must be TTYs).');
    return { code: 2 };
  }
  const rawNotify = rawActionGuard().notify;
  const channel = describeHumanChannel(rawNotify);
  if (!channel.configured) {
    error('No human approval channel is configured, so there is nothing to test.');
    error('Configure one first: shieldcortex config --action-guard-notify-openclaw  (or --action-guard-notify-webhook <https-url>)');
    return { code: 1 };
  }
  // 256 random bits: cannot equal any real pending request's hash.
  const hash = randomBytes(32).toString('hex');
  const record = (phase: 'request' | 'answer' | 'resolved', answer?: ReachAnswer, reason?: string) =>
    recordApprovalReach({ hash, phase, answer, channel: channel.kind, reason, synthetic: true, origin: 'guard-test-approval' }, { now: now() });

  if (channel.kind === 'openclaw-card') {
    const bin = deps.openclawBin
      ? await deps.openclawBin()
      : (await import('../defence/iron-dome/openclaw-approval-channel.js')).resolveOpenClawBinaryLite();
    if (!bin && !deps.cardRoundTrip) {
      record('resolved', 'unreached', 'openclaw binary not found');
      error('The OpenClaw approval channel is configured but the `openclaw` binary was not found — recorded as NOT reaching a human.');
      return { code: 1, answer: 'unreached' };
    }
    const { buildCardRequestParams, CARD_TIMEOUT_MS, WAIT_DECISION_TIMEOUT_MS } = await import('../defence/iron-dome/openclaw-approval-channel.js');
    const params = { ...buildCardRequestParams(syntheticNotification(hash, null)), timeoutMs: CARD_TIMEOUT_MS };
    record('request');
    log(`Sent a TEST approval card through OpenClaw [${hash.slice(0, 12)}]. Tap Approve or Deny on it (waiting up to ${Math.round(CARD_TIMEOUT_MS / 60000)} min)…`);
    const call = deps.cardRoundTrip
      ? await deps.cardRoundTrip(JSON.stringify(params), WAIT_DECISION_TIMEOUT_MS)
      : await defaultCardRoundTrip(bin as string, JSON.stringify(params), WAIT_DECISION_TIMEOUT_MS);
    // The decision is mapped to EVIDENCE only. Nothing here can reach the
    // approval store: this module does not import it.
    let answer: ReachAnswer;
    if (!call.ok) answer = 'unreached';
    else if (call.decision === 'allow-once') answer = 'approve';
    else if (call.decision === 'deny') answer = 'deny';
    else if (call.decision === null || call.decision === undefined) answer = 'timeout';
    else answer = 'unreached';
    record('answer', answer, call.ok ? undefined : call.reason);
    return report(answer, log);
  }

  // Webhook: one-way, so the round-trip is closed by the operator typing the
  // code the notification carried — proof the message reached a human.
  const code = String(randomInt(100000, 1000000));
  const webhook = deps.webhookChannel ? await deps.webhookChannel() : await buildWebhookChannel(rawNotify);
  if (!webhook) {
    record('resolved', 'unreached', 'webhook channel could not be built');
    error('The webhook channel could not be built from config — recorded as NOT reaching a human.');
    return { code: 1, answer: 'unreached' };
  }
  const sent = await webhook.send(syntheticNotification(hash, code), { timeoutMs: 10_000 }).catch(() => ({ delivered: false as const, reason: 'send threw' }));
  if (!sent.delivered) {
    record('resolved', 'unreached', 'webhook delivery failed');
    error('The webhook did not accept the test notification — recorded as NOT reaching a human.');
    return { code: 1, answer: 'unreached' };
  }
  record('request');
  const ask = deps.askCode ?? defaultAskCode;
  const typed = await ask(
    `Sent a TEST notification to your webhook. Type the 6-digit code it shows (${Math.round(REACH_ANSWER_WINDOW_MS / 60000)} min): `,
    REACH_ANSWER_WINDOW_MS,
  );
  const answer: ReachAnswer = typed === null ? 'timeout' : typed === code ? 'approve' : 'unreached';
  record('answer', answer, answer === 'unreached' ? 'code did not match' : undefined);
  return report(answer, log);
}

async function buildWebhookChannel(rawNotify: unknown): Promise<NotifyChannel | null> {
  try {
    const { normaliseNotifyConfig } = await import('../defence/iron-dome/notify-config.js');
    const { createWebhookNotifyChannel } = await import('../defence/iron-dome/webhook-notify-channel.js');
    const cfg = normaliseNotifyConfig(rawNotify);
    if (!cfg.enabled || !cfg.webhookUrl) return null;
    return createWebhookNotifyChannel({ url: cfg.webhookUrl, secret: cfg.webhookSecret });
  } catch {
    return null;
  }
}

function report(answer: ReachAnswer, log: (l: string) => void): { code: number; answer: ReachAnswer } {
  if (answer === 'approve' || answer === 'deny') {
    log(`Round-trip recorded: a human answered (${answer}). Nothing was approved or denied — this was a test.`);
    return { code: 0, answer };
  }
  log(`Round-trip recorded as NOT reaching a human (${answer}). This counts against the approval-reach bar.`);
  return { code: 1, answer };
}

// ==================== dispatcher ====================

export async function runGuardCommand(argv: string[]): Promise<number> {
  const sub = argv[0];
  if (sub === 'readiness') {
    const summary = buildReadinessSummary();
    if (argv.includes('--json')) {
      console.log(JSON.stringify(summary, null, 2));
    } else {
      for (const line of formatReadinessLines(summary)) console.log(line);
    }
    return summary.demoted ? 1 : 0;
  }
  if (sub === 'test-approval') {
    return (await runTestApproval()).code;
  }
  console.log('Usage: shieldcortex guard readiness [--json]    Show the enforce-when-ready readiness bars (#509)');
  console.log('       shieldcortex guard test-approval         Send a synthetic approval request through your channel');
  return sub === '--help' || sub === '-h' || sub === 'help' ? 0 : 1;
}
