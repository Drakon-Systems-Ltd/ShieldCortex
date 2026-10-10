/**
 * #509 — the enforce-when-ready readiness gate: the two operability proxies
 * (operational intervention rate, approval reachability — NOT the ADR-002 §5B
 * bars) measured from an install's own audit log, the effectiveness-evidence
 * condition, version pinning, the hysteresis rule, and the tamper direction
 * (deflation is never silent).
 *
 * Every test runs against a throwaway audit directory and state path; the
 * live ~/.shieldcortex is never read.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AWAITING_EFFECTIVENESS_MESSAGE,
  DEMOTE_AFTER_FAILING_MS,
  INTERVENTION_MIN_SAMPLE,
  REACHABILITY_MIN_SAMPLE,
  READINESS_CACHE_TTL_MS,
  REPROMOTE_COOLDOWN_MS,
  REVIEWED_EFFECTIVENESS_EVIDENCE,
  computeReadiness,
  currentReadinessPin,
  decideMode,
  describeHumanChannel,
  isDemoted,
  readReadinessState,
  readinessPaths,
  recordApprovalReach,
  resolveReadiness,
  initReadinessTransitions,
  readTransitionRecord,
  transitionsPathFor,
  NO_NOTICE_CHANNEL_MESSAGE,
  UNKNOWN_RECORD_REASON,
  type ReadinessPaths,
  type ReadinessPin,
} from '../guard-readiness.js';
import { approvalsDir } from '../action-approvals.js';
import { evaluateToolCall } from '../tool-action-guard.js';
import { applyPolicyLock, applyStrictFailClosedPosture } from '../policy-lock.js';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-09-28T12:00:00.000Z');
/** A card channel plus a webhook: approvals AND pushed demotion notices. */
const CHANNEL = { configured: true, kind: 'openclaw-card', pushesNotices: true };
const NO_CHANNEL = { configured: false, kind: null, pushesNotices: false };
const PIN = currentReadinessPin() as ReadinessPin;
/** Stands for a build that ships reviewed effectiveness evidence for this
 *  pin. The shipped registry is empty, and (option A, 29 Sep 2026) there is
 *  no setting that drops the condition — so promotion tests pass evidence
 *  through the in-process registry seam. */
const WITH_REVIEWED = {
  effectivenessRegistry: [{ ...PIN, reviewedAt: new Date(NOW - DAY).toISOString(), reviewedBy: 'fixture reviewer', reference: 'test fixture', cases: 60 }],
} as const;

let root: string;
let paths: ReadinessPaths;
let seq = 0;

function __dirname_509(): string {
  return dirname(fileURLToPath(import.meta.url));
}

function row(ts: number, fields: Record<string, unknown>): Record<string, unknown> {
  seq += 1;
  return { ts: new Date(ts).toISOString(), auditEventId: `e${seq.toString(16).padStart(8, '0')}`, readinessPin: PIN, ...fields };
}

function write(rows: Array<Record<string, unknown>>): void {
  mkdirSync(paths.auditDir, { recursive: true });
  for (const r of rows) {
    const date = String(r.ts).slice(0, 10);
    appendFileSync(join(paths.auditDir, `realtime-${date}.jsonl`), `${JSON.stringify(r)}\n`);
  }
}

function call(ts: number, outcome: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const action = outcome === 'allowed' ? 'allow' : 'require_approval';
  return row(ts, { type: 'intercept', origin: 'claude-code-hook', tool: 'Bash', severity: outcome === 'allowed' ? 'low' : 'high', action, outcome, ...extra });
}

/** `total` real calls spread evenly over `spanDays`, `stops` of them would-holds. */
function calls(total: number, stops: number, spanDays = 8): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (let i = 0; i < total; i += 1) {
    const ts = NOW - spanDays * DAY + Math.floor((i * spanDays * DAY) / total) + 1000;
    out.push(call(ts, i < stops ? 'would_hold' : 'allowed'));
  }
  return out;
}

/** `answered` reached round-trips + `unanswered` expired requests, within the last day. */
function reach(answered: number, unanswered: number, opts: { at?: number; synthetic?: boolean } = {}): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const base = opts.at ?? NOW - DAY;
  for (let i = 0; i < answered + unanswered; i += 1) {
    const reachId = `r${i.toString(16).padStart(8, '0')}${opts.at ?? ''}`;
    const t = base + i * 1000;
    const attemptId = `a-${reachId}`;
    out.push(row(t, { type: 'approval_reach', reachId, attemptId, phase: 'request', ...(opts.synthetic ? { synthetic: true } : {}) }));
    if (i < answered) out.push(row(t + 60_000, { type: 'approval_reach', reachId, attemptId, phase: 'answer', answer: i % 2 ? 'deny' : 'approve' }));
  }
  return out;
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-'));
  paths = {
    auditDir: join(root, 'audit'),
    statePath: join(root, 'approvals', 'guard-readiness.json'),
    readAuditDirs: [join(root, 'audit')],
  };
  // The posture was chosen (config/setup start the durable record) long ago.
  initReadinessTransitions({ postureChanged: true, reason: 'test posture', paths, now: NOW - 60 * DAY });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('#509 operational intervention rate (readiness proxy)', () => {
  it('below the minimum sample ⇒ not ready, however clean', () => {
    write(calls(INTERVENTION_MIN_SAMPLE - 1, 0));
    write(reach(20, 0));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.intervention.total).toBe(INTERVENTION_MIN_SAMPLE - 1);
    expect(r.intervention.pass).toBe(false);
    expect(r.intervention.missing).toMatch(/only 499 of the 500/);
    expect(r.ready).toBe(false);
  });

  it('2.1% would-stop ⇒ not ready', () => {
    write(calls(1000, 21));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.intervention.rate).toBeCloseTo(0.021, 5);
    expect(r.intervention.pass).toBe(false);
    expect(r.intervention.missing).toMatch(/2\.1%/);
  });

  it('1.9% would-stop ⇒ the intervention proxy passes', () => {
    write(calls(1000, 19));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.intervention.rate).toBeCloseTo(0.019, 5);
    expect(r.intervention.pass).toBe(true);
  });

  it('enough calls but under 7 days of span ⇒ not ready', () => {
    write(calls(1000, 0, 3));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.intervention.pass).toBe(false);
    expect(r.intervention.missing).toMatch(/span/);
  });

  it('gate_degraded rows, notify rows, test/proof origins, synthetic rows and lease refusals are excluded', () => {
    write(calls(1000, 19));
    const t = NOW - 2 * DAY;
    const noise: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 50; i += 1) {
      noise.push(call(t + i, 'failure_allowed', { action: 'gate_degraded' }));
      noise.push(call(t + i, 'notified', { action: 'notify' }));
      noise.push(call(t + i, 'would_hold', { origin: 'guard-proof' }));
      noise.push(call(t + i, 'would_hold', { origin: 'openclaw-interceptor' }));
      noise.push(call(t + i, 'would_hold', { synthetic: true }));
      noise.push(call(t + i, 'auto_denied', { threats: ['session-lease', 'frozen'] }));
    }
    write(noise);
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.intervention.total).toBe(1000);
    expect(r.intervention.stops).toBe(19);
    expect(r.intervention.pass).toBe(true);
  });

  it('catastrophic stops count in the denominator but never as an intervention', () => {
    const rows = calls(1000, 19);
    for (let i = 0; i < 30; i += 1) rows.push(call(NOW - DAY + i, 'auto_denied', { severity: 'critical', action: 'auto_deny' }));
    write(rows);
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.intervention.total).toBe(1030);
    expect(r.intervention.stops).toBe(19);
  });
});

describe('#509 approval reachability (readiness proxy)', () => {
  beforeEach(() => write(calls(1000, 0)));

  it('97% answered ⇒ not ready', () => {
    write(reach(97, 3));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.reachability.rate).toBeCloseTo(0.97, 5);
    expect(r.reachability.pass).toBe(false);
    expect(r.ready).toBe(false);
  });

  it('98% answered ⇒ ready', () => {
    write(reach(98, 2));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.reachability.rate).toBeCloseTo(0.98, 5);
    expect(r.reachability.pass).toBe(true);
    expect(r.ready).toBe(true);
    expect(r.missing).toEqual([]);
  });

  it('no configured channel ⇒ not ready, full stop', () => {
    write(reach(100, 0));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: NO_CHANNEL, paths, now: NOW });
    expect(r.reachability.pass).toBe(false);
    expect(r.reachability.missing).toMatch(/no human approval channel/);
    expect(r.ready).toBe(false);
  });

  it('below the minimum sample ⇒ not ready', () => {
    write(reach(REACHABILITY_MIN_SAMPLE - 1, 0));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.reachability.pass).toBe(false);
  });

  it('a last reached round-trip older than 7 days ⇒ not ready', () => {
    write(reach(30, 0, { at: NOW - 8 * DAY }));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.reachability.rate).toBe(1);
    expect(r.reachability.pass).toBe(false);
    expect(r.reachability.missing).toMatch(/last 7 days/);
  });

  it('transcript-only / no-surface / undelivered requests are resolved but never a reach', () => {
    write(reach(98, 0));
    write([
      row(NOW - DAY, { type: 'approval_reach', reachId: 'x1', phase: 'resolved', answer: 'no_surface' }),
      row(NOW - DAY, { type: 'approval_reach', reachId: 'x2', phase: 'resolved', answer: 'unreached' }),
      row(NOW - DAY, { type: 'approval_reach', reachId: 'x3', phase: 'resolved', answer: 'unreached' }),
    ]);
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.reachability.resolved).toBe(101);
    expect(r.reachability.reached).toBe(98);
    expect(r.reachability.pass).toBe(false);
  });

  it('an answer later than the answer window is a timeout; an unanswered fresh request is pending', () => {
    write(reach(20, 0));
    write([
      row(NOW - DAY, { type: 'approval_reach', reachId: 'late', attemptId: 'late-1', phase: 'request' }),
      row(NOW - DAY + 30 * 60_000, { type: 'approval_reach', reachId: 'late', attemptId: 'late-1', phase: 'answer', answer: 'approve' }),
      row(NOW - 60_000, { type: 'approval_reach', reachId: 'fresh', attemptId: 'fresh-1', phase: 'request' }),
    ]);
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.reachability.resolved).toBe(21);
    expect(r.reachability.reached).toBe(20);
    expect(r.reachability.pending).toBe(1);
  });

  it('recordApprovalReach pairs by attempt id: request + human answer to THAT attempt is a reach', () => {
    const hash = 'a'.repeat(64);
    recordApprovalReach({ hash, attemptId: 'att-1', phase: 'request', channel: 'openclaw' }, { auditDir: paths.auditDir, now: NOW - 5 * 60_000 });
    recordApprovalReach({ hash, attemptId: 'att-1', phase: 'answer', answer: 'deny' }, { auditDir: paths.auditDir, now: NOW - 4 * 60_000 });
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.reachability.reached).toBe(1);
    expect(r.reachability.lastRoundTripAt).toBe(new Date(NOW - 4 * 60_000).toISOString());
    const raw = readdirSync(paths.auditDir).map((f) => readFileSync(join(paths.auditDir, f), 'utf8')).join('');
    expect(raw).not.toContain(hash); // only the derived reach id is written
  });
});

describe('#509 describeHumanChannel', () => {
  it('needs enabled:true and a real channel', () => {
    expect(describeHumanChannel(undefined).configured).toBe(false);
    expect(describeHumanChannel({ enabled: 'yes', openclaw: true }).configured).toBe(false);
    expect(describeHumanChannel({ enabled: true }).configured).toBe(false);
    expect(describeHumanChannel({ enabled: true, webhookUrl: 'ftp://x' }).configured).toBe(false);
    expect(describeHumanChannel({ enabled: true, webhookUrl: 'https://hooks.example.com/x' })).toEqual({ configured: true, kind: 'webhook', pushesNotices: true });
    expect(describeHumanChannel({ enabled: true, openclaw: true })).toEqual({ configured: true, kind: 'openclaw-card', pushesNotices: false });
  });
});

describe('#509 hysteresis', () => {
  it('promotes as soon as the readiness conditions hold', () => {
    expect(decideMode({ prevMode: null, ready: true, now: NOW })).toEqual({ mode: 'enforcing', transition: 'promote' });
  });

  it('one failing recompute does not demote; failing for the full grace does', () => {
    const first = decideMode({ prevMode: 'enforcing', ready: false, now: NOW });
    expect(first.mode).toBe('enforcing');
    expect(first.transition).toBeNull();
    const later = decideMode({ prevMode: 'enforcing', ready: false, failingSince: first.failingSince, now: NOW + DEMOTE_AFTER_FAILING_MS - 1 });
    expect(later.mode).toBe('enforcing');
    const demoted = decideMode({ prevMode: 'enforcing', ready: false, failingSince: first.failingSince, now: NOW + DEMOTE_AFTER_FAILING_MS });
    expect(demoted).toEqual({ mode: 'shadow', transition: 'demote' });
  });

  it('no re-promotion inside the cooldown after a demotion', () => {
    const lastDemotedAt = new Date(NOW).toISOString();
    expect(decideMode({ prevMode: 'shadow', ready: true, lastDemotedAt, now: NOW + REPROMOTE_COOLDOWN_MS - 1 }).mode).toBe('shadow');
    expect(decideMode({ prevMode: 'shadow', ready: true, lastDemotedAt, now: NOW + REPROMOTE_COOLDOWN_MS }).transition).toBe('promote');
  });
});

describe('#509 resolveReadiness — transitions are audited, deflation is never silent', () => {
  function readyEvidence(): void {
    write(calls(1000, 5));
    write(reach(25, 0));
  }
  function transitions(): Array<Record<string, unknown>> {
    if (!existsSync(paths.auditDir)) return [];
    return readdirSync(paths.auditDir)
      .flatMap((f) => readFileSync(join(paths.auditDir, f), 'utf8').split('\n').filter(Boolean))
      .map((l) => JSON.parse(l) as Record<string, unknown>)
      .filter((r) => r.type === 'readiness_transition');
  }

  it('fresh store: shadow, no transition, and the state file is written', () => {
    const r = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.mode).toBe('shadow');
    expect(r.transition).toBeNull();
    expect(readReadinessState(paths.statePath)?.mode).toBe('shadow');
  });

  it('promotion is audited and cached for one TTL', () => {
    readyEvidence();
    const r = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.mode).toBe('enforcing');
    expect(r.transition).toBe('promote');
    expect(transitions().map((t) => t.to)).toEqual(['enforcing']);
    const again = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW + READINESS_CACHE_TTL_MS - 1 });
    expect(again.cached).toBe(true);
    expect(again.mode).toBe('enforcing');
  });

  it('forged would-block rows cause a VISIBLE demotion (transition row + isDemoted), never a silent one', () => {
    readyEvidence();
    expect(resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW }).mode).toBe('enforcing');
    // Same-UID forgery: 200 would-block rows appended to the audit.
    const forged: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 200; i += 1) forged.push(call(NOW + i, 'would_block'));
    write(forged);
    // Past the TTL: recompute sees the failing bar and starts the grace clock.
    const t1 = NOW + READINESS_CACHE_TTL_MS;
    const during = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: t1 });
    expect(during.mode).toBe('enforcing');
    expect(during.transition).toBeNull();
    // Still failing after the grace: demoted, audited, with the reason.
    const t2 = t1 + DEMOTE_AFTER_FAILING_MS;
    const out = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: t2 });
    expect(out.mode).toBe('shadow');
    expect(out.transition).toBe('demote');
    expect(out.demotionReason).toMatch(/would intervene/);
    const tr = transitions();
    expect(tr.map((t) => t.to)).toEqual(['enforcing', 'shadow']);
    expect(String(tr[1].reason)).toMatch(/would intervene/);
    expect(isDemoted(readReadinessState(paths.statePath), computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: t2 }))).toBe(true);
  });

  it('a deleted state file does not quietly end enforcement: the audit remembers the mode', () => {
    readyEvidence();
    expect(resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW }).mode).toBe('enforcing');
    rmSync(paths.statePath);
    // Evidence still holds → still enforcing, and no spurious promotion row.
    const r = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW + 1 });
    expect(r.mode).toBe('enforcing');
    expect(r.transition).toBeNull();
    expect(transitions()).toHaveLength(1);
  });

  it('a state file rewritten to "shadow" does not outrank an enforcing audit on recompute', () => {
    readyEvidence();
    resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    writeFileSync(paths.statePath, JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date(NOW - 2 * READINESS_CACHE_TTL_MS).toISOString() }));
    const r = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW + 1 });
    expect(r.mode).toBe('enforcing');
    expect(r.transition).toBeNull();
  });

  it('deleted approval evidence + missing state still demotes loudly (the audit remembers it was enforcing)', () => {
    readyEvidence();
    resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    rmSync(paths.statePath);
    // Wipe every approval_reach row, keep the rest (including the transition).
    for (const f of readdirSync(paths.auditDir)) {
      const p = join(paths.auditDir, f);
      const kept = readFileSync(p, 'utf8').split('\n').filter((l) => l && !l.includes('"approval_reach"'));
      writeFileSync(p, kept.map((l) => `${l}\n`).join(''));
    }
    const first = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW + 1 });
    expect(first.mode).toBe('enforcing'); // grace starts
    const out = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW + 1 + READINESS_CACHE_TTL_MS + DEMOTE_AFTER_FAILING_MS });
    expect(out.transition).toBe('demote');
    expect(transitions().map((t) => t.to)).toEqual(['enforcing', 'shadow']);
  });
});

describe('#509 readiness state is inside the guarded approval store', () => {
  it('lives in the approvals directory', () => {
    const home = mkdtempSync(join(tmpdir(), 'sc-readiness-home-'));
    try {
      const p = readinessPaths({ home });
      expect(p.statePath.startsWith(approvalsDir(home))).toBe(true);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('stays in the approval store even under a SHIELDCORTEX_CONFIG_DIR override (the path rules key on ~/.shieldcortex/approvals)', () => {
    const saved = process.env.SHIELDCORTEX_CONFIG_DIR;
    process.env.SHIELDCORTEX_CONFIG_DIR = join(root, 'elsewhere-config');
    try {
      const p = readinessPaths();
      expect(p.statePath).toBe(join(approvalsDir(), 'guard-readiness.json'));
      expect(p.auditDir).toBe(join(root, 'elsewhere-config', 'audit'));
    } finally {
      if (saved === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
      else process.env.SHIELDCORTEX_CONFIG_DIR = saved;
    }
  });

  it('the state file, its lock and its temp file match touch-approval-store on the core AND both WS2 fallback lists', () => {
    const repo = join(__dirname_509(), '..', '..', '..', '..');
    const ruleFrom = (file: string): RegExp => {
      const text = readFileSync(join(repo, file), 'utf8');
      const m = /\{ re: \/(.+?)\/(\w*), signal: 'touch-approval-store' \}/.exec(text);
      expect(m).not.toBeNull();
      return new RegExp(m![1], m![2]);
    };
    const rules = {
      core: ruleFrom('src/defence/iron-dome/tool-action-guard.ts'),
      hookFallback: ruleFrom('scripts/pre-tool-hook.mjs'),
      openclawFallback: ruleFrom('plugins/openclaw/interceptor.ts'),
    };
    const state = readinessPaths({ home: '/home/u' }).statePath;
    for (const target of [state, `${state}.lock`, `${state}.1234.tmp`, '~/.shieldcortex/approvals/guard-readiness.json']) {
      for (const [name, re] of Object.entries(rules)) {
        expect([name, re.test(target)]).toEqual([name, true]);
      }
    }
    for (const command of [
      'rm ~/.shieldcortex/approvals/guard-readiness.json.lock',
      'mv /tmp/x ~/.shieldcortex/approvals/guard-readiness.json',
      'cp /tmp/x ~/.shieldcortex/approvals/guard-readiness.json',
    ]) {
      const v = evaluateToolCall('Bash', { command });
      expect([command, v.decision === 'allow']).toEqual([command, false]);
      expect(v.signals).toContain('touch-approval-store');
    }
    for (const tool of ['Edit', 'Write'] as const) {
      const v = evaluateToolCall(tool, { file_path: '/home/u/.shieldcortex/approvals/guard-readiness.json', content: '{}', old_string: 'a', new_string: 'b' });
      expect([tool, v.decision === 'allow']).toEqual([tool, false]);
    }
  });

  it('a policy lock (locked or unverifiable) drops the readiness gate from the effective config', () => {
    const raw = { actionGuard: { enabled: true, enforce: true, readinessGate: true }, interceptor: { actionGuard: { readinessGate: true } } };
    const locked = applyPolicyLock(raw, { status: 'locked', policy: { actionGuard: { enforce: true } } } as never);
    expect((locked.actionGuard as Record<string, unknown>).readinessGate).toBeUndefined();
    const lockedOther = applyPolicyLock(raw, { status: 'locked', policy: { defenceMode: 'strict' } } as never);
    expect((lockedOther.actionGuard as Record<string, unknown>).readinessGate).toBeUndefined();
    const strict = applyStrictFailClosedPosture(raw);
    expect((strict.actionGuard as Record<string, unknown>).readinessGate).toBeUndefined();
    expect(((strict.interceptor as Record<string, unknown>).actionGuard as Record<string, unknown>).readinessGate).toBeUndefined();
    // Unlocked: untouched.
    expect(applyPolicyLock(raw, { status: 'absent' } as never)).toBe(raw);
  });

  it('an agent write to it is gated by the existing touch-approval-store rule', () => {
    for (const command of [
      'echo \'{"version":1,"mode":"shadow"}\' > ~/.shieldcortex/approvals/guard-readiness.json',
      'rm ~/.shieldcortex/approvals/guard-readiness.json',
    ]) {
      const v = evaluateToolCall('Bash', { command });
      expect(v.decision).not.toBe('allow');
      expect(v.signals).toContain('touch-approval-store');
    }
    const w = evaluateToolCall('Write', { file_path: `${process.env.HOME ?? '/home/u'}/.shieldcortex/approvals/guard-readiness.json`, content: '{}' });
    expect(w.decision).not.toBe('allow');
  });
});

// ── Addendum 1 (B): effectiveness evidence is its own condition ─────────────

describe('#509 effectiveness evidence (Addendum 1 B)', () => {
  function perfectProxies(): void {
    write(calls(1000, 0));
    write(reach(30, 0));
  }
  const reviewed = (over: Partial<Record<string, unknown>> = {}) => ({
    adapter: PIN.adapter,
    policy: PIN.policy,
    reviewedAt: new Date(NOW - DAY).toISOString(),
    reviewedBy: 'independent reviewer (test fixture)',
    reference: 'test-fixture://not-shipped',
    cases: 200,
    ...over,
  });

  it('option A: always REQUIRED — a legacy `requireEffectivenessEvidence: false` is not read', () => {
    perfectProxies();
    const legacy = { requireEffectivenessEvidence: false } as object;
    expect(computeReadiness({ channel: CHANNEL, paths, now: NOW, ...legacy }).ready).toBe(false);
  });

  it('no evidence ships: the reviewed registry is empty and frozen', () => {
    expect(REVIEWED_EFFECTIVENESS_EVIDENCE).toHaveLength(0);
    expect(Object.isFrozen(REVIEWED_EFFECTIVENESS_EVIDENCE)).toBe(true);
  });

  it('REQUIRED (default): perfect proxies never promote, and the output says exactly what it awaits', () => {
    perfectProxies();
    const r = computeReadiness({ channel: CHANNEL, paths, now: NOW });
    expect(r.proxiesMet).toBe(true);
    expect(r.effectiveness).toEqual({ evidence: null, pass: false, missing: expect.any(String) });
    expect(r.ready).toBe(false);
    expect(r.missing).toEqual(['operability proxies met; awaiting reviewed effectiveness evidence']);
    expect(AWAITING_EFFECTIVENESS_MESSAGE).toBe('operability proxies met; awaiting reviewed effectiveness evidence');
    for (let i = 0; i < 5; i += 1) {
      const out = resolveReadiness({ channel: CHANNEL, paths, now: NOW + i * READINESS_CACHE_TTL_MS * 7 });
      expect(out.mode).toBe('shadow');
      expect(out.transition).toBeNull();
    }
  });

  it('REQUIRED with proxies not met: lists every missing item, the evidence included', () => {
    write(calls(100, 0));
    const r = computeReadiness({ channel: NO_CHANNEL, paths, now: NOW });
    expect(r.ready).toBe(false);
    expect(r.missing).not.toContain(AWAITING_EFFECTIVENESS_MESSAGE);
    expect(r.missing.some((m) => /only 100 of the 500/.test(m))).toBe(true);
    expect(r.missing.some((m) => /no human approval channel/.test(m))).toBe(true);
    expect(r.missing.some((m) => /reviewed effectiveness evidence/.test(m))).toBe(true);
  });

  it('reviewed evidence for this pin in the build: the same perfect proxies promote', () => {
    perfectProxies();
    const r = computeReadiness({ channel: CHANNEL, paths, now: NOW, ...WITH_REVIEWED });
    expect(r.ready).toBe(true);
    expect(r.missing).toEqual([]);
    const out = resolveReadiness({ channel: CHANNEL, paths, now: NOW, ...WITH_REVIEWED });
    expect(out.mode).toBe('enforcing');
    expect(out.transition).toBe('promote');
  });

  it('only reviewed evidence pinned to THIS adapter + policy version, fresh and big enough, counts (test-only registry)', () => {
    perfectProxies();
    const at = (registry: ReturnType<typeof reviewed>[]) =>
      computeReadiness({ channel: CHANNEL, paths, now: NOW, effectivenessRegistry: registry }).ready;
    expect(at([reviewed()])).toBe(true);
    expect(at([reviewed({ policy: 'tool-action-guard:0000000000000000' })])).toBe(false);
    expect(at([reviewed({ adapter: 'claude-code-hook@0.0.0' })])).toBe(false);
    expect(at([reviewed({ reviewedAt: new Date(NOW - 91 * DAY).toISOString() })])).toBe(false);
    expect(at([reviewed({ reviewedAt: new Date(NOW + DAY).toISOString() })])).toBe(false);
    expect(at([reviewed({ cases: 3 })])).toBe(false);
    expect(at([reviewed({ reviewedBy: ' ' })])).toBe(false);
  });
});

// ── Addendum 1 (C): pinning, freshness, and unsound evidence ────────────────

describe('#509 evidence pinning and soundness (Addendum 1 C)', () => {
  const OTHER: ReadinessPin = { adapter: 'claude-code-hook@0.0.1', policy: 'tool-action-guard:ffffffffffffffff' };

  it('the pin in force names the adapter and a digest of the guard rules', () => {
    expect(PIN.adapter).toMatch(/^claude-code-hook@\d+\.\d+\.\d+/);
    expect(PIN.policy).toMatch(/^tool-action-guard:[0-9a-f]{16}$/);
  });

  it('rows pinned to another version, and unpinned rows, are not counted', () => {
    const rows = calls(1000, 0).map((r) => ({ ...r, readinessPin: OTHER }));
    const unpinned = reach(30, 0).map((r) => {
      const { readinessPin: _drop, ...rest } = r;
      return rest;
    });
    write(rows);
    write(unpinned);
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.intervention.total).toBe(0);
    expect(r.intervention.otherVersion).toBe(1000);
    expect(r.reachability.resolved).toBe(0);
    expect(r.ready).toBe(false);
  });

  it('a version change invalidates earlier evidence — and a cached mode computed under the old pin', () => {
    write(calls(1000, 0));
    write(reach(30, 0));
    expect(resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW }).mode).toBe('enforcing');
    const after = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW + 1, pin: OTHER });
    expect(after.ready).toBe(false);
    expect(after.intervention.otherVersion).toBe(1000);
    // Inside the old TTL, but the pin changed: recomputed, not served from cache.
    const again = resolveReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW + 1, pin: OTHER });
    expect(again.cached).toBe(false);
    expect(again.report?.ready).toBe(false);
  });

  it('an undeterminable pin is never ready', () => {
    write(calls(1000, 0));
    write(reach(30, 0));
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW, pin: null });
    expect(r.ready).toBe(false);
    expect(r.integrity.pass).toBe(false);
    expect(r.missing.join('\n')).toMatch(/could not be determined/);
  });

  it('missing audit directory ⇒ not ready', () => {
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(existsSync(paths.auditDir)).toBe(false);
    expect(r.ready).toBe(false);
    expect(r.intervention.total).toBe(0);
  });

  it('empty audit directory, and an empty evidence file ⇒ not ready', () => {
    mkdirSync(paths.auditDir, { recursive: true });
    expect(computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW }).ready).toBe(false);
    writeFileSync(join(paths.auditDir, `realtime-${new Date(NOW).toISOString().slice(0, 10)}.jsonl`), '');
    expect(computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW }).ready).toBe(false);
  });

  it('an unparseable evidence line ⇒ not ready, even when the rest would pass', () => {
    write(calls(1000, 0));
    write(reach(30, 0));
    expect(computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW }).ready).toBe(true);
    appendFileSync(join(paths.auditDir, `realtime-${new Date(NOW - DAY).toISOString().slice(0, 10)}.jsonl`), '{"type":"intercept","origin":"claude-code-hook",CORRUPT\n');
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.integrity.unparseableLines).toBe(1);
    expect(r.ready).toBe(false);
    expect(r.missing.join('\n')).toMatch(/malformed audit record/);
  });

  it('a trailing append still in flight (no newline) is not counted as corrupt', () => {
    write(calls(1000, 0));
    write(reach(30, 0));
    appendFileSync(join(paths.auditDir, `realtime-${new Date(NOW - DAY).toISOString().slice(0, 10)}.jsonl`), '{"type":"intercept","origin":"claude-code-h');
    const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    expect(r.integrity.unparseableLines).toBe(0);
    expect(r.ready).toBe(true);
  });

  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  (asRoot ? it.skip : it)('an unreadable evidence file ⇒ not ready, even when the rest would pass', () => {
    write(calls(1000, 0));
    write(reach(30, 0));
    const f = join(paths.auditDir, `realtime-${new Date(NOW - 3 * DAY).toISOString().slice(0, 10)}.jsonl`);
    expect(existsSync(f)).toBe(true);
    chmodSync(f, 0o000);
    try {
      const r = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
      expect(r.integrity.unreadableFiles).toBe(1);
      expect(r.ready).toBe(false);
      expect(r.missing.join('\n')).toMatch(/could not be read/);
    } finally {
      chmodSync(f, 0o600);
    }
  });
});

describe('#654 P9 — per-row auditEventId dedup collapses only a physical duplicate', () => {
  it('distinct ID rows count exactly as before; the same file reached through two dirs counts once', () => {
    write(calls(600, 6));
    const once = computeReadiness({ ...WITH_REVIEWED, channel: CHANNEL, paths, now: NOW });
    const twice = computeReadiness({
      ...WITH_REVIEWED, channel: CHANNEL, now: NOW,
      paths: { ...paths, readAuditDirs: [paths.auditDir, paths.auditDir] },
    });
    expect(once.intervention.total).toBe(600);
    expect(twice.intervention.total).toBe(600);
    expect(twice.intervention.rate).toBeCloseTo(once.intervention.rate as number, 10);
  });

  it('control: ID-less rows have nothing to join on, so the doubled read counts them twice', () => {
    write(calls(600, 6).map(({ auditEventId: _id, ...rest }) => rest));
    const twice = computeReadiness({
      ...WITH_REVIEWED, channel: CHANNEL, now: NOW,
      paths: { ...paths, readAuditDirs: [paths.auditDir, paths.auditDir] },
    });
    expect(twice.intervention.total).toBe(1200);
  });
});
