import { describe, expect, it } from '@jest/globals';
import {
  createInterceptor,
  DEFAULT_CONFIG,
  type InterceptAuditEntry,
  type ReadinessRuntime,
} from '../interceptor.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { createSessionTaintStore } from '../session-taint.js';

/**
 * #999 — a session-taint escalation is a SCANNED stop, not an unscanned one.
 *
 * `escalateForTaint` turns a dangerous-tier `require_approval` into `block`.
 * The #436 residual arm (`decision === 'block' && !terminalBlock`) then read
 * that block as one the guard never scanned, so watch-only (`enforce:false`)
 * and enforce-when-ready shadow both skipped their warn-and-proceed exits and
 * a headless run was denied by the failure policy. That is the 4 Nov nightly
 * red-team rejection (cron 96fa49e3): `exec` allow → require_approval warned
 * and ran, then the next `exec` require_approval → block was denied.
 *
 * The contract this file pins, driven through the REAL guard and the REAL
 * interceptor:
 *   - watch-only and shadow: a taint-minted block warns / is recorded as the
 *     stop it would have been, with `escalated` on the row, and proceeds;
 *   - enforce: unchanged — no allowlist, broker pre-clear or failure policy
 *     releases it;
 *   - #436 (schema-invalid), a block the guard minted before escalation,
 *     the catastrophic tier and the self-protection floor: unchanged in
 *     every posture.
 *
 * Catastrophic command text cannot be written into this file (the Action
 * Guard refuses it: write-content-catastrophic), so that tier — and a
 * sub-catastrophic block no shipped rule mints today — are driven with the
 * verdict for them through a wrapped evaluator, as in
 * enforce-when-ready-509.test.ts.
 */

const SESSION = 'agent:main:cron:96fa49e3';
const TAINT_REASON = 'conversation scan: MEDIUM (1 detections)';

// Tiers verified against the real guard in the premise test below.
const SENSITIVE_EXEC = { toolName: 'exec', arguments: { command: 'npm install left-pad' } };
const DANGEROUS_EXEC = { toolName: 'exec', arguments: { command: 'cat ~/.aws/credentials' } };
const SCHEMA_INVALID = { toolName: 'Bash', arguments: { command: 'ls', evil: 'x' } };
const FLOOR_WRITE = { toolName: 'exec', arguments: { command: 'echo {} > ~/.shieldcortex/config.json' } };
const CATASTROPHIC_MARK = 'sc-test-catastrophic-tier';
const NATIVE_BLOCK_MARK = 'sc-test-native-sub-catastrophic-block';

const evaluator = ((tool: string, args: Record<string, unknown>, ...rest: unknown[]) => {
  if (args?.command === CATASTROPHIC_MARK) {
    return { decision: 'block', severity: 'catastrophic', family: 'fs', action: 'recursive-delete', reason: 'catastrophic (test)', signals: ['recursive-force-delete'] };
  }
  if (args?.command === NATIVE_BLOCK_MARK) {
    return { decision: 'block', severity: 'dangerous', family: 'exec', action: 'future-rule', reason: 'sub-catastrophic block minted by a rule (test)', signals: ['future-rule'] };
  }
  return (evaluateToolCall as (...a: unknown[]) => unknown)(tool, args, ...rest);
}) as never;

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

/** enforce-when-ready that has not met its readiness conditions. */
function shadowReadiness(): ReadinessRuntime {
  return {
    resolve: async () => ({ mode: 'shadow', transition: null }),
    pin: () => ({ adapter: 'openclaw-interceptor@test', policy: 'test' }),
    channelConfigured: () => false,
    recordReach: () => {},
    newAttemptId: () => 'attempt-test',
    describeDemotion: () => 'demoted (test)',
    announce: async () => null,
  };
}

/** A broker that would pre-clear anything it is shown. The shipped decision
 *  core never pre-clears a `block`; this stands for one that did, so the
 *  interceptor's own exclusion is what is under test. */
function preClearingBroker() {
  return {
    config: {
      enabled: true,
      model: 'fixture',
      judgeTimeoutMs: 1_000,
      allowPreClear: true,
      preClearConfidence: 0,
      approvalTimeoutMs: { sensitive: 60_000, dangerous: 60_000 },
    },
    runJudge: async () => null,
    brokerDecision: () => ({ outcome: 'pre_clear', reason: 'fixture: pre-clear everything', audit: { fixture: 'pre-clear' } }),
    timeoutOutcome: () => 'approve',
    approvalTimeoutMs: () => 60_000,
  };
}

type Posture = 'watch-only' | 'shadow' | 'enforce';

function build(posture: Posture, opts: { tainted?: boolean; autoApprove?: string[]; broker?: unknown } = {}) {
  const audits: InterceptAuditEntry[] = [];
  const warnings: string[] = [];
  const store = createSessionTaintStore();
  if (opts.tainted !== false) store.mark(SESSION, { severity: 'medium', reason: TAINT_REASON });

  const i = createInterceptor(
    {
      ...DEFAULT_CONFIG,
      actionGuard: {
        ...DEFAULT_CONFIG.actionGuard,
        enabled: true,
        enforce: posture !== 'watch-only',
        ...(posture === 'shadow' ? { readinessGate: true } : {}),
        autoApprove: opts.autoApprove ?? [],
      },
      logger: { info: () => {}, warn: (m: string) => { warnings.push(m); } },
    } as never,
    okPipeline as never,
    {
      evaluateToolCall: evaluator,
      onAuditEntry: (e: InterceptAuditEntry) => audits.push(e),
      sessionTaint: (id: string | undefined) => {
        const rec = id ? store.get(id) : null;
        return rec ? { reason: rec.reason } : null;
      },
      ...(posture === 'shadow' ? { readiness: shadowReadiness() } : {}),
      ...(opts.broker ? { broker: opts.broker } : {}),
    } as never,
  );
  return { i, audits, warnings };
}

type Outcome = 'proceeded' | 'card' | 'denied';

/** One call in SESSION. Unattended (no approver) unless `attended`. */
async function call(
  i: { handleToolCall: (ctx: never) => Promise<void> },
  c: { toolName: string; arguments: Record<string, unknown> },
  attended = false,
): Promise<{ outcome: Outcome; error?: string }> {
  let asked = false;
  const ctx = {
    ...c,
    sessionId: SESSION,
    ...(attended ? { requireApproval: async () => { asked = true; return false; } } : {}),
  };
  try {
    await i.handleToolCall(ctx as never);
    return { outcome: asked ? 'card' : 'proceeded' };
  } catch (err) {
    return { outcome: asked ? 'card' : 'denied', error: err instanceof Error ? err.message : String(err) };
  }
}

const TAINT_ESCALATION = { by: 'session-taint', from: 'require_approval', to: 'block', reason: TAINT_REASON };

describe('#999 premise — the tiers this file relies on, from the real guard', () => {
  it('the exec calls and the schema-invalid bag are the tiers the cases below assume', () => {
    const tier = (c: { toolName: string; arguments: Record<string, unknown> }) => {
      const v = evaluateToolCall(c.toolName, c.arguments);
      return { decision: v.decision, severity: v.severity, schemaInvalid: v.signals.includes('invalid-tool-input') };
    };
    expect(tier(SENSITIVE_EXEC)).toEqual({ decision: 'allow', severity: 'sensitive', schemaInvalid: false });
    expect(tier(DANGEROUS_EXEC)).toEqual({ decision: 'require_approval', severity: 'dangerous', schemaInvalid: false });
    expect(tier(SCHEMA_INVALID)).toEqual({ decision: 'require_approval', severity: 'dangerous', schemaInvalid: true });
    const floor = evaluateToolCall(FLOOR_WRITE.toolName, FLOOR_WRITE.arguments);
    expect({ decision: floor.decision, severity: floor.severity }).toEqual({ decision: 'require_approval', severity: 'dangerous' });
    expect(floor.signals).toContain('touch-guard-config');
  });
});

describe('#999 — watch-only (enforce:false): a taint-escalated dangerous exec warns and proceeds', () => {
  it('replays the 4 Nov cron sequence: both calls proceed, each with a warn row carrying `escalated`', async () => {
    const { i, audits, warnings } = build('watch-only');

    // 04:30:22Z — allow → require_approval (this one already proceeded on 5.17.3).
    expect(await call(i, SENSITIVE_EXEC)).toEqual({ outcome: 'proceeded' });
    // 04:30:26Z — require_approval → block. The call that was denied.
    expect(await call(i, DANGEROUS_EXEC)).toEqual({ outcome: 'proceeded' });

    const rows = audits.filter((e) => e.escalated !== undefined);
    expect(rows.map((e) => ({ action: e.action, outcome: e.outcome, escalated: e.escalated }))).toEqual([
      { action: 'warn', outcome: 'warned', escalated: { by: 'session-taint', from: 'allow', to: 'require_approval', reason: TAINT_REASON } },
      { action: 'warn', outcome: 'warned', escalated: TAINT_ESCALATION },
    ]);
    expect(audits.some((e) => e.outcome === 'failure_denied' || e.outcome === 'auto_denied')).toBe(false);

    // The operator still sees the escalation AND the advisory warn for the
    // dangerous call — watch-only is loud, not silent.
    expect(warnings.some((w) => w.includes('ESCALATED exec: require_approval → block'))).toBe(true);
    expect(warnings.some((w) => w.includes('Action Guard: exec') && w.includes('ESCALATED by tainted session'))).toBe(true);
    expect(warnings.some((w) => /DENIED|BLOCKED/.test(w))).toBe(false);
  });

  it('attended: the operator is not paged — watch-only does not ask', async () => {
    const { i, audits } = build('watch-only');
    expect(await call(i, DANGEROUS_EXEC, true)).toEqual({ outcome: 'proceeded' });
    expect(audits.filter((e) => e.escalated).map((e) => e.outcome)).toEqual(['warned']);
  });

  it('a matching autoApprove entry does not release it — the posture does, and the row says so', async () => {
    // The allowlist is an operator release; a taint escalation is exactly
    // what it must not quietly absorb. Under watch-only the call proceeds on
    // the advisory exit, recorded as `warned` with `escalated`, not `approved`.
    const { i, audits } = build('watch-only', { autoApprove: ['touch-sensitive-path'] });
    expect(await call(i, DANGEROUS_EXEC)).toEqual({ outcome: 'proceeded' });
    expect(audits.filter((e) => e.escalated).map((e) => e.outcome)).toEqual(['warned']);
  });
});

describe('#999 — enforce-when-ready shadow: a taint-escalated dangerous exec is recorded and proceeds', () => {
  it('unattended: a `would_block` shadow row with `escalated`, and the call proceeds', async () => {
    const { i, audits, warnings } = build('shadow');
    expect(await call(i, SENSITIVE_EXEC)).toEqual({ outcome: 'proceeded' });
    expect(await call(i, DANGEROUS_EXEC)).toEqual({ outcome: 'proceeded' });

    const row = audits.find((e) => e.escalated?.to === 'block');
    expect(row).toMatchObject({
      action: 'require_approval',
      outcome: 'would_block',
      shadow: true,
      posture: 'enforce-when-ready',
      escalated: TAINT_ESCALATION,
    });
    expect(audits.some((e) => e.outcome === 'failure_denied' || e.outcome === 'auto_denied')).toBe(false);
    expect(warnings.some((w) => w.includes('would have BLOCKED exec'))).toBe(true);
  });

  it('attended: a `would_hold` shadow row, and no approver is asked', async () => {
    const { i, audits } = build('shadow');
    expect(await call(i, DANGEROUS_EXEC, true)).toEqual({ outcome: 'proceeded' });
    expect(audits.filter((e) => e.escalated).map((e) => ({ outcome: e.outcome, shadow: e.shadow }))).toEqual([
      { outcome: 'would_hold', shadow: true },
    ]);
  });
});

describe('#999 — enforce: a taint escalation still stops the call', () => {
  it('unattended: denied by the failure policy, with `escalated` on the row', async () => {
    const { i, audits } = build('enforce');
    const r = await call(i, DANGEROUS_EXEC);
    expect(r.outcome).toBe('denied');
    expect(r.error).toMatch(/no approver, failure policy: deny/);
    expect(audits.filter((e) => e.escalated).map((e) => ({ outcome: e.outcome, escalated: e.escalated }))).toEqual([
      { outcome: 'failure_denied', escalated: TAINT_ESCALATION },
    ]);
  });

  it('attended: the operator is asked', async () => {
    const { i } = build('enforce');
    expect((await call(i, DANGEROUS_EXEC, true)).outcome).toBe('card');
  });

  it('a matching autoApprove entry releases the clean call but NOT the taint-escalated one', async () => {
    const autoApprove = ['touch-sensitive-path'];
    const clean = build('enforce', { tainted: false, autoApprove });
    expect(await call(clean.i, DANGEROUS_EXEC)).toEqual({ outcome: 'proceeded' });
    expect(clean.audits.map((e) => e.outcome)).toContain('approved');

    const { i, audits } = build('enforce', { autoApprove });
    expect((await call(i, DANGEROUS_EXEC)).outcome).toBe('denied');
    expect(audits.some((e) => e.outcome === 'approved')).toBe(false);
  });

  it('a broker pre-clear releases the clean call but NOT the taint-escalated one', async () => {
    const clean = build('enforce', { tainted: false, broker: preClearingBroker() });
    expect(await call(clean.i, DANGEROUS_EXEC, true)).toEqual({ outcome: 'proceeded' });
    expect(clean.audits.map((e) => e.outcome)).toContain('approved');

    const { i, audits } = build('enforce', { broker: preClearingBroker() });
    expect((await call(i, DANGEROUS_EXEC, true)).outcome).toBe('card');
    expect(audits.some((e) => e.outcome === 'approved')).toBe(false);
  });
});

describe('#999 — floors that stay non-advisory in a tainted session', () => {
  for (const posture of ['watch-only', 'shadow'] as const) {
    it(`${posture}: a schema-invalid bag (#436) is still denied unattended, never warned or shadowed`, async () => {
      const { i, audits } = build(posture);
      const r = await call(i, SCHEMA_INVALID);
      expect(r.outcome).toBe('denied');
      expect(audits.map((e) => e.outcome)).toEqual(['failure_denied']);
      // Escalation still happened and is still recorded; it does not launder
      // the unscanned bag into a scanned one.
      expect(audits[0].escalated).toEqual(TAINT_ESCALATION);
    });

    it(`${posture}: a block the guard minted BEFORE escalation is still denied (#436 residual arm)`, async () => {
      const { i, audits } = build(posture);
      const r = await call(i, { toolName: 'exec', arguments: { command: NATIVE_BLOCK_MARK } });
      expect(r.outcome).toBe('denied');
      expect(audits.map((e) => e.outcome)).toEqual(['failure_denied']);
      // Taint did not change this verdict, so it carries no escalation.
      expect(audits[0].escalated).toBeUndefined();
    });

    it(`${posture}: the catastrophic tier still hard-blocks`, async () => {
      const { i, audits } = build(posture);
      const r = await call(i, { toolName: 'exec', arguments: { command: CATASTROPHIC_MARK } }, true);
      expect(r.outcome).toBe('denied');
      expect(r.error).toMatch(/tool call blocked — catastrophic \(test\)/);
      expect(audits.map((e) => e.outcome)).toEqual(['auto_denied']);
    });

    it(`${posture}: the self-protection floor is still denied unattended`, async () => {
      const { i, audits } = build(posture);
      const r = await call(i, FLOOR_WRITE);
      expect(r.outcome).toBe('denied');
      // #853 ruling §1: the self-protection floor is ALWAYS-BLOCK — denied up
      // front as `auto_denied` (parity with the Claude Code hook), before any
      // unattended/failure-policy exit. The taint escalation is still recorded.
      expect(audits.map((e) => ({ outcome: e.outcome, escalated: e.escalated }))).toEqual([
        { outcome: 'auto_denied', escalated: TAINT_ESCALATION },
      ]);
    });
  }
});
