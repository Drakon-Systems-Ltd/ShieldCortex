import { describe, expect, it } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../interceptor.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { createSessionTaintStore } from '../session-taint.js';

/**
 * Issue #233 — the WIRING half.
 *
 * The pure escalation policy is unit-tested in
 * src/__tests__/session-taint-233.test.ts. That proves nothing about whether a
 * real tool call is actually escalated: PR #226 shipped a policy function with
 * no working call site, and #222 shipped a reconciler state doctor never read.
 * This file drives the REAL guard through the REAL interceptor and asserts the
 * decision changes — delete the escalation block in runActionGuard and these go
 * red.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

function run(taintedSessions: string[] = []) {
  const captured: InterceptAuditEntry[] = [];
  const store = createSessionTaintStore();
  for (const s of taintedSessions) store.mark(s, { reason: 'conversation scan: HIGH (2 detections)' });

  const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, {
    evaluateToolCall: evaluateToolCall as never,
    onAuditEntry: (e) => captured.push(e),
    sessionTaint: (sessionId) => {
      const rec = sessionId ? store.get(sessionId) : null;
      return rec ? { reason: rec.reason } : null;
    },
  });
  return { i, captured, store };
}

// Tiers verified against the real guard, not assumed: this is `dangerous`
// (normally require_approval, which fails closed and throws when unattended).
const DANGEROUS_CALL = { toolName: 'Bash', arguments: { command: 'cat ~/.aws/credentials' } };
// Verified tiers: this is `sensitive` and normally ALLOWS outright — the case
// where escalation is most visible, because a clean session never even gates it.
const SENSITIVE_CALL = { toolName: 'Bash', arguments: { command: 'npm install left-pad' } };

describe('#233 — a clean session behaves exactly as before', () => {
  it('does not escalate when no conversation detection happened', async () => {
    const { i, captured } = run();
    await i.handleToolCall({ ...SENSITIVE_CALL, sessionId: 'clean-session' }).catch(() => {});
    expect(captured.some(e => e.escalated !== undefined)).toBe(false);
  });

  it('does not escalate when the call carries no session id at all', async () => {
    // Absent session must mean "no escalation", never a default-tainted state.
    const { i, captured } = run(['some-other-session']);
    await i.handleToolCall(SENSITIVE_CALL).catch(() => {});
    expect(captured.some(e => e.escalated !== undefined)).toBe(false);
  });

  it('does not leak taint from one session to another', async () => {
    const { i, captured } = run(['poisoned']);
    await i.handleToolCall({ ...SENSITIVE_CALL, sessionId: 'innocent' }).catch(() => {});
    expect(captured.some(e => e.escalated !== undefined)).toBe(false);
  });
});

describe('#233 — a tainted session is tightened', () => {
  it('escalates a call in the tainted session, and records why', async () => {
    const { i, captured } = run(['poisoned']);
    await i.handleToolCall({ ...DANGEROUS_CALL, sessionId: 'poisoned' }).catch(() => {});

    const row = captured.find(e => e.escalated !== undefined);
    expect(row).toBeDefined();
    // The audit must record it STRUCTURALLY and say why — an escalated denial
    // has to be tellable from a natively dangerous one after the fact, and the
    // entry has no reason field to hide it in.
    expect(row?.escalated?.by).toBe('session-taint');
    expect(row?.escalated?.from).toBe('require_approval');
    expect(row?.escalated?.to).toBe('block');
    expect(row?.escalated?.reason).toMatch(/conversation scan/i);
  });

  it('escalates SENSITIVE work from a silent allow to an approval', async () => {
    // The headline case: on a clean session this passes without gating at all.
    // In a tainted session it must start asking — that is the whole mechanism.
    const clean = run();
    await clean.i.handleToolCall({ ...SENSITIVE_CALL, sessionId: 'clean' }).catch(() => {});
    expect(clean.captured.some(e => e.escalated !== undefined)).toBe(false);

    const { i, captured } = run(['poisoned']);
    await i.handleToolCall({ ...SENSITIVE_CALL, sessionId: 'poisoned' }).catch(() => {});
    const row = captured.find(e => e.escalated !== undefined);
    expect(row?.escalated?.from).toBe('allow');
    expect(row?.escalated?.to).toBe('require_approval');
  });

  it('benign work in a tainted session still runs', async () => {
    // The property that keeps the agent usable: an agent that cannot read a
    // file is useless, and a taint response that halts ordinary work is one
    // operators will switch off.
    const { i } = run(['poisoned']);
    await expect(
      i.handleToolCall({ toolName: 'Read', arguments: { file_path: '/tmp/x.txt' }, sessionId: 'poisoned' }),
    ).resolves.not.toThrow();
  });

  it('stops escalating once the taint has expired', async () => {
    const { i, captured, store } = run();
    store.mark('poisoned', { reason: 'conversation scan: HIGH', nowMs: 1_000, ttlMs: 1 });
    // Well past the window — get() prunes and returns null.
    await i.handleToolCall({ ...SENSITIVE_CALL, sessionId: 'poisoned' }).catch(() => {});
    expect(captured.some(e => e.escalated !== undefined)).toBe(false);
  });
});

describe('#233 — a broken taint lookup can never create denials', () => {
  it('a throwing lookup leaves the guard exactly as it was', async () => {
    // Fail-soft by construction: taint is an ESCALATION input, so a broken
    // scanner must degrade to today's behaviour, never to new blocks.
    const captured: InterceptAuditEntry[] = [];
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, {
      evaluateToolCall: evaluateToolCall as never,
      onAuditEntry: (e) => captured.push(e),
      sessionTaint: () => { throw new Error('taint store exploded'); },
    });
    await expect(
      i.handleToolCall({ toolName: 'Read', arguments: { file_path: '/tmp/x.txt' }, sessionId: 's' }),
    ).resolves.not.toThrow();
    expect(captured.some(e => e.escalated !== undefined)).toBe(false);
  });

  it('no taint lookup wired at all is simply the old behaviour', async () => {
    const captured: InterceptAuditEntry[] = [];
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, {
      evaluateToolCall: evaluateToolCall as never,
      onAuditEntry: (e) => captured.push(e),
    });
    await i.handleToolCall({ ...SENSITIVE_CALL, sessionId: 's' }).catch(() => {});
    expect(captured.some(e => e.escalated !== undefined)).toBe(false);
  });
});
