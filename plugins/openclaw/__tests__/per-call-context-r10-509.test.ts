import { describe, expect, it } from '@jest/globals';

import { createInterceptor, DEFAULT_CONFIG } from '../interceptor.js';

/**
 * #509 round 10 — per-call evidence context (Tars, PR #610 scoped r7–r9 check
 * at 8a6fa9dc).
 *
 * The interceptor kept the in-flight call's session, args and readiness pin in
 * shared closure variables, and r8 SF6 "restored" them after the readiness
 * await. But the call yields again after that — in the broker and in the
 * approval request — and the card's decision row snapshotted whatever the
 * shared variables held by then. A second call running in that window made
 * the first call's row lose its pin (dropping a real intervention out of
 * readiness evidence) and carry the other call's session and args.
 *
 * Each case holds call A at one of those awaits, runs call B through a
 * different exit, then lets A mint its card and records the operator's
 * answer. A's decision row must be A's: session-A, fixture-A args, the pin.
 *
 * These drive the built handler with stub seams. They are not a real gateway.
 */

const PIN = { adapter: 'openclaw-interceptor@test', policy: 'r10-fixture-policy' };
const A_ARGS = { command: 'fixture-A' };
const DANGEROUS = {
  decision: 'require_approval', severity: 'dangerous', family: 'exec', action: 'r10-fixture',
  reason: 'fixture: dangerous', signals: ['r10-fixture-signal'],
};

type Captured = { entry: Record<string, unknown>; args: Record<string, unknown> | undefined };
type Call = Record<string, unknown>;

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

function deferred<T = void>(): { promise: Promise<T>; resolve: (v: T) => void } {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => { resolve = r; });
  return { promise, resolve };
}

function typedCard(): Error {
  const err = new Error('fixture card');
  err.name = 'TypedApprovalRequest';
  return err;
}

/** A broker stub whose judge waits on `judging` — the runBroker await. */
function heldBroker(entered: () => void, judging: Promise<void>) {
  return {
    config: {
      enabled: true, judgeTimeoutMs: 60_000, allowPreClear: false, preClearConfidence: 0.99,
      approvalTimeoutMs: { sensitive: 60_000, dangerous: 60_000 },
    },
    runJudge: async () => { entered(); await judging; return null; },
    brokerDecision: () => ({ outcome: 'hold', reason: 'fixture: hold for the operator', audit: { fixture: 'broker-held' } }),
    timeoutOutcome: () => 'deny',
    approvalTimeoutMs: () => 60_000,
  };
}

function build(extra: Record<string, unknown> = {}, config: Record<string, unknown> = {}) {
  const captured: Captured[] = [];
  const i = createInterceptor(
    {
      ...DEFAULT_CONFIG,
      ...config,
      actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, enforce: true, readinessGate: true, autoApprove: [] },
      logger: { info: () => {}, warn: () => {} },
    } as never,
    okPipeline as never,
    {
      evaluateToolCall: (_tool: string, args: Record<string, unknown>) => {
        if (args?.outage === true) throw new Error('fixture evaluator outage');
        if (args?.command === A_ARGS.command) return DANGEROUS;
        return { decision: 'allow', severity: 'benign', family: 'exec', action: 'fixture-benign', reason: 'benign', signals: [] };
      },
      readiness: {
        pin: () => PIN,
        resolve: async () => ({ mode: 'enforce', transition: null }),
        channelConfigured: () => false,
      },
      checkActionLease: (_tool: string, args: Record<string, unknown>) =>
        args?.leaseProbe ? { scope: 'fixture', decision: { verdict: 'deny', reason: 'fixture lease held' } } : null,
      bindAudit: (entry: Record<string, unknown>, args?: Record<string, unknown>) => {
        captured.push({ entry, args: args ? { ...args } : undefined });
        return entry;
      },
      sessionGuard: { keyFor: (id: string | undefined) => id, index: () => {} },
      maxPromptsPerMinute: 10_000,
      ...extra,
    } as never,
  );
  return { i, captured };
}

/**
 * Call A (session-A) is held at `await` — the approval request, or the broker
 * judge when `broker` is set. While it is held, `other` runs to completion.
 * Then A's card is minted and the operator approves once.
 */
async function runOverlap(other: Call | null, opts: { broker?: boolean } = {}) {
  const atHold = deferred();
  const card = deferred();
  const judging = deferred();
  const { i, captured } = build(opts.broker
    ? { broker: heldBroker(() => atHold.resolve(), judging.promise) }
    : {});
  const a = i.handleToolCall({
    toolName: 'Bash',
    arguments: { ...A_ARGS },
    sessionId: 'session-A',
    ...(opts.broker ? { invokeModel: async () => '{}' } : {}),
    requireApproval: () => {
      if (!opts.broker) atHold.resolve();
      return card.promise.then(() => { throw typedCard(); });
    },
  } as never).then(() => null, (e: unknown) => e as Error & { decisionAudit?: (o: string) => void });
  await atHold.promise;
  if (other) await i.handleToolCall(other as never).catch(() => {});
  judging.resolve();
  card.resolve();
  const err = await a;
  expect(err?.name).toBe('TypedApprovalRequest');
  expect(typeof err?.decisionAudit).toBe('function');
  err!.decisionAudit!('approved_once');
  const row = captured.find((r) => r.entry.outcome === 'approved_once');
  expect(row).toBeDefined();
  return { row: row!, captured };
}

function expectAsOwnCall(row: Captured): void {
  expect(row.entry.readinessPin).toEqual(PIN);
  expect(row.entry.sessionKey).toBe('session-A');
  expect(row.args).toEqual(A_ARGS);
}

describe('#509 r10 — a card decision row keeps its own call\'s context across overlapping calls', () => {
  it('sequential control: session-A, fixture-A args and the pin', async () => {
    const { row } = await runOverlap(null);
    expectAsOwnCall(row);
  });

  it('overlap-approval-vs-lease-exit: B refused by the session lease during A\'s hold', async () => {
    const { row, captured } = await runOverlap({ toolName: 'Bash', arguments: { leaseProbe: true }, sessionId: 'session-B' });
    expectAsOwnCall(row);
    // B's own refusal row is B's, and is written before any gate: no pin.
    const b = captured.find((r) => r.entry.outcome === 'auto_denied');
    expect(b?.entry.sessionKey).toBe('session-B');
    expect(b?.args).toEqual({ leaseProbe: true });
    expect(b?.entry.readinessPin).toBeUndefined();
  });

  it('overlap-approval-vs-memory-call: a memory-plane call (no lease) during A\'s hold', async () => {
    const { row, captured } = await runOverlap({
      toolName: 'remember', arguments: { title: 't', content: 'a note to keep' }, sessionId: 'session-B',
    });
    expectAsOwnCall(row);
    const b = captured.find((r) => r.entry.tool === 'remember');
    expect(b?.entry.sessionKey).toBe('session-B');
    expect(b?.entry.readinessPin).toBeUndefined();
  });

  it('overlap-approval-vs-evaluator-outage: B hits the evaluator-outage exit during A\'s hold', async () => {
    const { row, captured } = await runOverlap({ toolName: 'Bash', arguments: { outage: true }, sessionId: 'session-B' });
    expectAsOwnCall(row);
    const b = captured.find((r) => r.entry.firewallResult === 'ACTION_GUARD_FALLBACK');
    expect(b?.entry.sessionKey).toBe('session-B');
    expect(b?.args).toEqual({ outage: true });
    expect(b?.entry.readinessPin).toBeUndefined();
  });

  it('overlap-broker-await: B runs while A awaits the broker judge', async () => {
    const { row } = await runOverlap({ toolName: 'Bash', arguments: { leaseProbe: true }, sessionId: 'session-B' }, { broker: true });
    expectAsOwnCall(row);
    expect(row.entry.broker).toEqual({ fixture: 'broker-held' });
  });

  it('#654 P6: the held call\'s decision row has its own ID, distinct from every row of the overlapping call', async () => {
    const { row, captured } = await runOverlap({ toolName: 'Bash', arguments: { leaseProbe: true }, sessionId: 'session-B' });
    expectAsOwnCall(row);
    const id = row.entry.auditEventId;
    expect(id).toMatch(/^[a-f0-9]{32}$/);
    const others = captured.filter((r) => r !== row);
    expect(others.length).toBeGreaterThan(0);
    for (const r of others) {
      expect(r.entry.auditEventId).toMatch(/^[a-f0-9]{32}$/);
      expect(r.entry.auditEventId).not.toBe(id);
    }
  });

  it('the captured args are a snapshot: mutating the caller\'s params after the hold does not rewrite the row', async () => {
    const atHold = deferred();
    const card = deferred();
    const { i, captured } = build();
    const params: Record<string, unknown> = { ...A_ARGS };
    const a = i.handleToolCall({
      toolName: 'Bash', arguments: params, sessionId: 'session-A',
      requireApproval: () => { atHold.resolve(); return card.promise.then(() => { throw typedCard(); }); },
    } as never).catch((e: unknown) => e as Error & { decisionAudit: (o: string) => void });
    await atHold.promise;
    params.command = 'rewritten-after-hold';
    card.resolve();
    (await a).decisionAudit('approved_once');
    expect(captured.find((r) => r.entry.outcome === 'approved_once')?.args).toEqual(A_ARGS);
  });

  it('the memory-plane card (#372) keeps its own call\'s session and args when an Action Guard call runs during its hold', async () => {
    const atHold = deferred();
    const card = deferred();
    const { i, captured } = build({}, {
      severityActions: { low: 'require_approval', medium: 'require_approval', high: 'require_approval', critical: 'require_approval' },
    });
    const memArgs = { title: 't', content: 'a note held for the operator' };
    const a = i.handleToolCall({
      toolName: 'remember', arguments: { ...memArgs }, sessionId: 'session-A',
      requireApproval: () => { atHold.resolve(); return card.promise.then(() => { throw typedCard(); }); },
    } as never).catch((e: unknown) => e as Error & { decisionAudit: (o: string) => void });
    await atHold.promise;
    await i.handleToolCall({ toolName: 'Bash', arguments: { leaseProbe: true }, sessionId: 'session-B' } as never).catch(() => {});
    card.resolve();
    (await a).decisionAudit('approved_once');
    const row = captured.find((r) => r.entry.outcome === 'approved_once')!;
    expect(row.entry.sessionKey).toBe('session-A');
    expect(row.args).toEqual(memArgs);
    // Off the Action Guard path: never readiness evidence (r8 SF1).
    expect(row.entry.readinessPin).toBeUndefined();
  });
});
