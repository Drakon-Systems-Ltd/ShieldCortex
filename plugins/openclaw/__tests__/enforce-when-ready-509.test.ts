import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import * as defence from '../../../src/defence/index.js';
import * as readiness from '../../../src/defence/iron-dome/guard-readiness.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
  buildReadinessRuntime,
} from '../index.js';
import { __resetReadinessWarningsForTest, createInterceptor, DEFAULT_CONFIG, type ReadinessRuntime } from '../interceptor.js';

/**
 * #509 round 7 — the OpenClaw interceptor honours `actionGuard.readinessGate`
 * with the Claude Code hook's semantics (Tars, PR #610 review of 58b94575:
 * the interceptor had no shadow path, so "enforce when ready" enforced on
 * OpenClaw from the first call while the hook shadowed).
 *
 * Readiness comes from the ONE implementation, guard-readiness.ts, per
 * adapter: OpenClaw evidence, state and transition journal are pinned to the
 * `openclaw-interceptor` adapter, so hook evidence never promotes OpenClaw and
 * OpenClaw evidence never promotes the hook.
 *
 * Catastrophic command text cannot be written into this file (the Action
 * Guard refuses it: write-content-catastrophic), so the catastrophic and
 * exfil tiers are driven with the guard's verdict for them — `block` at
 * `catastrophic` severity — through a wrapped evaluator. What is under test
 * is the interceptor's handling of that verdict in each readiness state.
 */

const DANGEROUS = { command: 'sudo modprobe softdog' };
const FLOOR_WRITE = { command: 'echo {} > ~/.shieldcortex/approvals/guard-readiness.openclaw-interceptor.json' };
const SCHEMA_INVALID = { command: 'ls', evil: 'x' };
const BENIGN = { command: 'ls -la' };
const CATASTROPHIC_MARK = 'sc-test-catastrophic-tier';
const EXFIL_MARK = 'sc-test-exfil-tier';
const DAY = 24 * 60 * 60 * 1000;
const OPENCLAW = 'openclaw-interceptor';
const HOOK = 'claude-code-hook';

/** The real evaluator, except for two marker commands that stand for the
 *  catastrophic and exfil tiers and get the verdict the guard gives them. */
const evaluator = ((tool: string, args: Record<string, unknown>, ...rest: unknown[]) => {
  if (args?.command === CATASTROPHIC_MARK) {
    return { decision: 'block', severity: 'catastrophic', family: 'fs', action: 'recursive-delete', reason: 'catastrophic (test)', signals: ['recursive-force-delete'] };
  }
  if (args?.command === EXFIL_MARK) {
    return { decision: 'block', severity: 'catastrophic', family: 'network', action: 'exfil', reason: 'secret exfil (test)', signals: ['secret-egress'] };
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

let home = '';
let seq = 0;
const saved: Record<string, string | undefined> = {};
const ENV_KEYS = ['HOME', 'SHIELDCORTEX_CONFIG_DIR', 'SHIELDCORTEX_AUDIT_DIR'];

const auditDir = () => join(home, '.shieldcortex', 'audit');
const NOTIFY = { enabled: true, webhookUrl: 'https://hooks.example.invalid/sc' };

function rows(): Array<Record<string, unknown>> {
  if (!existsSync(auditDir())) return [];
  return readdirSync(auditDir())
    .filter((f) => /^realtime-.*\.jsonl$/.test(f))
    .flatMap((f) => readFileSync(join(auditDir(), f), 'utf8').split('\n').filter(Boolean))
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

function pinOf(adapter: string): readiness.ReadinessPin {
  return readiness.currentReadinessPin(adapter as readiness.ReadinessAdapter)!;
}

function seed(list: Array<Record<string, unknown>>, pin: readiness.ReadinessPin): void {
  mkdirSync(auditDir(), { recursive: true });
  for (const r of list) {
    seq += 1;
    const full = { auditEventId: `seed${seq}`, readinessPin: pin, ...r };
    appendFileSync(join(auditDir(), `realtime-${String(full.ts).slice(0, 10)}.jsonl`), `${JSON.stringify(full)}\n`);
  }
}

/** History meeting both readiness proxies for one adapter: 1000 calls over 8
 *  days at 0.5% would-stop, and 25 reached round-trips in the last day. */
function seedReadyHistory(adapter: string): void {
  const now = Date.now();
  const list: Array<Record<string, unknown>> = [];
  for (let i = 0; i < 1000; i += 1) {
    const ts = new Date(now - 8 * DAY + Math.floor((i * 8 * DAY) / 1000) + 1000).toISOString();
    const stop = i < 5;
    list.push({ ts, type: 'intercept', origin: adapter, tool: 'Bash', severity: stop ? 'high' : 'low', action: stop ? 'require_approval' : 'allow', outcome: stop ? 'would_hold' : 'allowed' });
  }
  for (let i = 0; i < 25; i += 1) {
    const t = now - DAY + i * 60_000;
    list.push({ ts: new Date(t).toISOString(), type: 'approval_reach', origin: adapter, reachId: `${adapter}-${i}`, attemptId: `${adapter}-a${i}`, phase: 'request' });
    list.push({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', origin: adapter, reachId: `${adapter}-${i}`, attemptId: `${adapter}-a${i}`, phase: 'answer', answer: 'approve' });
  }
  seed(list, pinOf(adapter));
}

function journalPath(adapter: string): string {
  return readiness.transitionsPathFor(readiness.readinessPaths({ home, adapter: adapter as readiness.ReadinessAdapter }));
}

function appendJournal(adapter: string, entry: Record<string, unknown>): void {
  const p = journalPath(adapter);
  mkdirSync(dirname(p), { recursive: true });
  appendFileSync(p, `${JSON.stringify(entry)}\n`);
}

function journal(adapter: string): Array<Record<string, unknown>> {
  const p = journalPath(adapter);
  if (!existsSync(p)) return [];
  return readFileSync(p, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Record<string, unknown>);
}

/** A reviewed-evidence registry for the adapter under test — the test seam
 *  standing for a build that ships reviewed evidence. Never config. */
function reviewed(adapter: string): readiness.EffectivenessEvidence[] {
  return [{ ...pinOf(adapter), reviewedAt: new Date(Date.now() - DAY).toISOString(), reviewedBy: 'test fixture reviewer', reference: 'test fixture', cases: 60 }];
}

function runtime(opts: { registry?: readiness.EffectivenessEvidence[]; announced?: string[]; notify?: unknown } = {}): ReadinessRuntime {
  const rt = buildReadinessRuntime(readiness as never, opts.notify ?? NOTIFY, {
    home,
    effectivenessRegistry: opts.registry ?? [],
    deliver: async (which) => {
      opts.announced?.push(which);
      return { deliveredVia: 'webhook', attempts: [{ channel: 'webhook', result: { delivered: true } }] };
    },
  });
  expect(rt).toBeDefined();
  return rt!;
}

function interceptor(
  guard: Record<string, unknown>,
  options: Record<string, unknown> = {},
  extra: Record<string, unknown> = {},
) {
  const warnings: string[] = [];
  const i = createInterceptor(
    {
      ...DEFAULT_CONFIG,
      ...extra,
      actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, enforce: true, readinessGate: true, ...guard },
      logger: { info: () => {}, warn: (m: string) => { warnings.push(m); } },
    } as never,
    okPipeline as never,
    { evaluateToolCall: evaluator, ...options } as never,
  );
  return { ...i, warnings };
}

type Decision = 'allowed' | 'card' | 'blocked';

/** Outcome of one call: 'allowed', 'card' (an approver was asked), or 'blocked'. */
async function decide(
  i: { handleToolCall: (ctx: never) => Promise<void> },
  args: Record<string, unknown>,
  attended = true,
): Promise<Decision> {
  let asked = false;
  const ctx = {
    toolName: 'Bash',
    arguments: args,
    ...(attended ? { requireApproval: async () => { asked = true; return false; } } : {}),
  };
  const res = await i.handleToolCall(ctx as never).then(() => 'ok', () => 'threw');
  if (asked) return 'card';
  return res === 'ok' ? 'allowed' : 'blocked';
}

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  __resetReadinessWarningsForTest();
  home = mkdtempSync(join(tmpdir(), 'sc-509-oc-'));
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  process.env.HOME = home;
  process.env.SHIELDCORTEX_CONFIG_DIR = join(home, '.shieldcortex');
  process.env.SHIELDCORTEX_AUDIT_DIR = auditDir();
  // What `shieldcortex config --action-guard-enforce-when-ready` does: start
  // the durable journal for every adapter that implements the gate.
  for (const a of [HOOK, OPENCLAW]) {
    appendJournal(a, { ts: new Date(Date.now() - 30 * DAY).toISOString(), event: 'init', to: 'shadow', reason: 'test posture' });
  }
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  rmSync(home, { recursive: true, force: true });
});

// ==================== reproduction ====================

describe('#509 r7 reproduction — OpenClaw under readinessGate:true, not promoted', () => {
  it('interceptor: a require_approval call is logged would-hold and ALLOWED — no approval card', async () => {
    const i = interceptor({}, { readiness: runtime() });
    expect(await decide(i, DANGEROUS)).toBe('allowed');
    const held = rows().filter((r) => r.type === 'intercept' && r.outcome === 'would_hold');
    expect(held).toHaveLength(1);
    expect(held[0]).toMatchObject({ origin: OPENCLAW, action: 'require_approval', shadow: true, posture: 'enforce-when-ready' });
    expect((held[0].readinessPin as { adapter: string }).adapter).toMatch(/^openclaw-interceptor@/);
  });

  it('plugin: before_tool_call returns no card for the dangerous call; the shield-config gate reaches the interceptor', async () => {
    const hooks: Record<string, (...args: any[]) => any> = {};
    const api = {
      id: 'shieldcortex-realtime',
      name: 'ShieldCortex Real-time Scanner',
      logger: { info: () => {}, warn: () => {} },
      on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
      registerCommand: () => {},
      runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: {} } } } }) } },
    };
    __resetConfigStateForTest();
    __setRuntimeForTest({
      callCortex: async () => null,
      isOpenClawAutoMemoryEnabled: () => false,
      loadShieldConfig: async () => ({ actionGuard: { enabled: true, enforce: true, readinessGate: true, notify: NOTIFY } }),
    } as never);
    __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall, ...readiness } as never);
    try {
      plugin.register(api as never);
      const result = await hooks.before_tool_call({ toolName: 'Bash', params: DANGEROUS }, { sessionId: 'agent:main:chat:509' });
      expect(result?.requireApproval).toBeUndefined();
      expect(result?.block).toBeUndefined();
      expect(rows().some((r) => r.origin === OPENCLAW && r.outcome === 'would_hold')).toBe(true);
    } finally {
      __setDefenceModuleForTest(undefined);
      __setRuntimeForTest(null);
      __resetConfigStateForTest();
    }
  });
});

// ==================== states ====================

/** Start OpenClaw in a state: shadow (fresh), promoted (evidence + reviewed
 *  registry; the first call promotes), or demoted (journal: promote then a
 *  recorded demote; evidence not ready). */
async function inState(state: 'shadow' | 'promoted' | 'demoted', options: Record<string, unknown> = {}) {
  const announced: string[] = [];
  if (state === 'promoted') seedReadyHistory(OPENCLAW);
  if (state === 'demoted') {
    appendJournal(OPENCLAW, { ts: new Date(Date.now() - 3 * DAY).toISOString(), event: 'promote', to: 'enforcing' });
    appendJournal(OPENCLAW, { ts: new Date(Date.now() - 2 * DAY).toISOString(), event: 'demote', to: 'shadow', reason: 'test demotion' });
  }
  const i = interceptor({}, { readiness: runtime({ registry: state === 'promoted' ? reviewed(OPENCLAW) : [], announced }), ...options });
  // One benign call resolves (and, when promoted, makes) the transition.
  expect(await decide(i, BENIGN)).toBe('allowed');
  return { i, announced };
}

describe('#509 r7 req 3 — shadow behaviour on OpenClaw, and the floors in every state', () => {
  it('shadow: dangerous is would-hold (attended) / would-block (unattended), allowed, no card', async () => {
    const { i } = await inState('shadow');
    expect(await decide(i, DANGEROUS, true)).toBe('allowed');
    expect(await decide(i, DANGEROUS, false)).toBe('allowed');
    const outcomes = rows().filter((r) => r.shadow === true).map((r) => r.outcome);
    expect(outcomes).toEqual(['would_hold', 'would_block']);
  });

  it('promoted: the same dangerous call gets a card (enforced), and the promotion was announced', async () => {
    const { i, announced } = await inState('promoted');
    expect(announced).toEqual(['promote']);
    expect(await decide(i, DANGEROUS)).toBe('card');
    expect(await decide(i, DANGEROUS, false)).toBe('blocked');
  });

  for (const state of ['shadow', 'demoted', 'promoted'] as const) {
    it(`${state}: catastrophic, exfil, self-protection floor, lease floor and unscanned calls are STILL enforced`, async () => {
      const lease = {
        checkActionLease: (_t: string, args: Record<string, unknown>) => (args.command === 'npm publish'
          ? { scope: 'publish', decision: { verdict: 'frozen', reason: 'publish is frozen (test lease)' } }
          : null),
      };
      const { i } = await inState(state, lease);
      expect({
        catastrophic: await decide(i, { command: CATASTROPHIC_MARK }),
        exfil: await decide(i, { command: EXFIL_MARK }),
        floorAttended: await decide(i, FLOOR_WRITE),
        floorUnattended: await decide(i, FLOOR_WRITE, false),
        schemaInvalid: await decide(i, SCHEMA_INVALID),
        lease: await decide(i, { command: 'npm publish' }),
      }).toEqual({
        catastrophic: 'blocked',
        exfil: 'blocked',
        floorAttended: 'card',
        floorUnattended: 'blocked',
        schemaInvalid: 'card',
        lease: 'blocked',
      });
      // None of them was recorded as a shadowed would-stop.
      expect(rows().filter((r) => r.shadow === true)).toEqual([]);
    });
  }

  it('demoted: dangerous is shadowed again (logged, allowed)', async () => {
    const { i } = await inState('demoted');
    expect(await decide(i, DANGEROUS)).toBe('allowed');
    expect(rows().some((r) => r.outcome === 'would_hold')).toBe(true);
  });

  it('a benign allow writes the minimal tally row — tool name only, no args — pinned to OpenClaw', async () => {
    await inState('shadow');
    const tally = rows().filter((r) => r.readinessTally === true);
    expect(tally).toHaveLength(1);
    expect(tally[0]).toMatchObject({ origin: OPENCLAW, action: 'allow', outcome: 'allowed', preview: 'Bash :: tally', threats: [] });
    expect(JSON.stringify(tally[0])).not.toContain('ls -la');
    expect((tally[0].readinessPin as { adapter: string }).adapter).toBe(pinOf(OPENCLAW).adapter);
    // And the tally is counted: one OpenClaw call observed.
    const report = readiness.computeReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, adapter: OPENCLAW });
    expect(report.intervention.total).toBe(1);
  });
});

describe('#509 r7 req 1–2 — gate conditions and failure direction match the hook', () => {
  it('enforce:false stays advisory (warned), not shadow', async () => {
    const i = interceptor({ enforce: false }, { readiness: runtime() });
    expect(await decide(i, DANGEROUS)).toBe('allowed');
    expect(rows().map((r) => r.outcome)).toEqual(['warned']);
  });

  it('readinessGate absent: plain enforce — card', async () => {
    const i = interceptor({ readinessGate: undefined }, { readiness: runtime() });
    expect(await decide(i, DANGEROUS)).toBe('card');
  });

  it('a policy lock pins enforcement: the gate is ignored and no readiness state is written', async () => {
    const i = interceptor({}, { readiness: runtime(), policyLockPresent: () => true });
    expect(await decide(i, DANGEROUS)).toBe('card');
    expect(existsSync(readiness.readinessPaths({ home, adapter: OPENCLAW }).statePath)).toBe(false);
    const throwing = interceptor({}, { readiness: runtime(), policyLockPresent: () => { throw new Error('probe broke'); } });
    expect(await decide(throwing, DANGEROUS)).toBe('card');
  });

  it('readiness module missing from the build: ENFORCES, and says so', async () => {
    const i = interceptor({});
    expect(await decide(i, DANGEROUS)).toBe('card');
    expect(i.warnings.some((w) => /readiness module is missing from this build — ENFORCING/.test(w))).toBe(true);
  });

  it('readiness that throws: ENFORCES, and says so', async () => {
    const rt = { ...runtime(), resolve: () => { throw new Error('journal exploded'); } };
    const i = interceptor({}, { readiness: rt });
    expect(await decide(i, DANGEROUS)).toBe('card');
    expect(i.warnings.some((w) => /could not be resolved \(journal exploded\) — ENFORCING/.test(w))).toBe(true);
  });

  it('buildReadinessRuntime refuses a module without per-adapter readiness (it would use the hook journal)', () => {
    const { READINESS_ADAPTERS: _omit, ...legacy } = readiness as unknown as Record<string, unknown>;
    expect(buildReadinessRuntime(legacy as never, NOTIFY)).toBeUndefined();
    expect(buildReadinessRuntime({ ...legacy, READINESS_ADAPTERS: ['claude-code-hook'] } as never, NOTIFY)).toBeUndefined();
    expect(buildReadinessRuntime(null, NOTIFY)).toBeUndefined();
  });
});

describe('#509 r7 req 4 — per-adapter evidence: neither surface promotes the other', () => {
  const both = () => [...reviewed(HOOK), ...reviewed(OPENCLAW)];

  it('a PROMOTED Claude Code hook does not make OpenClaw enforce', () => {
    seedReadyHistory(HOOK);
    const hook = readiness.resolveReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, effectivenessRegistry: both() });
    expect(hook).toMatchObject({ mode: 'enforcing', transition: 'promote' });
    const oc = readiness.resolveReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, effectivenessRegistry: both(), adapter: OPENCLAW });
    expect(oc.mode).toBe('shadow');
    expect(oc.report?.intervention.total).toBe(0);
    expect(oc.report?.intervention.otherVersion).toBe(1000);
    expect(journal(OPENCLAW).some((e) => e.event === 'promote')).toBe(false);
  });

  it('a promoted Claude Code hook: the OpenClaw interceptor still shadows the dangerous call', async () => {
    seedReadyHistory(HOOK);
    readiness.resolveReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, effectivenessRegistry: both() });
    const i = interceptor({}, { readiness: runtime({ registry: both() }) });
    expect(await decide(i, DANGEROUS)).toBe('allowed');
  });

  it('a PROMOTED OpenClaw interceptor does not make the Claude Code hook enforce', async () => {
    seedReadyHistory(OPENCLAW);
    const i = interceptor({}, { readiness: runtime({ registry: both() }) });
    expect(await decide(i, DANGEROUS)).toBe('card');
    expect(journal(OPENCLAW).some((e) => e.event === 'promote')).toBe(true);
    const hook = readiness.resolveReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, effectivenessRegistry: both() });
    expect(hook.mode).toBe('shadow');
    expect(journal(HOOK).some((e) => e.event === 'promote')).toBe(false);
  });

  it('separate state files and journals; the hook keeps its original names', () => {
    const h = readiness.readinessPaths({ home });
    const o = readiness.readinessPaths({ home, adapter: OPENCLAW });
    expect(h.statePath.endsWith('approvals/guard-readiness.json')).toBe(true);
    expect(readiness.transitionsPathFor(h).endsWith('approvals/guard-readiness-transitions.jsonl')).toBe(true);
    expect(o.statePath.endsWith('approvals/guard-readiness.openclaw-interceptor.json')).toBe(true);
    expect(readiness.transitionsPathFor(o).endsWith('approvals/guard-readiness-transitions.openclaw-interceptor.jsonl')).toBe(true);
    // Both under the approval store, which the floor protects.
    expect(evaluateToolCall('Bash', { command: `echo x >> ${readiness.transitionsPathFor(o)}` }).signals).toContain('touch-approval-store');
  });
});

describe('#509 r7 req 5 — approval reach on OpenClaw: the card, attempt-bound', () => {
  function report() {
    return readiness.computeReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, adapter: OPENCLAW }).reachability;
  }

  async function card(i: { handleToolCall: (ctx: never) => Promise<void> }) {
    const err = await i.handleToolCall({
      toolName: 'Bash',
      arguments: DANGEROUS,
      requireApproval: async () => { const e = new Error('card') as Error & { decisionAudit?: (o: string) => void }; e.name = 'TypedApprovalRequest'; throw e; },
    } as never).then(() => null, (e: unknown) => e as Error & { decisionAudit?: (o: string) => void });
    expect(err?.name).toBe('TypedApprovalRequest');
    return err!;
  }

  it('a card answered allow-once / deny is a reach bound to ITS attempt; timeout and cancel are not', async () => {
    const i = interceptor({ readinessGate: false }, { readiness: runtime() });
    const answers = ['approved_once', 'card_denied', 'card_timeout', 'card_cancelled'];
    for (const a of answers) (await card(i)).decisionAudit!(a);
    const reach = rows().filter((r) => r.type === 'approval_reach');
    const requests = reach.filter((r) => r.phase === 'request');
    expect(requests).toHaveLength(4);
    for (const r of requests) {
      expect(r).toMatchObject({ origin: OPENCLAW, channel: 'openclaw-card' });
      expect((r.readinessPin as { adapter: string }).adapter).toBe(pinOf(OPENCLAW).adapter);
    }
    // Each answer names its own attempt.
    const answered = reach.filter((r) => r.phase === 'answer');
    expect(answered.map((r) => r.answer)).toEqual(['approve', 'deny', 'timeout', 'unreached']);
    expect(answered.map((r) => r.attemptId)).toEqual(requests.map((r) => r.attemptId));
    expect(report()).toMatchObject({ reached: 2, resolved: 4 });
    // The hook's reachability is untouched.
    expect(readiness.computeReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home }).reachability.resolved).toBe(0);
  });

  it('a second answer to the same card is not a second reach', async () => {
    const i = interceptor({ readinessGate: false }, { readiness: runtime() });
    const c = await card(i);
    c.decisionAudit!('approved_once');
    c.decisionAudit!('approved_once');
    expect(rows().filter((r) => r.phase === 'answer')).toHaveLength(1);
  });

  it('unattended (no approver): recorded as not reaching a human', async () => {
    const i = interceptor({ readinessGate: false }, { readiness: runtime() });
    await decide(i, DANGEROUS, false);
    expect(rows().filter((r) => r.type === 'approval_reach')).toEqual([
      expect.objectContaining({ phase: 'resolved', answer: 'no_surface', origin: OPENCLAW }),
    ]);
  });

  it('a hash-only terminal approval (no attempt) and hook-pinned requests never count for OpenClaw', async () => {
    readiness.recordApprovalReach({ hash: 'h1', attemptId: 'hook-att', phase: 'request' }, { home });
    readiness.recordApprovalReach({ hash: 'h1', attemptId: 'hook-att', phase: 'answer', answer: 'approve' }, { home });
    readiness.recordApprovalReach({ hash: 'h2', phase: 'answer', answer: 'approve' }, { home, adapter: OPENCLAW });
    expect(report()).toMatchObject({ reached: 0, resolved: 0, otherVersion: 1 });
  });

  it('no human channel configured: no reach rows are written', async () => {
    const i = interceptor({ readinessGate: false }, { readiness: runtime({ notify: {} }) });
    (await card(i)).decisionAudit!('approved_once');
    expect(rows().filter((r) => r.type === 'approval_reach')).toEqual([]);
  });
});

describe('#509 r7 req 6 — transitions announced on OpenClaw\'s own notify path', () => {
  it('promotion: announced, journalled with its notice, audited as an OpenClaw transition', async () => {
    const { announced } = await inState('promoted');
    expect(announced).toEqual(['promote']);
    const j = journal(OPENCLAW);
    const promote = j.find((e) => e.event === 'promote')!;
    expect(j).toContainEqual(expect.objectContaining({ event: 'notice', of: 'promote', transitionTs: promote.ts, delivered: true, channel: 'webhook' }));
    expect(rows().filter((r) => r.type === 'readiness_transition')).toEqual([
      expect.objectContaining({ origin: OPENCLAW, to: 'enforcing', transition: 'promote' }),
    ]);
    expect(journal(HOOK).map((e) => e.event)).toEqual(['init']);
  });

  it('demotion: announced loudly (log + notice), journalled, audited', async () => {
    const pin = pinOf(OPENCLAW);
    appendJournal(OPENCLAW, { ts: new Date(Date.now() - 3 * DAY).toISOString(), event: 'promote', to: 'enforcing', pin });
    const statePath = readiness.readinessPaths({ home, adapter: OPENCLAW }).statePath;
    mkdirSync(dirname(statePath), { recursive: true });
    const { writeFileSync } = await import('node:fs');
    writeFileSync(statePath, JSON.stringify({
      version: 1, mode: 'enforcing', pin,
      computedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
      failingSince: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    }));
    const announced: string[] = [];
    const i = interceptor({}, { readiness: runtime({ announced }) });
    expect(await decide(i, DANGEROUS)).toBe('allowed');
    expect(announced).toEqual(['demote']);
    expect(i.warnings.some((w) => /DEMOTED to shadow mode/.test(w))).toBe(true);
    const j = journal(OPENCLAW);
    const demote = j.find((e) => e.event === 'demote')!;
    expect(j).toContainEqual(expect.objectContaining({ event: 'notice', of: 'demote', transitionTs: demote.ts, delivered: true }));
    expect(rows()).toContainEqual(expect.objectContaining({ type: 'readiness_transition', origin: OPENCLAW, to: 'shadow', transition: 'demote' }));
  });

  it('unexplained demotion (r6 S1): not trusted — a tamper signal, then the full demotion protocol', async () => {
    appendJournal(OPENCLAW, { ts: new Date(Date.now() - 3 * DAY).toISOString(), event: 'promote', to: 'enforcing' });
    appendJournal(OPENCLAW, { ts: new Date(Date.now() - DAY).toISOString(), event: 'init', to: 'shadow', reason: 'forged' });
    const announced: string[] = [];
    const i = interceptor({}, { readiness: runtime({ announced }) });
    await decide(i, DANGEROUS);
    expect(i.warnings.some((w) => /readiness tamper signal — the transition record's newest entry is an unexplained demotion/.test(w))).toBe(true);
    expect(announced).toEqual(['demote']);
    expect(journal(OPENCLAW)).toContainEqual(expect.objectContaining({ event: 'tamper' }));
    expect(rows()).toContainEqual(expect.objectContaining({ type: 'readiness_tamper', origin: OPENCLAW }));
  });

  it('a notice that could not be delivered is journalled as failed, not silently dropped', async () => {
    seedReadyHistory(OPENCLAW);
    const rt = buildReadinessRuntime(readiness as never, NOTIFY, {
      home,
      effectivenessRegistry: reviewed(OPENCLAW),
      deliver: async () => ({ deliveredVia: null, attempts: [{ channel: 'webhook', result: { delivered: false, reason: 'HTTP 503' } }] }),
    });
    const i = interceptor({}, { readiness: rt });
    await decide(i, BENIGN);
    expect(journal(OPENCLAW)).toContainEqual(expect.objectContaining({ event: 'notice', of: 'promote', delivered: false, reason: 'HTTP 503' }));
  });
});

// ==================== round 8 ====================

const EVALUATOR_THROWS = 'sc-test-evaluator-throws';

/** The r7 evaluator, except that one marker command makes it throw — the
 *  guard-unavailable (WS2 fallback) path. */
const throwingEvaluator = ((tool: string, args: Record<string, unknown>, ...rest: unknown[]) => {
  if (args?.command === EVALUATOR_THROWS) throw new Error('evaluator exploded (test)');
  return (evaluator as unknown as (...a: unknown[]) => unknown)(tool, args, ...rest);
}) as never;

/** A memory-write pipeline that QUARANTINEs: severity high, action `warn`
 *  under the default config — a `warned` row, which the OpenClaw readiness
 *  count would read as a stop if it were pinned. */
const quarantinePipeline = () => ({
  ...okPipeline(),
  allowed: false,
  firewall: { result: 'QUARANTINE' as const, reason: 'test', threatIndicators: ['test-threat'], anomalyScore: 0.7, blockedPatterns: [] as string[] },
});

function pinnedRowsOf(list: Array<Record<string, unknown>>): Array<Record<string, unknown>> {
  return list.filter((r) => r.readinessPin !== undefined);
}

describe('#509 r8 SF1 — a row written before the gate resolves carries no stale readiness pin', () => {
  function gatedInterceptor(options: Record<string, unknown> = {}, pipeline: unknown = okPipeline) {
    const warnings: string[] = [];
    const i = createInterceptor(
      {
        ...DEFAULT_CONFIG,
        actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, enforce: true, readinessGate: true },
        logger: { info: () => {}, warn: (m: string) => { warnings.push(m); } },
      } as never,
      pipeline as never,
      { evaluateToolCall: throwingEvaluator, readiness: runtime(), ...options } as never,
    );
    return { ...i, warnings };
  }

  it('lease refusal after a gated call: no pin, not counted', async () => {
    const i = gatedInterceptor({
      checkActionLease: (_t: string, args: Record<string, unknown>) => (args.command === 'npm publish'
        ? { scope: 'publish', decision: { verdict: 'frozen', reason: 'publish is frozen (test lease)' } }
        : null),
    });
    expect(await decide(i, BENIGN)).toBe('allowed');
    expect(await decide(i, { command: 'npm publish' })).toBe('blocked');
    const lease = rows().find((r) => Array.isArray(r.threats) && (r.threats as string[]).includes('session-lease'))!;
    expect(lease).toBeDefined();
    expect(lease.readinessPin).toBeUndefined();
    // Only the gated call's tally row is OpenClaw readiness evidence.
    expect(pinnedRowsOf(rows()).map((r) => r.readinessTally)).toEqual([true]);
  });

  it('guard unavailable (evaluator throws) after a gated call: the fallback row has no pin', async () => {
    const i = gatedInterceptor();
    expect(await decide(i, BENIGN)).toBe('allowed');
    await decide(i, { command: EVALUATOR_THROWS });
    const degraded = rows().filter((r) => r.firewallResult === 'ACTION_GUARD_FALLBACK');
    expect(degraded).toHaveLength(1);
    expect(degraded[0].readinessPin).toBeUndefined();
    expect(pinnedRowsOf(rows())).toHaveLength(1);
  });

  it('memory-write pipeline row after a gated call: no pin, and it is not an OpenClaw stop', async () => {
    const i = gatedInterceptor({}, quarantinePipeline);
    expect(await decide(i, BENIGN)).toBe('allowed');
    await i.handleToolCall({ toolName: 'remember', arguments: { title: 't', content: 'a note to keep' } } as never);
    const memory = rows().find((r) => r.tool === 'remember')!;
    expect(memory).toMatchObject({ outcome: 'warned' });
    expect(memory.readinessPin).toBeUndefined();
    const report = readiness.computeReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, adapter: OPENCLAW });
    expect(report.intervention).toMatchObject({ total: 1, stops: 0 });
  });
});

describe('#509 r8 SF5 — tally rows stay local: no per-call cloud traffic', () => {
  it('a benign gated call writes its tally row to disk and hands nothing to onAuditEntry (the cloud sink)', async () => {
    const sent: Array<Record<string, unknown>> = [];
    const i = interceptor({}, { readiness: runtime(), onAuditEntry: (e: Record<string, unknown>) => { sent.push(e); } });
    expect(await decide(i, BENIGN)).toBe('allowed');
    expect(await decide(i, BENIGN)).toBe('allowed');
    expect(rows().filter((r) => r.readinessTally === true)).toHaveLength(2);
    expect(sent).toEqual([]);
  });

  it('a verdict row (would-hold) still reaches onAuditEntry as before', async () => {
    const sent: Array<Record<string, unknown>> = [];
    const i = interceptor({}, { readiness: runtime(), onAuditEntry: (e: Record<string, unknown>) => { sent.push(e); } });
    expect(await decide(i, DANGEROUS)).toBe('allowed');
    expect(sent.map((e) => e.outcome)).toEqual(['would_hold']);
  });
});

describe('#509 r8 N1 — "readiness module is missing" is said once per process, not per call', () => {
  it('three gated calls across two interceptors: one warning', async () => {
    __resetReadinessWarningsForTest();
    const a = interceptor({});
    const b = interceptor({});
    expect(await decide(a, DANGEROUS)).toBe('card');
    expect(await decide(a, BENIGN)).toBe('allowed');
    expect(await decide(b, DANGEROUS)).toBe('card');
    const all = [...a.warnings, ...b.warnings].filter((w) => /readiness module is missing from this build/.test(w));
    expect(all).toHaveLength(1);
  });
});

describe('#509 r8 N2 — an OpenClaw transition leaves a notify audit row, as the hook does', () => {
  it('promotion: a local notify row naming the transition and its delivery; not a counted call', async () => {
    const sent: Array<Record<string, unknown>> = [];
    await inState('promoted', { onAuditEntry: (e: Record<string, unknown>) => { sent.push(e); } });
    const notify = rows().filter((r) => r.type === 'intercept' && r.action === 'notify');
    expect(notify).toEqual([
      expect.objectContaining({ origin: OPENCLAW, outcome: 'notified', readinessTransition: 'promote', notify: { status: 'delivered', deliveredVia: 'webhook' } }),
    ]);
    expect(sent.filter((e) => e.action === 'notify')).toEqual([]);
    // One tally row is the only counted call.
    const report = readiness.computeReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, adapter: OPENCLAW, effectivenessRegistry: reviewed(OPENCLAW) });
    expect(report.intervention.total).toBe(1001);
  });

  it('a notice that failed: the notify row says so (notify_failed)', async () => {
    seedReadyHistory(OPENCLAW);
    const rt = buildReadinessRuntime(readiness as never, NOTIFY, {
      home,
      effectivenessRegistry: reviewed(OPENCLAW),
      deliver: async () => ({ deliveredVia: null, attempts: [{ channel: 'webhook', result: { delivered: false, reason: 'HTTP 503' } }] }),
    });
    const i = interceptor({}, { readiness: rt });
    await decide(i, BENIGN);
    expect(rows().filter((r) => r.action === 'notify')).toEqual([
      expect.objectContaining({ outcome: 'notify_failed', readinessTransition: 'promote', notify: { status: 'error', deliveredVia: null } }),
    ]);
  });
});

describe('#509 r8 SF4 — upgrade path: OpenClaw with no record starts watching first, announced once', () => {
  /** The posture was chosen before OpenClaw was gated: no OpenClaw journal. */
  function upgraded(): void {
    rmSync(journalPath(OPENCLAW), { force: true });
  }

  it('first gated call: journal started (init → shadow), announced once as "watching first" — not a demotion, not tamper', async () => {
    upgraded();
    const announced: string[] = [];
    const i = interceptor({}, { readiness: runtime({ announced }) });
    expect(await decide(i, DANGEROUS)).toBe('allowed');
    expect(await decide(i, DANGEROUS)).toBe('allowed');
    expect(announced).toEqual(['start']);
    const started = i.warnings.filter((w) => /OpenClaw plugin now watches first/.test(w));
    expect(started).toHaveLength(1);
    expect(i.warnings.some((w) => /DEMOTED|tamper/i.test(w))).toBe(false);
    const j = journal(OPENCLAW);
    expect(j.map((e) => e.event)).toEqual(['init']);
    expect(j[0]).toMatchObject({ to: 'shadow', reason: expect.stringMatching(/watching first/) });
    expect(rows().filter((r) => r.type === 'readiness_transition' || r.type === 'readiness_tamper')).toEqual([]);
    expect(rows().filter((r) => r.action === 'notify')).toEqual([
      expect.objectContaining({ readinessTransition: 'start', outcome: 'notified' }),
    ]);
    // The hook's journal is untouched.
    expect(journal(HOOK).map((e) => e.event)).toEqual(['init']);
  });

  it('OpenClaw had run under the posture (state file present), journal gone: the r3 loud path — a demotion, not a quiet start', async () => {
    upgraded();
    const statePath = readiness.readinessPaths({ home, adapter: OPENCLAW }).statePath;
    mkdirSync(dirname(statePath), { recursive: true });
    const { writeFileSync } = await import('node:fs');
    writeFileSync(statePath, JSON.stringify({ version: 1, mode: 'shadow', computedAt: new Date(Date.now() - DAY).toISOString(), pin: pinOf(OPENCLAW) }));
    const announced: string[] = [];
    const i = interceptor({}, { readiness: runtime({ announced }) });
    await decide(i, DANGEROUS);
    expect(announced).toEqual(['demote']);
    expect(journal(OPENCLAW).map((e) => e.event)).toEqual(['demote', 'notice']);
  });
});

describe('#509 r8 SF6 — the gateway recompute never holds the event loop for the whole read', () => {
  /** ~6 MB of benign OpenClaw calls over 8 days on top of a ready history:
   *  read and parsed in one go, this holds the loop for tens of ms. */
  function seedBulk(): void {
    const now = Date.now();
    const list: Array<Record<string, unknown>> = [];
    for (let i = 0; i < 3000; i += 1) {
      const ts = new Date(now - 8 * DAY + Math.floor((i * 8 * DAY) / 3000) + 2000).toISOString();
      list.push({ ts, type: 'intercept', origin: OPENCLAW, tool: 'Bash', severity: 'low', action: 'allow', outcome: 'allowed', preview: 'x'.repeat(2000) });
    }
    seed(list, pinOf(OPENCLAW));
  }

  /** The runtime exactly as the plugin builds it: from the `shieldcortex/defence` barrel. */
  function barrelRuntime(announced: string[] = []): ReadinessRuntime {
    const rt = buildReadinessRuntime(defence as never, NOTIFY, {
      home,
      effectivenessRegistry: reviewed(OPENCLAW),
      deliver: async (which) => {
        announced.push(which);
        return { deliveredVia: 'webhook', attempts: [{ channel: 'webhook', result: { delivered: true } }] };
      },
    });
    expect(rt).toBeDefined();
    return rt!;
  }

  it('the plugin-built runtime recomputes in slices: the event loop keeps turning while it reads', async () => {
    seedReadyHistory(OPENCLAW);
    seedBulk();
    const rt = barrelRuntime();
    let ticks = 0;
    let stop = false;
    const tick = (): void => { ticks += 1; if (!stop) setImmediate(tick); };
    setImmediate(tick);
    const resolved = await rt.resolve();
    stop = true;
    expect(resolved).toMatchObject({ mode: 'enforcing', transition: 'promote' });
    expect(ticks).toBeGreaterThan(5);
  });

  it('gated calls that arrive while a recompute runs share it: one read, one promotion, announced once', async () => {
    seedReadyHistory(OPENCLAW);
    seedBulk();
    const announced: string[] = [];
    const i = interceptor({}, { readiness: barrelRuntime(announced) });
    const out = await Promise.all([decide(i, DANGEROUS), decide(i, DANGEROUS), decide(i, BENIGN)]);
    expect(out).toEqual(['card', 'card', 'allowed']);
    expect(announced).toEqual(['promote']);
    expect(journal(OPENCLAW).filter((e) => e.event === 'promote')).toHaveLength(1);
    expect(i.warnings.filter((w) => /now ENFORCING/.test(w))).toHaveLength(1);
  });

  it('a call that runs while the gate awaits the recompute does not strip the waiting call\'s pin', async () => {
    const i = interceptor({}, { readiness: barrelRuntime() });
    const gated = decide(i, DANGEROUS); // shadow: would-hold, allowed
    // A memory write lands while the gated call awaits its resolve; its entry
    // clears the in-flight pin (SF1).
    await i.handleToolCall({ toolName: 'remember', arguments: { title: 't', content: 'a note to keep' } } as never);
    expect(await gated).toBe('allowed');
    const held = rows().find((r) => r.outcome === 'would_hold')!;
    expect(held.readinessPin).toEqual(pinOf(OPENCLAW));
    const report = readiness.computeReadiness({ channel: readiness.describeHumanChannel(NOTIFY), home, adapter: OPENCLAW });
    expect(report.intervention).toMatchObject({ total: 1, stops: 1 });
  });
});

describe('#509 r7 — openclaw.json cannot switch the gate on', () => {
  it('readinessGate in the plugin entry only is ignored: the guard enforces', async () => {
    const hooks: Record<string, (...args: any[]) => any> = {};
    const api = {
      id: 'shieldcortex-realtime',
      name: 'ShieldCortex Real-time Scanner',
      logger: { info: () => {}, warn: () => {} },
      on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
      registerCommand: () => {},
      pluginConfig: { interceptor: { actionGuard: { readinessGate: true } } },
      runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: { interceptor: { actionGuard: { readinessGate: true } } } } } } }) } },
    };
    __resetConfigStateForTest();
    __setRuntimeForTest({
      callCortex: async () => null,
      isOpenClawAutoMemoryEnabled: () => false,
      loadShieldConfig: async () => ({ actionGuard: { enabled: true, enforce: true, notify: NOTIFY } }),
    } as never);
    __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall, ...readiness } as never);
    try {
      plugin.register(api as never);
      const result = await hooks.before_tool_call({ toolName: 'Bash', params: DANGEROUS }, { sessionId: 'agent:main:chat:509' });
      expect(result?.requireApproval).toBeDefined();
    } finally {
      __setDefenceModuleForTest(undefined);
      __setRuntimeForTest(null);
      __resetConfigStateForTest();
    }
  });
});
