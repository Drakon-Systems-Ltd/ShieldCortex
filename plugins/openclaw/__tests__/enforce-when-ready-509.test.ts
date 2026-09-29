import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import * as readiness from '../../../src/defence/iron-dome/guard-readiness.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
  buildReadinessRuntime,
} from '../index.js';
import { createInterceptor, DEFAULT_CONFIG, type ReadinessRuntime } from '../interceptor.js';

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
