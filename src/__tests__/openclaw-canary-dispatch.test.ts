import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';
import {
  buildSyntheticCanaryOp,
  dispatchCanaryThroughInstalledInterceptor,
  defaultTriggerSyntheticOp,
  findFreshEnforcementEntry,
  CANARY_MARKER,
  type ActiveDispatchDeps,
} from '../setup/openclaw-selfcheck.js';

/**
 * Item 3 (#74 follow-up): wire the REAL consent-gated active canary in
 * openclaw-selfcheck. `defaultTriggerSyntheticOp` shipped deliberately unwired
 * in 4.47.3 — it reported "roster proof stands; enforcement not actively proven"
 * rather than fabricating a live-dispatch pass. This wires the actual dispatch:
 * a harmless synthetic op driven through the live interceptor path, whose real
 * deny + audit entry the existing observe logic then confirms.
 *
 * Fail-closed contract (non-negotiable):
 *  - No consent → identical to today (honest "not actively proven").
 *  - Dispatch attempted but unobservable/failed → reported loudly as NOT proven;
 *    never fabricate a pass.
 *  - The synthetic op is provably harmless + clearly canary-tagged.
 */

describe('buildSyntheticCanaryOp — provably harmless, known-bad, canary-tagged', () => {
  it('is genuinely denied by the REAL Action Guard evaluator (catastrophic block)', () => {
    const op = buildSyntheticCanaryOp('sc-canary-NONCE1');
    const v = evaluateToolCall(op.toolName, op.arguments);
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });

  it('is provably harmless: targets a synthetic nonce-named dotdir (a no-op even if it ran)', () => {
    // Was a /tmp path — #170's target-aware precision made /tmp deletes
    // workspace-confined and ALLOWED, which silently broke the canary's
    // known-bad property (caught by the sibling test above going red). The
    // canary now targets `~/.<nonce>`: the confinement check permanently
    // rejects `~` (it can expand anywhere), so the shape stays catastrophic —
    // and a nonexistent nonce-named dotdir is still a no-op if it ever runs.
    const op = buildSyntheticCanaryOp('sc-canary-NONCE1');
    const command = String(op.arguments.command);
    expect(command).toContain('~/.sc-canary-NONCE1');
    // Never a bare root/home target — the delete surface is the synthetic
    // dotdir only, not `~` or `/` themselves.
    expect(command).not.toMatch(/\srm\b[^\n]*\s(?:\/|~|\$HOME)(?:\s|$)/);
  });

  it('carries the nonce and the canary marker so the audit entry is unmistakable', () => {
    const op = buildSyntheticCanaryOp('sc-canary-NONCE1');
    const blob = JSON.stringify(op.arguments);
    expect(blob).toContain('sc-canary-NONCE1');
    expect(blob).toContain(CANARY_MARKER);
  });
});

describe('dispatchCanaryThroughInstalledInterceptor — fail-closed orchestration', () => {
  const evaluator = evaluateToolCall as unknown as ActiveDispatchDeps['evaluator'];

  it('reports NOT dispatched (loudly) when the realtime plugin is not found on disk', async () => {
    const r = await dispatchCanaryThroughInstalledInterceptor('/home/x', 'p', 'sc-canary-N', {
      resolveInstallPath: () => null,
      loadInterceptorModule: async () => { throw new Error('should not be called'); },
      evaluator,
    });
    expect(r.dispatched).toBe(false);
    expect(r.detail).toMatch(/not found|could not|cannot/i);
  });

  it('reports NOT dispatched when the installed interceptor module cannot be loaded', async () => {
    const r = await dispatchCanaryThroughInstalledInterceptor('/home/x', 'p', 'sc-canary-N', {
      resolveInstallPath: () => '/opt/plugin',
      loadInterceptorModule: async () => null,
      evaluator,
    });
    expect(r.dispatched).toBe(false);
    expect(r.detail).toMatch(/interceptor|module|cannot/i);
  });

  it('reports NOT dispatched when constructing the interceptor throws (never fabricates a pass)', async () => {
    const r = await dispatchCanaryThroughInstalledInterceptor('/home/x', 'p', 'sc-canary-N', {
      resolveInstallPath: () => '/opt/plugin',
      loadInterceptorModule: async () => ({
        createInterceptor: () => { throw new Error('boom'); },
        DEFAULT_CONFIG: {},
      }),
      evaluator,
    });
    expect(r.dispatched).toBe(false);
    expect(r.detail).toMatch(/interceptor|construct|failed/i);
  });

  it('dispatches the exact synthetic canary op through the interceptor, with the evaluator wired', async () => {
    let received: { toolName: string; arguments: Record<string, unknown> } | undefined;
    let evaluatorWired = false;
    const r = await dispatchCanaryThroughInstalledInterceptor('/home/x', 'p', 'sc-canary-N', {
      resolveInstallPath: () => '/opt/plugin',
      loadInterceptorModule: async () => ({
        createInterceptor: (_cfg: unknown, _pipe: unknown, opts: { evaluateToolCall?: unknown }) => {
          evaluatorWired = typeof opts?.evaluateToolCall === 'function';
          return {
            handleToolCall: async (ctx: { toolName: string; arguments: Record<string, unknown> }) => {
              received = ctx;
              // A real block throws after auditing — mimic that so the catch path is exercised.
              throw new Error('ShieldCortex: tool call blocked — canary');
            },
            resetSession: () => {},
          };
        },
        DEFAULT_CONFIG: {},
      }),
      evaluator,
    });
    expect(r.dispatched).toBe(true);
    expect(evaluatorWired).toBe(true);
    expect(received).toEqual(buildSyntheticCanaryOp('sc-canary-N'));
  });
});

describe('active canary end-to-end through the REAL interceptor (hermetic, no gateway)', () => {
  let home: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let previousAuditDir: string | undefined;

  beforeEach(() => {
    jest.resetModules();
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-canary-e2e-'));
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(home);
    // #226: the interceptor now honours this process-level isolation seam.
    // Point it at the same synthetic home that findFreshEnforcementEntry reads,
    // rather than inheriting a suite-wide override aimed somewhere else.
    previousAuditDir = process.env.SHIELDCORTEX_AUDIT_DIR;
    process.env.SHIELDCORTEX_AUDIT_DIR = path.join(home, '.shieldcortex', 'audit');
    fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ interceptor: { actionGuard: { enabled: true, enforce: true } } }),
    );
  });
  afterEach(() => {
    if (previousAuditDir === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
    else process.env.SHIELDCORTEX_AUDIT_DIR = previousAuditDir;
    homedirSpy.mockRestore();
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('the real interceptor denies + audits the synthetic op; findFresh confirms a fresh nonce-matched deny', async () => {
    const nonce = 'sc-canary-E2E-UNIQUE';
    const sinceMs = Date.now() - 1000;
    // Load the ACTUAL plugin interceptor (its AUDIT_DIR resolves under the mocked
    // home) and drive the synthetic op through it via the real defence evaluator.
    const interceptorMod = await import('../../plugins/openclaw/interceptor.js');
    const r = await dispatchCanaryThroughInstalledInterceptor(home, 'shieldcortex-realtime', nonce, {
      resolveInstallPath: () => '/unused-real-module-injected',
      loadInterceptorModule: async () => interceptorMod as unknown as Awaited<ReturnType<ActiveDispatchDeps['loadInterceptorModule']>>,
      evaluator: evaluateToolCall as unknown as ActiveDispatchDeps['evaluator'],
    });
    expect(r.dispatched).toBe(true);

    // The observe half of the canary: a FRESH audit deny carrying our nonce.
    const fresh = findFreshEnforcementEntry(home, { nonce, sinceMs });
    expect(fresh.found).toBe(true);
  });
});

describe('defaultTriggerSyntheticOp — fail-closed guards preserved', () => {
  it('is skipped under the test runner (JEST_WORKER_ID guard preserved — never dispatches in tests)', async () => {
    const r = await defaultTriggerSyntheticOp('/home/x', 'shieldcortex-realtime', 'sc-canary-N');
    expect(r.dispatched).toBe(false);
    expect(r.detail).toMatch(/test runner/i);
  });
});

describe('#94 — the live canary honours the BOX config, not DEFAULT_CONFIG', () => {
  const evaluator2 = evaluateToolCall as unknown as ActiveDispatchDeps['evaluator'];

  it('merges ~/.shieldcortex/config.json interceptor overrides over the module defaults', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-canary-cfg-'));
    fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(
      path.join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ interceptor: { failurePolicy: { high: 'allow' }, actionGuard: { enforce: false } } }),
    );
    let receivedCfg: any;
    await dispatchCanaryThroughInstalledInterceptor(home, 'p', 'sc-canary-CFG', {
      resolveInstallPath: () => '/opt/plugin',
      loadInterceptorModule: async () => ({
        createInterceptor: (cfg: unknown) => {
          receivedCfg = cfg;
          return { handleToolCall: async () => { throw new Error('blocked — canary'); }, resetSession: () => {} };
        },
        DEFAULT_CONFIG: {
          enabled: true,
          severityActions: { low: 'log', medium: 'log', high: 'warn', critical: 'log' },
          failurePolicy: { low: 'allow', medium: 'allow', high: 'deny', critical: 'deny' },
          actionGuard: { enabled: true, enforce: true, autoApprove: [] },
        },
      }),
      evaluator: evaluator2,
    });
    fs.rmSync(home, { recursive: true, force: true });
    // Box overrides applied…
    expect(receivedCfg.failurePolicy.high).toBe('allow');
    expect(receivedCfg.actionGuard.enforce).toBe(false);
    // …while untouched defaults survive the merge.
    expect(receivedCfg.failurePolicy.critical).toBe('deny');
    expect(receivedCfg.actionGuard.enabled).toBe(true);
    expect(receivedCfg.severityActions.high).toBe('warn');
  });

  it('falls back to the module defaults when the config file is absent or unreadable', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-canary-nocfg-'));
    let receivedCfg: any;
    await dispatchCanaryThroughInstalledInterceptor(home, 'p', 'sc-canary-NOCFG', {
      resolveInstallPath: () => '/opt/plugin',
      loadInterceptorModule: async () => ({
        createInterceptor: (cfg: unknown) => {
          receivedCfg = cfg;
          return { handleToolCall: async () => { throw new Error('blocked — canary'); }, resetSession: () => {} };
        },
        DEFAULT_CONFIG: {
          enabled: true,
          failurePolicy: { low: 'allow', medium: 'allow', high: 'deny', critical: 'deny' },
          actionGuard: { enabled: true, enforce: true, autoApprove: [] },
        },
      }),
      evaluator: evaluator2,
    });
    fs.rmSync(home, { recursive: true, force: true });
    expect(receivedCfg.failurePolicy.high).toBe('deny');
    expect(receivedCfg.actionGuard.enforce).toBe(true);
  });
});
