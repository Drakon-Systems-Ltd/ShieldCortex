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

  it('is provably harmless: targets a synthetic /tmp canary path (a no-op even if it ran)', () => {
    const op = buildSyntheticCanaryOp('sc-canary-NONCE1');
    const command = String(op.arguments.command);
    expect(command).toContain('/tmp/');
    // Never a real/root/home target — the delete surface is a synthetic path only.
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

  beforeEach(() => {
    jest.resetModules();
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-canary-e2e-'));
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(home);
  });
  afterEach(() => {
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
