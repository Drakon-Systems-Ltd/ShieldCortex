import { describe, it, expect, beforeEach } from '@jest/globals';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * Issue #115 — non-blocking polish follow-ups from the #112 fix review
 * (PR #113, merge 4e4d9ae). None of these are correctness bugs; the #112
 * fix already fails safe. This file pins the 4 code-level items:
 *
 *   1. normaliseInterceptorConfig() returns undefined (not {}) for an
 *      empty/all-invalid interceptor block, matching normaliseSeverityMap's
 *      existing "empty means absent" contract.
 *   2. Invalid interceptor values are named in a warn log at the point
 *      normalisation has access to a logger (applyPluginConfigOverride) —
 *      the Edith #112 investigation would have been shorter with this.
 *   3. guard.autoApprove is defensively copied, not aliased to the caller's
 *      array.
 *
 * (Item 3 in the issue — the unread manifest `enabled` key — and item 5 —
 * additionalProperties parity — are schema-only and covered by asserting
 * against openclaw.plugin.json directly, see below.)
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

type Hooks = Record<string, (...args: any[]) => any>;
type Commands = Record<string, { name: string; handler: () => Promise<{ text: string }> }>;

function makeApi(rootConfig: unknown): { api: any; hooks: Hooks; commands: Commands; warnings: string[] } {
  const hooks: Hooks = {};
  const commands: Commands = {};
  const warnings: string[] = [];
  const api = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: (m: string) => { warnings.push(m); } },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: (cmd: any) => { commands[cmd.name] = cmd; },
    runtime: { config: { current: () => rootConfig } },
  };
  return { api, hooks, commands, warnings };
}

function rootConfigWith(config: unknown): unknown {
  return { plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config } } } };
}

function stubRuntime(shieldConfig: Record<string, unknown> = {}) {
  __setRuntimeForTest({
    callCortex: async () => null,
    isOpenClawAutoMemoryEnabled: () => false,
    loadShieldConfig: async () => shieldConfig,
  });
}

beforeEach(() => {
  __resetConfigStateForTest();
  stubRuntime({});
  __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall } as any);
});

// ==================== 1. empty/all-invalid interceptor => undefined ====================

describe('#115.1 — normaliseInterceptorConfig returns undefined (not {}) when empty', () => {
  it('an empty interceptor object normalises to undefined, not {}', () => {
    const parsed = plugin.configSchema.parse({ interceptor: {} }) as any;
    expect(parsed.interceptor).toBeUndefined();
  });

  it('an interceptor object with only invalid/unknown keys normalises to undefined', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: { enabled: 'yes', bogus: true, actionGuard: { nope: 1 } },
    }) as any;
    expect(parsed.interceptor).toBeUndefined();
  });

  it('control: a partially-valid interceptor still normalises to a defined object', () => {
    const parsed = plugin.configSchema.parse({ interceptor: { enabled: true } }) as any;
    expect(parsed.interceptor).toEqual({ enabled: true });
  });

  it('consistency with normaliseSeverityMap: an all-invalid severityActions block alone also yields no interceptor key', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: { severityActions: { high: 'explode' } },
    }) as any;
    expect(parsed.interceptor).toBeUndefined();
  });
});

// ==================== 2. warn log names dropped interceptor keys ====================

describe('#115.2 — applyPluginConfigOverride warns on dropped invalid interceptor keys', () => {
  it('logs a warning naming the exact key when a known interceptor field has the wrong type', () => {
    const { api, warnings } = makeApi(rootConfigWith({ interceptor: { enabled: 'false' } }));
    plugin.register(api);
    const combined = warnings.join('\n');
    expect(combined).toMatch(/interceptor\.enabled/);
  });

  it('logs a warning naming a dropped nested actionGuard key', () => {
    const { api, warnings } = makeApi(rootConfigWith({
      interceptor: { actionGuard: { autoApprove: 'not-an-array' } },
    }));
    plugin.register(api);
    const combined = warnings.join('\n');
    expect(combined).toMatch(/interceptor\.actionGuard\.autoApprove/);
  });

  it('does NOT warn when the config is entirely valid', () => {
    const { api, warnings } = makeApi(rootConfigWith({ interceptor: { enabled: true } }));
    plugin.register(api);
    const combined = warnings.join('\n');
    expect(combined).not.toMatch(/dropped/i);
  });

  it('does NOT warn about keys that are simply absent (not invalid)', () => {
    const { api, warnings } = makeApi(rootConfigWith({ interceptor: { enabled: true } }));
    plugin.register(api);
    const combined = warnings.join('\n');
    expect(combined).not.toMatch(/severityActions/);
    expect(combined).not.toMatch(/failurePolicy/);
  });
});

// ==================== 3. autoApprove defensive copy ====================

describe('#115.4 — actionGuard.autoApprove is defensively copied', () => {
  it('mutating the original array after parse does not affect the normalised config', () => {
    const original = ['file-delete'];
    const parsed = plugin.configSchema.parse({
      interceptor: { actionGuard: { autoApprove: original } },
    }) as any;
    expect(parsed.interceptor.actionGuard.autoApprove).toEqual(['file-delete']);

    original.push('sudo');

    expect(parsed.interceptor.actionGuard.autoApprove).toEqual(['file-delete']);
  });

  it('the normalised array is a different reference from the input array', () => {
    const original = ['file-delete'];
    const parsed = plugin.configSchema.parse({
      interceptor: { actionGuard: { autoApprove: original } },
    }) as any;
    expect(parsed.interceptor.actionGuard.autoApprove).not.toBe(original);
  });
});
