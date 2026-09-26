/**
 * #594 — the plugin hands the detected host version to the guard's native
 * contract table (`setNativeHostVersion`) so `sessions_spawn` is judged by the
 * revision measured at THIS host. Pinned so it fails with the wire removed:
 *
 *   - the helper: the runtime's own version outranks the on-disk package.json,
 *     exactly as the conversation gate's evidence order; a null probe records
 *     null (unknown host), never a guess; an older dist with no setter is a
 *     no-op, and a throwing setter never takes interceptor construction down;
 *   - the WIRE: `register()` → first `before_tool_call` → the defence module's
 *     setter has been called with the host's runtime version; and, with the
 *     REAL setter and evaluator, ordinary coordinator dispatch on the pinned
 *     release writes no CONTRACT DRIFT line, while the same dispatch on the
 *     older release writes one that names the older revision.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import plugin, {
  recordHostVersionForGuard,
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
  __setHostOpenClawProbeForTest,
  __setHostRuntimeVersionForTest,
} from '../index.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import {
  setNativeHostVersion,
  nativeHostVersion,
  measuredOpenClawSpawnRevisions,
} from '../../../src/defence/iron-dome/tool-input-schema.js';

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

type Hooks = Record<string, (...args: any[]) => any>;

function makeApi(hostRuntimeVersion: string | null) {
  const hooks: Hooks = {};
  const warns: string[] = [];
  const api = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: (m: unknown) => { warns.push(String(m)); } },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: () => {},
    runtime: {
      // The Action Guard is off by default; arm it so the drift observation
      // (which rides on the guard's allow path) can be seen at all.
      config: {
        current: () => ({
          plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: { interceptor: { actionGuard: { enabled: true, enforce: true } } } } } },
        }),
      },
      ...(hostRuntimeVersion ? { version: hostRuntimeVersion } : {}),
    },
  };
  return { api, hooks, warns };
}

const revisions = measuredOpenClawSpawnRevisions();
const OLDEST = revisions[0]!.hostVersion;
const NEWEST = revisions[revisions.length - 1]!.hostVersion;

/** The spawn an ordinary coordinator sends. */
const ORDINARY_DISPATCH = {
  task: 'review the failing suite and report',
  label: 'review',
  runtime: 'subagent',
  mode: 'run',
  cleanup: 'keep',
  context: 'isolated',
  expectsCompletionMessage: true,
};

beforeEach(() => {
  __resetConfigStateForTest();
  __setRuntimeForTest({
    callCortex: async () => null,
    isOpenClawAutoMemoryEnabled: () => false,
    loadShieldConfig: async () => ({}),
  } as never);
  __setHostOpenClawProbeForTest(null);
});

afterEach(() => {
  __setHostOpenClawProbeForTest(undefined);
  __setHostRuntimeVersionForTest(null);
  __setDefenceModuleForTest(undefined);
  setNativeHostVersion('openclaw', null);
});

describe('recordHostVersionForGuard (#594) — the helper', () => {
  it('records the runtime version first, then the package.json version', () => {
    const calls: unknown[][] = [];
    const mod = { setNativeHostVersion: (...a: unknown[]) => { calls.push(a); } };
    __setHostOpenClawProbeForTest({ version: '2026.9.5', root: '/x', declaresGate: true, versionSource: 'package.json' } as never);
    __setHostRuntimeVersionForTest('2026.9.6');
    expect(recordHostVersionForGuard(mod as never)).toBe('2026.9.6');
    expect(calls).toEqual([['openclaw', '2026.9.6']]);

    __setHostRuntimeVersionForTest(null);
    expect(recordHostVersionForGuard(mod as never)).toBe('2026.9.5');
    expect(calls[1]).toEqual(['openclaw', '2026.9.5']);
  });

  it('records null — unknown host — when neither source knows, never a guess', () => {
    const calls: unknown[][] = [];
    const mod = { setNativeHostVersion: (...a: unknown[]) => { calls.push(a); } };
    __setHostRuntimeVersionForTest(null);
    expect(recordHostVersionForGuard(mod as never)).toBeNull();
    expect(calls).toEqual([['openclaw', null]]);
  });

  it('an older dist without the setter is a no-op; a throwing setter is contained', () => {
    __setHostRuntimeVersionForTest('2026.9.6');
    expect(recordHostVersionForGuard({} as never)).toBeNull();
    expect(recordHostVersionForGuard(null)).toBeNull();
    expect(recordHostVersionForGuard(undefined)).toBeNull();
    const throwing = { setNativeHostVersion: () => { throw new Error('boom'); } };
    expect(() => recordHostVersionForGuard(throwing as never)).not.toThrow();
    expect(recordHostVersionForGuard(throwing as never)).toBeNull();
  });
});

describe('register() → before_tool_call — the wire (#594)', () => {
  it('the first tool call hands the host runtime version to the defence module', async () => {
    const calls: unknown[][] = [];
    __setDefenceModuleForTest({
      runDefencePipeline: okPipeline,
      evaluateToolCall,
      setNativeHostVersion: (...a: unknown[]) => { calls.push(a); },
    } as never);
    const { api, hooks } = makeApi(NEWEST);
    plugin.register(api as never);
    expect(calls).toEqual([]);
    await hooks['before_tool_call']!({ toolName: 'Bash', params: { command: 'echo hi' } });
    expect(calls).toEqual([['openclaw', NEWEST]]);
  });

  it(`with the REAL setter: ordinary dispatch on ${NEWEST} writes no CONTRACT DRIFT line; on ${OLDEST} it names the older revision`, async () => {
    __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall, setNativeHostVersion } as never);

    const quiet = makeApi(NEWEST);
    plugin.register(quiet.api as never);
    await quiet.hooks['before_tool_call']!({ toolName: 'sessions_spawn', params: ORDINARY_DISPATCH });
    expect(nativeHostVersion('openclaw')).toBe(NEWEST);
    expect(quiet.warns.filter((w) => w.includes('CONTRACT DRIFT'))).toEqual([]);

    __resetConfigStateForTest();
    const loud = makeApi(OLDEST);
    plugin.register(loud.api as never);
    await loud.hooks['before_tool_call']!({ toolName: 'sessions_spawn', params: ORDINARY_DISPATCH });
    expect(nativeHostVersion('openclaw')).toBe(OLDEST);
    const drift = loud.warns.filter((w) => w.includes('CONTRACT DRIFT'));
    expect(drift).toHaveLength(1);
    expect(drift[0]).toContain(`judged by revision ${OLDEST} = host ${OLDEST}`);
    expect(drift[0]).toContain('dropped unread field(s) expectsCompletionMessage');
  });

  it('a host that states no version leaves the contract on the measured union: routine dispatch stays quiet', async () => {
    __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall, setNativeHostVersion } as never);
    const { api, hooks, warns } = makeApi(null);
    plugin.register(api as never);
    await hooks['before_tool_call']!({ toolName: 'sessions_spawn', params: ORDINARY_DISPATCH });
    expect(nativeHostVersion('openclaw')).toBeNull();
    expect(warns.filter((w) => w.includes('CONTRACT DRIFT'))).toEqual([]);
  });
});
