import { describe, it, expect, beforeEach } from '@jest/globals';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * Issue #112 — live incident (Edith, shieldcortex-realtime 4.47.12 + OpenClaw
 * 2026.7.1-2): `extractPluginConfig()` routes the plugin config through
 * `normaliseConfig()`, which is a strict key allowlist that predates the
 * interceptor and silently DROPS the entire nested `interceptor` object.
 * `interceptor.enabled: false` was therefore ignored, DEFAULT_INTERCEPTOR_CONFIG
 * re-armed the before_tool_call approval gate, Codex tool calls waited 120s on a
 * Telegram approval that could never resolve, and the agent went catatonic
 * ("visible channel turn dispatched with no queued reply payloads").
 *
 * These tests pin the contract at every layer the config crosses:
 *   1. normaliseConfig (via plugin.configSchema.parse) preserves every nested
 *      interceptor key — including explicit `false` values — and still validates.
 *   2. End-to-end: extractPluginConfig → loadConfig → initInterceptor →
 *      before_tool_call. `interceptor.enabled:false` means the gate never arms;
 *      `actionGuard.enforce:false` means advisory (warn-and-allow) for dangerous
 *      ops while catastrophic ops still hard-block.
 *   3. Merge semantics: defaults only fill gaps, never override explicit values;
 *      plugin config deep-merges over shield config per-key, not wholesale.
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

function makeApi(rootConfig: unknown): { api: any; hooks: Hooks; commands: Commands } {
  const hooks: Hooks = {};
  const commands: Commands = {};
  const api = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: () => {} },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: (cmd: any) => { commands[cmd.name] = cmd; },
    runtime: { config: { current: () => rootConfig } },
  };
  return { api, hooks, commands };
}

/** Root OpenClaw config with the plugin entry config exactly as on Edith. */
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
  // Real Action Guard evaluator + stub pipeline: the gate logic is genuine,
  // only the disk/embedding-backed defence pipeline is stubbed.
  __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall } as any);
});

// ==================== 1. normaliseConfig preserves the interceptor block ====================

describe('#112 — normaliseConfig() preserves nested interceptor config', () => {
  it('keeps interceptor.enabled:false (the exact Edith incident config)', () => {
    const parsed = plugin.configSchema.parse({ interceptor: { enabled: false } }) as any;
    expect(parsed.interceptor).toBeDefined();
    expect(parsed.interceptor.enabled).toBe(false);
  });

  it('keeps every nested interceptor key intact', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: {
        enabled: true,
        severityActions: { high: 'require_approval', critical: 'require_approval' },
        failurePolicy: { high: 'allow', critical: 'deny' },
        actionGuard: { enabled: true, enforce: false, autoApprove: ['file-delete'], auditAllows: false },
      },
    }) as any;
    expect(parsed.interceptor).toEqual({
      enabled: true,
      severityActions: { high: 'require_approval', critical: 'require_approval' },
      failurePolicy: { high: 'allow', critical: 'deny' },
      actionGuard: { enabled: true, enforce: false, autoApprove: ['file-delete'], auditAllows: false },
    });
  });

  it('explicit false values survive — false is a value, not an absence', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: { enabled: false, actionGuard: { enabled: false, enforce: false, auditAllows: false } },
    }) as any;
    expect(parsed.interceptor.enabled).toBe(false);
    expect(parsed.interceptor.actionGuard).toEqual({ enabled: false, enforce: false, auditAllows: false });
  });

  it('absent interceptor stays absent — defaults fill downstream, never during normalisation', () => {
    const parsed = plugin.configSchema.parse({ openclawAutoMemory: true }) as any;
    expect(parsed.interceptor).toBeUndefined();
    expect(parsed.openclawAutoMemory).toBe(true);
  });

  it('still validates: invalid interceptor values are dropped, valid siblings kept', () => {
    const parsed = plugin.configSchema.parse({
      interceptor: {
        enabled: 'yes',
        severityActions: { high: 'explode', critical: 'require_approval' },
        failurePolicy: { high: 'maybe' },
        actionGuard: { enforce: false, autoApprove: 'rm', bogus: true },
      },
    }) as any;
    expect(parsed.interceptor?.enabled).toBeUndefined();
    expect(parsed.interceptor?.severityActions?.high).toBeUndefined();
    expect(parsed.interceptor?.severityActions?.critical).toBe('require_approval');
    expect(parsed.interceptor?.failurePolicy?.high).toBeUndefined();
    expect(parsed.interceptor?.actionGuard?.enforce).toBe(false);
    expect(parsed.interceptor?.actionGuard?.autoApprove).toBeUndefined();
    expect(parsed.interceptor?.actionGuard?.bogus).toBeUndefined();
  });

  it('allowlist behaviour for everything else is unchanged (unknown keys dropped, scalars kept)', () => {
    const parsed = plugin.configSchema.parse({ evil: true, cloudApiKey: ' sc_x ', openclawAutoMemoryNoveltyThreshold: 0.8 }) as any;
    expect(parsed.evil).toBeUndefined();
    expect(parsed.cloudApiKey).toBe('sc_x');
    expect(parsed.openclawAutoMemoryNoveltyThreshold).toBe(0.8);
  });
});

// ==================== 2. End-to-end: config → before_tool_call gate ====================

describe('#112 — end-to-end: plugin config controls the before_tool_call gate', () => {
  // "Gate armed" observable: the typed-hook bridge currently surfaces an armed
  // gate either as { requireApproval } or as a failure-policy { block } (the
  // interceptor catches the TypedApprovalRequest bridge throw as an approval
  // error). Both mean the tool call was intercepted; neither may appear when
  // the user disabled the gate.
  const intercepted = (result: any): boolean => Boolean(result && (result.requireApproval || result.block));

  it('CONTROL (harness validity): default config arms the gate — dangerous op is intercepted', async () => {
    const { api, hooks } = makeApi(rootConfigWith({}));
    plugin.register(api);
    const result = await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } });
    expect(intercepted(result)).toBe(true);
  });

  it('interceptor.enabled:false → the before_tool_call hook is not registered at all (stronger contract post-#112-follow-up)', () => {
    const { api, hooks } = makeApi(rootConfigWith({ interceptor: { enabled: false } }));
    plugin.register(api);
    // Not a no-op handler — the hook must be ABSENT so the host's approval
    // pipeline can never route a tool call (or an approval wait) through us.
    expect(hooks['before_tool_call']).toBeUndefined();
  });

  it('interceptor.enabled:false → scanning hooks still register; only the tool-call gate is gone', () => {
    const { api, hooks } = makeApi(rootConfigWith({ interceptor: { enabled: false } }));
    plugin.register(api);
    expect(hooks['before_tool_call']).toBeUndefined();
    expect(typeof hooks['llm_input']).toBe('function');
    expect(typeof hooks['llm_output']).toBe('function');
  });

  it('actionGuard.enforce:false → advisory mode: dangerous op allowed without approval', async () => {
    const { api, hooks } = makeApi(rootConfigWith({ interceptor: { actionGuard: { enforce: false } } }));
    plugin.register(api);
    const result = await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } });
    expect(result).toBeUndefined();
  });

  it('actionGuard.enforce:false still hard-blocks catastrophic ops (safety floor preserved)', async () => {
    const { api, hooks } = makeApi(rootConfigWith({ interceptor: { actionGuard: { enforce: false } } }));
    plugin.register(api);
    const result = await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'rm -rf /' } });
    expect(result?.block).toBe(true);
  });

  it('defaults only fill gaps: partial interceptor config keeps the secure defaults for unspecified sections', async () => {
    const { api, hooks } = makeApi(rootConfigWith({ interceptor: { severityActions: { high: 'require_approval' } } }));
    plugin.register(api);
    const result = await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } });
    expect(intercepted(result)).toBe(true);
  });
});

// ==================== 3. Merge semantics across config sources ====================

describe('#112 — deep-merge semantics: shield config + plugin override, per-key', () => {
  it('plugin config deep-merges over shield config instead of wholesale-replacing the interceptor object', async () => {
    // Shield config file contributes autoApprove; plugin config contributes
    // enforce:false. BOTH must survive into the effective config.
    stubRuntime({ interceptor: { actionGuard: { autoApprove: ['file-delete'] } } });
    const { api, commands } = makeApi(rootConfigWith({ interceptor: { actionGuard: { enforce: false } } }));
    plugin.register(api);
    const status = await commands['shieldcortex-status'].handler();
    expect(status.text).toContain('Action guard: warn (1 auto-approved)');
  });

  it('shieldcortex-status reflects interceptor.enabled:false from plugin config', async () => {
    const { api, commands } = makeApi(rootConfigWith({ interceptor: { enabled: false } }));
    plugin.register(api);
    const status = await commands['shieldcortex-status'].handler();
    expect(status.text).toContain('Action guard: off');
  });

  it('interceptor config in the shield config file alone is honoured too (both sources route through normaliseConfig)', async () => {
    stubRuntime({ interceptor: { enabled: false } });
    const { api, hooks } = makeApi(rootConfigWith({}));
    plugin.register(api);
    const result = await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } });
    expect(result).toBeUndefined();
  });
});
