import { describe, it, expect, beforeEach } from '@jest/globals';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * Issue #112 follow-up — unattended Codex command execution regression.
 *
 * Live incident (Edith, v4.47.13 + OpenClaw 2026.7.1-2, gpt-5.6-sol/terra +
 * gpt-5.5 over Telegram): a before_tool_call hook that exists in the host
 * roster — even as a no-op — changes how OpenClaw resolves tool-call
 * approvals. `shouldAutoApproveCodexAppServerApprovals()` only auto-resolves
 * when no plugin approval path is in play; otherwise native shell calls wait
 * on plugin.approval.waitDecision for ~120s, time out, and the Telegram turn
 * emits no reply.
 *
 * Contract pinned here, at the two layers config can disable the interceptor:
 *  1. Host plugin config `interceptor.enabled:false` (the unattended-agent
 *     config) → the hook is NOT REGISTERED. No hook, no approval path, the
 *     host's native auto-approval decides alone. Scanning hooks stay live.
 *  2. Shield config file `interceptor.enabled:false` (only loadable async,
 *     after registration) → the hook exists but must resolve IMMEDIATELY with
 *     no approval request and no block for a native shell call — never a
 *     waitDecision-shaped result.
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

function makeApi(rootConfig: unknown): { api: any; hooks: Hooks; commands: Commands; log: string[] } {
  const hooks: Hooks = {};
  const commands: Commands = {};
  const log: string[] = [];
  const api = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: (m: string) => { log.push(m); }, warn: (m: string) => { log.push(m); } },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: (cmd: any) => { commands[cmd.name] = cmd; },
    runtime: { config: { current: () => rootConfig } },
  };
  return { api, hooks, commands, log };
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

// The shapes an unattended Codex agent actually dispatches: native shell
// commands via the exec/bash family. Includes a benign command AND a
// "dangerous but non-catastrophic" one — with the interceptor disabled,
// NEITHER may produce an approval request (there is no one to approve it).
const UNATTENDED_SHELL_CALLS = [
  { toolName: 'exec', params: { command: 'ls -la /tmp' } },
  { toolName: 'Bash', params: { command: 'npm test' } },
  { toolName: 'Bash', params: { command: 'sudo systemctl restart myservice' } },
];

beforeEach(() => {
  __resetConfigStateForTest();
  stubRuntime({});
  __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall } as any);
});

describe('#112 follow-up — unattended Codex: interceptor disabled in host plugin config', () => {
  it('before_tool_call is not registered — the host approval pipeline has no plugin to wait on', () => {
    const { api, hooks } = makeApi(rootConfigWith({ interceptor: { enabled: false } }));
    plugin.register(api);
    expect(hooks['before_tool_call']).toBeUndefined();
    // #226: session_end IS registered now, and deliberately. What #112 is about
    // is the APPROVAL pipeline: a registered `before_tool_call` changes how
    // OpenClaw resolves tool-call approvals, so an unattended Codex turn waited
    // 120s on a decision nobody could give. `session_end` is a notification —
    // it cannot block, approve or delay anything — and the conversation gate
    // (registered regardless of `interceptor.enabled`) keeps per-session state
    // that needs freeing, so skipping it leaked a suppression window per
    // session for the life of the gateway.
    expect(typeof hooks['session_end']).toBe('function');
  });

  it('scanning stays live and the skip is logged', () => {
    const { api, hooks, log } = makeApi(rootConfigWith({ interceptor: { enabled: false } }));
    plugin.register(api);
    expect(typeof hooks['llm_input']).toBe('function');
    expect(typeof hooks['llm_output']).toBe('function');
    expect(log.some((m) => m.includes('before_tool_call hook not registered'))).toBe(true);
  });

  it('shieldcortex-status reports the unregistered gate honestly', async () => {
    const { api, commands } = makeApi(rootConfigWith({ interceptor: { enabled: false } }));
    plugin.register(api);
    const status = await commands['shieldcortex-status'].handler();
    expect(status.text).toContain('before_tool_call not registered');
    expect(status.text).not.toContain('before_tool_call (action guard)');
  });

  it('CONTROL (harness validity): without the disable, the hook IS registered and still gates dangerous ops', async () => {
    const { api, hooks } = makeApi(rootConfigWith({ interceptor: { actionGuard: { enabled: true } } }));
    plugin.register(api);
    expect(typeof hooks['before_tool_call']).toBe('function');
    const result = await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } });
    expect(Boolean(result && (result.requireApproval || result.block))).toBe(true);
  });
});

describe('#112 follow-up — unattended Codex: interceptor disabled via shield config file only', () => {
  // Registration cannot see the shield file (async load), so the hook exists —
  // but every unattended shell call must pass through instantly, untouched.
  it.each(UNATTENDED_SHELL_CALLS)(
    'native shell call %# resolves with no approval request and no block',
    async (event) => {
      stubRuntime({ interceptor: { enabled: false } });
      const { api, hooks } = makeApi(rootConfigWith({}));
      plugin.register(api);
      const result = await hooks['before_tool_call'](event);
      expect(result).toBeUndefined();
    },
  );

  it('resolves immediately — no timer-based wait anywhere in the disabled path', async () => {
    stubRuntime({ interceptor: { enabled: false } });
    const { api, hooks } = makeApi(rootConfigWith({}));
    plugin.register(api);
    const started = Date.now();
    await hooks['before_tool_call']({ toolName: 'exec', params: { command: 'echo unattended' } });
    // The Edith failure mode was a 120s waitDecision timeout. The disabled
    // path must be pure function calls — bound it well under any approval
    // timeout while staying CI-safe.
    expect(Date.now() - started).toBeLessThan(1000);
  });
});
