import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { __resetPostureStateForTest } from '../posture-report.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';

/**
 * The plugin gate over the REAL runtime reader (v5.17.2 release review B1/B2).
 *
 * `loadConfig` re-merges only when `loadShieldConfig()` hands back a different
 * object, and `initInterceptor` rebuilds from nothing when the merged
 * `actionGuard` posture changes — so a runtime that turned a blanked or
 * unreadable config.json into `{}` rebuilt the gate with Action Guard off
 * (interceptor.ts `runActionGuard`: `if (!actionGuardCfg.enabled) return`).
 * Here the runtime is `hooks/openclaw/cortex-memory/runtime.mjs` itself, with
 * only `callCortex` replaced (it shells out to mcporter); the decision is the
 * one `before_tool_call` returns to OpenClaw.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

const ENFORCING = { actionGuard: { enabled: true, enforce: true } };
/** Gated by an enabled, enforcing guard; passed with no decision when the guard is off. */
const GATED = { toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } };
const PINNED = 1_767_225_600;

type Hooks = Record<string, (...args: any[]) => any>;

let root: string;
let configDir: string;
const prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const configPath = () => join(configDir, 'config.json');

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-plugin-hold-'));
  configDir = join(root, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  __resetConfigStateForTest();
  __resetPostureStateForTest();
});

afterEach(() => {
  try {
    chmodSync(configPath(), 0o600);
  } catch { /* removed */ }
  rmSync(root, { recursive: true, force: true });
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  __setRuntimeForTest(null);
});

const tick = () => new Promise((resolve) => setTimeout(resolve, 25));

async function registerWithRealRuntime(): Promise<Hooks> {
  const { createOpenClawRuntime } = (await import('../../../hooks/openclaw/cortex-memory/runtime.mjs')) as {
    createOpenClawRuntime: (opts?: { configPath?: string }) => Record<string, any>;
  };
  const runtime = createOpenClawRuntime({ configPath: configPath() });
  __setRuntimeForTest({ ...runtime, callCortex: async () => null } as any);
  __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall } as any);
  const hooks: Hooks = {};
  plugin.register({
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: () => {} },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: () => {},
    // No plugin-entry actionGuard: the live enabled bit comes from config.json.
    runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: {} } } } }) } },
  } as any);
  expect(typeof hooks['before_tool_call']).toBe('function');
  return hooks;
}

const gated = (result: any): boolean => Boolean(result && (result.requireApproval || result.block));

describe('plugin gate over the real runtime: a blanked or unreadable config.json keeps the gate', () => {
  it('same-mtime whitespace blank after an enforcing read: still gated', async () => {
    const text = JSON.stringify(ENFORCING, null, 2);
    writeFileSync(configPath(), text, { mode: 0o600 });
    utimesSync(configPath(), PINNED, PINNED);
    const hooks = await registerWithRealRuntime();
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);

    const before = statSync(configPath(), { bigint: true });
    await tick();
    writeFileSync(configPath(), ' '.repeat(Buffer.byteLength(text)));
    utimesSync(configPath(), PINNED, PINNED);
    const after = statSync(configPath(), { bigint: true });
    expect([after.ino, after.size, after.mtimeNs]).toEqual([before.ino, before.size, before.mtimeNs]);
    expect(after.ctimeNs).not.toBe(before.ctimeNs);

    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
  });

  it('unreadable (mode 000) after an enforcing read: still gated', async () => {
    if (process.getuid?.() === 0) return; // root reads through mode 000
    writeFileSync(configPath(), JSON.stringify(ENFORCING), { mode: 0o600 });
    const hooks = await registerWithRealRuntime();
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
    await tick();
    chmodSync(configPath(), 0o000);
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
  });

  it('control (harness validity): removing config.json is the documented recovery — Guard off, not gated', async () => {
    writeFileSync(configPath(), JSON.stringify(ENFORCING), { mode: 0o600 });
    const hooks = await registerWithRealRuntime();
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
    rmSync(configPath());
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(false);
  });

  it('control: a valid Guard-off file replacing the enforcing one takes effect — not gated', async () => {
    writeFileSync(configPath(), JSON.stringify(ENFORCING), { mode: 0o600 });
    const hooks = await registerWithRealRuntime();
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
    await tick();
    writeFileSync(configPath(), JSON.stringify({ actionGuard: { enabled: false } }));
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(false);
  });

  it('control: a cold blank config.json is Guard off by default — not gated', async () => {
    writeFileSync(configPath(), '   ', { mode: 0o600 });
    const hooks = await registerWithRealRuntime();
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(false);
  });
});
