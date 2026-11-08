import { createHmac } from 'node:crypto';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, promises as fsPromises, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
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

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

type FsFn = (...args: any[]) => any;
/**
 * Route `node:fs/promises` <name> calls on THIS test's config.json through
 * `wrap` (every other path untouched) until the returned restore runs. The
 * runtime imports that module's default object, which is this one.
 */
function interceptConfig(name: 'lstat' | 'readFile', wrap: (orig: FsFn, args: any[]) => any): () => void {
  const target = fsPromises as unknown as Record<string, FsFn>;
  const orig = target[name];
  target[name] = (...args: any[]) => (args[0] === configPath() ? wrap(orig, args) : orig(...args));
  return () => { target[name] = orig; };
}

const eio = (): NodeJS.ErrnoException => Object.assign(new Error('test-injected EIO'), { code: 'EIO' });

/** The real plugin over an unsigned link whose target says Guard off: the runtime holds it strict, so it is gated. */
async function warmUnsignedLinkGate(): Promise<{ hooks: Hooks; target: string }> {
  const target = join(root, 'unsigned-target.json');
  writeFileSync(target, JSON.stringify({ actionGuard: { enabled: false } }));
  symlinkSync(target, configPath());
  const hooks = await registerWithRealRuntime();
  expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
  return { hooks, target };
}

/** Atomically replace the link with a whitespace-only regular file (no ENOENT in between). */
function renameBlankOverLink(): void {
  const replacement = join(configDir, 'replacement.json');
  writeFileSync(replacement, '   ');
  renameSync(replacement, configPath());
  expect(lstatSync(configPath()).isFile()).toBe(true);
}

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

describe('plugin gate over the real runtime: lstat faults and overlapping reads keep the strict gate (#983 review)', () => {
  it('unsigned link held strict, lstat EIO on config.json with the Guard-off target readable: still gated, and after recovery', async () => {
    const { hooks } = await warmUnsignedLinkGate();
    let hits = 0;
    const restore = interceptConfig('lstat', () => {
      hits += 1;
      return Promise.reject(eio());
    });
    let during = false;
    try {
      during = gated(await hooks['before_tool_call'](GATED));
    } finally {
      restore();
    }
    const recovered = gated(await hooks['before_tool_call'](GATED));
    expect(hits).toBeGreaterThan(0);
    expect({ during, recovered }).toEqual({ during: true, recovered: true });
  });

  it('target blanked while the lstat fault persists, then the fault clears: gated throughout', async () => {
    const { hooks, target } = await warmUnsignedLinkGate();
    let hits = 0;
    const restore = interceptConfig('lstat', () => {
      hits += 1;
      return Promise.reject(eio());
    });
    let during = false;
    let blankDuring = false;
    try {
      during = gated(await hooks['before_tool_call'](GATED));
      await tick();
      writeFileSync(target, '   ');
      blankDuring = gated(await hooks['before_tool_call'](GATED));
    } finally {
      restore();
    }
    const recovered = gated(await hooks['before_tool_call'](GATED));
    expect(hits).toBeGreaterThan(0);
    expect({ during, blankDuring, recovered }).toEqual({ during: true, blankDuring: true, recovered: true });
  });

  it('a blank regular file renamed over the unsigned link while another tool call is reading: every call stays gated', async () => {
    const { hooks } = await warmUnsignedLinkGate();
    renameBlankOverLink();
    let release!: () => void;
    const released = new Promise<void>((resolve) => { release = resolve; });
    let began!: () => void;
    const parked = new Promise<void>((resolve) => { began = resolve; });
    let fired = false;
    const restore = interceptConfig('readFile', (orig, args) => {
      if (fired) return orig(...args);
      fired = true;
      began();
      return released.then(() => orig(...args));
    });
    let pending: Promise<any> = Promise.resolve();
    let second = false;
    try {
      // The first call parks inside its config read; the second runs while it is parked.
      pending = hooks['before_tool_call'](GATED);
      await Promise.race([parked, pending]);
      const secondCall = hooks['before_tool_call'](GATED);
      await Promise.race([secondCall, sleep(150)]);
      release();
      second = gated(await secondCall);
    } finally {
      release();
      restore();
    }
    const completed = gated(await pending);
    const subsequent = gated(await hooks['before_tool_call'](GATED));
    expect(fired).toBe(true);
    expect({ second, completed, subsequent }).toEqual({ second: true, completed: true, subsequent: true });
  });

  it('control: the same rename with one tool call at a time stays gated', async () => {
    const { hooks } = await warmUnsignedLinkGate();
    renameBlankOverLink();
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
    expect(gated(await hooks['before_tool_call'](GATED))).toBe(true);
  });
});

describe('plugin gate over the real runtime: a cold gateway whose config.json cannot be lstat\'d (v5.17.2 release review r3 B1)', () => {
  // The CLI's signature over the object minus `_sig`, keyed by the local `.integrity-key`.
  const KEY = 'c'.repeat(64);
  function writeSigned(body: Record<string, unknown>): void {
    writeFileSync(join(configDir, '.integrity-key'), KEY, { mode: 0o600 });
    const sig = createHmac('sha256', KEY).update(JSON.stringify(body, null, 2)).digest('hex');
    writeFileSync(configPath(), JSON.stringify({ ...body, _sig: sig }, null, 2), { mode: 0o600 });
  }

  /** Register and make the first tool call with every lstat of config.json failing EIO after `pass` go through. */
  async function firstCallUnderLstatFault(pass: number): Promise<{ gatedFirst: boolean; hits: number }> {
    let hits = 0;
    let passes = pass;
    const restore = interceptConfig('lstat', (orig, args) => {
      if (passes > 0) {
        passes -= 1;
        return orig(...args);
      }
      hits += 1;
      return Promise.reject(eio());
    });
    try {
      const hooks = await registerWithRealRuntime();
      return { gatedFirst: gated(await hooks['before_tool_call'](GATED)), hits };
    } finally {
      restore();
    }
  }

  for (const [where, pass] of [['first entry snapshot', 0], ['post-read entry snapshot', 1]] as const) {
    it(`signed enforcing config.json, lstat EIO at the ${where}: gated from the first tool call (v5.17.1 gated it; #983 let it through)`, async () => {
      writeSigned(ENFORCING);
      const { gatedFirst, hits } = await firstCallUnderLstatFault(pass);
      expect(hits).toBeGreaterThan(0);
      expect(gatedFirst).toBe(true);
    });

    it(`control: signed default-off config.json, lstat EIO at the ${where}: not gated — Guard stays off`, async () => {
      writeSigned({ actionGuard: { enabled: false } });
      const { gatedFirst, hits } = await firstCallUnderLstatFault(pass);
      expect(hits).toBeGreaterThan(0);
      expect(gatedFirst).toBe(false);
    });
  }
});
