import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { __resetPostureStateForTest, writePostureSelfReport } from '../posture-report.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { parseSelfReport } from '../../../src/posture/posture-record.js';
import { collectPostureRecords, linuxProcessStart } from '../../../src/posture/collect.js';

/**
 * #613 — the OpenClaw plugin's process-side posture self-report.
 *
 * The plugin writes `<configDir>/posture/openclaw--<profile>.json` when it
 * registers and again once the interceptor has resolved its effective Action
 * Guard posture. The write is best-effort: it never throws into register()
 * or before_tool_call, and never changes what before_tool_call returns.
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

function makeApi(pluginConfig: unknown): { api: any; hooks: Hooks } {
  const hooks: Hooks = {};
  const api = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: () => {} },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: () => {},
    runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: pluginConfig } } } }) } },
  };
  return { api, hooks };
}

let root: string;
let configDir: string;
const prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const prevProfile = process.env.OPENCLAW_PROFILE;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-oc-posture-613-'));
  configDir = path.join(root, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true });
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  delete process.env.OPENCLAW_PROFILE;
  __resetConfigStateForTest();
  __resetPostureStateForTest();
  __setRuntimeForTest({
    callCortex: async () => null,
    isOpenClawAutoMemoryEnabled: () => false,
    loadShieldConfig: async () => ({}),
  } as any);
  __setDefenceModuleForTest({ runDefencePipeline: okPipeline, evaluateToolCall } as any);
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  if (prevProfile === undefined) delete process.env.OPENCLAW_PROFILE;
  else process.env.OPENCLAW_PROFILE = prevProfile;
});

const reportDir = (profile = 'default') => path.join(configDir, 'posture', 'openclaw', profile);
const reportFile = (profile = 'default') => {
  const files = fs.readdirSync(reportDir(profile)).filter((f) => f.endsWith('.json'));
  if (files.length !== 1) throw new Error(`expected one report, found ${files.join(', ')}`);
  return path.join(reportDir(profile), files[0]);
};

function readReport(profile = 'default') {
  const text = fs.readFileSync(reportFile(profile), 'utf8');
  const parsed = parseSelfReport(text, Buffer.byteLength(text));
  if (parsed.kind !== 'valid') throw new Error(`invalid report: ${parsed.kind === "invalid" ? parsed.reason : parsed.kind}`);
  return parsed.report;
}

describe('#613 writer', () => {
  it('writes a report the CLI validator accepts, privately, with no temp file left', () => {
    expect(writePostureSelfReport({ configDir, profile: 'default', configuredPosture: 'enforce', scanner: 'available', policy: { enforce: true } })).toBe(true);
    const r = readReport();
    expect(r.runtime).toBe('openclaw');
    expect(r.policy_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.instance.liveness).toBe('process');
    expect(r.instance.pid).toBe(process.pid);
    expect(fs.readdirSync(reportDir())).toEqual([`${r.instance.key}.json`]);
    expect(fs.statSync(reportFile()).mode & 0o077).toBe(0);
    for (const d of [path.join(configDir, 'posture'), path.join(configDir, 'posture', 'openclaw'), reportDir()]) {
      expect(fs.statSync(d).mode & 0o077).toBe(0);
    }
  });

  it('never throws when the directory is unwritable, and reports false', () => {
    fs.writeFileSync(path.join(configDir, 'posture'), 'a file');
    expect(() => writePostureSelfReport({ configDir, profile: 'default', configuredPosture: 'enforce', scanner: 'available' })).not.toThrow();
    expect(writePostureSelfReport({ configDir, profile: 'default', configuredPosture: 'enforce', scanner: 'available' })).toBe(false);
  });

  it('this live process reads back as current and loaded through the real collector (Linux start check)', () => {
    if (process.platform !== 'linux' || !linuxProcessStart(process.pid)) return;
    writePostureSelfReport({ configDir, profile: 'default', configuredPosture: 'enforce', scanner: 'available', policy: { enforce: true } });
    const home = path.join(root, 'home');
    fs.mkdirSync(home, { recursive: true });
    const [rec] = collectPostureRecords({ home, configDir, hostDeps: { openclawBinaryPresent: () => false } })
      .filter((x) => x.runtime === 'openclaw');
    expect(rec.liveness.value).toBe('alive');
    expect(rec.membership).toBe('current');
    expect(rec.runtime_loaded.value).toBe('yes');
  });

  it('a denial keeps its own timestamp and identity; a later policy change leaves it obsolete, not refreshed', () => {
    writePostureSelfReport({ configDir, configuredPosture: 'enforce', scanner: 'available', policy: { enforce: true }, nowMs: Date.parse('2026-09-29T10:00:00.000Z') });
    writePostureSelfReport({ configDir, denial: { kind: 'blocked-action', testedPath: 'before_tool_call:Bash' }, nowMs: Date.parse('2026-09-29T10:01:00.000Z') });
    writePostureSelfReport({ configDir, policy: { enforce: true, autoApprove: ['x'] }, nowMs: Date.parse('2026-09-29T10:02:00.000Z') });
    const r = readReport();
    expect(r.heartbeat_at).toBe('2026-09-29T10:02:00.000Z');
    expect(r.denials.blocked_action!.at).toBe('2026-09-29T10:01:00.000Z');
    expect(r.denials.blocked_action!.tested_path).toBe('before_tool_call:Bash');
    expect(r.denials.blocked_action!.policy_hash).not.toBe(r.policy_hash);
    expect(r.denials.blocked_action_count).toBe(1);
  });

  it('a synthetic probe is recorded separately and never counted', () => {
    writePostureSelfReport({ configDir, configuredPosture: 'enforce', scanner: 'available', denial: { kind: 'synthetic-probe', testedPath: 'probe:Bash' } });
    const r = readReport();
    expect(r.denials.synthetic_probe!.tested_path).toBe('probe:Bash');
    expect(r.denials.blocked_action).toBeNull();
    expect(r.denials.blocked_action_count).toBe(0);
  });

  it('bounds free text so the file stays under the size cap', () => {
    writePostureSelfReport({ configDir, profile: 'default', configuredPosture: 'enforce', scanner: 'degraded', degradedReason: 'y'.repeat(50_000) });
    expect(readReport().degraded_intervals[0].reason.length).toBeLessThanOrEqual(120);
  });
});

describe('#613 register() self-report', () => {
  it('reports loaded on register, then the resolved posture once the interceptor is built', async () => {
    const { api, hooks } = makeApi({ interceptor: { actionGuard: { enabled: true, enforce: true } } });
    plugin.register(api);
    expect(readReport().loaded).toBe(true);
    await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'ls' } });
    expect(readReport().configured_posture).toBe('enforce');
    expect(readReport().scanner).toBe('available');
  });

  it('interceptor disabled in host config → intentionally-off', () => {
    const { api } = makeApi({ interceptor: { enabled: false } });
    plugin.register(api);
    expect(readReport().configured_posture).toBe('intentionally-off');
  });

  it('OPENCLAW_PROFILE names the profile record', () => {
    process.env.OPENCLAW_PROFILE = 'Night';
    const { api } = makeApi({});
    plugin.register(api);
    expect(readReport('night').profile).toBe('night');
    expect(fs.existsSync(reportDir('default'))).toBe(false);
  });

  it('a block from before_tool_call is recorded as a blocked action (unattended cron session)', async () => {
    const { api, hooks } = makeApi({ interceptor: { actionGuard: { enabled: true, enforce: true } } });
    plugin.register(api);
    // No operator on a cron run: the dangerous tier denies instead of carding.
    const result = await hooks['before_tool_call'](
      { toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } },
      { sessionId: 'agent:main:cron:nightly' },
    );
    expect(result?.block).toBe(true);
    const r = readReport();
    expect(r.denials.blocked_action!.tested_path).toBe('before_tool_call:Bash');
    expect(r.denials.blocked_action!.configured_posture).toBe('enforce');
    expect(r.denials.blocked_action_count).toBe(1);
    expect(r.denials.synthetic_probe).toBeNull();
  });

  it('an approval card is not a denial', async () => {
    const { api, hooks } = makeApi({ interceptor: { actionGuard: { enabled: true, enforce: true } } });
    plugin.register(api);
    const result = await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } });
    expect(result?.requireApproval).toBeDefined();
    expect(readReport().denials.blocked_action).toBeNull();
  });
});

describe('#613 a self-report failure never changes a decision', () => {
  const cron = { sessionId: 'agent:main:cron:nightly' };
  const calls: Array<[Record<string, unknown>, Record<string, unknown> | undefined]> = [
    [{ toolName: 'Bash', params: { command: 'ls -la' } }, undefined],
    [{ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } }, undefined],
    [{ toolName: 'Bash', params: { command: 'crontab -e' } }, undefined],
    [{ toolName: 'Bash', params: { command: 'sudo systemctl stop ssh' } }, cron],
    [{ toolName: 'Bash', params: { command: 'ls -la' } }, cron],
  ];

  async function decisions(): Promise<string[]> {
    __resetConfigStateForTest();
    __resetPostureStateForTest();
    const { api, hooks } = makeApi({ interceptor: { actionGuard: { enabled: true, enforce: true } } });
    plugin.register(api);
    const out: string[] = [];
    for (const [event, ctx] of calls) {
      const r = await hooks['before_tool_call'](event, ctx);
      out.push(r === undefined ? 'allow' : r.block ? 'block' : r.requireApproval ? 'approval' : JSON.stringify(r));
    }
    return out;
  }

  it('identical results with the posture path blocked', async () => {
    const normal = await decisions();
    fs.rmSync(path.join(configDir, 'posture'), { recursive: true, force: true });
    fs.writeFileSync(path.join(configDir, 'posture'), 'blocked');
    const blocked = await decisions();
    expect(blocked).toEqual(normal);
    expect(new Set(normal)).toEqual(new Set(['allow', 'approval', 'block']));
  });
});
