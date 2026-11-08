import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import plugin, {
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { __resetPostureStateForTest } from '../posture-report.js';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { applyPolicyLock, type PolicyLockState } from '../../../src/defence/iron-dome/policy-lock.js';
import { parseSelfReport } from '../../../src/posture/posture-record.js';
import { resolvePlanePostures, type PlanePosture } from '../../../src/guard/posture-switch.js';

/**
 * #922 PR939 r1 — the OpenClaw plane of `guard posture` / doctor's posture row
 * must equal what the real plugin resolves. Each row runs the actual plugin
 * (normaliseConfig → mergeConfigs → applyPolicyLockToPluginConfig →
 * register/initInterceptor) and the resolver over the same two files, and
 * compares. The defence module carries the REAL `applyPolicyLock` and an
 * unlocked reader, so the plugin takes its production path (withGuardPosture)
 * rather than the no-module degrade.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

const NO_LOCK: PolicyLockState = { status: 'absent', path: '/nonexistent/policy.json' };

type Hooks = Record<string, (...args: any[]) => any>;

let root: string;
let configDir: string;
const prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const prevProfile = process.env.OPENCLAW_PROFILE;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-922-diff-')));
  configDir = path.join(root, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true });
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  delete process.env.OPENCLAW_PROFILE;
  __resetConfigStateForTest();
  __resetPostureStateForTest();
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  if (prevProfile === undefined) delete process.env.OPENCLAW_PROFILE;
  else process.env.OPENCLAW_PROFILE = prevProfile;
});

function readConfiguredPosture(): string {
  const dir = path.join(configDir, 'posture', 'openclaw', 'default');
  const [file] = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
  const text = fs.readFileSync(path.join(dir, file), 'utf8');
  const parsed = parseSelfReport(text, Buffer.byteLength(text));
  if (parsed.kind !== 'valid') throw new Error('invalid self-report');
  return parsed.report.configured_posture;
}

/** What the real plugin gates with, in the resolver's vocabulary. */
async function pluginPosture(shield: Record<string, unknown>, entryConfig: Record<string, unknown>): Promise<PlanePosture> {
  __setRuntimeForTest({
    callCortex: async () => null,
    isOpenClawAutoMemoryEnabled: () => false,
    loadShieldConfig: async () => shield,
  } as any);
  __setDefenceModuleForTest({
    runDefencePipeline: okPipeline,
    evaluateToolCall,
    readPolicyLock: () => NO_LOCK,
    applyPolicyLock,
  } as any);
  const hooks: Hooks = {};
  plugin.register({
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: { info: () => {}, warn: () => {} },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: () => {},
    runtime: { config: { current: () => ({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: entryConfig } } } }) } },
  } as any);
  if (!hooks['before_tool_call']) return 'off';
  await hooks['before_tool_call']({ toolName: 'Bash', params: { command: 'ls' } });
  const p = readConfiguredPosture();
  return p === 'intentionally-off' ? 'off' : (p as PlanePosture);
}

function resolverPosture(shield: Record<string, unknown>, entryConfig: Record<string, unknown>): PlanePosture | null {
  const report = resolvePlanePostures({
    signedRaw: shield,
    integrity: 'valid',
    lock: NO_LOCK,
    claudeWired: false,
    openclaw: { state: 'ok', raw: { plugins: { entries: { 'shieldcortex-realtime': { enabled: true, config: entryConfig } } } } },
    postureRecords: [],
  });
  return report.planes.find((p) => p.plane === 'openclaw')?.posture ?? null;
}

const ON = { enabled: true, enforce: true };
const ADV = { enabled: true, enforce: false };

const CASES: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
  ['shield enforce, empty entry', { actionGuard: ON }, {}],
  ['shield advisory, empty entry', { actionGuard: ADV }, {}],
  ['shield interceptor.enabled:false + guard enforce (withGuardPosture re-arms)', { interceptor: { enabled: false }, actionGuard: ON }, {}],
  ['shield interceptor.enabled:false, guard off', { interceptor: { enabled: false } }, {}],
  ['entry interceptor.enabled:false (not registered)', { actionGuard: ON }, { interceptor: { enabled: false } }],
  ['entry interceptor.enabled:"false" string is dropped', { actionGuard: ON }, { interceptor: { enabled: 'false' } }],
  ['entry enforce:"false" string is dropped, base advisory survives', { actionGuard: ADV }, { actionGuard: { enforce: 'false' } }],
  ['entry enforce:0 is dropped', { actionGuard: ADV }, { actionGuard: { enforce: 0 } }],
  ['entry enforce:null is dropped', { actionGuard: ADV }, { actionGuard: { enforce: null } }],
  ['entry enabled:"true" is dropped, base off survives', {}, { actionGuard: { enabled: 'true', enforce: true } }],
  ['entry enabled:1 is dropped', { actionGuard: { enabled: false } }, { actionGuard: { enabled: 1 } }],
  ['entry enforce:false boolean wins', { actionGuard: ON }, { actionGuard: { enforce: false } }],
  ['entry enabled:false boolean wins', { actionGuard: ON }, { actionGuard: { enabled: false } }],
  ['shield invalid top enforce does not obscure alias enforce:false',
    { actionGuard: { enabled: true, enforce: 'yes' }, interceptor: { actionGuard: { enforce: false } } }, {}],
  ['entry invalid top enforce does not obscure entry alias enforce:false',
    { actionGuard: ON }, { actionGuard: { enforce: null }, interceptor: { actionGuard: { enforce: false } } }],
  ['shield invalid top enabled does not obscure alias enabled:true',
    { actionGuard: { enabled: 'true', enforce: true }, interceptor: { actionGuard: { enabled: true } } }, {}],
  ['shield non-object top actionGuard falls to the alias', { actionGuard: 'on', interceptor: { actionGuard: ADV } }, {}],
  ['entry non-object top actionGuard leaves base', { actionGuard: ADV }, { actionGuard: true }],
];

describe('#922 OpenClaw plane equals the real plugin (differential)', () => {
  it.each(CASES)('%s', async (_name, shield, entryConfig) => {
    expect(resolverPosture(shield, entryConfig)).toBe(await pluginPosture(shield, entryConfig));
  });
});
