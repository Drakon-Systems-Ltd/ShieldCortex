import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  __isDefenceModuleDistrustedForTest,
  __loadConfigForTest,
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { applyPolicyLock } from '../../../src/defence/iron-dome/policy-lock.js';

const hostHasProductionRoot = fs.existsSync('/etc/shieldcortex') || fs.existsSync('/etc/shieldcortex.conf');
const describeHere = hostHasProductionRoot || process.platform === 'win32' ? describe.skip : describe;
const UNSIGNED = {
  interceptor: { enabled: false, failurePolicy: { high: 'allow' } },
  actionGuard: { enabled: false, enforce: false, autoApprove: ['exec'] },
};

let root: string;
let protectedRoot: string;
const previousConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const previousProtectedRoot = process.env.SHIELDCORTEX_PROTECTED_ROOT;
const previousProfile = process.env.OPENCLAW_PROFILE;
const originalWarn = console.warn;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1146-plugin-')));
  const configDir = path.join(root, '.shieldcortex');
  protectedRoot = path.join(root, 'protected');
  fs.mkdirSync(configDir);
  fs.mkdirSync(protectedRoot);
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env.SHIELDCORTEX_PROTECTED_ROOT = protectedRoot;
  delete process.env.OPENCLAW_PROFILE;
  console.warn = () => {};
  __resetConfigStateForTest();
  __setRuntimeForTest({
    callCortex: async () => null,
    isOpenClawAutoMemoryEnabled: () => false,
    loadShieldConfig: async () => UNSIGNED,
  } as any);
});

afterEach(() => {
  console.warn = originalWarn;
  __setDefenceModuleForTest(undefined);
  __setRuntimeForTest(null);
  fs.rmSync(root, { recursive: true, force: true });
  if (previousConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = previousConfigDir;
  if (previousProtectedRoot === undefined) delete process.env.SHIELDCORTEX_PROTECTED_ROOT;
  else process.env.SHIELDCORTEX_PROTECTED_ROOT = previousProtectedRoot;
  if (previousProfile === undefined) delete process.env.OPENCLAW_PROFILE;
  else process.env.OPENCLAW_PROFILE = previousProfile;
});

function writeLock(): void {
  fs.writeFileSync(path.join(protectedRoot, 'policy.json'), JSON.stringify({ v: 1, actionGuard: { enabled: true, enforce: true } }));
}

function useEmptyGuardConfig(): void {
  __setRuntimeForTest({
    callCortex: async () => null,
    isOpenClawAutoMemoryEnabled: () => false,
    loadShieldConfig: async () => ({ interceptor: { enabled: false, failurePolicy: { high: 'allow' } }, actionGuard: {} }),
  } as any);
}

function expectStrictPosture(config: any): void {
  expect(config.interceptor).toMatchObject({
    enabled: true,
    failurePolicy: { high: 'deny' },
    actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [] },
  });
  expect(__isDefenceModuleDistrustedForTest()).toBe(true);
}

async function loadWithOutput(output: Record<string, unknown>): Promise<any> {
  __setDefenceModuleForTest({
    readPolicyLock: () => ({ status: 'locked' }),
    applyPolicyLock: () => output,
  } as any);
  return __loadConfigForTest();
}

describeHere('#1146 malformed loaded policy-lock output', () => {
  it.each([
    ['defenceMode only', { defenceMode: 'balanced' }, { defenceMode: 'balanced' }],
    ['memory only', { memory: { inject: { mode: 'off' } } }, { memory: { inject: { mode: 'off' } } }],
    ['actionGuard.enabled false only', { actionGuard: { enabled: false } }, {}],
  ])('trusts the real applier for a %s lock with an empty input guard', async (_name, policy, expectedPosture) => {
    fs.writeFileSync(path.join(protectedRoot, 'policy.json'), JSON.stringify({ v: 1, ...policy }));
    useEmptyGuardConfig();
    const verdict = { status: 'locked', path: path.join(protectedRoot, 'policy.json'), policy };
    expect(applyPolicyLock({ actionGuard: {} }, verdict as any)).toMatchObject({ actionGuard: {}, ...expectedPosture });
    __setDefenceModuleForTest({ readPolicyLock: () => verdict, applyPolicyLock } as any);

    const config = await __loadConfigForTest();
    expect(config.interceptor).toMatchObject({ enabled: false, failurePolicy: { high: 'allow' }, actionGuard: {} });
    expect(config.interceptor.actionGuard).toEqual({});
    expect(__isDefenceModuleDistrustedForTest()).toBe(false);
  });

  it.each([
    ['missing', {}],
    ['null', { actionGuard: null }],
    ['array', { actionGuard: [] }],
    ['empty object', { actionGuard: {} }],
  ])('fails closed and distrusts the module for %s actionGuard with an inline lock', async (_name, output) => {
    writeLock();
    const config = await loadWithOutput(output);
    expect(config.interceptor).toMatchObject({
      enabled: true,
      failurePolicy: { high: 'deny' },
      actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [] },
    });
    expect(__isDefenceModuleDistrustedForTest()).toBe(true);
  });

  it.each([
    ['missing', {}],
    ['null', { actionGuard: null }],
    ['array', { actionGuard: [] }],
    ['empty object', { actionGuard: {} }],
  ])('keeps the unsigned config on a no-lock host for %s actionGuard', async (_name, output) => {
    const config = await loadWithOutput(output);
    expect(config.interceptor).toMatchObject({
      enabled: false,
      failurePolicy: { high: 'allow' },
      actionGuard: { enabled: false, enforce: false, autoApprove: ['exec'] },
    });
    expect(__isDefenceModuleDistrustedForTest()).toBe(false);
  });

  it('accepts an ordinary nonempty locked guard and trusts the module', async () => {
    writeLock();
    __setDefenceModuleForTest({
      readPolicyLock: () => ({ status: 'locked', policy: { actionGuard: { enabled: true, enforce: true, autoApprove: [] } } }),
      applyPolicyLock,
    } as any);
    const config = await __loadConfigForTest();
    expect(config.interceptor).toMatchObject({
      enabled: true,
      failurePolicy: { high: 'deny' },
      actionGuard: { enabled: true, enforce: true, autoApprove: [] },
    });
    expect(__isDefenceModuleDistrustedForTest()).toBe(false);
  });

  it.each([
    ['null policy', null],
    ['array policy', []],
    ['scalar policy', 'locked'],
    ['null guard pin', { actionGuard: null }],
    ['array guard pin', { actionGuard: [] }],
    ['malformed enabled pin', { actionGuard: { enabled: 'false' } }],
    ['malformed broker pin', { actionGuard: { broker: null } }],
    ['malformed broker enabled pin', { actionGuard: { broker: { enabled: 'true' } } }],
  ])('rejects %s with an empty guard on an inline-locked host', async (_name, policy) => {
    writeLock();
    useEmptyGuardConfig();
    __setDefenceModuleForTest({
      readPolicyLock: () => ({ status: 'locked', policy }),
      applyPolicyLock: () => ({ actionGuard: {} }),
    } as any);
    expectStrictPosture(await __loadConfigForTest());
  });

  it('keeps an empty unsigned config for a null policy without an inline lock', async () => {
    useEmptyGuardConfig();
    __setDefenceModuleForTest({
      readPolicyLock: () => ({ status: 'locked', policy: null }),
      applyPolicyLock: () => ({ actionGuard: {} }),
    } as any);
    const config = await __loadConfigForTest();
    expect(config.interceptor).toMatchObject({ enabled: false, failurePolicy: { high: 'allow' } });
    expect(__isDefenceModuleDistrustedForTest()).toBe(false);
  });

  it.each([
    ['applier changes input guard', (view: any, _verdict: any) => {
      view.actionGuard = {};
      return { actionGuard: {} };
    }],
    ['result accessor changes input guard', (view: any, _verdict: any) => ({
      get actionGuard() { view.actionGuard = {}; return {}; },
    })],
    ['applier removes guard pin', (_view: any, verdict: any) => {
      verdict.policy = {};
      return { actionGuard: {} };
    }],
    ['result accessor removes guard pin', (_view: any, verdict: any) => ({
      get actionGuard() { verdict.policy = {}; return {}; },
    })],
  ] as const)('rejects empty guard when %s', async (_name, apply) => {
    writeLock();
    const mutatesInput = _name.includes('input guard');
    if (!mutatesInput) useEmptyGuardConfig();
    const verdict = { status: 'locked', policy: mutatesInput ? {} : { actionGuard: { enabled: true } } };
    __setDefenceModuleForTest({ readPolicyLock: () => verdict, applyPolicyLock: apply } as any);
    const config = await __loadConfigForTest();
    expectStrictPosture(config);
  });

  it('keeps the unsigned config when the accessor mutates evidence without an inline lock', async () => {
    const verdict = { status: 'locked', policy: { actionGuard: { enabled: true } } };
    __setDefenceModuleForTest({
      readPolicyLock: () => verdict,
      applyPolicyLock: () => ({
        get actionGuard() { verdict.policy = {} as any; return {}; },
      }),
    } as any);
    const config = await __loadConfigForTest();
    expect(config.interceptor).toMatchObject({
      enabled: false,
      failurePolicy: { high: 'allow' },
      actionGuard: { enabled: false, enforce: false, autoApprove: ['exec'] },
    });
    expect(__isDefenceModuleDistrustedForTest()).toBe(false);
  });
});
