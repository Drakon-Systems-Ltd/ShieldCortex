import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  __loadConfigForTest,
  __resetConfigStateForTest,
  __setDefenceModuleForTest,
  __setRuntimeForTest,
} from '../index.js';
import { applyPolicyLock } from '../../../src/defence/iron-dome/policy-lock.js';

/**
 * #889 review item 6, the plugin's INLINE fail-closed copy.
 *
 * `applyStrictFailClosedPosture` in dist drops `packageVetting.enabled:false`
 * (package-vetting-policy-889.test.ts). The plugin has its own copy of that
 * posture for the case where a policy lock is on disk but the defence module
 * cannot be loaded, has no reader, throws, or lies about the lock
 * (`applyPolicyLockToPluginConfig` → `failClosed`). This pins that the copy
 * drops the opt-out too, keeps `minAgeDays`, and that without a lock the
 * operator's opt-out survives (control). The effective config is read through
 * the test seam; no tool call is made and no guard verdict is produced.
 *
 * The lock is a plain file under `SHIELDCORTEX_PROTECTED_ROOT`, which the
 * inline probe consults only on a host where neither production root
 * (`/etc/shieldcortex`, `/etc/shieldcortex.conf`) answers; on a host that has
 * one, these rows are skipped rather than run against the real lock.
 */

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

const hostHasProductionRoot = fs.existsSync('/etc/shieldcortex') || fs.existsSync('/etc/shieldcortex.conf');
const describeHere = hostHasProductionRoot || process.platform === 'win32' ? describe.skip : describe;

let root: string;
let protectedRoot: string;
const prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const prevProtectedRoot = process.env.SHIELDCORTEX_PROTECTED_ROOT;
const prevProfile = process.env.OPENCLAW_PROFILE;
const realWarn = console.warn;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-889-r4-plugin-')));
  const configDir = path.join(root, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true });
  protectedRoot = path.join(root, 'protected');
  fs.mkdirSync(protectedRoot, { recursive: true });
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env.SHIELDCORTEX_PROTECTED_ROOT = protectedRoot;
  delete process.env.OPENCLAW_PROFILE;
  // The once-per-load degrade note belongs to the plugin, not to this log.
  console.warn = () => {};
  __resetConfigStateForTest();
});

afterEach(() => {
  console.warn = realWarn;
  __setDefenceModuleForTest(undefined);
  __setRuntimeForTest(null);
  fs.rmSync(root, { recursive: true, force: true });
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  if (prevProtectedRoot === undefined) delete process.env.SHIELDCORTEX_PROTECTED_ROOT;
  else process.env.SHIELDCORTEX_PROTECTED_ROOT = prevProtectedRoot;
  if (prevProfile === undefined) delete process.env.OPENCLAW_PROFILE;
  else process.env.OPENCLAW_PROFILE = prevProfile;
});

const writeLock = () => fs.writeFileSync(path.join(protectedRoot, 'policy.json'), JSON.stringify({ v: 1, actionGuard: { enabled: true, enforce: true } }));

async function effectiveGuard(shield: Record<string, unknown>, mod: Record<string, unknown> | null): Promise<Record<string, any>> {
  __setRuntimeForTest({
    callCortex: async () => null,
    isOpenClawAutoMemoryEnabled: () => false,
    loadShieldConfig: async () => shield,
  } as any);
  __setDefenceModuleForTest(mod as any);
  const cfg = (await __loadConfigForTest()) as any;
  return cfg.interceptor?.actionGuard ?? {};
}

const OPT_OUT = { actionGuard: { enabled: true, enforce: false, packageVetting: { enabled: false, minAgeDays: 3 } } };
const NO_READER = { runDefencePipeline: okPipeline };
const LYING_READER = { runDefencePipeline: okPipeline, readPolicyLock: () => ({ status: 'absent', path: '/x' }), applyPolicyLock };
const THROWING_READER = { runDefencePipeline: okPipeline, readPolicyLock: () => { throw new Error('reader broke'); }, applyPolicyLock };

describeHere('#889 item 6 — the plugin inline fail-closed posture and packageVetting', () => {
  it.each([
    ['no policy reader on the module', NO_READER],
    ['a reader that says "absent" while the lock is on disk', LYING_READER],
    ['a reader that throws', THROWING_READER],
  ])('with a lock on disk and %s: enabled:false is dropped, minAgeDays kept, posture strict', async (_name, mod) => {
    writeLock();
    const guard = await effectiveGuard(OPT_OUT, mod);
    expect(guard.packageVetting).toEqual({ minAgeDays: 3 });
    expect(guard).toMatchObject({ enabled: true, enforce: true, autoApprove: [], reviewedScripts: [] });
    expect(guard.broker).toEqual({ enabled: false });
  });

  it('the deprecated interceptor.actionGuard spelling cannot carry the opt-out past the posture either', async () => {
    writeLock();
    const guard = await effectiveGuard({ interceptor: { actionGuard: { enabled: true, packageVetting: { enabled: false, minAgeDays: 2 } } } }, NO_READER);
    expect(guard.packageVetting).toEqual({ minAgeDays: 2 });
    expect(guard).toMatchObject({ enabled: true, enforce: true });
  });

  it('a config with no packageVetting block gains none (the posture adds nothing)', async () => {
    writeLock();
    const guard = await effectiveGuard({ actionGuard: { enabled: false } }, NO_READER);
    expect(guard).not.toHaveProperty('packageVetting');
    expect(guard).toMatchObject({ enabled: true, enforce: true });
  });

  it('control: with no lock on disk the operator opt-out survives a missing reader', async () => {
    const guard = await effectiveGuard(OPT_OUT, NO_READER);
    expect(guard.packageVetting).toEqual({ enabled: false, minAgeDays: 3 });
    expect(guard).toMatchObject({ enabled: true, enforce: false });
  });
});
