/**
 * #501 — the policy lock wired into the config reader.
 *
 * The precedence ALGEBRA (which of the lock and the config is tighter, per key)
 * is exhaustively covered in
 * `src/defence/iron-dome/__tests__/policy-lock-501.test.ts` against an injected
 * stat seam, including the genuinely root-owned positive case. This file covers
 * the WIRING: that `src/cloud/config.ts` actually consults the lock, that a
 * `tampered` HMAC verdict now forces the same posture, that the signed setters
 * refuse to loosen a locked key, and that a lock never leaks into the file on
 * disk.
 *
 * The lock used here is a same-UID one, so it reads as `unverifiable` — the
 * fail-closed branch. That is not a limitation of the test, it is the one lock
 * state a non-root process can create, and it is the state an attacker would
 * produce by forging or corrupting the real one.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV } from '../defence/iron-dome/protected-root.js';
import { POLICY_LOCK_FILENAME, clearPolicyLockReportState } from '../defence/iron-dome/policy-lock.js';

type ConfigModule = typeof import('../cloud/config.js');

let configDir: string;
let protectedRoot: string;
let prevConfigDir: string | undefined;
let prevProtectedRoot: string | undefined;

/**
 * A FRESH module instance per test.
 *
 * `src/cloud/config.ts` keeps process-lifetime state that no exported helper
 * clears — most importantly the `configTampered` flag, which is only ever reset
 * by a successful write. A tamper case would otherwise leak its posture into
 * every test that ran after it in the same file, and the suite would pass for
 * the wrong reason.
 */
async function freshConfig(): Promise<ConfigModule> {
  jest.resetModules();
  clearPolicyLockReportState();
  return import('../cloud/config.js');
}

/** Drop a same-UID policy.json into the protected root: an unverifiable lock. */
function writeSameUidLock(policy: unknown = { actionGuard: { enabled: true } }): string {
  const lockPath = path.join(protectedRoot, POLICY_LOCK_FILENAME);
  fs.writeFileSync(lockPath, JSON.stringify(policy, null, 2));
  return lockPath;
}

function readOnDisk(): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8'));
}

beforeEach(() => {
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-501-cfg-'));
  protectedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-501-root-'));
  prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
  prevProtectedRoot = process.env[PROTECTED_ROOT_ENV];
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = protectedRoot;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  if (prevProtectedRoot === undefined) delete process.env[PROTECTED_ROOT_ENV];
  else process.env[PROTECTED_ROOT_ENV] = prevProtectedRoot;
  fs.rmSync(configDir, { recursive: true, force: true });
  fs.rmSync(protectedRoot, { recursive: true, force: true });
});

describe('#501 an UNLOCKED host behaves exactly as it did before', () => {
  it('reads actionGuard.enabled: false as false', async () => {
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: false });
    expect(config.getActionGuardCoreConfig()).toEqual({ enabled: false, enforce: true });
  });

  it('lets the signed setter disable the guard', async () => {
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: true });
    expect(() => config.setActionGuardCoreConfig({ enabled: false })).not.toThrow();
    expect(config.getActionGuardCoreConfig().enabled).toBe(false);
  });

  it('leaves defenceMode at its configured value', async () => {
    const config = await freshConfig();
    config.setDefenceMode('permissive');
    expect(config.getDefenceMode()).toBe('permissive');
  });

  it('reports the lock as absent', async () => {
    const config = await freshConfig();
    const state = config.getPolicyLockState();
    expect(state.status).toBe('absent');
  });
});

describe('#501 an UNVERIFIABLE lock forces the strict posture through the config reader', () => {
  it('turns the guard on and enforcing over a config that says off', async () => {
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: false, enforce: false });
    writeSameUidLock();
    config.clearCloudConfigCache();

    const fresh = await freshConfig();
    expect(fresh.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true });
  });

  it('raises defenceMode to strict over a permissive config', async () => {
    const config = await freshConfig();
    config.setDefenceMode('permissive');
    writeSameUidLock();

    const fresh = await freshConfig();
    expect(fresh.getDefenceMode()).toBe('strict');
  });

  it('empties autoApprove and disables the broker in one pass', async () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      actionGuard: { enabled: false, autoApprove: ['ls', 'curl'], broker: { enabled: true } },
    }));
    writeSameUidLock();

    const fresh = await freshConfig();
    const guard = fresh.readRawConfig().actionGuard as Record<string, unknown>;
    expect(guard.autoApprove).toEqual([]);
    expect(guard.broker).toEqual({ enabled: false });
  });

  it('is reported as unverifiable, naming the reason', async () => {
    writeSameUidLock();
    const fresh = await freshConfig();
    const state = fresh.getPolicyLockState();
    expect(state.status).toBe('unverifiable');
    expect(state.status === 'unverifiable' && state.reason).toBe('owned-by-agent');
  });

  it('a corrupt lock is just as binding as a forged one', async () => {
    fs.writeFileSync(path.join(protectedRoot, POLICY_LOCK_FILENAME), '{ not json');
    const fresh = await freshConfig();
    expect(fresh.getActionGuardCoreConfig().enabled).toBe(true);
  });
});

describe('#501 the lock never leaks into config.json', () => {
  it('a later signed write persists what the operator set, not what the lock forced', async () => {
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: false });
    writeSameUidLock();

    const fresh = await freshConfig();
    // The lock is in force for READS…
    expect(fresh.getActionGuardCoreConfig().enabled).toBe(true);
    // …and an unrelated signed write must not bake that into the file. If it
    // did, removing the lock would leave the forced posture behind for ever.
    fresh.setCloudConfig({ cloudEnabled: true });
    const onDisk = readOnDisk();
    expect((onDisk.actionGuard as Record<string, unknown>).enabled).toBe(false);
    expect(onDisk.cloudEnabled).toBe(true);
    expect(onDisk.defenceMode).toBeUndefined();
  });
});

describe('#501 signed setters refuse to loosen a locked key', () => {
  it('refuses to disable the Action Guard, naming the lock file', async () => {
    writeSameUidLock();
    const fresh = await freshConfig();
    expect(() => fresh.setActionGuardCoreConfig({ enabled: false }))
      .toThrow(new RegExp(path.join(protectedRoot, POLICY_LOCK_FILENAME).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  });

  it('refuses an advisory downgrade', async () => {
    writeSameUidLock();
    const fresh = await freshConfig();
    expect(() => fresh.setActionGuardCoreConfig({ enforce: false })).toThrow(/Refusing to loosen/);
  });

  it('refuses a defenceMode below the locked floor', async () => {
    writeSameUidLock();
    const fresh = await freshConfig();
    expect(() => fresh.setDefenceMode('permissive')).toThrow(/Refusing to loosen/);
    expect(() => fresh.setDefenceMode('strict')).not.toThrow();
  });

  it('still allows a write that TIGHTENS', async () => {
    writeSameUidLock();
    const fresh = await freshConfig();
    expect(() => fresh.setActionGuardCoreConfig({ enabled: true, enforce: true })).not.toThrow();
  });

  it('refuses nothing on an unlocked host', async () => {
    const fresh = await freshConfig();
    expect(() => fresh.setActionGuardCoreConfig({ enabled: false })).not.toThrow();
    expect(() => fresh.setDefenceMode('permissive')).not.toThrow();
  });
});

describe('#501 a tampered HMAC verdict forces the SAME posture, not just defenceMode', () => {
  /** A signed config, then hand-edited so the embedded `_sig` no longer matches. */
  async function tamperedConfig(): Promise<ConfigModule> {
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: true, enforce: true });
    const onDisk = readOnDisk();
    onDisk.actionGuard = { enabled: false, enforce: false, autoApprove: ['anything'], broker: { enabled: true } };
    onDisk.defenceMode = 'permissive';
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify(onDisk, null, 2));
    return freshConfig();
  }

  it('flags the config as tampered', async () => {
    const fresh = await tamperedConfig();
    fresh.readRawConfig();
    expect(fresh.isConfigTampered()).toBe(true);
  });

  it('forces the guard on and enforcing — the pre-#501 gap', async () => {
    // Before #501 this returned { enabled: false, enforce: false }: the switches
    // were read straight out of the bytes the integrity check had just called
    // untrustworthy, so a detected tamper left the guard exactly as the tamper
    // wanted it.
    const fresh = await tamperedConfig();
    expect(fresh.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true });
  });

  it('forces defenceMode strict, empties autoApprove and disables the broker', async () => {
    const fresh = await tamperedConfig();
    const raw = fresh.readRawConfig();
    expect(raw.defenceMode).toBe('strict');
    const guard = raw.actionGuard as Record<string, unknown>;
    expect(guard.autoApprove).toEqual([]);
    expect(guard.broker).toEqual({ enabled: false });
  });
});

describe('#501 hasTrustedMemorySidecarPosture', () => {
  const SIDECAR = { hostContract: { posture: 'mcp_sidecar_no_inject' }, inject: { mode: 'off' } };

  it('trusts a valid embedded _sig when the host is UNLOCKED', async () => {
    const config = await freshConfig();
    config.setMemoryHostPosture('mcp_sidecar_no_inject');
    const raw = JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8'));
    expect(config.hasTrustedMemorySidecarPosture(raw)).toBe(true);
  });

  it('refuses the _sig fallback once a lock exists but cannot be verified', async () => {
    const config = await freshConfig();
    config.setMemoryHostPosture('mcp_sidecar_no_inject');
    const raw = JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8'));
    writeSameUidLock();

    const fresh = await freshConfig();
    expect(fresh.hasTrustedMemorySidecarPosture(raw)).toBe(false);
  });

  it('refuses a locked host whose lock says nothing about the memory keys', async () => {
    // Silence from the authority is not permission.
    const config = await freshConfig();
    config.setMemoryHostPosture('mcp_sidecar_no_inject');
    const raw = JSON.parse(fs.readFileSync(path.join(configDir, 'config.json'), 'utf-8'));
    writeSameUidLock({ actionGuard: { enabled: true } });

    const fresh = await freshConfig();
    expect(fresh.hasTrustedMemorySidecarPosture(raw)).toBe(false);
    expect(SIDECAR.inject.mode).toBe('off');
  });
});
