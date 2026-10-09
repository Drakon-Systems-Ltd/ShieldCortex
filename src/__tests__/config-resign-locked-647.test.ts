/**
 * #647 — the deliberate re-sign on a host with a VERIFIED policy lock: the
 * #501 §8.4 runbook (hand-edit config.json, `sudo shieldcortex protect
 * --from-config`, then re-sign).
 *
 * A verified lock is root-owned, which an unprivileged test process cannot
 * create on disk. The ownership rules themselves are exhaustively covered
 * through the injected stat seam in policy-lock-501 / protected-root-501; here
 * `readPolicyLock` is replaced with one that answers `locked`, and everything
 * else in policy-lock (precedence, coverage, the loosening check, the refusal
 * class) is the real module.
 *
 * Isolation as in config-tamper-preserve-647: temp config dir and OPENCLAW_HOME,
 * mocked audit logger and plugin guard sync, no home directory, no network.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { PolicyLockState } from '../defence/iron-dome/policy-lock.js';

type AuditEntry = { action: string; allowed: boolean; reason: string };
const auditSpy = jest.fn<(entry: AuditEntry) => void>();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));

jest.unstable_mockModule('../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

type ConfigModule = typeof import('../cloud/config.js');

const LOCK_PATH = '/etc/shieldcortex/policy.json';
const PINS = [{ path: '/opt/reviewed/deploy.sh', sha256: 'a'.repeat(64) }];
let lockState: PolicyLockState = { status: 'absent', path: LOCK_PATH };

beforeAll(async () => {
  const actual = await import('../defence/iron-dome/policy-lock.js');
  jest.unstable_mockModule('../defence/iron-dome/policy-lock.js', () => ({
    ...actual,
    readPolicyLock: () => lockState,
  }));
});

let configDir: string;
let openclawHome: string;
let prevConfigDir: string | undefined;
let prevOpenclawHome: string | undefined;

const configFile = () => path.join(configDir, 'config.json');

async function freshConfig(): Promise<ConfigModule> {
  jest.resetModules();
  return import('../cloud/config.js');
}

function readOnDisk(): Record<string, any> {
  return JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
}

/** §8.4 steps 1-2: a signed, guarded config, then the operator's hand edit. */
async function handEditedConfig(): Promise<Buffer> {
  lockState = { status: 'absent', path: LOCK_PATH };
  const seed = await freshConfig();
  seed.setActionGuardCoreConfig({ enabled: true, enforce: true });
  seed.setDefenceMode('strict');
  const onDisk = readOnDisk();
  onDisk.actionGuard = { ...onDisk.actionGuard, enforce: false, autoApprove: ['git_status'], reviewedScripts: PINS };
  onDisk.defenceMode = 'balanced';
  fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
  auditSpy.mockClear();
  guardSyncSpy.mockClear();
  return fs.readFileSync(configFile());
}

/** §8.4 step 3: what `protect --from-config` pins from that edited file. */
function lockFromConfig(overrides: Partial<{ enforce: boolean; reviewedScripts: typeof PINS | undefined }> = {}): void {
  const actionGuard: Record<string, unknown> = {
    enabled: true,
    enforce: overrides.enforce ?? false,
    autoApprove: ['git_status'],
    broker: { enabled: false },
  };
  if (!('reviewedScripts' in overrides) || overrides.reviewedScripts !== undefined) {
    actionGuard.reviewedScripts = overrides.reviewedScripts ?? PINS;
  }
  lockState = {
    status: 'locked',
    path: LOCK_PATH,
    policy: { version: 1, actionGuard, defenceMode: 'balanced' } as never,
  };
}

async function flushAudit(): Promise<void> {
  for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r));
}

beforeEach(() => {
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-647-lk-cfg-'));
  openclawHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-647-lk-oc-'));
  prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
  prevOpenclawHome = process.env.OPENCLAW_HOME;
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env.OPENCLAW_HOME = openclawHome;
  auditSpy.mockClear();
  guardSyncSpy.mockClear();
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  if (prevOpenclawHome === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = prevOpenclawHome;
  fs.rmSync(configDir, { recursive: true, force: true });
  fs.rmSync(openclawHome, { recursive: true, force: true });
  lockState = { status: 'absent', path: LOCK_PATH };
});

describe('#647 §8.4 with a verified lock: the lock is the authority, the re-sign follows it', () => {
  it('after protect --from-config, the re-sign makes the operator values effective, with backup and audit', async () => {
    const edited = await handEditedConfig();
    lockFromConfig();
    const config = await freshConfig();

    // Still strict until re-signed — the lock alone cannot undo a tampered verdict.
    expect(config.getActionGuardCoreConfig().enforce).toBe(true);
    // And an incidental setter still refuses rather than signing the forced view.
    expect(() => config.setProactiveRecall(true)).toThrow(config.ConfigIntegrityRefusal);

    const preview = config.previewConfigResign();
    expect(preview.lockStatus).toBe('locked');
    expect(preview.lockRefusal).toBeNull();
    expect(preview.unauthorisedKeys).toEqual([]);
    expect(preview.loosenedKeys).toEqual(expect.arrayContaining([
      'actionGuard.enforce', 'actionGuard.autoApprove', 'actionGuard.reviewedScripts', 'defenceMode',
    ]));

    const result = config.resignTamperedConfig(preview.sha256!);
    expect(fs.readFileSync(result.backupPath).equals(edited)).toBe(true);

    const fresh = await freshConfig();
    expect(fresh.inspectConfigIntegrity().verdict).toBe('valid');
    expect(fresh.isConfigTampered()).toBe(false);
    expect(fresh.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: false, readinessGate: false });
    expect(fresh.getReviewedScriptsRaw()).toEqual(PINS);
    const guard = fresh.readRawConfig().actionGuard as Record<string, unknown>;
    expect(guard.autoApprove).toEqual(['git_status']);
    expect(fresh.getDefenceMode()).toBe('balanced');

    await flushAudit();
    const rows = auditSpy.mock.calls.map((c) => c[0]).filter((e) => e.reason.startsWith('config_resigned'));
    expect(rows).toHaveLength(1);
    expect(rows[0].reason).toContain('actionGuard.enforce');
    expect(rows[0].reason).not.toContain('git_status'); // names, never values
    expect(guardSyncSpy).not.toHaveBeenCalled();
  });

  it('a lock that pins a TIGHTER value than the file refuses the re-sign (PolicyLockRefusal), nothing written', async () => {
    const edited = await handEditedConfig();
    lockFromConfig({ enforce: true });
    const config = await freshConfig();
    const preview = config.previewConfigResign();
    expect(preview.lockRefusal).toMatch(/Refusing to loosen `actionGuard\.enforce`/);
    let thrown: unknown;
    try { config.resignTamperedConfig(preview.sha256!); } catch (err) { thrown = err; }
    expect((thrown as Error).name).toBe('PolicyLockRefusal');
    expect(fs.readFileSync(configFile()).equals(edited)).toBe(true);
    expect(fs.readdirSync(configDir).filter((n) => n.includes('.bak-resign-'))).toEqual([]);
  });

  it('a key the lock does not cover is not authorised by it: pins outside the lock are refused', async () => {
    const edited = await handEditedConfig();
    lockFromConfig({ reviewedScripts: undefined });
    const config = await freshConfig();
    const preview = config.previewConfigResign();
    expect(preview.unauthorisedKeys).toEqual(['actionGuard.reviewedScripts']);
    expect(() => config.resignTamperedConfig(preview.sha256!)).toThrow(/no verified policy lock covers/);
    expect(fs.readFileSync(configFile()).equals(edited)).toBe(true);
    await flushAudit();
    expect(auditSpy.mock.calls.map((c) => c[0]).filter((e) => e.reason.startsWith('config_resigned'))).toHaveLength(0);
  });
});
