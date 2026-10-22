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
 * mocked audit logger, re-sign audit sink and plugin guard sync, no home
 * directory, no network.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { PolicyLockState } from '../defence/iron-dome/policy-lock.js';
import { describeProtectedAudit, type ProtectedAuditEvent } from '../defence/iron-dome/protected-root.js';

type AuditEntry = { action: string; allowed: boolean; reason: string };
const auditSpy = jest.fn<(entry: AuditEntry) => void>();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));

jest.unstable_mockModule('../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
/** How many times the re-sign opened its audit sink: a refused re-sign never does. */
let sinkOpens = 0;
jest.unstable_mockModule('../cloud/recovery-audit.js', () => ({
  openRecoveryAuditSink: async () => {
    sinkOpens += 1;
    return {
      location: '/test/memories.db',
      record: (event: ProtectedAuditEvent) => { auditSpy(describeProtectedAudit(event)); return 1; },
      close: () => undefined,
    };
  },
}));
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
let logs: string[] = [];
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
  sinkOpens = 0;
  logs = [];
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')); });
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

    const result = await config.resignTamperedConfig(preview.sha256!);
    expect(result.audit.recorded).toBe(true);
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
    try { await config.resignTamperedConfig(preview.sha256!); } catch (err) { thrown = err; }
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
    await expect(config.resignTamperedConfig(preview.sha256!)).rejects.toThrow(/no verified policy lock covers/);
    expect(fs.readFileSync(configFile()).equals(edited)).toBe(true);
    await flushAudit();
    expect(auditSpy.mock.calls.map((c) => c[0]).filter((e) => e.reason.startsWith('config_resigned'))).toHaveLength(0);
  });
});

/**
 * Round-1 review B1: the admission must read the RAW file. A verified lock
 * drops `readinessGate` from the effective view and an unverifiable one forces
 * the strict posture over both Action Guard blocks, so a comparison of
 * lock-applied views saw nothing — while the re-sign signed the raw values,
 * to take effect the day the lock goes away.
 */
describe('#647 a lock never masks a hand edit the re-sign would sign', () => {
  const UNVERIFIABLE: PolicyLockState = {
    status: 'unverifiable', path: LOCK_PATH, reason: 'schema-failed', detail: `${LOCK_PATH}: test`,
  };
  /** A verified lock pinning exactly the strict posture the file otherwise has. */
  const STRICT_LOCK: PolicyLockState = {
    status: 'locked',
    path: LOCK_PATH,
    policy: {
      version: 1,
      actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [] },
      defenceMode: 'strict',
    } as never,
  };
  const LOCKS: Record<string, PolicyLockState> = {
    absent: { status: 'absent', path: LOCK_PATH },
    locked: STRICT_LOCK,
    unverifiable: UNVERIFIABLE,
  };

  /** A signed strict config whose ONLY hand edit is `edit`. */
  async function strictThenEdit(edit: (cfg: Record<string, any>) => void): Promise<Buffer> {
    lockState = { status: 'absent', path: LOCK_PATH };
    const seed = await freshConfig();
    seed.setActionGuardCoreConfig({ enabled: true, enforce: true });
    seed.setDefenceMode('strict');
    const onDisk = readOnDisk();
    edit(onDisk);
    fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
    auditSpy.mockClear();
    return fs.readFileSync(configFile());
  }

  async function expectRefusedEverywhere(edited: Buffer): Promise<void> {
    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('tampered');
    const preview = config.previewConfigResign();
    expect(preview.lockRefusal !== null || preview.unauthorisedKeys.length > 0).toBe(true);

    // The CLI preview says REFUSED and does not offer the confirm command.
    const cli = await import('../cloud/cli.js');
    logs = [];
    await cli.handleCloudConfig(['--resign']);
    const out = logs.join('\n');
    expect(out).toMatch(/Will be REFUSED/);
    expect(out).not.toMatch(/--resign --confirm/);

    await expect(config.resignTamperedConfig(preview.sha256!)).rejects.toThrow(/Not re-signing|Refusing to loosen/);
    expect(fs.readFileSync(configFile()).equals(edited)).toBe(true);
    expect(fs.readdirSync(configDir).filter((n) => n.includes('.bak-resign-'))).toEqual([]);
    expect(sinkOpens).toBe(0);
    await flushAudit();
    expect(auditSpy.mock.calls.map((c) => c[0]).filter((e) => e.reason.startsWith('config_resigned'))).toHaveLength(0);
  }

  it.each(Object.keys(LOCKS))('readinessGate: true is the only edit, lock %s: REFUSED, nothing written', async (status) => {
    const edited = await strictThenEdit((cfg) => { cfg.actionGuard.readinessGate = true; });
    lockState = LOCKS[status];
    const config = await freshConfig();
    const preview = config.previewConfigResign();
    expect(preview.lockRefusal).toBeNull();
    expect(preview.unauthorisedKeys).toEqual(['actionGuard.readinessGate']);
    expect(preview.loosenedKeys).toContain('actionGuard.readinessGate');
    await expectRefusedEverywhere(edited);
  });

  it.each(Object.keys(LOCKS))('alias-only readinessGate: true, lock %s: REFUSED, nothing written', async (status) => {
    const edited = await strictThenEdit((cfg) => { cfg.interceptor = { actionGuard: { readinessGate: true } }; });
    lockState = LOCKS[status];
    const config = await freshConfig();
    expect(config.previewConfigResign().unauthorisedKeys).toEqual(['actionGuard.readinessGate']);
    await expectRefusedEverywhere(edited);
  });

  const ALIAS_LOOSENINGS: Array<[string, Record<string, unknown>]> = [
    ['enabled: false', { enabled: false }],
    ['enforce: false', { enforce: false }],
    ['a non-empty autoApprove', { autoApprove: ['git_status'] }],
    ['broker.enabled: true', { broker: { enabled: true } }],
    ['a non-empty reviewedScripts', { reviewedScripts: PINS }],
  ];
  const ALIAS_CASES = ['locked', 'unverifiable'].flatMap((status) =>
    ALIAS_LOOSENINGS.map(([label, alias]) => [status, label, alias] as const));

  it.each(ALIAS_CASES)('lock %s, alias-only %s (top-level strict): REFUSED, nothing written', async (status, _label, alias) => {
    const edited = await strictThenEdit((cfg) => { cfg.interceptor = { actionGuard: alias }; });
    lockState = LOCKS[status];
    await expectRefusedEverywhere(edited);
  });

  it('the same strict file with no hand-edited loosening still re-signs under a verified lock (the fix is not a blanket refusal)', async () => {
    await strictThenEdit((cfg) => { cfg.proactiveRecall = true; });
    lockState = STRICT_LOCK;
    const config = await freshConfig();
    const preview = config.previewConfigResign();
    expect(preview.unauthorisedKeys).toEqual([]);
    expect(preview.lockRefusal).toBeNull();
    const result = await config.resignTamperedConfig(preview.sha256!);
    expect(result.audit.recorded).toBe(true);
  });
});
