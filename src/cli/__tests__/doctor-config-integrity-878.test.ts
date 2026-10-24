/**
 * #878 item 4 — doctor's Action Guard rows read config.json without side
 * effects, and `doctor --fix-action-guard` names a file that changed during
 * the migration.
 *
 * Before #878 doctor read the core config through getActionGuardCoreConfig(),
 * whose ordinary read adopts an unsigned file (writing `.config-sig`) and
 * re-signs a self-heal one (rewriting config.json). So the `unsigned` row's
 * "the next read adopts it" was doctor's own read, and running doctor changed
 * the file it was reporting on.
 *
 * Isolation: as doctor-config-integrity-647 — per-test SHIELDCORTEX_CONFIG_DIR,
 * SHIELDCORTEX_PROTECTED_ROOT and OPENCLAW_HOME under os.tmpdir(), os.homedir()
 * spied to the same temp tree, the iron-dome audit logger, the recovery audit
 * sink and the OpenClaw plugin guard sync mocked.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac } from 'crypto';
import { afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';

const auditSpy = jest.fn();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));
const openSinkSpy = jest.fn(async () => { throw new Error('not used here'); });

jest.unstable_mockModule('../../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../../cloud/recovery-audit.js', () => ({ openRecoveryAuditSink: openSinkSpy }));
jest.unstable_mockModule('../../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

type Doctor = typeof import('../doctor.js');
type Config = typeof import('../../cloud/config.js');

let doctor: Doctor;
let config: Config;
let PROTECTED_ROOT_ENV: string;

beforeAll(async () => {
  ({ PROTECTED_ROOT_ENV } = await import('../../defence/iron-dome/protected-root.js'));
  config = await import('../../cloud/config.js');
  doctor = await import('../doctor.js');
});

const FIXED_MTIME_S = 1_700_000_000;

let tmp: string;
let configDir: string;
let saved: Record<string, string | undefined>;

const configFile = () => path.join(configDir, 'config.json');

interface Snapshot { bytes: Buffer; mtimeMs: number; entries: string[] }

function snapshot(): Snapshot {
  return {
    bytes: fs.readFileSync(configFile()),
    mtimeMs: fs.statSync(configFile()).mtimeMs,
    entries: fs.readdirSync(configDir).sort(),
  };
}

function expectUnchanged(before: Snapshot): void {
  const after = snapshot();
  expect(after.bytes.equals(before.bytes)).toBe(true);
  expect(after.mtimeMs).toBe(before.mtimeMs);
  // No `.config-sig` adopted, no `.integrity-key` minted, no temp file.
  expect(after.entries).toEqual(before.entries);
}

/** A config with no signature at all (pre-v4.32): the next ordinary read adopts it. */
function unsignedFixture(guard: Record<string, unknown> = { enabled: true, enforce: true }): Snapshot {
  fs.writeFileSync(configFile(), JSON.stringify({ actionGuard: guard }, null, 2) + '\n');
  fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
  config.clearCloudConfigCache();
  return snapshot();
}

/**
 * A stale embedded `_sig` beside a legacy whole-file `.config-sig` that still
 * authenticates the exact bytes: the next ordinary read re-signs it.
 */
function selfHealFixture(guard: Record<string, unknown> = { enabled: true, enforce: true }): Snapshot {
  config.setDefenceMode('balanced'); // mints the integrity key
  const key = fs.readFileSync(path.join(configDir, '.integrity-key'), 'utf-8').trim();
  const content = JSON.stringify({ actionGuard: guard, _sig: 'f'.repeat(64) }, null, 2) + '\n';
  fs.writeFileSync(configFile(), content);
  fs.writeFileSync(path.join(configDir, '.config-sig'), createHmac('sha256', key).update(content, 'utf-8').digest('hex'));
  fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
  config.clearCloudConfigCache();
  expect(config.inspectConfigIntegrity().verdict).toBe('self-heal');
  return snapshot();
}

async function runDoctorActionGuardChecks(): Promise<void> {
  doctor.policyLockRows();
  await doctor.checkActionGuard();
  doctor.readHostGatePlanes();
  await doctor.checkActionGuardReadiness();
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-878-doc-'));
  configDir = path.join(tmp, 'cfg');
  fs.mkdirSync(configDir);
  fs.mkdirSync(path.join(tmp, 'root'));
  fs.mkdirSync(path.join(tmp, 'home'));
  saved = {
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    [PROTECTED_ROOT_ENV]: process.env[PROTECTED_ROOT_ENV],
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
  };
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = path.join(tmp, 'root');
  process.env.OPENCLAW_HOME = path.join(tmp, 'home');
  jest.spyOn(os, 'homedir').mockReturnValue(path.join(tmp, 'home'));
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  config.clearCloudConfigCache();
  auditSpy.mockClear();
  guardSyncSpy.mockClear();
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  config.clearCloudConfigCache();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('#878 doctor reads the Action Guard config without side effects', () => {
  it('unsigned: no adoption — config.json bytes, mtime and the directory are unchanged', async () => {
    const before = unsignedFixture();
    await runDoctorActionGuardChecks();
    expectUnchanged(before);
    // The row still says what the next ordinary read will do.
    const row = doctor.policyLockRows().find((r) => r.label.includes('config integrity'))!;
    expect(row.message).toContain('verdict: unsigned');
    // And the signed answer doctor reports is the one that adoption gives.
    expect(doctor.readHostGatePlanes().signedEnabled).toBe(true);
    expectUnchanged(before);
  });

  it('self-heal: no re-sign — config.json bytes, mtime and the legacy signature are unchanged', async () => {
    const before = selfHealFixture();
    await runDoctorActionGuardChecks();
    expectUnchanged(before);
    expect(config.inspectConfigIntegrity().verdict).toBe('self-heal');
    expect(doctor.readHostGatePlanes()).toMatchObject({ signedEnabled: true, signedEnforce: true });
    expectUnchanged(before);
  });
});

describe('#878 doctor\'s readiness rows read the config without side effects', () => {
  // `readinessGate: true` is what takes checkActionGuardReadiness past its
  // pre-check into the real buildReadinessSummaries() path (no injected summaries).
  const GATED = { enabled: true, enforce: true, readinessGate: true };
  const exists = (name: string) => fs.existsSync(path.join(configDir, name));

  it('unsigned: no `.config-sig` adopted, no `.integrity-key` minted, config.json unchanged', async () => {
    const before = unsignedFixture(GATED);
    expect(exists('.config-sig')).toBe(false);
    expect(exists('.integrity-key')).toBe(false);
    const rows = await doctor.checkActionGuardReadiness();
    expect(rows.length).toBeGreaterThan(0);
    expect(exists('.config-sig')).toBe(false);
    expect(exists('.integrity-key')).toBe(false);
    expectUnchanged(before);
  });

  it('self-heal: config.json is not re-signed and the legacy `.config-sig` is kept', async () => {
    const before = selfHealFixture(GATED);
    const legacySig = fs.readFileSync(path.join(configDir, '.config-sig'));
    const rows = await doctor.checkActionGuardReadiness();
    expect(rows.length).toBeGreaterThan(0);
    expect(fs.readFileSync(path.join(configDir, '.config-sig')).equals(legacySig)).toBe(true);
    expectUnchanged(before);
    expect(config.inspectConfigIntegrity().verdict).toBe('self-heal');
  });
});

describe('#878 doctor --fix-action-guard: a file that changes during the migration', () => {
  it('fails with a specific error naming the change and the backup, and writes nothing', () => {
    fs.writeFileSync(configFile(), JSON.stringify({ interceptor: { actionGuard: { enforce: false } } }, null, 2) + '\n');
    config.clearCloudConfigCache();
    let tampered: Buffer | undefined;
    const realCopy = fs.copyFileSync;
    // Another writer, between doctor's inspection and the migration's read:
    // right after the backup copy, the file gains a signature that does not verify.
    jest.spyOn(fs, 'copyFileSync').mockImplementation((src, dest, mode) => {
      realCopy(src, dest, mode);
      const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
      onDisk._sig = '0'.repeat(64);
      fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
      tampered = fs.readFileSync(configFile());
    });

    let thrown: unknown;
    try { doctor.fixActionGuardConfig(); } catch (err) { thrown = err; }
    expect(thrown).toBeInstanceOf(Error);
    const message = (thrown as Error).message;
    expect(message).toMatch(/changed during the migration/);
    expect(message).toMatch(/Nothing was written/);
    expect(message).toMatch(/verdict: tampered/);
    const backup = fs.readdirSync(configDir).find((n) => n.includes('.bak-fix-209-'));
    expect(backup).toBeDefined();
    expect(message).toContain(path.join(configDir, backup!));
    // Not the generic refusal.
    expect(thrown).not.toBeInstanceOf(config.ConfigIntegrityRefusal);
    expect(fs.readFileSync(configFile()).equals(tampered!)).toBe(true);
    expect(config.inspectConfigIntegrity().verdict).toBe('tampered');
  });
});
