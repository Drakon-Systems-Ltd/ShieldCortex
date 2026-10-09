/**
 * #647 — the surfaces around the config write gate: doctor's integrity row and
 * `--fix-action-guard`, the reviewed-script allowlist's whole-list write, and
 * the `shieldcortex config` CLI (refusal exit and `--resign`).
 *
 * Doctor must not report a laundered config as clean, must name the verdict
 * outright, and must not prescribe the laundering path ("re-run the flags, they
 * re-sign"). `doctor --fix-action-guard` must refuse a tampered file BEFORE it
 * takes its backup copy.
 *
 * Isolation: per-test SHIELDCORTEX_CONFIG_DIR, SHIELDCORTEX_PROTECTED_ROOT and
 * OPENCLAW_HOME under os.tmpdir(), os.homedir() spied to the same temp tree
 * (doctor's Claude wiring probe), the iron-dome audit logger and the OpenClaw
 * plugin guard sync mocked. Modules are imported once, after the mocks are
 * registered; per-test state is reset through clearCloudConfigCache().
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash } from 'crypto';
import { afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';

type AuditEntry = { action: string; allowed: boolean; reason: string };
const auditSpy = jest.fn<(entry: AuditEntry) => void>();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));

jest.unstable_mockModule('../../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

type Doctor = typeof import('../doctor.js');
type Config = typeof import('../../cloud/config.js');
type Allowlist = typeof import('../allowlist.js');
type CloudCli = typeof import('../../cloud/cli.js');

let doctor: Doctor;
let config: Config;
let allowlist: Allowlist;
let cli: CloudCli;
let PROTECTED_ROOT_ENV: string;

beforeAll(async () => {
  ({ PROTECTED_ROOT_ENV } = await import('../../defence/iron-dome/protected-root.js'));
  config = await import('../../cloud/config.js');
  doctor = await import('../doctor.js');
  allowlist = await import('../allowlist.js');
  cli = await import('../../cloud/cli.js');
});

const SENTINEL = 'sc_live_SENTINEL_647_doctor';
const PINS = [{ path: '/opt/reviewed/deploy.sh', sha256: 'a'.repeat(64), addedAt: 1 }];

let tmp: string;
let configDir: string;
let saved: Record<string, string | undefined>;
let errors: string[];
let logs: string[];

const configFile = () => path.join(configDir, 'config.json');
const readOnDisk = (): Record<string, any> => JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');

function integrityRow() {
  return doctor.policyLockRows().find((r) => r.label.includes('config integrity'))!;
}

/** Signed config with operator pins + alias, then a hand edit: tampered. */
function tamperedFixture(edit?: (cfg: Record<string, any>) => void): Buffer {
  config.setCloudConfig({ cloudApiKey: SENTINEL, cloudEnabled: false });
  config.setReviewedScripts(PINS);
  config.setActionGuardCoreConfig({ enabled: true, enforce: true });
  const onDisk = readOnDisk();
  onDisk.actionGuard.enabled = false;
  onDisk.actionGuard.autoApprove = ['git_status'];
  if (edit) edit(onDisk);
  fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
  config.clearCloudConfigCache();
  guardSyncSpy.mockClear();
  return fs.readFileSync(configFile());
}

function mockExit(): void {
  jest.spyOn(process, 'exit').mockImplementation(((): never => { throw new Error('exit'); }) as never);
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-647-doc-'));
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
  errors = [];
  logs = [];
  jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { errors.push(a.map(String).join(' ')); });
  jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')); });
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

describe('#647 doctor names the integrity verdict', () => {
  it('tampered: FAIL, says so, and the fix never prescribes the laundering re-run', () => {
    tamperedFixture();
    const row = integrityRow();
    expect(row.status).toBe('fail');
    expect(row.message).toMatch(/verdict: tampered/);
    expect(row.message).toMatch(/config writes are refused/);
    expect(row.fix).toMatch(/config --resign/);
    expect(row.fix).toMatch(/Do not re-run/);
    expect(row.fix).not.toMatch(/\(they re-sign\)|Re-write the affected settings/);
  });

  it('a refused setter does not launder it: doctor still says tampered afterwards', () => {
    tamperedFixture();
    expect(() => config.addTrustedSkill('/skills/x.md')).toThrow(config.ConfigIntegrityRefusal);
    expect(() => config.setDefenceMode('strict')).toThrow(config.ConfigIntegrityRefusal);
    config.getDeviceId();
    expect(integrityRow().message).toMatch(/verdict: tampered/);
    expect(readOnDisk().actionGuard.reviewedScripts).toEqual(PINS);
  });

  const verdictCases: Array<[string, () => void, 'pass' | 'fail']> = [
    ['absent', () => undefined, 'pass'],
    ['valid', () => config.setDefenceMode('balanced'), 'pass'],
    ['unsigned', () => fs.writeFileSync(configFile(), JSON.stringify({ proactiveRecall: true })), 'pass'],
    ['malformed', () => fs.writeFileSync(configFile(), '{ torn'), 'fail'],
    ['unreadable', () => { fs.mkdirSync(configFile()); }, 'fail'],
  ];
  it.each(verdictCases)('%s: the row names the verdict', (verdict, arrange, status) => {
    arrange();
    config.clearCloudConfigCache();
    const row = integrityRow();
    expect(row.message).toContain(`verdict: ${verdict}`);
    expect(row.status).toBe(status);
    // Every row keeps the honest description of what the HMAC is.
    expect(row.message).toMatch(/not tamper protection/);
  });

  it('the posture row grades the ENFORCED (strict) view on a tampered file, agreeing with the integrity row', async () => {
    tamperedFixture(); // the file says enabled: false
    const results = await doctor.checkActionGuard();
    expect(results.find((r) => /Action Guard is disabled in config/.test(r.message))).toBeUndefined();
  });
});

describe('#647 doctor --fix-action-guard refuses a tampered file before any side effect', () => {
  it('no backup copy, no write, no re-sign', () => {
    const before = tamperedFixture((cfg) => { cfg.interceptor = { actionGuard: { enforce: false } }; });
    const entriesBefore = fs.readdirSync(configDir).sort();
    const fix = doctor.fixActionGuardConfig();
    expect(fix.changed).toBe(false);
    expect(fix.backupPath).toBeUndefined();
    expect(fix.message).toMatch(/tampered/);
    expect(fs.readFileSync(configFile()).equals(before)).toBe(true);
    expect(fs.readdirSync(configDir).sort()).toEqual(entriesBefore);
    expect(fs.readdirSync(configDir).some((n) => n.includes('.bak-fix-209-'))).toBe(false);
    expect(integrityRow().message).toMatch(/verdict: tampered/);
  });

  it('an unsigned alias config still migrates (the gate is for tampered only)', () => {
    fs.writeFileSync(configFile(), JSON.stringify({ interceptor: { actionGuard: { enforce: false } } }, null, 2));
    const fix = doctor.fixActionGuardConfig();
    expect(fix.changed).toBe(true);
    expect(readOnDisk().actionGuard).toEqual({ enforce: false });
    if (fix.backupPath) fs.rmSync(fix.backupPath, { force: true });
  });
});

describe('#647 allowlist whole-list replacement cannot wipe pins on a tampered config', () => {
  it('pinReviewedScript refuses with the integrity reason; the pins on disk are unchanged', () => {
    const script = path.join(tmp, 'new-script.sh');
    fs.writeFileSync(script, 'echo reviewed\n');
    const before = tamperedFixture();
    // Through the forced view the existing pins read as []: a write here would
    // have replaced the whole list with just the new entry.
    expect(config.getReviewedScriptsRaw()).toEqual([]);
    const result = allowlist.pinReviewedScript(script, 'note');
    expect(result.ok).toBe(false);
    expect(!result.ok && result.error).toMatch(/Could not write the allowlist/);
    expect(!result.ok && result.error).toMatch(/tampered/);
    expect(fs.readFileSync(configFile()).equals(before)).toBe(true);
    expect(readOnDisk().actionGuard.reviewedScripts).toEqual(PINS);
  });
});

describe('#647 shieldcortex config CLI', () => {
  it('a setting flag on a tampered config exits 1 with the refusal, and writes nothing', () => {
    const before = tamperedFixture();
    mockExit();
    expect(() => cli.handleCloudConfig(['--mode', 'strict'])).toThrow('exit');
    expect(process.exit).toHaveBeenCalledWith(1);
    expect(errors.join('\n')).toMatch(/Refusing to write .*verdict: tampered/s);
    expect(fs.readFileSync(configFile()).equals(before)).toBe(true);
  });

  it('--resign previews: verdict, full sha256, key names — never a config value — and writes nothing', () => {
    const before = tamperedFixture();
    cli.handleCloudConfig(['--resign']);
    const out = logs.join('\n');
    expect(out).toMatch(/config\.json integrity: tampered/);
    expect(out).toContain(sha256(before));
    expect(out).toMatch(/actionGuard\.enabled/);
    expect(out).toMatch(/Will be REFUSED/);
    expect(out).not.toContain(SENTINEL);
    expect(out).not.toContain('git_status');
    expect(fs.readFileSync(configFile()).equals(before)).toBe(true);
    expect(fs.readdirSync(configDir).some((n) => n.includes('.bak-resign-'))).toBe(false);
  });

  it('--resign --confirm needs a value and the full hash', () => {
    tamperedFixture();
    mockExit();
    expect(() => cli.handleCloudConfig(['--resign', '--confirm'])).toThrow('exit');
    expect(() => cli.handleCloudConfig(['--resign', '--confirm', 'abc123'])).toThrow('exit');
    expect(errors.join('\n')).toMatch(/full 64-character/);
  });

  it('--resign --confirm <sha256> re-signs a benign tamper, prints the backup, and doctor reads valid', async () => {
    config.setCloudConfig({ cloudApiKey: SENTINEL });
    config.setActionGuardCoreConfig({ enabled: true, enforce: true });
    const onDisk = readOnDisk();
    onDisk.proactiveRecall = true;
    fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
    config.clearCloudConfigCache();
    const bytes = fs.readFileSync(configFile());

    cli.handleCloudConfig(['--resign', '--confirm', sha256(bytes)]);
    const out = logs.join('\n');
    expect(out).toMatch(/Re-signed .*\(was: tampered\)/);
    const backup = fs.readdirSync(configDir).find((n) => n.includes('.bak-resign-'));
    expect(backup).toBeDefined();
    expect(fs.readFileSync(path.join(configDir, backup!)).equals(bytes)).toBe(true);
    expect(out).not.toContain(SENTINEL);
    config.clearCloudConfigCache();
    expect(integrityRow().message).toMatch(/verdict: valid/);

    for (let i = 0; i < 50; i++) await new Promise((r) => setImmediate(r));
    expect(auditSpy.mock.calls.map((c) => c[0]).filter((e) => e.reason.startsWith('config_resigned'))).toHaveLength(1);
  });
});
