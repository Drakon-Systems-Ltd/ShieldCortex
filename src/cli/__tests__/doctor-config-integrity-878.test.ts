/**
 * #878 item 4 — doctor reads the config without changing it, and renders an
 * unknown signed posture as unknown.
 *
 * Every doctor check that reads config.json is run against fixtures whose
 * ordinary read WOULD write (an unsigned file is adopted; a stale embedded
 * `_sig` is self-healed), plus a live and a dangling symlink. The complete
 * config directory (names, link targets, bytes) must be unchanged afterwards.
 * A control shows the same fixture is adopted by the ordinary getter, so the
 * "unchanged" assertions are sensitive.
 *
 * `fixActionGuardConfig` refuses a symlinked config.json before its backup
 * copy, and names a file that turned tampered between doctor's inspection and
 * the migration instead of throwing the generic refusal.
 *
 * Isolation: per-test SHIELDCORTEX_CONFIG_DIR, protected root, OPENCLAW_HOME
 * and HOME under os.tmpdir(); a fresh module registry per test. `fs` is a
 * pass-through owned by this test whose copyFileSync can run a hook after a
 * config backup is copied; nothing in shipped code knows it exists.
 */
import * as realFs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac, randomBytes } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV } from '../../defence/iron-dome/protected-root.js';

const auditSpy = jest.fn();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));
jest.unstable_mockModule('../../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

let afterBackupCopy: (() => void) | null = null;
const hookedCopyFileSync = ((src: unknown, dest: unknown, ...rest: unknown[]) => {
  (realFs.copyFileSync as (...args: unknown[]) => unknown)(src, dest, ...rest);
  if (typeof dest === 'string' && path.basename(dest).includes('.bak-fix-209-') && afterBackupCopy) {
    const hook = afterBackupCopy;
    afterBackupCopy = null;
    hook();
  }
}) as typeof realFs.copyFileSync;
const hookedFs = { ...realFs, copyFileSync: hookedCopyFileSync };
jest.unstable_mockModule('fs', () => ({ ...hookedFs, default: hookedFs }));

const fs = realFs;

let configDir: string;
let home: string;
let scratch: string[];
let saved: Record<string, string | undefined>;

const file = (name: string) => path.join(configDir, name);
const configFile = () => file('config.json');
const bytes = (obj: Record<string, unknown>) => JSON.stringify(obj, null, 2) + '\n';

function snapshot(): string[] {
  return fs.readdirSync(configDir).sort().map((name) => {
    const p = file(name);
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return `${name} -> ${fs.readlinkSync(p)}`;
    if (st.isDirectory()) return `${name}/`;
    return `${name} ${fs.readFileSync(p).toString('base64')}`;
  });
}

// Disabled threat graph: its check returns at the config gate (no database).
const BODY = { defenceMode: 'balanced', threatGraph: { enabled: false }, actionGuard: { enabled: false } };

const fixtures: Record<string, () => void> = {
  'unsigned regular file (the ordinary read adopts it)': () => {
    fs.writeFileSync(configFile(), bytes(BODY));
  },
  'stale embedded _sig, legacy sig valid (the ordinary read self-heals it)': () => {
    const key = randomBytes(32).toString('hex');
    fs.writeFileSync(file('.integrity-key'), key, { mode: 0o600 });
    const content = bytes({ ...BODY, _sig: '0'.repeat(64) });
    fs.writeFileSync(configFile(), content);
    fs.writeFileSync(file('.config-sig'), createHmac('sha256', key).update(content, 'utf-8').digest('hex'));
  },
  'live symlink to an unsigned target': () => {
    fs.writeFileSync(file('target.json'), bytes(BODY));
    fs.symlinkSync(file('target.json'), configFile());
  },
  'dangling symlink': () => {
    fs.symlinkSync(file(path.join('missing', 'config.json')), configFile());
  },
};

type Doctor = typeof import('../doctor.js');
type Config = typeof import('../../cloud/config.js');

async function fresh(): Promise<{ doctor: Doctor; config: Config }> {
  jest.resetModules();
  const config = await import('../../cloud/config.js');
  const doctor = await import('../doctor.js');
  return { doctor, config };
}

/** Every doctor check this PR moved to the read-only readers. */
async function runDoctorConfigReads(doctor: Doctor): Promise<void> {
  doctor.readHostGatePlanes(home);
  doctor.policyLockRows();
  await doctor.checkActionGuard();
  await doctor.checkActionGuardReadiness();
  await doctor.checkAutoMemoryHooks();
  await doctor.checkThreatGraph();
  doctor.runMemoryStatsCheck(path.join(home, 'no-such.db'));
}

beforeEach(() => {
  const mk = (tag: string) => fs.mkdtempSync(path.join(os.tmpdir(), `sc-878-doc-${tag}-`));
  configDir = mk('cfg');
  const protectedRoot = mk('root');
  const openclawHome = mk('oc');
  home = mk('home');
  scratch = [configDir, protectedRoot, openclawHome, home];
  saved = {
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    [PROTECTED_ROOT_ENV]: process.env[PROTECTED_ROOT_ENV],
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
    HOME: process.env.HOME,
  };
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = protectedRoot;
  process.env.OPENCLAW_HOME = openclawHome;
  process.env.HOME = home;
  afterBackupCopy = null;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const dir of scratch) fs.rmSync(dir, { recursive: true, force: true });
});

describe('#878 item 4: doctor writes nothing to the config directory', () => {
  for (const [name, setup] of Object.entries(fixtures)) {
    it(`${name}: every config-reading doctor check leaves the directory byte-identical`, async () => {
      setup();
      const before = snapshot();
      const { doctor } = await fresh();
      await runDoctorConfigReads(doctor);
      expect(snapshot()).toEqual(before);
    });
  }

  it('control: the same unsigned fixture IS adopted by the ordinary getter, so the check above is sensitive', async () => {
    fixtures['unsigned regular file (the ordinary read adopts it)']();
    const before = snapshot();
    const { config } = await fresh();
    config.getActionGuardCoreConfig();
    expect(snapshot()).not.toEqual(before);
    expect(fs.readdirSync(configDir).sort()).toEqual(['.config-sig', '.integrity-key', 'config.json']);
  });

  it('control: the same self-heal fixture IS rewritten by the ordinary getter', async () => {
    fixtures['stale embedded _sig, legacy sig valid (the ordinary read self-heals it)']();
    const before = snapshot();
    const { config } = await fresh();
    config.getActionGuardCoreConfig();
    expect(snapshot()).not.toEqual(before);
  });
});

describe('#878 design: an unknown signed posture is rendered unknown, never off', () => {
  it('live link to an unsigned Guard-off target: planes are signedUnknown, the header says Guard unknown', async () => {
    fixtures['live symlink to an unsigned target']();
    const { doctor } = await fresh();
    const planes = doctor.readHostGatePlanes(home);
    expect(planes.signedUnknown).toBe(true);
    expect(planes.signedEnabled).toBe(false);
    const { guardHeadlineFromPlanes, formatHostTable } = await import('../../setup/host-table.js');
    expect(guardHeadlineFromPlanes(planes)).toBe('unknown');
    expect(formatHostTable({ rows: [] } as never, '0.0.0', planes)[0]).toContain('Guard unknown');
    expect(guardHeadlineFromPlanes({ ...planes, claudeWired: true })).toBe('unknown');
  });

  it('the readiness row says not evaluated, and the policy-lock row does not say Guard is off', async () => {
    fixtures['live symlink to an unsigned target']();
    const { doctor } = await fresh();
    const readiness = await doctor.checkActionGuardReadiness();
    expect(readiness).toHaveLength(1);
    expect(readiness[0].message).toMatch(/not evaluated.*unknown/);
    const lockRow = doctor.policyLockRows().find((r) => r.label === 'Action guard policy lock');
    expect(lockRow?.message ?? '').not.toMatch(/Guard is off on this host/);
  });

  it('control: an unobstructed unsigned regular file is rendered as it reads (off), not unknown', async () => {
    fixtures['unsigned regular file (the ordinary read adopts it)']();
    const { doctor } = await fresh();
    const planes = doctor.readHostGatePlanes(home);
    expect(planes.signedUnknown).toBeUndefined();
    expect(planes.signedEnabled).toBe(false);
  });
});

describe('#878 item 4: fixActionGuardConfig refusals', () => {
  const ALIAS = { interceptor: { actionGuard: { enforce: false } } };

  it('a symlinked config.json is refused BEFORE the backup copy: nothing at all is written', async () => {
    fs.writeFileSync(file('target.json'), bytes(ALIAS));
    fs.symlinkSync(file('target.json'), configFile());
    const before = snapshot();
    const { doctor } = await fresh();
    const result = doctor.fixActionGuardConfig();
    expect(result.changed).toBe(false);
    expect(result.message).toMatch(/symbolic link.*Nothing was changed/s);
    expect(snapshot()).toEqual(before);
  });

  it('a file that turns tampered between inspection and migration gets the specific message, config.json untouched', async () => {
    const { doctor, config } = await fresh();
    config.setCloudConfig({ cloudApiKey: 'k' });
    // Seed the alias through a signed write so the file inspects valid.
    const signed = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    delete signed._sig;
    fs.writeFileSync(configFile(), bytes({ ...signed, ...ALIAS }));
    fs.rmSync(file('.config-sig'), { force: true });
    config.clearCloudConfigCache();
    config.readRawConfig(); // adopt (regular file): valid
    expect(config.inspectConfigIntegrity().verdict).toBe('valid');

    let tamperedBytes = '';
    afterBackupCopy = () => {
      const body = fs.readFileSync(configFile(), 'utf-8');
      tamperedBytes = body.replace('"cloudApiKey": "k"', '"cloudApiKey": "x"');
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30); // coarse ctime clock
      fs.writeFileSync(configFile(), tamperedBytes);
      fs.writeFileSync(file('.config-sig'), '0'.repeat(64));
    };
    expect(() => doctor.fixActionGuardConfig()).toThrow(
      /changed during the migration.*verdict: tampered.*config\.json was not written.*bak-fix-209-/s,
    );
    expect(tamperedBytes).not.toBe('');
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(tamperedBytes);
  });

  it('regular-file control: the alias is migrated and the file re-signed', async () => {
    const { doctor, config } = await fresh();
    config.setCloudConfig({ cloudApiKey: 'k' });
    const signed = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    delete signed._sig;
    fs.writeFileSync(configFile(), bytes({ ...signed, ...ALIAS }));
    config.clearCloudConfigCache();
    const result = doctor.fixActionGuardConfig();
    expect(result.changed).toBe(true);
    const after = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(after.actionGuard).toMatchObject({ enforce: false });
    expect(after.interceptor).toBeUndefined();
    expect(after._sig).toMatch(/^[0-9a-f]{64}$/);
  });
});
