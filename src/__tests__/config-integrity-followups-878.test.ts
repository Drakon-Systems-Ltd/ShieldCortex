/**
 * #878 — config integrity follow-ups after #699 (items 1, 2 and 6), and the
 * read-layer rule that replaces the per-call-site folds of the first attempt.
 *
 * The rule: the ordinary config read never writes through a symlinked
 * `config.json` (live or dangling). It does not adopt an unsigned target
 * (`.integrity-key`, `.config-sig`), mint a key, or self-heal a stale `_sig`.
 * Every caller inherits that from the read layer, so each reviewer row below —
 * getters, getter-then-setter pairs, the lazy device writers, the CLI flag, the
 * setup prompt, the iron-dome sync — is pinned with the complete config
 * directory (names, link targets, bytes) unchanged, plus a regular-file
 * control proving persistence still works.
 *
 * An unsigned file behind a link is never adopted, so its verdict is unknown;
 * the runtime enforces unknown as the strict fail-closed posture, never off.
 *
 * Isolation: every case gets its own SHIELDCORTEX_CONFIG_DIR, protected root,
 * OPENCLAW_HOME and HOME under os.tmpdir(), and a fresh module registry (so
 * per-process state such as the ephemeral device id and the one-shot warnings
 * cannot leak between cases). The iron-dome audit logger, the recovery audit
 * sink and the OpenClaw plugin guard sync are mocked. `fs` is a pass-through
 * owned by this test that counts reads of config.json, so the cache cases can
 * assert real read counts; nothing in shipped code knows it exists.
 */
import * as realFs from 'fs';
import os from 'os';
import path from 'path';
import { createHash, createHmac, randomBytes } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV } from '../defence/iron-dome/protected-root.js';

type Sink = { location: string; record: (row: unknown) => number; close: () => void };
const auditSpy = jest.fn();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));
const openSinkSpy = jest.fn<() => Promise<Sink>>(async () => { throw new Error('not used here'); });

jest.unstable_mockModule('../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../cloud/recovery-audit.js', () => ({ openRecoveryAuditSink: openSinkSpy }));
jest.unstable_mockModule('../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

let configReads = 0;
const countingReadFileSync = ((p: unknown, ...rest: unknown[]) => {
  if (typeof p === 'string' && path.basename(p) === 'config.json') configReads += 1;
  return (realFs.readFileSync as (...args: unknown[]) => unknown)(p, ...rest);
}) as typeof realFs.readFileSync;
const countingFs = { ...realFs, readFileSync: countingReadFileSync };
jest.unstable_mockModule('fs', () => ({ ...countingFs, default: countingFs }));

const fs = realFs;

type ConfigModule = typeof import('../cloud/config.js');

const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;

let configDir: string;
let scratch: string[];
let saved: Record<string, string | undefined>;
let errorSpy: ReturnType<typeof jest.spyOn>;

const file = (name: string) => path.join(configDir, name);
const configFile = () => file('config.json');

/** The whole config directory: names, link targets and bytes. */
function snapshot(): string[] {
  return fs.readdirSync(configDir).sort().map((name) => {
    const p = file(name);
    const st = fs.lstatSync(p);
    if (st.isSymbolicLink()) return `${name} -> ${fs.readlinkSync(p)}`;
    if (st.isDirectory()) return `${name}/`;
    return `${name} ${fs.readFileSync(p).toString('base64')}`;
  });
}

function errors(): string {
  return errorSpy.mock.calls.map((c: unknown[]) => String(c[0])).join('\n');
}

const bytes = (obj: Record<string, unknown>) => JSON.stringify(obj, null, 2) + '\n';

/** config.json -> target.json, the target unsigned (no `_sig`, no `.config-sig`). */
function liveUnsignedLink(obj: Record<string, unknown>): void {
  fs.writeFileSync(file('target.json'), bytes(obj));
  fs.symlinkSync(file('target.json'), configFile());
  expect(fs.readdirSync(configDir).sort()).toEqual(['config.json', 'target.json']);
}

/** config.json -> a path that does not exist. */
function danglingLink(): string {
  const target = file(path.join('missing', 'config.json'));
  fs.symlinkSync(target, configFile());
  expect(fs.readdirSync(configDir)).toEqual(['config.json']);
  return target;
}

function regularUnsigned(obj: Record<string, unknown>): void {
  fs.writeFileSync(configFile(), bytes(obj));
}

/** Bytes whose embedded `_sig` is stale while the legacy whole-file sig validates them: self-heal. */
function selfHealBytes(obj: Record<string, unknown>): string {
  const key = randomBytes(32).toString('hex');
  fs.writeFileSync(file('.integrity-key'), key, { mode: 0o600 });
  const content = bytes({ ...obj, _sig: '0'.repeat(64) });
  fs.writeFileSync(file('.config-sig'), createHmac('sha256', key).update(content, 'utf-8').digest('hex'));
  return content;
}

async function freshConfig(): Promise<ConfigModule> {
  jest.resetModules();
  return import('../cloud/config.js');
}

function expectLinkIntact(): void {
  expect(fs.lstatSync(configFile()).isSymbolicLink()).toBe(true);
}

beforeEach(() => {
  const mk = (tag: string) => fs.mkdtempSync(path.join(os.tmpdir(), `sc-878-${tag}-`));
  configDir = mk('cfg');
  const protectedRoot = mk('root');
  const openclawHome = mk('oc');
  const home = mk('home');
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
  configReads = 0;
  openSinkSpy.mockReset();
  openSinkSpy.mockImplementation(async () => { throw new Error('not used here'); });
  errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try { fs.chmodSync(configDir, 0o700); } catch { /* gone */ }
  for (const dir of scratch) fs.rmSync(dir, { recursive: true, force: true });
});

// ── The mechanism: the read layer ───────────────────────────────────────

describe('#878 read layer: no write through a symlinked config.json', () => {
  it('a plain read of a live link to an unsigned target writes nothing, and reads strict (unknown is never off)', async () => {
    liveUnsignedLink({ defenceMode: 'balanced', actionGuard: { enabled: false } });
    const before = snapshot();
    const config = await freshConfig();

    const raw = config.readRawConfig();
    expect(snapshot()).toEqual(before);
    expectLinkIntact();
    // Not adopted, so the verdict is unknown; the runtime enforces strict.
    expect(raw.defenceMode).toBe('strict');
    expect(config.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
    expect(snapshot()).toEqual(before);
    expect(errors()).toMatch(/symbolic link to a file with no signature.*not adopted/s);
  });

  it('regular-file control: the same unsigned bytes are adopted and enforced as written', async () => {
    regularUnsigned({ defenceMode: 'balanced', actionGuard: { enabled: false } });
    const config = await freshConfig();
    expect(config.readRawConfig().defenceMode).toBe('balanced');
    expect(config.getActionGuardCoreConfig().enabled).toBe(false);
    expect(fs.readdirSync(configDir).sort()).toEqual(['.config-sig', '.integrity-key', 'config.json']);
  });

  it('a self-heal verdict through a live link is read as authentic but not rewritten', async () => {
    const content = selfHealBytes({ defenceMode: 'balanced' });
    fs.writeFileSync(file('target.json'), content);
    fs.symlinkSync(file('target.json'), configFile());
    const before = snapshot();
    const config = await freshConfig();

    expect(config.readRawConfig().defenceMode).toBe('balanced');
    expect(config.isConfigTampered()).toBe(false);
    expect(snapshot()).toEqual(before);
    expectLinkIntact();
  });

  it('regular-file control: a self-heal verdict is re-signed in place', async () => {
    const content = selfHealBytes({ defenceMode: 'balanced' });
    fs.writeFileSync(configFile(), content);
    const config = await freshConfig();
    expect(config.readRawConfig().defenceMode).toBe('balanced');
    expect(fs.readFileSync(configFile(), 'utf-8')).not.toBe(content);
    expect(fs.existsSync(file('.config-sig'))).toBe(false);
  });

  it('a signed target behind a link with no key file does not mint one', async () => {
    fs.writeFileSync(file('target.json'), bytes({ defenceMode: 'balanced', _sig: 'a'.repeat(64) }));
    fs.symlinkSync(file('target.json'), configFile());
    const before = snapshot();
    const config = await freshConfig();
    expect(config.readRawConfig().defenceMode).toBe('strict');
    expect(snapshot()).toEqual(before);
  });

  it('item 1: a dangling link reads as unreadable, never absent, and writes nothing', async () => {
    const target = danglingLink();
    const before = snapshot();
    const config = await freshConfig();
    expect(config.readRawConfig()).toEqual({});
    expect(config.inspectConfigIntegrity().verdict).toBe('unreadable');
    expect(() => config.setDefenceMode('balanced')).toThrow(config.ConfigSymlinkRefusal);
    expect(snapshot()).toEqual(before);
    expect(fs.existsSync(target)).toBe(false);
  });
});

// ── Guard-off and watch-only under failed adoption ──────────────────────

describe('#878 Guard off / watch-only under failed or impossible adoption are not reported as such', () => {
  const postures: Array<[string, Record<string, unknown>]> = [
    ['Guard off', { enabled: false }],
    ['watch-only', { enabled: true, enforce: false }],
  ];

  for (const [name, guard] of postures) {
    it(`${name}: a directory at .integrity-key fails adoption — doctor's inspector and the runtime both say strict`, async () => {
      regularUnsigned({ actionGuard: guard });
      fs.mkdirSync(file('.integrity-key'));
      const config = await freshConfig();
      const strict = { enabled: true, enforce: true, readinessGate: false };
      expect(config.inspectActionGuardCoreConfig()).toEqual(strict);
      expect(config.getActionGuardCoreConfig()).toEqual(strict);
    });

    (asRoot ? it.skip : it)(`${name}: an unwritable config directory makes the outcome unknown to doctor, never ${name}`, async () => {
      regularUnsigned({ actionGuard: guard });
      fs.chmodSync(configDir, 0o500);
      const config = await freshConfig();
      expect(config.inspectActionGuardCoreConfig()).toBe('unknown');
      // The runtime's adoption fails, so it reads the file tampered: strict.
      expect(config.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
    });

    it(`${name}: behind a link the inspector says unknown and the runtime holds strict, with nothing written`, async () => {
      liveUnsignedLink({ actionGuard: guard });
      const before = snapshot();
      const config = await freshConfig();
      expect(config.inspectActionGuardCoreConfig()).toBe('unknown');
      expect(config.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
      expect(snapshot()).toEqual(before);
    });

    it(`${name}: regular-file control — an unobstructed adoption is reported as the file says, and the runtime agrees`, async () => {
      regularUnsigned({ actionGuard: guard });
      const config = await freshConfig();
      const inspected = config.inspectActionGuardCoreConfig();
      expect(fs.readdirSync(configDir)).toEqual(['config.json']); // the inspector wrote nothing
      expect(inspected).toEqual(config.getActionGuardCoreConfig());
      expect(inspected).toMatchObject({ enabled: guard.enabled, enforce: guard.enforce ?? true });
    });
  }
});

// ── Getter-then-setter pairs ────────────────────────────────────────────

describe('#878 getter-then-setter pairs write nothing through a link', () => {
  it('getActionGuardCoreConfig → setActionGuardCoreConfig (live unsigned link): refusal is true, directory unchanged', async () => {
    liveUnsignedLink({ defenceMode: 'balanced' });
    const before = snapshot();
    const config = await freshConfig();
    config.getActionGuardCoreConfig();
    let thrown: unknown;
    try { config.setActionGuardCoreConfig({ enabled: true }); } catch (err) { thrown = err; }
    expect(thrown).toBeInstanceOf(config.ConfigSymlinkRefusal);
    expect((thrown as Error).message).toMatch(/symbolic link.*Nothing was written/s);
    expect(snapshot()).toEqual(before);
    expectLinkIntact();
  });

  it('getActionGuardCoreConfig → setActionGuardCoreConfig (dangling link): refused, target never created', async () => {
    const target = danglingLink();
    const before = snapshot();
    const config = await freshConfig();
    config.getActionGuardCoreConfig();
    expect(() => config.setActionGuardCoreConfig({ enabled: true })).toThrow(/symbolic link.*Nothing was written/s);
    expect(snapshot()).toEqual(before);
    expect(fs.existsSync(target)).toBe(false);
  });

  it('regular-file control: getActionGuardCoreConfig → setActionGuardCoreConfig persists', async () => {
    regularUnsigned({ defenceMode: 'balanced' });
    const config = await freshConfig();
    config.getActionGuardCoreConfig();
    config.setActionGuardCoreConfig({ enabled: true, enforce: false });
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.actionGuard).toMatchObject({ enabled: true, enforce: false });
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    expect((await freshConfig()).getActionGuardCoreConfig()).toMatchObject({ enabled: true, enforce: false });
  });

  it('getCloudConfig → setCloudIronDomeCache (live unsigned link): skipped without a throw, directory unchanged', async () => {
    liveUnsignedLink({ cloudEnabled: true, cloudApiKey: 'k' });
    const before = snapshot();
    const config = await freshConfig();
    expect(config.getCloudConfig().cloudEnabled).toBe(true);
    expect(() => config.setCloudIronDomeCache({ patterns: [] })).not.toThrow();
    expect(snapshot()).toEqual(before);
    expect(errors()).toMatch(/symbolic link.*Nothing was written/s);
  });

  it('getCloudConfig → setCloudIronDomeCache (dangling link): skipped, target never created', async () => {
    const target = danglingLink();
    const before = snapshot();
    const config = await freshConfig();
    config.getCloudConfig();
    expect(() => config.setCloudIronDomeCache({ patterns: [] })).not.toThrow();
    expect(snapshot()).toEqual(before);
    expect(fs.existsSync(target)).toBe(false);
  });

  it('regular-file control: getCloudConfig → setCloudIronDomeCache persists', async () => {
    regularUnsigned({ cloudEnabled: true, cloudApiKey: 'k' });
    const config = await freshConfig();
    config.getCloudConfig();
    config.setCloudIronDomeCache({ patterns: [], policy: null });
    expect(JSON.parse(fs.readFileSync(configFile(), 'utf-8')).cloudIronDome).toEqual({ patterns: [], policy: null });
  });

  it('item 6: setCloudIronDomeCache skips a corrupt config explicitly, without a throw and without overwriting', async () => {
    fs.writeFileSync(configFile(), '{ not json');
    const config = await freshConfig();
    expect(() => config.setCloudIronDomeCache({ patterns: [] })).not.toThrow();
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe('{ not json');
  });
});

// ── Lazy device writers ─────────────────────────────────────────────────

describe('#878 getDeviceId / getDeviceName write nothing through a link', () => {
  const writers: Array<['getDeviceId' | 'getDeviceName', string]> = [['getDeviceId', 'deviceId'], ['getDeviceName', 'deviceName']];

  for (const [fn, key] of writers) {
    it(`${fn}: live link to an unsigned target — directory unchanged, value non-empty, the refusal it logs is true`, async () => {
      liveUnsignedLink({ defenceMode: 'balanced' });
      const before = snapshot();
      const config = await freshConfig();
      const first = config[fn]();
      const second = config[fn]();
      expect(first).toEqual(expect.any(String));
      expect(first.length).toBeGreaterThan(0);
      expect(second).toBe(first);
      expect(snapshot()).toEqual(before);
      expectLinkIntact();
      // It says nothing was written, and nothing was.
      expect(errors()).toMatch(/symbolic link.*Nothing was written/s);
    });

    it(`${fn}: dangling link — directory unchanged, value non-empty, says NOT persisted`, async () => {
      const target = danglingLink();
      const before = snapshot();
      const config = await freshConfig();
      const value = config[fn]();
      expect(value.length).toBeGreaterThan(0);
      expect(snapshot()).toEqual(before);
      expect(fs.existsSync(target)).toBe(false);
      expect(errors()).toMatch(/NOT persisted/);
    });

    it(`${fn}: regular-file control — persists, and a fresh process reads the same value back`, async () => {
      regularUnsigned({ defenceMode: 'balanced' });
      const config = await freshConfig();
      const value = config[fn]();
      expect(value.length).toBeGreaterThan(0);
      const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
      expect(onDisk[key]).toBe(value);
      expect(onDisk.defenceMode).toBe('balanced');
      expect(fs.lstatSync(configFile()).isFile()).toBe(true);
      expect((await freshConfig())[fn]()).toBe(value);
    });
  }
});

// ── Reviewer rows: the CLI flag, setup posture, iron-dome sync ──────────

describe('#878 entry points that read the core config and then write it', () => {
  it('config --action-guard-enforce-when-ready on a live unsigned link: refused, nothing written', async () => {
    liveUnsignedLink({ defenceMode: 'balanced' });
    const before = snapshot();
    await freshConfig();
    const { handleCloudConfig } = await import('../cloud/cli.js');
    let thrown: unknown;
    try { await handleCloudConfig(['--action-guard-enforce-when-ready']); } catch (err) { thrown = err; }
    expect((thrown as Error | undefined)?.message).toMatch(/symbolic link.*Nothing was written/s);
    expect(snapshot()).toEqual(before);
  });

  it('regular-file control: config --action-guard-enforce-when-ready persists the posture', async () => {
    regularUnsigned({ defenceMode: 'balanced' });
    const config = await freshConfig();
    const { handleCloudConfig } = await import('../cloud/cli.js');
    await handleCloudConfig(['--action-guard-enforce-when-ready']);
    expect(config.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: true });
  });

  for (const answer of ['1', '2', '3']) {
    it(`setup posture choice ${answer} on a live unsigned link: says why, changes nothing`, async () => {
      liveUnsignedLink({ defenceMode: 'balanced' });
      const before = snapshot();
      await freshConfig();
      const { offerActionGuardPosture } = await import('../setup/action-guard-posture.js');
      const lines: string[] = [];
      const picked = await offerActionGuardPosture({ tty: true, ask: async () => answer, log: (l) => lines.push(l) });
      expect(picked).toBeNull();
      expect(lines.join('\n')).toMatch(/symbolic link.*Nothing was written/s);
      expect(snapshot()).toEqual(before);
    });
  }

  it('regular-file control: setup posture choice 2 (watch-only) persists', async () => {
    regularUnsigned({ defenceMode: 'balanced' });
    const config = await freshConfig();
    const { offerActionGuardPosture } = await import('../setup/action-guard-posture.js');
    const picked = await offerActionGuardPosture({ tty: true, ask: async () => '2', log: () => undefined });
    expect(picked).toBe('watch-only');
    expect(config.getActionGuardCoreConfig()).toMatchObject({ enabled: true, enforce: false });
  });

  function mockCloudFetch(): void {
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      const body = url.includes('/patterns/')
        ? { patterns: [], updated_at: '2026-11-01T00:00:00Z' }
        : { policy: null, updated_at: '2026-11-01T00:00:00Z' };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
  }

  it('iron-dome sync on a live unsigned link: fetched, not persisted, nothing written', async () => {
    liveUnsignedLink({ cloudEnabled: true, cloudApiKey: 'k', cloudBaseUrl: 'https://cloud.invalid' });
    const before = snapshot();
    await freshConfig();
    mockCloudFetch();
    const sync = await import('../cloud/iron-dome-sync.js');
    await sync.refreshCloudIronDome();
    expect(globalThis.fetch).toHaveBeenCalled();
    expect(snapshot()).toEqual(before);
    expect(errors()).toMatch(/symbolic link.*Nothing was written/s);
  });

  it('regular-file control: iron-dome sync persists the fetched cache', async () => {
    regularUnsigned({ cloudEnabled: true, cloudApiKey: 'k', cloudBaseUrl: 'https://cloud.invalid' });
    await freshConfig();
    mockCloudFetch();
    const sync = await import('../cloud/iron-dome-sync.js');
    await sync.refreshCloudIronDome();
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.cloudIronDome).toMatchObject({ patterns: [], policy: null });
  });
});

// ── Item 2: the cache key ───────────────────────────────────────────────

describe('#878 item 2: a same-size in-place edit with the mtime restored is re-read, not served from cache', () => {
  it('the getter re-reads the edited bytes (and their verdict) instead of its cached valid answer', async () => {
    regularUnsigned({});
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: true, enforce: false });
    const mtime = 1_700_000_000;
    fs.utimesSync(configFile(), mtime, mtime);
    expect(config.getActionGuardCoreConfig()).toMatchObject({ enabled: true, enforce: false }); // cached, valid

    const signed = fs.readFileSync(configFile(), 'utf-8');
    // "enabled": true / "enforce": false → "enabled": false / "enforce": true — same length.
    const edited = signed.replace('"enabled": true', '"enabled": false').replace('"enforce": false', '"enforce": true');
    expect(edited).not.toBe(signed);
    expect(edited.length).toBe(signed.length);
    const ino = fs.statSync(configFile()).ino;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30); // coarse ctime clock
    fs.writeFileSync(configFile(), edited);
    fs.utimesSync(configFile(), mtime, mtime);
    expect(fs.statSync(configFile()).ino).toBe(ino);

    // Re-read: the stale `_sig` no longer matches, so it is tampered → strict.
    configReads = 0;
    expect(config.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
    expect(configReads).toBe(1);
    expect(config.isConfigTampered()).toBe(true);
  });

  it('control: with nothing changed the getter answers from its cache — config.json is not read again', async () => {
    regularUnsigned({});
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: true, enforce: false });
    expect(config.getActionGuardCoreConfig()).toMatchObject({ enabled: true, enforce: false }); // populates the cache
    configReads = 0;
    for (let i = 0; i < 5; i += 1) {
      expect(config.getActionGuardCoreConfig()).toMatchObject({ enabled: true, enforce: false });
    }
    expect(configReads).toBe(0);
    expect(config.isConfigTampered()).toBe(false);
  });

  /** Re-sign `obj` the way writeRawConfig does, with the key on disk (same layout, same size). */
  function signedBytes(obj: Record<string, unknown>): string {
    const key = fs.readFileSync(file('.integrity-key'), 'utf-8').trim();
    const rest = { ...obj };
    delete rest._sig;
    const sig = createHmac('sha256', key).update(JSON.stringify(rest, null, 2), 'utf-8').digest('hex');
    return JSON.stringify({ ...rest, _sig: sig }, null, 2) + '\n';
  }

  it('N2: getCloudConfig re-derives after another writer\'s same-size, validly signed edit with the mtime restored', async () => {
    regularUnsigned({});
    const config = await freshConfig();
    config.setCloudConfig({ cloudEnabled: true, cloudApiKey: 'k', cloudBaseUrl: 'https://aaaa.invalid' });
    const mtime = 1_700_000_000;
    fs.utimesSync(configFile(), mtime, mtime);
    expect(config.getCloudConfig().cloudBaseUrl).toBe('https://aaaa.invalid'); // derived and cached

    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    const edited = signedBytes({ ...onDisk, cloudBaseUrl: 'https://bbbb.invalid' });
    expect(edited.length).toBe(fs.statSync(configFile()).size);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30); // coarse ctime clock
    fs.writeFileSync(configFile(), edited);
    fs.utimesSync(configFile(), mtime, mtime);

    expect(config.getCloudConfig().cloudBaseUrl).toBe('https://bbbb.invalid');
    expect(config.isConfigTampered()).toBe(false);
  });

  it('N2 control: with nothing changed getCloudConfig answers from its derived cache without reading config.json', async () => {
    regularUnsigned({});
    const config = await freshConfig();
    config.setCloudConfig({ cloudEnabled: true, cloudApiKey: 'k' });
    const first = config.getCloudConfig();
    configReads = 0;
    expect(config.getCloudConfig()).toBe(first);
    expect(configReads).toBe(0);
  });
});

// ── Round-1 fold: the rows the restart had not pinned ───────────────────

describe('#878 getCloudSyncControls (the v4.27 migration reader) writes nothing through a link', () => {
  const PRE_MIGRATION = { cloudEnabled: true, cloudApiKey: 'k' };

  it('live unsigned link: the safe default is answered in memory, the migration is not persisted, directory unchanged', async () => {
    liveUnsignedLink(PRE_MIGRATION);
    const before = snapshot();
    const config = await freshConfig();
    expect(config.getCloudSyncControls().excludeSensitive).toBe(true);
    expect(snapshot()).toEqual(before);
    expectLinkIntact();
    expect(errors()).toMatch(/symbolic link.*Nothing was written/s);
  });

  it('dangling link: defaults, nothing written, target never created', async () => {
    const target = danglingLink();
    const before = snapshot();
    const config = await freshConfig();
    expect(config.getCloudSyncControls()).toEqual({
      projectMode: 'all', projects: [], contentMode: 'full', excludeSensitive: true,
    });
    expect(snapshot()).toEqual(before);
    expect(fs.existsSync(target)).toBe(false);
  });

  it('regular-file control: the migration is persisted and signed', async () => {
    regularUnsigned(PRE_MIGRATION);
    const config = await freshConfig();
    expect(config.getCloudSyncControls().excludeSensitive).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    expect(onDisk.cloudSyncExcludeSensitive).toBe(true);
    expect(onDisk.cloudSyncDefaultsMigratedAt).toEqual(expect.any(String));
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('#878 config --resign refuses a symlinked config.json before any backup, audit or write', () => {
  /** Tampered (the embedded `_sig` is wrong) but strict-shaped, so nothing else refuses the re-sign. */
  const TAMPERED = bytes({ defenceMode: 'strict', actionGuard: { enabled: true, enforce: true }, _sig: 'b'.repeat(64) });
  const sha = (b: string) => createHash('sha256').update(b, 'utf-8').digest('hex');

  it('live link to a tampered target: the preview says refused; the confirm throws the link refusal; nothing written', async () => {
    fs.writeFileSync(file('.integrity-key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    fs.writeFileSync(file('target.json'), TAMPERED);
    fs.symlinkSync(file('target.json'), configFile());
    const before = snapshot();
    const config = await freshConfig();
    // A working audit sink, so that only the link refusal can stop the backup.
    openSinkSpy.mockImplementationOnce(async () => ({ location: 'test-sink', record: () => 1, close: () => undefined }));
    const preview = config.previewConfigResign();
    expect(preview).toMatchObject({ verdict: 'tampered', linked: true, unauthorisedKeys: [], lockRefusal: null });
    expect(preview.sha256).toBe(sha(TAMPERED));

    let thrown: unknown;
    try { await config.resignTamperedConfig(preview.sha256!); } catch (err) { thrown = err; }
    expect(thrown).toBeInstanceOf(config.ConfigSymlinkRefusal);
    expect((thrown as Error).message).toMatch(/symbolic link.*Nothing was written/s);
    // The message is true: no backup, nothing else either — and the audit log was never opened.
    expect(snapshot()).toEqual(before);
    expect(fs.readdirSync(configDir).some((n) => n.includes('.bak-resign-'))).toBe(false);
    expect(openSinkSpy).not.toHaveBeenCalled();
    expectLinkIntact();
  });

  it('dangling link: the confirm throws the link refusal, not "not tampered"; target never created', async () => {
    const target = danglingLink();
    const before = snapshot();
    const config = await freshConfig();
    expect(config.previewConfigResign()).toMatchObject({ verdict: 'unreadable', linked: true });
    await expect(config.resignTamperedConfig('c'.repeat(64))).rejects.toBeInstanceOf(config.ConfigSymlinkRefusal);
    expect(openSinkSpy).not.toHaveBeenCalled();
    expect(snapshot()).toEqual(before);
    expect(fs.existsSync(target)).toBe(false);
  });

  it('regular-file control: the same tampered bytes are backed up, re-signed and recorded', async () => {
    fs.writeFileSync(file('.integrity-key'), randomBytes(32).toString('hex'), { mode: 0o600 });
    fs.writeFileSync(configFile(), TAMPERED);
    const config = await freshConfig();
    const record = jest.fn((_row: unknown) => 41);
    openSinkSpy.mockImplementationOnce(async () => ({ location: 'test-sink', record, close: () => undefined }));
    const preview = config.previewConfigResign();
    expect(preview).toMatchObject({ verdict: 'tampered', linked: false, unauthorisedKeys: [], lockRefusal: null });

    const result = await config.resignTamperedConfig(preview.sha256!, { now: new Date('2026-11-01T00:00:00.000Z') });
    expect(fs.readdirSync(configDir).sort()).toEqual([
      '.integrity-key', 'config.json', 'config.json.bak-resign-2026-11-01T00-00-00-000Z',
    ]);
    expect(fs.readFileSync(result.backupPath, 'utf-8')).toBe(TAMPERED);
    expect(config.inspectConfigIntegrity().verdict).toBe('valid');
    expect(result.audit).toMatchObject({ recorded: true, rowId: 41 });
  });
});

describe('#878 resolveLedgerConfig: the read-only seam doctor\'s chained-ledger check uses writes nothing', () => {
  const LEDGER = { defenceMode: 'balanced', ledger: { heartbeatMinutes: 5 } };
  const cases: Array<[string, () => void]> = [
    ['regular unsigned', () => regularUnsigned(LEDGER)],
    ['regular self-heal', () => fs.writeFileSync(configFile(), selfHealBytes(LEDGER))],
    ['regular, embedded _sig with no key', () => fs.writeFileSync(configFile(), bytes({ ...LEDGER, _sig: 'a'.repeat(64) }))],
    ['live unsigned link', () => liveUnsignedLink(LEDGER)],
  ];

  for (const [name, arrange] of cases) {
    it(`${name}: resolveLedgerConfig({ readOnly: true }) reads the setting and leaves the directory unchanged`, async () => {
      arrange();
      const before = snapshot();
      await freshConfig();
      const { resolveLedgerConfig } = await import('../defence/ledger/config.js');
      expect(resolveLedgerConfig({ readOnly: true }).heartbeatIntervalMs).toBe(5 * 60_000);
      expect(snapshot()).toEqual(before);
    });
  }

  it('control: the ledger writer\'s ordinary read still adopts an unsigned regular file', async () => {
    regularUnsigned(LEDGER);
    await freshConfig();
    const { resolveLedgerConfig } = await import('../defence/ledger/config.js');
    expect(resolveLedgerConfig().heartbeatIntervalMs).toBe(5 * 60_000);
    expect(fs.readdirSync(configDir).sort()).toEqual(['.config-sig', '.integrity-key', 'config.json']);
  });
});

describe('#878 inspectConfigIntegrity: one outlook for an unsigned file, shared with the core-config inspector', () => {
  it('regular and unobstructed: unsigned, graded by the file', async () => {
    regularUnsigned({ actionGuard: { enabled: false } });
    const config = await freshConfig();
    const report = config.inspectConfigIntegrity();
    expect(report).toEqual({ path: configFile(), verdict: 'unsigned', linked: false });
    expect(config.configPostureOutlook(report)).toBe('file');
    expect(fs.readdirSync(configDir)).toEqual(['config.json']);
  });

  it('behind a live link: unverified (linked), outlook unknown — and the core inspector says unknown too', async () => {
    liveUnsignedLink({ actionGuard: { enabled: false } });
    const before = snapshot();
    const config = await freshConfig();
    const report = config.inspectConfigIntegrity();
    expect(report).toEqual({ path: configFile(), verdict: 'unverified', adoption: 'linked', linked: true });
    expect(config.configPostureOutlook(report)).toBe('unknown');
    expect(config.inspectActionGuardCoreConfig()).toBe('unknown');
    expect(snapshot()).toEqual(before);
  });

  it('a .integrity-key directory: unverified (fails), outlook strict — and the core inspector answers strict', async () => {
    regularUnsigned({ actionGuard: { enabled: false } });
    fs.mkdirSync(file('.integrity-key'));
    const config = await freshConfig();
    const report = config.inspectConfigIntegrity();
    expect(report).toMatchObject({ verdict: 'unverified', adoption: 'fails', linked: false });
    expect(config.configPostureOutlook(report)).toBe('strict');
    expect(config.inspectActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
  });

  (asRoot ? it.skip : it)('an unwritable config directory: unverified (unknown), outlook unknown, as the core inspector says', async () => {
    regularUnsigned({ actionGuard: { enabled: false } });
    fs.chmodSync(configDir, 0o500);
    const config = await freshConfig();
    const report = config.inspectConfigIntegrity();
    expect(report).toMatchObject({ verdict: 'unverified', adoption: 'unknown' });
    expect(config.configPostureOutlook(report)).toBe('unknown');
    expect(config.inspectActionGuardCoreConfig()).toBe('unknown');
  });

  it('tampered is strict; absent, valid, malformed and unreadable are graded as the runtime reads them', async () => {
    const config = await freshConfig();
    expect(config.configPostureOutlook({ verdict: 'tampered' })).toBe('strict');
    for (const verdict of ['absent', 'valid', 'self-heal', 'malformed', 'unreadable'] as const) {
      expect(config.configPostureOutlook({ verdict })).toBe('file');
    }
  });
});
