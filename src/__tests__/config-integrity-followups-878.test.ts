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
 * sink and the OpenClaw plugin guard sync are mocked.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac, randomBytes } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV } from '../defence/iron-dome/protected-root.js';

const auditSpy = jest.fn();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));
const openSinkSpy = jest.fn(async () => { throw new Error('not used here'); });

jest.unstable_mockModule('../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../cloud/recovery-audit.js', () => ({ openRecoveryAuditSink: openSinkSpy }));
jest.unstable_mockModule('../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

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
    expect(config.getActionGuardCoreConfig()).toEqual({ enabled: true, enforce: true, readinessGate: false });
    expect(config.isConfigTampered()).toBe(true);
  });

  it('control: with nothing changed the getter keeps answering from its cache', async () => {
    regularUnsigned({});
    const config = await freshConfig();
    config.setActionGuardCoreConfig({ enabled: true, enforce: false });
    expect(config.getActionGuardCoreConfig()).toMatchObject({ enabled: true, enforce: false });
    expect(config.getActionGuardCoreConfig()).toMatchObject({ enabled: true, enforce: false });
    expect(config.isConfigTampered()).toBe(false);
  });
});
