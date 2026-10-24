/**
 * #878 — config integrity follow-ups after #699 (items 1, 2 and 6).
 *
 *   1. A symlink at config.json, dangling or not, is never replaced. A dangling
 *      one used to read as `absent` (existsSync follows the link), and the next
 *      setter renamed a regular file over it.
 *   2. The raw-config cache key is the file's identity (dev, inode, size,
 *      mtime), not its mtime alone: bytes swapped in at the same mtime used to
 *      be answered from the cache — `valid` included — and the next write
 *      signed them.
 *   6. setCloudIronDomeCache is an automatic writer and skips explicitly; it
 *      still never re-signs a tampered config.
 *
 * Isolation: a per-test SHIELDCORTEX_CONFIG_DIR, SHIELDCORTEX_PROTECTED_ROOT and
 * OPENCLAW_HOME under os.tmpdir(); the iron-dome audit logger, the recovery
 * audit sink and the OpenClaw plugin guard sync are mocked. `fs` is a
 * pass-through owned by this test that counts reads of config.json, so a cache
 * hit can be told from a re-read; nothing in shipped code knows it exists.
 */
import fs from 'fs';
import * as realFs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV } from '../defence/iron-dome/protected-root.js';
import { clearPolicyLockReportState } from '../defence/iron-dome/policy-lock.js';

const auditSpy = jest.fn();
const guardSyncSpy = jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const }));
const openSinkSpy = jest.fn(async () => { throw new Error('not used here'); });

jest.unstable_mockModule('../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: auditSpy }));
jest.unstable_mockModule('../cloud/recovery-audit.js', () => ({ openRecoveryAuditSink: openSinkSpy }));
jest.unstable_mockModule('../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: guardSyncSpy,
}));

let configReads = 0;
const countingReadFileSync = ((file: unknown, ...rest: unknown[]) => {
  if (typeof file === 'string' && path.basename(file) === 'config.json') configReads++;
  return (realFs.readFileSync as (...args: unknown[]) => unknown)(file, ...rest);
}) as typeof realFs.readFileSync;
// Runs once when a config temp file is written, before it is renamed into place.
let onTempWrite: (() => void) | null = null;
const hookedWriteFileSync = ((file: unknown, ...rest: unknown[]) => {
  const out = (realFs.writeFileSync as (...args: unknown[]) => unknown)(file, ...rest);
  if (typeof file === 'string' && path.basename(file).startsWith('config.json.tmp-') && onTempWrite) {
    const hook = onTempWrite;
    onTempWrite = null;
    hook();
  }
  return out;
}) as typeof realFs.writeFileSync;
const countingFs = { ...realFs, readFileSync: countingReadFileSync, writeFileSync: hookedWriteFileSync };
jest.unstable_mockModule('fs', () => ({ ...countingFs, default: countingFs }));

type ConfigModule = typeof import('../cloud/config.js');

const SENTINEL = 'sc_live_SENTINEL_878';
const FIXED_MTIME_S = 1_700_000_000;

let configDir: string;
let protectedRoot: string;
let openclawHome: string;
let saved: Record<string, string | undefined>;

const configFile = () => path.join(configDir, 'config.json');

async function freshConfig(): Promise<ConfigModule> {
  jest.resetModules();
  clearPolicyLockReportState();
  return import('../cloud/config.js');
}

beforeEach(() => {
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-878-cfg-'));
  protectedRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-878-root-'));
  openclawHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-878-oc-'));
  saved = {
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    [PROTECTED_ROOT_ENV]: process.env[PROTECTED_ROOT_ENV],
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
  };
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = protectedRoot;
  process.env.OPENCLAW_HOME = openclawHome;
  configReads = 0;
  onTempWrite = null;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const dir of [configDir, protectedRoot, openclawHome]) fs.rmSync(dir, { recursive: true, force: true });
});

describe('#878 item 1: a symlink at config.json is never replaced', () => {
  it('dangling: setters refuse, the link survives, nothing is written anywhere', async () => {
    const target = path.join(configDir, 'elsewhere', 'config.json');
    fs.symlinkSync(target, configFile());
    const entriesBefore = fs.readdirSync(configDir).sort();
    const config = await freshConfig();

    let thrown: unknown;
    try { config.setCloudConfig({ cloudApiKey: SENTINEL }); } catch (err) { thrown = err; }
    // The link is still the link: no regular file was renamed over it.
    expect(fs.lstatSync(configFile()).isSymbolicLink()).toBe(true);
    expect(fs.readlinkSync(configFile())).toBe(target);
    expect(fs.existsSync(target)).toBe(false);
    expect((thrown as Error | undefined)?.message).toMatch(/symbolic link.*Nothing was written/s);

    expect(() => config.setDefenceMode('balanced')).toThrow(/symbolic link/);
    // Automatic writers skip without throwing.
    expect(() => config.getDeviceId()).not.toThrow();
    expect(() => config.setCloudIronDomeCache({ patterns: [] })).not.toThrow();
    expect(fs.lstatSync(configFile()).isSymbolicLink()).toBe(true);
    expect(fs.readdirSync(configDir).sort()).toEqual(entriesBefore);

    // Reported as the file it is — present, unreadable — never as absent.
    expect(config.inspectConfigIntegrity().verdict).toBe('unreadable');
    expect(config.readActionGuardCoreConfigReadOnly()).toBeNull();
  });

  it('live: readers follow the link, setters refuse, the link and its target are unchanged', async () => {
    const seed = await freshConfig();
    seed.setCloudConfig({ cloudApiKey: SENTINEL });
    const target = path.join(configDir, 'real-config.json');
    fs.renameSync(configFile(), target);
    fs.symlinkSync(target, configFile());
    const targetBefore = fs.readFileSync(target);
    const config = await freshConfig();

    expect(config.getCloudConfig().cloudApiKey).toBe(SENTINEL);
    expect(config.inspectConfigIntegrity().verdict).toBe('valid');

    let thrown: unknown;
    try { config.setDefenceMode('strict'); } catch (err) { thrown = err; }
    expect(fs.lstatSync(configFile()).isSymbolicLink()).toBe(true);
    expect(fs.readlinkSync(configFile())).toBe(target);
    expect(fs.readFileSync(target).equals(targetBefore)).toBe(true);
    expect((thrown as Error | undefined)?.message).toMatch(/symbolic link/);

    expect(() => config.setCloudIronDomeCache({ patterns: [] })).not.toThrow();
    expect(fs.lstatSync(configFile()).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(target).equals(targetBefore)).toBe(true);
  });
});

describe('#878 item 1: a symlink that appears mid-write', () => {
  /** Swap config.json for a link to it while the writer's temp file is being written. */
  function linkDuringWrite(target: string): void {
    onTempWrite = () => {
      fs.renameSync(configFile(), target);
      fs.symlinkSync(target, configFile());
    };
  }

  it('a skip-policy writer declines without throwing; the link and its target are unchanged', async () => {
    const config = await freshConfig();
    config.setCloudConfig({ cloudApiKey: SENTINEL });
    const target = path.join(configDir, 'real-config.json');
    const bytes = fs.readFileSync(configFile());
    linkDuringWrite(target);

    expect(() => config.setCloudIronDomeCache({ patterns: ['p'] })).not.toThrow();
    expect(onTempWrite).toBeNull(); // the hook ran: the link appeared after the initial check
    expect(fs.lstatSync(configFile()).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(target).equals(bytes)).toBe(true);
    expect(fs.readdirSync(configDir).filter((n) => n.includes('.tmp-'))).toEqual([]);
  });

  it('a throw-policy setter still throws the symlink refusal', async () => {
    const config = await freshConfig();
    config.setCloudConfig({ cloudApiKey: SENTINEL });
    linkDuringWrite(path.join(configDir, 'real-config.json'));
    expect(() => config.setDefenceMode('strict')).toThrow(/symbolic link/);
    expect(fs.lstatSync(configFile()).isSymbolicLink()).toBe(true);
  });
});

describe('#878 item 2: the raw-config cache key is the file, not its mtime', () => {
  /** A signed config, mtime pinned, cache primed through the mutating reader. */
  async function primed(): Promise<{ config: ConfigModule; signed: string }> {
    const seed = await freshConfig();
    seed.setCloudConfig({ cloudApiKey: SENTINEL });
    seed.setDefenceMode('balanced');
    fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
    const config = await freshConfig();
    expect(config.readRawConfig().defenceMode).toBe('balanced');
    expect(config.isConfigTampered()).toBe(false);
    return { config, signed: fs.readFileSync(configFile(), 'utf-8') };
  }

  it('an unchanged file is still answered from the cache', async () => {
    const { config } = await primed();
    const reads = configReads;
    expect(config.readRawConfig().defenceMode).toBe('balanced');
    expect(config.getDefenceMode()).toBe('balanced');
    expect(configReads).toBe(reads);
  });

  it('same inode and mtime, different size: re-read, tampered, and the writer refuses', async () => {
    const { config, signed } = await primed();
    const edited = signed.replace('"balanced"', '"permissive"');
    expect(edited.length).not.toBe(signed.length);
    const inode = fs.statSync(configFile()).ino;
    fs.writeFileSync(configFile(), edited); // in place: same inode
    fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
    expect(fs.statSync(configFile()).ino).toBe(inode);

    expect(config.readRawConfig().defenceMode).toBe('strict');
    expect(config.isConfigTampered()).toBe(true);
    expect(() => config.addTrustedSkill('/skills/x.md')).toThrow(config.ConfigIntegrityRefusal);
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(edited);
  });

  it('same inode, size and mtime, different bytes: re-read, tampered, writers refuse or skip', async () => {
    const { config, signed } = await primed();
    const edited = signed.replace(SENTINEL, SENTINEL.slice(0, -1) + 'X');
    expect(edited.length).toBe(signed.length);
    const before = fs.statSync(configFile());
    // Let the kernel's coarse timestamp clock move on, so the edit's ctime
    // differs from the primed file's even without fine-grained timestamps.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30);
    fs.writeFileSync(configFile(), edited); // in place: same inode, same size
    fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
    const after = fs.statSync(configFile());
    // Every field the old cache key compared is preserved; only ctime moved.
    expect([after.dev, after.ino, after.size, after.mtimeMs]).toEqual([before.dev, before.ino, before.size, before.mtimeMs]);
    expect(after.ctimeMs).not.toBe(before.ctimeMs);

    const reads = configReads;
    expect(config.readRawConfig().defenceMode).toBe('strict');
    expect(configReads).toBeGreaterThan(reads); // re-read, not the cached verdict
    expect(config.isConfigTampered()).toBe(true);
    expect(() => config.addTrustedSkill('/skills/x.md')).toThrow(config.ConfigIntegrityRefusal);
    expect(() => config.setCloudIronDomeCache({ patterns: ['p'] })).not.toThrow();
    expect(config.getDeviceId()).toEqual(expect.any(String));
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(edited);
    expect(config.isConfigTampered()).toBe(true);
  });

  it('same size and mtime, different inode: re-read, tampered, and the writer refuses', async () => {
    const { config, signed } = await primed();
    // One character of the credential changed: same length, stale `_sig`.
    const edited = signed.replace(SENTINEL, SENTINEL.slice(0, -1) + 'X');
    expect(edited.length).toBe(signed.length);
    const inode = fs.statSync(configFile()).ino;
    const swap = path.join(configDir, 'swap.json');
    fs.writeFileSync(swap, edited);
    fs.renameSync(swap, configFile()); // a different file at the same path
    fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
    expect(fs.statSync(configFile()).ino).not.toBe(inode);
    expect(fs.statSync(configFile()).size).toBe(Buffer.byteLength(signed));

    expect(config.readRawConfig().defenceMode).toBe('strict');
    expect(config.isConfigTampered()).toBe(true);
    expect(() => config.addTrustedSkill('/skills/x.md')).toThrow(config.ConfigIntegrityRefusal);
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(edited);
  });
});

describe('#878 item 6: setCloudIronDomeCache skips explicitly', () => {
  it('on a tampered config it neither throws nor re-signs: bytes and mtime unchanged, still tampered', async () => {
    const seed = await freshConfig();
    seed.setCloudConfig({ cloudApiKey: SENTINEL });
    const onDisk = JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
    onDisk.proactiveRecall = true; // a hand edit: `_sig` no longer verifies
    fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
    fs.utimesSync(configFile(), FIXED_MTIME_S, FIXED_MTIME_S);
    const before = { bytes: fs.readFileSync(configFile()), mtimeMs: fs.statSync(configFile()).mtimeMs };
    const config = await freshConfig();

    expect(() => config.setCloudIronDomeCache({ patterns: ['p'] })).not.toThrow();

    expect(fs.readFileSync(configFile()).equals(before.bytes)).toBe(true);
    expect(fs.statSync(configFile()).mtimeMs).toBe(before.mtimeMs);
    expect(config.inspectConfigIntegrity().verdict).toBe('tampered');
    expect(config.isConfigTampered()).toBe(true);
  });
});
