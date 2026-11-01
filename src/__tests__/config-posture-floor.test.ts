/**
 * A newly observed error or blank state never relaxes a posture this process
 * already established (review finding on v5.17.2 / #878).
 *
 * #878 put an unconditional `lstat` of config.json in front of the mutating
 * read and keyed the raw-config cache on (dev, ino, size, mtime, ctime). Two
 * new paths then failed open against v5.17.1:
 *
 *  A. any non-ENOENT lstat error (EIO) returned `{}` / `unreadable`: Guard off
 *     and defenceMode balanced on a signed enforcing/strict config, cold, and
 *     warm before the previous good read was consulted;
 *  B. bytes replaced with whitespace in place (inode and mtime kept) missed
 *     the identity cache and read as `absent`: Guard off / balanced.
 *
 * The contract pinned here: an lstat error alone proves nothing about the
 * bytes, so the read goes on and takes the no-write path (link state unknown,
 * as for a link). A file that is then blank, unreadable or malformed, after
 * this process established a posture from it, holds that posture on every
 * read and refuses writes. The fresh-install contract is unchanged: a missing
 * file, a blank file on first read, a genuine default-off file and an
 * unreadable file on first read resolve as before, and an authenticated
 * posture change (including to off) takes effect.
 *
 * Isolation: every case has its own SHIELDCORTEX_CONFIG_DIR, protected root
 * and HOME under the temp dir, and a fresh module registry. `fs` is a
 * pass-through owned by this test that can fail lstat/readFileSync of
 * config.json with EIO; nothing in shipped code knows it exists.
 */
import * as realFs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac, randomBytes } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { PROTECTED_ROOT_ENV } from '../defence/iron-dome/protected-root.js';

jest.unstable_mockModule('../defence/iron-dome/audit.js', () => ({ logIronDomeAudit: jest.fn() }));
jest.unstable_mockModule('../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: () => ({ status: 'skipped', reason: 'no-entry' }),
}));

/** Which config.json syscalls fail with EIO right now. */
const fail = { lstat: false, read: false };
const eio = (syscall: string, p: string): NodeJS.ErrnoException =>
  Object.assign(new Error(`EIO: i/o error, ${syscall} '${p}'`), { code: 'EIO', errno: -5, syscall, path: p });
const isConfig = (p: unknown): p is string => typeof p === 'string' && path.basename(p) === 'config.json';
const faultyFs = {
  ...realFs,
  lstatSync: ((p: unknown, ...rest: unknown[]) => {
    if (fail.lstat && isConfig(p)) throw eio('lstat', p);
    return (realFs.lstatSync as (...a: unknown[]) => unknown)(p, ...rest);
  }) as typeof realFs.lstatSync,
  readFileSync: ((p: unknown, ...rest: unknown[]) => {
    if (fail.read && isConfig(p)) throw eio('open', p);
    return (realFs.readFileSync as (...a: unknown[]) => unknown)(p, ...rest);
  }) as typeof realFs.readFileSync,
};
jest.unstable_mockModule('fs', () => ({ ...faultyFs, default: faultyFs }));

const fs = realFs;
type ConfigModule = typeof import('../cloud/config.js');

let configDir: string;
let scratch: string[];
let saved: Record<string, string | undefined>;
let key: string;

const file = (name: string) => path.join(configDir, name);
const configFile = () => file('config.json');

const ENFORCING = { defenceMode: 'strict', actionGuard: { enabled: true, enforce: true } };
const GUARD_ON = { enabled: true, enforce: true, readinessGate: false };
const GUARD_OFF = { enabled: false, enforce: true, readinessGate: false };

/** A regular config.json with a valid embedded `_sig`, as writeRawConfig writes it. */
function writeSigned(body: Record<string, unknown>): void {
  const sig = createHmac('sha256', key).update(JSON.stringify(body, null, 2), 'utf-8').digest('hex');
  fs.writeFileSync(configFile(), JSON.stringify({ ...body, _sig: sig }, null, 2) + '\n', { mode: 0o600 });
}

/** Replace the bytes in place (same inode), restoring the mtime: the #878 identity key moves on size/ctime only. */
function replaceKeepingMtime(content: string): void {
  const st = fs.statSync(configFile());
  fs.writeFileSync(configFile(), content);
  fs.utimesSync(configFile(), st.atime, st.mtime);
  const after = fs.statSync(configFile());
  expect(after.ino).toBe(st.ino);
  expect(Math.abs(after.mtimeMs - st.mtimeMs)).toBeLessThan(1);
}

function dirListing(): string[] {
  return fs.readdirSync(configDir).sort().map((n) => `${n} ${fs.readFileSync(file(n)).toString('base64')}`);
}

async function freshConfig(): Promise<ConfigModule> {
  jest.resetModules();
  return import('../cloud/config.js');
}

function posture(config: ConfigModule): { guard: unknown; mode: string } {
  return { guard: config.getActionGuardCoreConfig(), mode: config.getDefenceMode() };
}

beforeEach(() => {
  const mk = (tag: string) => fs.mkdtempSync(path.join(os.tmpdir(), `sc-floor-${tag}-`));
  configDir = mk('cfg');
  const protectedRoot = mk('root');
  const home = mk('home');
  scratch = [configDir, protectedRoot, home];
  saved = {
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    [PROTECTED_ROOT_ENV]: process.env[PROTECTED_ROOT_ENV],
    HOME: process.env.HOME,
  };
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = protectedRoot;
  process.env.HOME = home;
  fail.lstat = false;
  fail.read = false;
  key = randomBytes(32).toString('hex');
  fs.writeFileSync(file('.integrity-key'), key, { mode: 0o600 });
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  fail.lstat = false;
  fail.read = false;
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const dir of scratch) fs.rmSync(dir, { recursive: true, force: true });
});

describe('A: an lstat error on config.json does not relax the posture', () => {
  it('cold: a signed enforcing/strict config is still enforced when lstat fails with EIO', async () => {
    writeSigned(ENFORCING);
    const before = dirListing();
    const config = await freshConfig();
    fail.lstat = true;
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    // Whether config.json is a link is unknown, so nothing writes over it (#878).
    expect(() => config.setDefenceMode('permissive')).toThrow(/refusing to overwrite/);
    expect(dirListing()).toEqual(before);
  });

  it('cold: with the link state unknown an unsigned file is not adopted, and reads strict', async () => {
    fs.rmSync(file('.integrity-key'));
    fs.writeFileSync(configFile(), JSON.stringify({ defenceMode: 'permissive', actionGuard: { enabled: false } }, null, 2));
    const before = dirListing();
    const config = await freshConfig();
    fail.lstat = true;
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    // Nothing written beside a file whose link state is unknown (#878).
    expect(dirListing()).toEqual(before);
  });

  it('warm: after a good read, an lstat EIO keeps the enforced posture', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    fail.lstat = true;
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
  });

  it('warm: lstat and read both failing hold the established posture and refuse writes', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    const before = fs.readFileSync(configFile(), 'utf-8');
    fail.lstat = true;
    fail.read = true;
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    expect(() => config.setDefenceMode('permissive')).toThrow(/refusing to overwrite/);
    fail.lstat = false;
    fail.read = false;
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(before);
  });
});

describe('B: blank or broken bytes after an enforcing read do not relax the posture', () => {
  it('whitespace written in place with the mtime restored keeps Guard on and strict', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    replaceKeepingMtime('  \n');
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    // The read-only reader cannot call that "off": the getter enforces more.
    expect(config.readActionGuardCoreConfigReadOnly()).toBeNull();
    expect(config.inspectActionGuardCoreConfig()).toBe('unknown');
    // And no incidental writer turns the blank file into a signed default-off one.
    expect(() => config.setDefenceMode('permissive')).toThrow(/refusing to overwrite/);
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe('  \n');
    expect(config.getDefenceMode()).toBe('strict');
  });

  it('an emptied file with a new mtime is held the same way', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    fs.writeFileSync(configFile(), '');
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
  });

  it('corrupt JSON written in place after an enforcing read keeps Guard on and strict', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    replaceKeepingMtime('{"actionGuard": {"enabled": fal');
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
  });

  it('a strict posture from a tampered read is held strict, not as the tampered bytes', async () => {
    fs.writeFileSync(configFile(), JSON.stringify({ defenceMode: 'permissive', actionGuard: { enabled: false }, _sig: '0'.repeat(64) }, null, 2));
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    fs.writeFileSync(configFile(), ' ');
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    expect(config.isConfigTampered()).toBe(true);
  });
});

describe('controls: the fresh-install and deliberate-change contracts are unchanged', () => {
  it('a genuine regular default-off file reads off and balanced, cold and warm', async () => {
    writeSigned({ deviceName: 'box' });
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    expect(config.readActionGuardCoreConfigReadOnly()).toEqual(GUARD_OFF);
  });

  it('a missing file on first read is absent: off, balanced, and setters create it', async () => {
    const config = await freshConfig();
    expect(config.inspectConfigIntegrity().verdict).toBe('absent');
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    config.setDefenceMode('strict');
    expect(config.getDefenceMode()).toBe('strict');
  });

  it('a blank file on first read is still "no config yet"', async () => {
    fs.writeFileSync(configFile(), '  \n');
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    expect(config.readActionGuardCoreConfigReadOnly()).toEqual(GUARD_OFF);
    config.setDefenceMode('strict');
    expect(config.getDefenceMode()).toBe('strict');
  });

  it('an authenticated switch to off takes effect, and is what a later blank file holds', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    config.setActionGuardCoreConfig({ enabled: false });
    config.setDefenceMode('balanced');
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    replaceKeepingMtime(' ');
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
  });

  it('an authenticated switch to off written by another process takes effect', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    writeSigned({ defenceMode: 'balanced', actionGuard: { enabled: false } });
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
  });

  it('a file unreadable on first read resolves per the documented contract: off at runtime, unknown read-only, never overwritten', async () => {
    writeSigned(ENFORCING);
    const before = fs.readFileSync(configFile(), 'utf-8');
    const config = await freshConfig();
    fail.read = true;
    // docs/design/2026-09-16-501-policy-lock.md: the signed read returns off
    // for an unreadable config as well as a real off (no posture was ever
    // established in this process to hold).
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    expect(config.readActionGuardCoreConfigReadOnly()).toBeNull();
    expect(() => config.setDefenceMode('permissive')).toThrow(/refusing to overwrite/);
    fail.read = false;
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(before);
    // Readable again: the file's own posture.
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
  });

  it('a file removed after an enforcing read is absent, as before (the move-aside recovery path)', async () => {
    writeSigned(ENFORCING);
    const config = await freshConfig();
    expect(posture(config)).toEqual({ guard: GUARD_ON, mode: 'strict' });
    fs.rmSync(configFile());
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    // ...and once absent has been seen, a later blank file is "no config yet".
    fs.writeFileSync(configFile(), ' ');
    expect(posture(config)).toEqual({ guard: GUARD_OFF, mode: 'balanced' });
    config.setDefenceMode('strict');
    expect(config.getDefenceMode()).toBe('strict');
  });
});
