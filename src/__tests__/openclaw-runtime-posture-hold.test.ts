/**
 * The OpenClaw runtime holds an established posture (v5.17.2 release review
 * B1/B2, the runtime sibling of #981).
 *
 * #981 made src/cloud/config.ts hold the posture a process established from
 * config.json when the file later reads blank, unreadable or malformed. The
 * long-lived OpenClaw gateway reads the same file through
 * hooks/openclaw/cortex-memory/runtime.mjs `loadShieldConfig`, and that reader
 * did not hold: #878 r4 keyed its cache on (dev, ino, size, mtime, ctime), so
 * an in-place blank that restores the mtime still moves ctime, misses the
 * cache, and the re-read turned into `{}` — Action Guard off at the plugin
 * gate. v5.17.1's mtime-only cache answered the same blank with the cached
 * enforcing object.
 *
 * Every case here drives the REAL `createOpenClawRuntime().loadShieldConfig()`.
 * Each warm case pins the mtime by assertion, so only the identity key (ctime,
 * size) can see the change. The read faults come from a pass-through over
 * `node:fs/promises` owned by this test that fails lstat/readFile of THIS
 * test's config.json with EIO when armed; nothing in shipped code knows it
 * exists. The fresh-install contract is pinned beside it: a missing, blank,
 * malformed or unreadable file on a cold runtime reads `{}` (Guard off by
 * default), removing the file clears the hold, and a valid new file — Guard
 * off included — takes effect.
 */
import * as realFsp from 'node:fs/promises';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/** Which syscalls on this test's config.json fail with EIO right now, and how often they did. */
const fault = { path: '', lstat: false, read: false, hits: 0 };
const eio = (syscall: string, p: string): NodeJS.ErrnoException =>
  Object.assign(new Error(`EIO: i/o error, ${syscall} '${p}'`), { code: 'EIO', errno: -5, syscall, path: p });
const armed = (on: boolean, p: unknown): p is string => on && typeof p === 'string' && p === fault.path;
const faultyFsp = {
  ...realFsp,
  lstat: ((p: unknown, ...rest: unknown[]) => {
    if (armed(fault.lstat, p)) {
      fault.hits += 1;
      return Promise.reject(eio('lstat', p));
    }
    return (realFsp.lstat as (...a: unknown[]) => Promise<unknown>)(p, ...rest);
  }) as typeof realFsp.lstat,
  readFile: ((p: unknown, ...rest: unknown[]) => {
    if (armed(fault.read, p)) {
      fault.hits += 1;
      return Promise.reject(eio('open', p));
    }
    return (realFsp.readFile as (...a: unknown[]) => Promise<unknown>)(p, ...rest);
  }) as typeof realFsp.readFile,
};
jest.unstable_mockModule('node:fs/promises', () => ({ ...faultyFsp, default: faultyFsp }));

type Runtime = { loadShieldConfig: () => Promise<Record<string, any>> };

async function runtimeFor(configPath: string): Promise<Runtime> {
  const mod = (await import('../../hooks/openclaw/cortex-memory/runtime.mjs')) as {
    createOpenClawRuntime: (opts?: { configPath?: string }) => Runtime;
  };
  return mod.createOpenClawRuntime({ configPath });
}

const ENFORCING = { defenceMode: 'strict', actionGuard: { enabled: true, enforce: true } };
const GUARD_OFF = { actionGuard: { enabled: false } };
// Whole seconds: a utimes round trip is exact, so "same mtime" holds bit for bit.
const PINNED = 1_767_225_600;

let home: string;
let configDir: string;
const configPath = () => join(configDir, 'config.json');

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-rt-hold-'));
  configDir = join(home, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  fault.path = configPath();
  fault.lstat = false;
  fault.read = false;
  fault.hits = 0;
});

afterEach(() => {
  fault.lstat = false;
  fault.read = false;
  try {
    chmodSync(configPath(), 0o600);
  } catch { /* gone, a directory, or a link */ }
  rmSync(home, { recursive: true, force: true });
});

const pin = (file = configPath()): void => utimesSync(file, PINNED, PINNED);

function writeConfig(body: unknown): string {
  const text = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
  writeFileSync(configPath(), text, { mode: 0o600 });
  pin();
  return text;
}

/**
 * Linux stamps ctime from a coarse clock unless a stat queried it since the
 * last change; wait past one tick so the change below is guaranteed to move it
 * and the identity key really misses (asserted by the callers).
 */
const tick = () => new Promise((resolve) => setTimeout(resolve, 25));

const ctimeNs = (file = configPath()): bigint => statSync(file, { bigint: true }).ctimeNs;

/** Rewrite the bytes in place (same inode), restoring the pinned mtime. Asserts ctime moved. */
async function replaceInPlace(content: string): Promise<void> {
  const before = statSync(configPath(), { bigint: true });
  await tick();
  writeFileSync(configPath(), content);
  pin();
  const after = statSync(configPath(), { bigint: true });
  expect(after.ino).toBe(before.ino);
  expect(after.mtimeNs).toBe(BigInt(PINNED) * 1_000_000_000n);
  expect(after.ctimeNs).not.toBe(before.ctimeNs);
}

/** A warm runtime that has read the enforcing posture from a regular config.json. */
async function warmEnforcing(): Promise<{ runtime: Runtime; first: Record<string, any>; text: string }> {
  const text = writeConfig(ENFORCING);
  const runtime = await runtimeFor(configPath());
  const first = await runtime.loadShieldConfig();
  expect(first).toEqual(ENFORCING);
  return { runtime, first, text };
}

/** The held answer: the same object (the plugin re-merges on identity change), still enforcing, on every read. */
async function expectHeld(runtime: Runtime, first: Record<string, any>): Promise<void> {
  const held = await runtime.loadShieldConfig();
  expect(held).toBe(first);
  expect(held.actionGuard).toEqual({ enabled: true, enforce: true });
  expect(held.defenceMode).toBe('strict');
  expect(await runtime.loadShieldConfig()).toBe(first);
}

describe('warm runtime: a no-data read after an enforcing read holds the established posture', () => {
  it('same-mtime, same-size whitespace blank (only ctime moves): held, not {}', async () => {
    const { runtime, first, text } = await warmEnforcing();
    await replaceInPlace(' '.repeat(Buffer.byteLength(text)));
    expect(statSync(configPath()).size).toBe(Buffer.byteLength(text));
    await expectHeld(runtime, first);
  });

  it('same-mtime empty file: held, not {}', async () => {
    const { runtime, first } = await warmEnforcing();
    await replaceInPlace('');
    await expectHeld(runtime, first);
  });

  it('same-mtime, same-size malformed JSON: held, not {}', async () => {
    const { runtime, first, text } = await warmEnforcing();
    await replaceInPlace(`{${'x'.repeat(Buffer.byteLength(text) - 1)}`);
    await expectHeld(runtime, first);
  });

  for (const [name, bytes] of [['null', 'null'], ['array', '[]'], ['scalar', '42']] as const) {
    it(`same-mtime non-object JSON (${name}): held — it is malformed, as src reads it`, async () => {
      const { runtime, first } = await warmEnforcing();
      await replaceInPlace(bytes);
      await expectHeld(runtime, first);
    });
  }

  it('readFile EIO after a ctime-only change (chmod, same bytes and mtime): held, not {}', async () => {
    const { runtime, first } = await warmEnforcing();
    const before = ctimeNs();
    await tick();
    chmodSync(configPath(), 0o644);
    expect(ctimeNs()).not.toBe(before);
    expect(statSync(configPath()).mtimeMs).toBe(PINNED * 1000);
    fault.read = true;
    await expectHeld(runtime, first);
    expect(fault.hits).toBeGreaterThan(0); // the seam fired: this is the error path, not a cache hit
  });

  it('lstat AND readFile EIO: held, not {}', async () => {
    const { runtime, first } = await warmEnforcing();
    fault.lstat = true;
    fault.read = true;
    await expectHeld(runtime, first);
    expect(fault.hits).toBeGreaterThan(0);
  });

  it('EACCES (mode 000, a real permission error): held, not {}', async () => {
    if (process.getuid?.() === 0) return; // root reads through mode 000
    const { runtime, first } = await warmEnforcing();
    await tick();
    chmodSync(configPath(), 0o000);
    await expectHeld(runtime, first);
  });

  it('config.json replaced by a directory (EISDIR): held, not {}', async () => {
    const { runtime, first } = await warmEnforcing();
    renameSync(configPath(), join(configDir, 'config.json.aside'));
    mkdirSync(configPath());
    await expectHeld(runtime, first);
  });

  it('config.json replaced by a dangling link: held — the entry exists, its bytes cannot be read (as src)', async () => {
    const { runtime, first } = await warmEnforcing();
    renameSync(configPath(), join(configDir, 'config.json.aside'));
    symlinkSync(join(home, 'missing.json'), configPath());
    expect(lstatSync(configPath()).isSymbolicLink()).toBe(true);
    await expectHeld(runtime, first);
  });

  it('an established strict posture (unsigned link) is held strict when the target turns blank', async () => {
    const target = join(home, 'target.json');
    writeFileSync(target, JSON.stringify(GUARD_OFF));
    pin(target);
    symlinkSync(target, configPath());
    const runtime = await runtimeFor(configPath());
    const first = await runtime.loadShieldConfig();
    expect(first.actionGuard).toMatchObject({ enabled: true, enforce: true });
    expect(first.defenceMode).toBe('strict');

    await tick();
    writeFileSync(target, '   ');
    pin(target);
    const held = await runtime.loadShieldConfig();
    expect(held).toBe(first);
    expect(held.actionGuard).toMatchObject({ enabled: true, enforce: true });
  });

  it('the hold ends when a valid file lands: the new bytes are in force', async () => {
    const { runtime, first } = await warmEnforcing();
    await replaceInPlace('   ');
    await expectHeld(runtime, first);
    await replaceInPlace(JSON.stringify({ ...ENFORCING, openclawAutoMemory: true }));
    const next = await runtime.loadShieldConfig();
    expect(next).not.toBe(first);
    expect(next).toEqual({ ...ENFORCING, openclawAutoMemory: true });
  });
});

describe('controls: the fresh-install and deliberate-change contract is unchanged', () => {
  it('lstat EIO with the enforcing bytes still readable: enforcing (read from the bytes)', async () => {
    const { runtime } = await warmEnforcing();
    fault.lstat = true;
    const cfg = await runtime.loadShieldConfig();
    expect(cfg).toEqual(ENFORCING);
    expect(fault.hits).toBeGreaterThan(0);
  });

  it('removing config.json (ENOENT) clears the hold: {} — the documented move-aside recovery', async () => {
    const { runtime } = await warmEnforcing();
    rmSync(configPath());
    expect(await runtime.loadShieldConfig()).toEqual({});
    // Cleared, not merely masked: a blank file after the removal is a fresh blank.
    writeConfig('   ');
    expect(await runtime.loadShieldConfig()).toEqual({});
  });

  it('a valid new file with Guard off takes effect (same mtime), and is what a later blank holds', async () => {
    const { runtime, first } = await warmEnforcing();
    await replaceInPlace(JSON.stringify(GUARD_OFF));
    const off = await runtime.loadShieldConfig();
    expect(off).not.toBe(first);
    expect(off).toEqual(GUARD_OFF);

    await replaceInPlace('   ');
    expect(await runtime.loadShieldConfig()).toBe(off);
  });

  it('an authenticated (signed) link to a Guard-off target replaces an enforcing posture', async () => {
    const { createHmac } = await import('node:crypto');
    const key = 'b'.repeat(64);
    writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
    const { runtime } = await warmEnforcing();
    const target = join(home, 'signed.json');
    const sig = createHmac('sha256', key).update(JSON.stringify(GUARD_OFF, null, 2)).digest('hex');
    writeFileSync(target, JSON.stringify({ ...GUARD_OFF, _sig: sig }));
    rmSync(configPath());
    symlinkSync(target, configPath());
    const cfg = await runtime.loadShieldConfig();
    expect(cfg.actionGuard).toEqual({ enabled: false });
    expect(cfg.defenceMode).toBeUndefined();
  });

  it('a regular default-off file stays off, and a later blank holds it off (not on)', async () => {
    writeConfig(GUARD_OFF);
    const runtime = await runtimeFor(configPath());
    const off = await runtime.loadShieldConfig();
    expect(off).toEqual(GUARD_OFF);
    await replaceInPlace('   ');
    expect(await runtime.loadShieldConfig()).toBe(off);
  });

  for (const [name, setup] of [
    ['missing', () => undefined],
    ['blank', () => writeConfig('   ')],
    ['empty', () => writeConfig('')],
    ['malformed', () => writeConfig('{not json')],
    ['non-object', () => writeConfig('[]')],
    ['readFile EIO', () => { writeConfig(ENFORCING); fault.read = true; }],
  ] as const) {
    it(`cold start, ${name}: {} — Guard stays off by default`, async () => {
      setup();
      const runtime = await runtimeFor(configPath());
      const cfg = await runtime.loadShieldConfig();
      expect(cfg).toEqual({});
      // Stable identity while nothing changes: no re-merge per call.
      expect(await runtime.loadShieldConfig()).toBe(cfg);
    });
  }
});
