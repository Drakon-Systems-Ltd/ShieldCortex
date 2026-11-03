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
 * test's config.json with EIO when armed (or parks one readFile of it until
 * released, to overlap two reads); nothing in shipped code knows it exists.
 * The fresh-install contract is pinned beside it: a missing, blank,
 * malformed or unreadable file on a cold runtime reads `{}` (Guard off by
 * default), removing the file clears the hold, and a valid new file — Guard
 * off included — takes effect.
 *
 * A cold runtime whose config.json ENTRY cannot be lstat'd (or whose bytes
 * cannot be pinned to one entry) is not one of those: the bytes are readable.
 * v5.17.2 release review r3 B1: #983 answered it `{}` without reading them,
 * where v5.17.1 and #981 read a signed enforcing file as enforcing. It now
 * reads them and judges them as a link would be judged (the link state is
 * unknown): a signature the local `.integrity-key` verifies puts them in
 * force, anything else is held strict.
 */
import { createHmac } from 'node:crypto';
import * as realFsp from 'node:fs/promises';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * Which syscalls on this test's config.json fail with EIO right now, and how
 * often they did. `lstatPass`: how many armed lstats still go through before
 * the rest fail (a fault that starts between two lstats of one read).
 * `parkRead`: the next readFile of config.json waits for `release()`.
 * `reads`: readFile calls on config.json that reached the disk.
 * `afterRead`: runs after each such read resolves (an entry replaced under
 * every read).
 */
const fault = {
  path: '',
  lstat: false,
  lstatPass: 0,
  read: false,
  hits: 0,
  reads: 0,
  afterRead: null as null | (() => void),
  parkRead: null as null | { parked: boolean; released: Promise<void> },
};
const eio = (syscall: string, p: string): NodeJS.ErrnoException =>
  Object.assign(new Error(`EIO: i/o error, ${syscall} '${p}'`), { code: 'EIO', errno: -5, syscall, path: p });
const armed = (on: boolean, p: unknown): p is string => on && typeof p === 'string' && p === fault.path;
const faultyFsp = {
  ...realFsp,
  lstat: ((p: unknown, ...rest: unknown[]) => {
    if (armed(fault.lstat, p)) {
      if (fault.lstatPass > 0) {
        fault.lstatPass -= 1;
      } else {
        fault.hits += 1;
        return Promise.reject(eio('lstat', p));
      }
    }
    return (realFsp.lstat as (...a: unknown[]) => Promise<unknown>)(p, ...rest);
  }) as typeof realFsp.lstat,
  readFile: ((p: unknown, ...rest: unknown[]) => {
    if (armed(fault.read, p)) {
      fault.hits += 1;
      return Promise.reject(eio('open', p));
    }
    const read = () => {
      const pending = (realFsp.readFile as (...a: unknown[]) => Promise<unknown>)(p, ...rest);
      if (p !== fault.path) return pending;
      fault.reads += 1;
      const after = fault.afterRead;
      return after ? pending.then((bytes) => { after(); return bytes; }) : pending;
    };
    const park = fault.parkRead;
    if (park && !park.parked && p === fault.path) {
      park.parked = true;
      return park.released.then(read);
    }
    return read();
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
  fault.lstatPass = 0;
  fault.read = false;
  fault.hits = 0;
  fault.reads = 0;
  fault.afterRead = null;
  fault.parkRead = null;
});

afterEach(() => {
  fault.lstat = false;
  fault.read = false;
  fault.afterRead = null;
  fault.parkRead = null;
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

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const expectStrict = (cfg: Record<string, any>): void => {
  expect(cfg.actionGuard).toMatchObject({ enabled: true, enforce: true });
  expect(cfg.defenceMode).toBe('strict');
};

/** The whole strict fail-closed posture over `raw` (runtime.mjs strictFailClosedPosture, spelled out). */
const strictOf = (raw: Record<string, any>): Record<string, any> => ({
  ...raw,
  defenceMode: 'strict',
  actionGuard: { ...(raw.actionGuard ?? {}), enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [] },
});

// The CLI's signature: HMAC-SHA256 with the local `.integrity-key` over the
// object minus `_sig`, `JSON.stringify(rest, null, 2)` (checkConfigIntegrity).
const KEY = 'a'.repeat(64);
const signed = (body: Record<string, unknown>): Record<string, unknown> => ({
  ...body,
  _sig: createHmac('sha256', KEY).update(JSON.stringify(body, null, 2)).digest('hex'),
});

/** A regular config.json the CLI signed, with its `.integrity-key` beside it. */
function writeSignedConfig(body: Record<string, unknown>): string {
  writeFileSync(join(configDir, '.integrity-key'), KEY, { mode: 0o600 });
  return writeConfig(signed(body));
}

/**
 * What a fresh runtime reads from config.json with no fault armed — the
 * answer v5.17.1 also gave a cold lstat fault over these bytes (it read them
 * and took them as a regular file; release review r3 B1 harness). Resets the
 * read counter after.
 */
async function unfaultedBaseline(): Promise<Record<string, any>> {
  expect(fault.lstat || fault.read).toBe(false);
  const cfg = await (await runtimeFor(configPath())).loadShieldConfig();
  fault.reads = 0;
  return cfg;
}

/** Replace the config.json entry with a new inode holding the same bytes (no ENOENT in between). */
function churnEntry(): void {
  const replacement = join(configDir, 'churn.json');
  writeFileSync(replacement, readFileSync(configPath()));
  renameSync(replacement, configPath());
}

/** A warm runtime holding the strict posture over an unsigned link whose target says Guard off. */
async function warmUnsignedLink(): Promise<{ runtime: Runtime; first: Record<string, any>; target: string }> {
  const target = join(home, 'target.json');
  writeFileSync(target, JSON.stringify(GUARD_OFF));
  pin(target);
  symlinkSync(target, configPath());
  const runtime = await runtimeFor(configPath());
  const first = await runtime.loadShieldConfig();
  expectStrict(first);
  return { runtime, first, target };
}

/** Atomically replace the config.json entry (a link here) with a regular blank file: no ENOENT in between. */
function renameBlankOverEntry(): void {
  const replacement = join(configDir, 'replacement.json');
  writeFileSync(replacement, '   ');
  renameSync(replacement, configPath());
  expect(lstatSync(configPath()).isFile()).toBe(true);
}

/**
 * Two loads in flight at once — two tool calls reading config.json together —
 * with the first readFile of config.json parked until one load settles or
 * 100 ms pass. `parked`: a read really was in flight while the other load ran.
 */
async function overlappingLoads(runtime: Runtime): Promise<{ a: Record<string, any>; b: Record<string, any>; parked: boolean }> {
  let release!: () => void;
  const park = { parked: false, released: new Promise<void>((resolve) => { release = resolve; }) };
  fault.parkRead = park;
  const pa = runtime.loadShieldConfig();
  const pb = runtime.loadShieldConfig();
  await Promise.race([pa, pb, sleep(100)]).finally(release);
  const [a, b] = await Promise.all([pa, pb]);
  fault.parkRead = null;
  return { a, b, parked: park.parked };
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

describe('warm runtime: an lstat fault on the config.json entry holds the established posture (#983 review)', () => {
  it('unsigned link held strict, lstat EIO with the Guard-off target still readable: the same strict object, and again after recovery', async () => {
    const { runtime, first } = await warmUnsignedLink();
    fault.lstat = true;
    expect(await runtime.loadShieldConfig()).toBe(first);
    expect(await runtime.loadShieldConfig()).toBe(first);
    expect(fault.hits).toBeGreaterThan(0);
    fault.lstat = false;
    const recovered = await runtime.loadShieldConfig();
    expect(recovered).toBe(first);
    expectStrict(recovered);
  });

  it('the target turns blank while the lstat fault persists, then the fault clears: still the ORIGINAL strict object', async () => {
    const { runtime, first, target } = await warmUnsignedLink();
    fault.lstat = true;
    expect(await runtime.loadShieldConfig()).toBe(first);
    await tick();
    writeFileSync(target, '   ');
    pin(target);
    expect(await runtime.loadShieldConfig()).toBe(first);
    expect(fault.hits).toBeGreaterThan(0);
    fault.lstat = false;
    const recovered = await runtime.loadShieldConfig();
    expect(recovered).toBe(first);
    expectStrict(recovered);
    expect(await runtime.loadShieldConfig()).toBe(first);
  });

  it('an lstat that fails after the identity lstat succeeded (entry unchanged): held strict, not the target taken as a regular file', async () => {
    const { runtime, first } = await warmUnsignedLink();
    fault.lstat = true;
    fault.lstatPass = 1;
    expect(await runtime.loadShieldConfig()).toBe(first);
    expect(fault.lstatPass).toBe(0); // the first lstat of the call went through
    fault.lstat = false;
    expect(await runtime.loadShieldConfig()).toBe(first);
  });

  it('the target changes and the lstat after the read fails: held, then the new bytes are judged as the link they are', async () => {
    const { runtime, first, target } = await warmUnsignedLink();
    await tick();
    writeFileSync(target, JSON.stringify({ ...GUARD_OFF, openclawAutoMemory: true }));
    pin(target);
    fault.lstat = true;
    fault.lstatPass = 1;
    expect(await runtime.loadShieldConfig()).toBe(first);
    expect(fault.hits).toBeGreaterThan(0);
    fault.lstat = false;
    const next = await runtime.loadShieldConfig();
    expect(next).not.toBe(first);
    expectStrict(next);
    expect(next.openclawAutoMemory).toBe(true);
  });

  it('a valid Guard-off file that lands while lstat fails waits for lstat: held until then, then in force', async () => {
    const { runtime, first } = await warmEnforcing();
    fault.lstat = true;
    await replaceInPlace(JSON.stringify(GUARD_OFF));
    await expectHeld(runtime, first);
    expect(fault.hits).toBeGreaterThan(0);
    fault.lstat = false;
    expect(await runtime.loadShieldConfig()).toEqual(GUARD_OFF);
  });
});

describe('overlapping loads (two tool calls at once) answer from one consistent read (#983 review)', () => {
  it('a blank regular file renamed over the unsigned link, read by two loads at once: both and the next hold the strict object', async () => {
    const { runtime, first } = await warmUnsignedLink();
    renameBlankOverEntry();
    const { a, b, parked } = await overlappingLoads(runtime);
    expect(parked).toBe(true);
    expect(a).toBe(first);
    expect(b).toBe(first);
    expect(await runtime.loadShieldConfig()).toBe(first);
  });

  it('control: the same rename read by one load at a time holds the strict object', async () => {
    const { runtime, first } = await warmUnsignedLink();
    renameBlankOverEntry();
    expect(await runtime.loadShieldConfig()).toBe(first);
    expect(await runtime.loadShieldConfig()).toBe(first);
  });

  it('config.json removed, read by two loads at once: both and the next read {} — the removal is not undone by the overlap', async () => {
    const { runtime } = await warmEnforcing();
    rmSync(configPath());
    const { a, b } = await overlappingLoads(runtime);
    expect(a).toEqual({});
    expect(b).toEqual({});
    expect(await runtime.loadShieldConfig()).toEqual({});
    // Cleared, not merely masked: a blank file after the removal is a fresh blank.
    writeConfig('   ');
    expect(await runtime.loadShieldConfig()).toEqual({});
  });

  it('control: a valid Guard-off file read by two loads at once takes effect for both', async () => {
    const { runtime, first } = await warmEnforcing();
    await replaceInPlace(JSON.stringify(GUARD_OFF));
    const { a, b, parked } = await overlappingLoads(runtime);
    expect(parked).toBe(true);
    expect(a).not.toBe(first);
    expect(a).toEqual(GUARD_OFF);
    expect(b).toBe(a);
  });
});

describe('controls: the fresh-install and deliberate-change contract is unchanged', () => {
  it('regular enforcing file, lstat EIO with the bytes still readable: enforcing — the same object, held while the entry is unknown', async () => {
    const { runtime, first } = await warmEnforcing();
    fault.lstat = true;
    await expectHeld(runtime, first);
    expect(fault.hits).toBeGreaterThan(0);
    fault.lstat = false;
    expect(await runtime.loadShieldConfig()).toBe(first);
  });

  it('cold start, lstat EIO, unsigned regular enforcing file: strict, not {} — an entry that cannot be lstat\'d is judged like a link; the file reads as itself once it can be lstat\'d', async () => {
    writeConfig(ENFORCING);
    fault.lstat = true;
    const runtime = await runtimeFor(configPath());
    const cfg = await runtime.loadShieldConfig();
    expect(cfg).toEqual(strictOf(ENFORCING));
    expect(await runtime.loadShieldConfig()).toBe(cfg);
    expect(fault.hits).toBeGreaterThan(0);
    fault.lstat = false;
    expect(await runtime.loadShieldConfig()).toEqual(ENFORCING);
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

describe('cold runtime: readable bytes behind an entry that cannot be lstat\'d are read, not answered {} (v5.17.2 release review r3 B1)', () => {
  // Where the lstat fails: before the read (the first entry snapshot), or
  // after it (the snapshot that pins the bytes to that entry).
  const WHERE = [
    ['first snapshot', 0],
    ['post-read snapshot', 1],
  ] as const;

  for (const [where, pass] of WHERE) {
    it(`${where} lstat EIO, signed enforcing regular file: the bytes' own enforcing posture — what an unfaulted read (and v5.17.1) gives — and the bytes were read`, async () => {
      writeSignedConfig(ENFORCING);
      const baseline = await unfaultedBaseline();
      expect(baseline.actionGuard).toEqual({ enabled: true, enforce: true });
      expect(baseline.defenceMode).toBe('strict');

      fault.lstat = true;
      fault.lstatPass = pass;
      const runtime = await runtimeFor(configPath());
      const cfg = await runtime.loadShieldConfig();
      expect(fault.hits).toBeGreaterThan(0);
      expect(fault.lstatPass).toBe(0);
      // Read once, as the release review's harness counted (v5.17.1: 1; #983: 0).
      expect(fault.reads).toBe(1);
      expect(cfg).toEqual(baseline);
      // Stable identity while the fault lasts: the plugin does not re-merge per call.
      expect(await runtime.loadShieldConfig()).toBe(cfg);
      fault.lstat = false;
      expect(await runtime.loadShieldConfig()).toEqual(baseline);
    });

    it(`${where} lstat EIO, unsigned link to a Guard-off target: strict — the unknown entry is not taken as a regular file`, async () => {
      const target = join(home, 'target.json');
      writeFileSync(target, JSON.stringify(GUARD_OFF));
      symlinkSync(target, configPath());
      fault.lstat = true;
      fault.lstatPass = pass;
      const runtime = await runtimeFor(configPath());
      const cfg = await runtime.loadShieldConfig();
      expect(fault.hits).toBeGreaterThan(0);
      expect(cfg).toEqual(strictOf(GUARD_OFF));
      fault.lstat = false;
      expect(await runtime.loadShieldConfig()).toEqual(strictOf(GUARD_OFF));
    });

    it(`${where} lstat EIO, unsigned or mis-signed regular Guard-off file: strict — no signature, no Guard off while the entry is unknown`, async () => {
      writeFileSync(join(configDir, '.integrity-key'), KEY, { mode: 0o600 });
      for (const body of [GUARD_OFF, { ...GUARD_OFF, _sig: 'f'.repeat(64) }]) {
        writeConfig(body);
        fault.lstat = true;
        fault.lstatPass = pass;
        const cfg = await (await runtimeFor(configPath())).loadShieldConfig();
        fault.lstat = false;
        expectStrict(cfg);
        expect(cfg.actionGuard.autoApprove).toEqual([]);
      }
    });

    it(`control (${where}): a genuine signed default-off file stays off — the authenticated bytes, not strict`, async () => {
      writeSignedConfig(GUARD_OFF);
      const baseline = await unfaultedBaseline();
      expect(baseline.actionGuard).toEqual({ enabled: false });
      fault.lstat = true;
      fault.lstatPass = pass;
      const cfg = await (await runtimeFor(configPath())).loadShieldConfig();
      expect(fault.hits).toBeGreaterThan(0);
      expect(cfg).toEqual(baseline);
      expect(cfg.defenceMode).toBeUndefined();
    });

    it(`control (${where}): warm floor — an enforcing posture is held while the lstat fault lasts, even over newly signed Guard-off bytes; they are honoured once it clears`, async () => {
      writeSignedConfig(ENFORCING);
      const runtime = await runtimeFor(configPath());
      const first = await runtime.loadShieldConfig();
      expect(first.actionGuard).toEqual({ enabled: true, enforce: true });
      await tick();
      writeSignedConfig(GUARD_OFF);
      fault.lstat = true;
      fault.lstatPass = pass;
      expect(await runtime.loadShieldConfig()).toBe(first);
      expect(fault.hits).toBeGreaterThan(0);
      fault.lstat = false;
      const next = await runtime.loadShieldConfig();
      expect(next).not.toBe(first);
      expect(next.actionGuard).toEqual({ enabled: false });
    });
  }

  it('the posture read under the fault is the floor: a blank while it lasts and after it clears holds it; removing the file clears it', async () => {
    const text = writeSignedConfig(ENFORCING);
    fault.lstat = true;
    const runtime = await runtimeFor(configPath());
    const cfg = await runtime.loadShieldConfig();
    expect(cfg.actionGuard).toEqual({ enabled: true, enforce: true });
    await replaceInPlace(' '.repeat(Buffer.byteLength(text)));
    expect(await runtime.loadShieldConfig()).toBe(cfg);
    fault.lstat = false;
    expect(await runtime.loadShieldConfig()).toBe(cfg);
    rmSync(configPath());
    expect(await runtime.loadShieldConfig()).toEqual({});
  });

  it('an entry replaced under every read (never pinned to one entry): signed enforcing bytes read enforcing, not {}; held after', async () => {
    writeSignedConfig(ENFORCING);
    const baseline = await unfaultedBaseline();
    let churns = 0;
    fault.afterRead = () => { churns += 1; churnEntry(); };
    const runtime = await runtimeFor(configPath());
    const cfg = await runtime.loadShieldConfig();
    expect(churns).toBeGreaterThanOrEqual(3);
    expect(cfg).toEqual(baseline);
    expect(await runtime.loadShieldConfig()).toBe(cfg);
  });

  it('an unsigned link swapped in under every read: strict, not {} and not its target\'s Guard-off values', async () => {
    const target = join(home, 'target.json');
    writeFileSync(target, JSON.stringify(GUARD_OFF));
    symlinkSync(target, configPath());
    fault.afterRead = () => {
      const next = join(configDir, 'link.next');
      symlinkSync(target, next);
      renameSync(next, configPath());
    };
    const cfg = await (await runtimeFor(configPath())).loadShieldConfig();
    expect(cfg).toEqual(strictOf(GUARD_OFF));
  });

  for (const [name, setup] of [
    ['lstat AND readFile EIO', () => { writeSignedConfig(ENFORCING); fault.read = true; }],
    ['blank file', () => writeConfig('   ')],
    ['malformed file', () => writeConfig('{not json')],
  ] as const) {
    it(`control: cold, lstat EIO, ${name} — no bytes to judge: {} (the unreadable-from-the-start default)`, async () => {
      setup();
      fault.lstat = true;
      const runtime = await runtimeFor(configPath());
      const cfg = await runtime.loadShieldConfig();
      expect(cfg).toEqual({});
      expect(await runtime.loadShieldConfig()).toBe(cfg);
      expect(fault.hits).toBeGreaterThan(0);
    });
  }
});
