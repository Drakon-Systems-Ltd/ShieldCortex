/**
 * #1109 round 2 — `shieldcortex openclaw repair`, driven through its entry
 * point (`repairOpenClawPlugin`).
 *
 *  - Astra P1 (duplicate repair): the preservation / exact-pin / npm-publication
 *    checks run before EVERY destructive branch, including the
 *    extension-only deletion, and a candidate is deleted only once OpenClaw's
 *    records prove a DIFFERENT copy is the one it selected. Otherwise the
 *    repair reports, stops, and exits 1 with nothing changed.
 *  - Astra P2 (managed pins): a failed managed-pin heal makes the command exit
 *    non-zero, even when nothing else in the repair has work to do.
 *
 * Nothing here spawns `openclaw` or `npm`: the publication check is answered
 * through its seam, and every repair gets a recording no-op launcher for the
 * managed-pin heal (#1179) — refusing earlier is not what keeps a case off
 * the host's `openclaw`. The runQuiet case below runs `node` on purpose.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { SpawnSyncReturns } from 'child_process';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { repairOpenClawPlugin, __setRealtimePublishCheckForTest, confirmRealtimePluginPublishedSync } from '../openclaw.js';
import { __runQuietForTest } from '../../cli/update.js';
import { parseNpmViewVersion } from '../openclaw-plugin-spec.js';

const ID = 'shieldcortex-realtime';
const PKG = '@drakon-systems/shieldcortex-realtime';
const SELF = (): string => JSON.parse(
  fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
).version;

let home: string;
let prevHome: string | undefined;
let prevExit: typeof process.exitCode;
let out: string[];

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1109-repair-'));
  fs.mkdirSync(path.join(home, '.openclaw', 'plugins'), { recursive: true });
  prevHome = process.env.OPENCLAW_HOME;
  process.env.OPENCLAW_HOME = home;
  prevExit = process.exitCode;
  process.exitCode = undefined;
  out = [];
  const capture = (...a: unknown[]) => { out.push(a.map(String).join(' ')); };
  jest.spyOn(console, 'log').mockImplementation(capture);
  jest.spyOn(console, 'warn').mockImplementation(capture);
  jest.spyOn(console, 'error').mockImplementation(capture);
  // A repair must never reach process.exit in these cases.
  jest.spyOn(process, 'exit').mockImplementation(((code?: number) => { throw new Error(`process.exit(${code})`); }) as never);
});

afterEach(() => {
  __setRealtimePublishCheckForTest(null);
  jest.restoreAllMocks();
  if (prevHome === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = prevHome;
  process.exitCode = prevExit;
  fs.rmSync(home, { recursive: true, force: true });
});

const writeJson = (rel: string, v: unknown): void => {
  const file = path.join(home, '.openclaw', rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(v));
};
/** A local extension copy (a duplicate candidate) at `version`. */
const extensionCopy = (version: string): string => {
  const dir = path.join(home, '.openclaw', 'extensions', ID);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'index.js'), '');
  fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version }));
  return dir;
};
/** An npm project install OpenClaw records (installs.json) at `version`. */
const recordedNpmInstall = (version: string, extra: Record<string, unknown> = {}): string => {
  const root = path.join(home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc');
  const dir = path.join(root, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version }));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'project', dependencies: { [PKG]: version }, ...extra }));
  writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'npm', installPath: dir } } });
  return dir;
};
const said = (): string => out.join('\n');

/**
 * #1179: what the managed-pin heal launches, for every repair here: a recording
 * fake with no `openclaw` (`resolveOpenClawBin` → null), never the real
 * `which openclaw` and runner. A heal that gets past its refusals stops at
 * "`openclaw` is not on PATH", after its manifest writes.
 */
const launch = {
  lookups: 0,
  runs: [] as string[][],
  deps: {
    resolveOpenClawBin: (): string | null => {
      launch.lookups += 1;
      return null;
    },
    runOpenClaw: (_bin: string, args: string[]): SpawnSyncReturns<string> => {
      launch.runs.push(args);
      return { pid: 0, output: [], stdout: '', stderr: '', status: 1, signal: null };
    },
  },
};
beforeEach(() => {
  launch.lookups = 0;
  launch.runs = [];
});
afterEach(() => {
  // Reads only the fake, so it is independent of the cleanup hook above.
  expect(launch.runs).toEqual([]);
});

describe('duplicate repair — extension-only branch is preflighted too', () => {
  it('the extension copy IS the only install (no record names another): nothing deleted, exit 1', async () => {
    const ext = extensionCopy(SELF());
    let asked = false;
    __setRealtimePublishCheckForTest(() => { asked = true; return { ok: true }; });

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(true);
    expect(said()).toMatch(/Not repairing: .*Nothing was changed/);
    expect(said()).not.toMatch(/Repair complete/);
    expect(asked).toBe(false);
    expect(process.exitCode).toBe(1);
  });

  it('the extension copy is newer than this CLI: nothing deleted, exit 1', async () => {
    recordedNpmInstall(SELF());
    const ext = extensionCopy('999.0.0');
    __setRealtimePublishCheckForTest(() => ({ ok: true }));

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(true);
    expect(said()).toMatch(/holds v999\.0\.0, newer than this CLI/);
    expect(process.exitCode).toBe(1);
  });

  it('the plugin is a linked install: nothing deleted, exit 1', async () => {
    recordedNpmInstall(SELF());
    const ext = extensionCopy(SELF());
    writeJson('openclaw.json', { plugins: { load: { paths: [ext] } } });
    __setRealtimePublishCheckForTest(() => ({ ok: true }));

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(true);
    expect(said()).toMatch(/Not repairing: the plugin is a linked install/);
    expect(process.exitCode).toBe(1);
  });

  it('OpenClaw\'s records cannot be read: nothing deleted, exit 1', async () => {
    recordedNpmInstall(SELF());
    const ext = extensionCopy(SELF());
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), '{ json5: true, }');
    __setRealtimePublishCheckForTest(() => ({ ok: true }));

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(true);
    expect(said()).toMatch(/could not tell whether the plugin is a linked install/);
    expect(process.exitCode).toBe(1);
  });

  it('the pin is not on npm (release-publication gap): nothing deleted, exit 1', async () => {
    recordedNpmInstall(SELF());
    const ext = extensionCopy(SELF());
    __setRealtimePublishCheckForTest((pin) => ({ ok: false, reason: `npm has no ${PKG}@${pin} yet` }));

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(true);
    expect(said()).toMatch(/Not repairing: npm has no .* yet\. Nothing was changed/);
    expect(process.exitCode).toBe(1);
  });

  it('a different, recorded copy is selected and every check passes: the leftover is removed', async () => {
    const live = recordedNpmInstall(SELF());
    const ext = extensionCopy(SELF());
    __setRealtimePublishCheckForTest(() => ({ ok: true }));

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(false);
    expect(fs.existsSync(live)).toBe(true);
    expect(said()).toMatch(/Repair complete/);
    expect(process.exitCode).not.toBe(1);
  });

  it('#1109 round 3: leftovers removed, but the SELECTED copy is older than this CLI — not "Repair complete", exit 1, command printed', async () => {
    recordedNpmInstall('0.0.1');
    const ext = extensionCopy('0.0.1');
    __setRealtimePublishCheckForTest(() => ({ ok: true }));

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(false);
    expect(said()).not.toMatch(/Repair complete\./);
    expect(said()).toMatch(/Repair incomplete: duplicates removed, but the plugin is on v0\.0\.1, CLI is v/);
    expect(said()).toContain(`openclaw plugins install --force npm:${PKG}@${SELF()}`);
    expect(process.exitCode).toBe(1);
  });

  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  (asRoot ? it.skip : it)('#1109 round 3: a duplicate that cannot be removed is not "Repair complete" — exit 1', async () => {
    recordedNpmInstall(SELF());
    const ext = extensionCopy(SELF());
    const extensions = path.dirname(ext);
    __setRealtimePublishCheckForTest(() => ({ ok: true }));
    fs.chmodSync(extensions, 0o555);
    try {
      await repairOpenClawPlugin(launch.deps);
    } finally {
      fs.chmodSync(extensions, 0o755);
    }

    expect(fs.existsSync(ext)).toBe(true);
    expect(said()).toMatch(/failed to remove/);
    expect(said()).not.toMatch(/Repair complete\./);
    expect(said()).toMatch(/Repair incomplete: a duplicate could not be removed/);
    expect(process.exitCode).toBe(1);
  });

  it('#1109 round 3: a candidate whose version cannot be read is not deleted', async () => {
    recordedNpmInstall(SELF());
    const ext = extensionCopy(SELF());
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), '{ not json');
    __setRealtimePublishCheckForTest(() => ({ ok: true }));

    await repairOpenClawPlugin(launch.deps);

    expect(fs.existsSync(ext)).toBe(true);
    expect(said()).toMatch(/Not repairing: could not read the copy at .* that the install would remove/);
    expect(process.exitCode).toBe(1);
  });
});

describe('managed-pin heal — a failure reaches the exit code', () => {
  it('a failed heal (the plugin is linked, so nothing is changed) exits 1 even with no duplicates to repair', async () => {
    // A managed project with a drifted peer pin, so the heal has work to do…
    recordedNpmInstall('5.0.0', { dependencies: { hono: '4.12.18' }, overrides: { hono: '4.12.21' } });
    // …but the plugin is a linked checkout, so the heal refuses to reinstall over it.
    const checkout = path.join(home, 'src', 'ShieldCortex', 'plugins', 'openclaw');
    fs.mkdirSync(checkout, { recursive: true });
    fs.writeFileSync(path.join(checkout, 'package.json'), JSON.stringify({ name: PKG, version: SELF() }));
    writeJson('openclaw.json', { plugins: { load: { paths: [checkout] } } });

    await repairOpenClawPlugin(launch.deps);

    expect(said()).toMatch(/✗ Realtime plugin left alone — the plugin is a linked install/);
    expect(said()).toMatch(/No duplicate shieldcortex-realtime installs detected/);
    expect(process.exitCode).toBe(1);
  });

  it('#1179: a heal that gets past every refusal asks the INJECTED lookup for `openclaw`, never the real one', async () => {
    // A recorded, unlinked install at this CLI's version whose managed project
    // has a drifted peer pin: nothing refuses, so the heal rewrites the
    // manifest and then looks for `openclaw` to reinstall.
    const live = recordedNpmInstall(SELF(), { dependencies: { [PKG]: SELF(), hono: '4.12.18' }, overrides: { hono: '4.12.21' } });
    const projectRoot = path.resolve(live, '..', '..', '..');

    await repairOpenClawPlugin(launch.deps);

    expect(launch.lookups).toBe(1);
    expect(launch.runs).toEqual([]);
    expect(said()).toMatch(/✗ Manifest reconciled, but `openclaw` is not on PATH/);
    expect((JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf-8')) as { dependencies: unknown }).dependencies)
      .toEqual({ [PKG]: SELF() });
    expect(process.exitCode).toBe(1);
  });

  it('control: a clean host with nothing to heal and no duplicates exits 0', async () => {
    recordedNpmInstall(SELF());

    await repairOpenClawPlugin(launch.deps);

    expect(said()).toMatch(/No duplicate shieldcortex-realtime installs detected/);
    expect(process.exitCode).not.toBe(1);
  });
});

describe('npm view publication check — strict JSON, normal exit 0 only (nit)', () => {
  type R = ReturnType<typeof import('child_process').spawnSync>;
  const answer = (r: Partial<R>) => (() => ({ status: 0, signal: null, stdout: '', stderr: '', ...r })) as never;

  it('parses `npm view … version --json` strictly', () => {
    expect(parseNpmViewVersion('')).toEqual({ state: 'versions', versions: [] });
    expect(parseNpmViewVersion('"5.20.2"\n')).toEqual({ state: 'versions', versions: ['5.20.2'] });
    expect(parseNpmViewVersion('["5.20.2","5.20.3"]')).toEqual({ state: 'versions', versions: ['5.20.2', '5.20.3'] });
    expect(parseNpmViewVersion('5.20.2')).toEqual({ state: 'unparseable' });
    expect(parseNpmViewVersion('npm notice x\n"5.20.2"')).toEqual({ state: 'unparseable' });
    expect(parseNpmViewVersion('{"error":{"code":"E404"}}')).toEqual({ state: 'unparseable' });
  });

  it('asks with --json and accepts only exactly the pin', () => {
    let argv: string[] = [];
    const spawn = ((_c: string, a: string[]) => { argv = a; return { status: 0, signal: null, stdout: '"5.20.2"\n', stderr: '' }; }) as never;
    expect(confirmRealtimePluginPublishedSync('5.20.2', {}, spawn)).toEqual({ ok: true });
    expect(argv).toEqual(['view', `${PKG}@5.20.2`, 'version', '--json']);
  });

  it.each([
    ['empty output (version not published)', { stdout: '' }, /npm has no .*@5\.20\.2 yet/],
    ['a different version', { stdout: '"5.20.1"' }, /npm has no/],
    ['plain text, not JSON', { stdout: '5.20.2' }, /something other than JSON/],
    ['a non-zero exit', { status: 1, stdout: '"5.20.2"' }, /npm view exited 1/],
    ['a signal (status null)', { status: null, signal: 'SIGTERM' as NodeJS.Signals, stdout: '"5.20.2"' }, /killed by SIGTERM/],
    ['a spawn error / timeout', { status: null, error: Object.assign(new Error('spawnSync npm ETIMEDOUT'), { code: 'ETIMEDOUT' }), stdout: '"5.20.2"' }, /ETIMEDOUT/],
  ])('%s is not "published"', (_label, r, why) => {
    const res = confirmRealtimePluginPublishedSync('5.20.2', {}, answer(r as Partial<R>));
    expect(res.ok).toBe(false);
    expect((res as { reason: string }).reason).toMatch(why);
  });

  it('runQuiet REJECTS a child killed by a signal (it used to resolve like exit 0)', async () => {
    await expect(__runQuietForTest(process.execPath, ['-e', 'process.kill(process.pid, "SIGTERM")'], { timeout: 20000 }))
      .rejects.toMatchObject({ exitCode: null, signal: 'SIGTERM' });
    await expect(__runQuietForTest(process.execPath, ['-e', 'process.stdout.write("ok")'], { timeout: 20000 }))
      .resolves.toEqual({ stdout: 'ok', stderr: '' });
  });
});

describe('install self-check names the actual mismatch (nit)', () => {
  it('source: the version failure line prints the version-proof reason, not a fixed "OLDER"', () => {
    const src = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'openclaw.ts'), 'utf-8');
    expect(src).not.toContain('the loaded plugin version is OLDER than expected');
    const at = src.indexOf('} else if (!check.versionProof) {');
    expect(at).toBeGreaterThan(0);
    const block = src.slice(at, at + 900);
    expect(block).toContain("check.reasons.find((r) => r.startsWith('version proof FAILED'))");
    expect(block).toContain('the plugin version is not the one this CLI expects — ${versionReason');
  });
});
