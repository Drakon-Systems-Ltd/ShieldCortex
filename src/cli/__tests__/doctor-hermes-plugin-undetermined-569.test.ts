import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { checkHermesPluginShadowing, fixHermesPluginShadowing } from '../doctor.js';
import { probeHermesDiscovery } from '../../setup/hermes-plugins.js';

/**
 * #569 r6 — a directory that cannot be READ is not an empty directory.
 *
 * The root set was built with `except OSError: names = []` around
 * `os.listdir(<root>/profiles)`. A `profiles/` that can be traversed but not
 * listed (mode `--x`, or an ACL) raises PermissionError, so the profile list
 * silently became empty, every sibling profile left the protective scan, and
 * the repair moved the backup that `profiles/work/plugins/shieldcortex`
 * pointed at — leaving that profile's install dangling.
 *
 * Every case here uses the review's layout:
 *
 *     plugins/shieldcortex          real, canonical
 *     plugins/shieldcortex.bak-x    real
 *     profiles/work/plugins/shieldcortex -> <root>/plugins/shieldcortex.bak-x
 *
 * and asserts the same two things about the outcome: NOTHING moved, and the
 * work profile's canonical still resolves to its own bytes.
 *
 * The failure is driven two ways on purpose — a real `chmod 0o311`, which is
 * the host condition itself, and an injected failure, which reaches the branch
 * on a box where the real one cannot be staged (running as root, or a
 * filesystem that ignores modes).
 */
let home: string;
let hermes: string;
let plugins: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedPythonPath = process.env.PYTHONPATH;
const savedInjection = process.env.SC569_FAIL_LISTDIR;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-undet-'));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  delete process.env.HERMES_HOME;
});

afterEach(() => {
  jest.restoreAllMocks();
  // Modes are put back before the tree is taken away: a directory left at
  // `--x` cannot be cleaned up, and the failure would land on a later suite.
  restoreModes();
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedPythonPath === undefined) delete process.env.PYTHONPATH;
  else process.env.PYTHONPATH = savedPythonPath;
  if (savedInjection === undefined) delete process.env.SC569_FAIL_LISTDIR;
  else process.env.SC569_FAIL_LISTDIR = savedInjection;
});

/** Directories whose mode this test changed, and what it was. */
const chmodded: Array<{ dir: string; mode: number }> = [];

/** Make `dir` traversable but not listable — the exact condition #569 r6 is about. */
function makeUnlistable(dir: string): void {
  chmodded.push({ dir, mode: fs.statSync(dir).mode & 0o7777 });
  fs.chmodSync(dir, 0o311);
}

function restoreModes(): void {
  while (chmodded.length > 0) {
    const entry = chmodded.pop()!;
    try {
      fs.chmodSync(entry.dir, entry.mode);
    } catch {
      /* the tree is about to go anyway */
    }
  }
}

const FROZEN = new Date('2026-09-24T12:34:56.789Z');

/** Doctor prints paths tildified; a temp dir can itself live under $HOME. */
function shown(target: string): string {
  const real = os.homedir();
  return target.startsWith(real) ? target.replace(real, '~') : target;
}

function makePlugin(root: string, dirName: string): string {
  const dir = path.join(root, dirName);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'plugin.yaml'),
    `# a manifest\nname: shieldcortex\nkind: standalone\nversion: 0.1.0\n`,
  );
  return dir;
}

/** The review's layout, built under the default home. */
function buildReviewLayout(): { canonical: string; backup: string; profileLink: string } {
  const canonical = makePlugin(plugins, 'shieldcortex');
  fs.writeFileSync(path.join(canonical, 'marker'), 'installed\n');
  const backup = makePlugin(plugins, 'shieldcortex.bak-x');
  fs.writeFileSync(path.join(backup, 'marker'), 'the work profile runs this\n');

  const profilePlugins = path.join(hermes, 'profiles', 'work', 'plugins');
  fs.mkdirSync(profilePlugins, { recursive: true });
  const profileLink = path.join(profilePlugins, 'shieldcortex');
  fs.symlinkSync(backup, profileLink);
  return { canonical, backup, profileLink };
}

/** Nothing moved anywhere, and the work profile still resolves to its bytes. */
function expectRefusedAndIntact(
  fix: ReturnType<typeof fixHermesPluginShadowing>,
  layout: { canonical: string; backup: string; profileLink: string },
): void {
  expect(fix.moved).toEqual([]);
  expect(fix.changed).toBe(false);
  // Non-zero from the CLI: the operator asked for a repair and did not get one.
  expect(fix.failed).toBe(true);
  expect(fs.readFileSync(path.join(layout.backup, 'marker'), 'utf8')).toBe(
    'the work profile runs this\n',
  );
  expect(fs.readFileSync(path.join(layout.profileLink, 'marker'), 'utf8')).toBe(
    'the work profile runs this\n',
  );
  expect(fs.readFileSync(path.join(layout.canonical, 'marker'), 'utf8')).toBe('installed\n');
  expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
}

/** Whether this box can be asked at all — see the sibling suite's note. */
const HAS_HERMES = (() => {
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-probe-'));
  try {
    fs.mkdirSync(path.join(probeDir, '.hermes', 'plugins'), { recursive: true });
    return 'roots' in probeHermesDiscovery({ home: probeDir, hermesHome: null });
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();
const describeWithHermes = HAS_HERMES ? describe : describe.skip;

/** Root can read anything, so the real-mode cases cannot be staged there. */
const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;
const itUnlessRoot = IS_ROOT ? it.skip : it;

/**
 * Make ONE `os.listdir` call fail inside the probe child, without a seam in
 * production code: a `sitecustomize` module on `PYTHONPATH` that wraps
 * `os.listdir` and raises PermissionError for one path. The child inherits the
 * environment, so this reaches it and nothing else.
 */
function injectProbeListdirFailure(target: string): void {
  const hookDir = path.join(home, 'probe-hook');
  fs.mkdirSync(hookDir, { recursive: true });
  fs.writeFileSync(
    path.join(hookDir, 'sitecustomize.py'),
    [
      'import os',
      '_real = os.listdir',
      'def _listdir(path="."):',
      '    _want = os.environ.get("SC569_FAIL_LISTDIR")',
      '    if _want and os.fspath(path) == _want:',
      '        raise PermissionError(13, "injected: refusing to list")',
      '    return _real(path)',
      'os.listdir = _listdir',
      '',
    ].join('\n'),
  );
  process.env.PYTHONPATH =
    savedPythonPath === undefined ? hookDir : `${hookDir}${path.delimiter}${savedPythonPath}`;
  process.env.SC569_FAIL_LISTDIR = target;
}

describeWithHermes('an unlistable profiles/ is undetermined, not empty (#569 r6)', () => {
  itUnlessRoot('refuses the whole plan when `profiles/` cannot be listed (real chmod)', () => {
    const layout = buildReviewLayout();
    const profiles = path.join(hermes, 'profiles');
    makeUnlistable(profiles);

    // The premise: the directory really is traversable and really is not
    // listable, so the old `except OSError: []` would have read it as empty.
    expect(() => fs.readdirSync(profiles)).toThrow(/EACCES/);
    expect(fs.existsSync(layout.profileLink)).toBe(true);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expectRefusedAndIntact(fix, layout);
    // The refusal names the path that could not be read, and the error.
    expect(fix.message).toContain(shown(profiles));
    expect(fix.message).toMatch(/Permission denied|EACCES/);
    expect(fix.refused.some((r) => r.dir === profiles)).toBe(true);
  });

  itUnlessRoot('warns, names the path, and gives no verdict (real chmod)', async () => {
    buildReviewLayout();
    const profiles = path.join(hermes, 'profiles');
    makeUnlistable(profiles);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toContain(shown(profiles));
    expect(row.message).toMatch(/Permission denied|EACCES/);
    // Never a verdict: not "clean", and no winner named.
    expect(row.message).not.toMatch(/clean/);
    expect(row.message).not.toMatch(/Hermes loads/);
    expect(row.fix).toMatch(/moves nothing in any root/);
  });

  it('refuses the whole plan when `profiles/` enumeration is injected to fail', () => {
    const layout = buildReviewLayout();
    const profiles = path.join(hermes, 'profiles');
    // No chmod at all — the tree is perfectly readable and the failure is
    // injected into the probe, so this case runs as root too.
    injectProbeListdirFailure(profiles);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expectRefusedAndIntact(fix, layout);
    expect(fix.message).toContain(shown(profiles));
    expect(fix.message).toContain('injected: refusing to list');
  });

  it('carries the failure out of the probe as a structured undetermined entry', () => {
    buildReviewLayout();
    const profiles = path.join(hermes, 'profiles');
    injectProbeListdirFailure(profiles);

    const probe = probeHermesDiscovery({ home, hermesHome: null });

    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    expect(probe.undetermined).toEqual([
      { path: profiles, error: expect.stringContaining('PermissionError') },
    ]);
  });

  itUnlessRoot('never reports clean for a `plugins/` root it could not list', async () => {
    // The worst shape of the same bug: Hermes' own `scan_directory` logs a
    // warning and returns what it read, so an unlistable root came back with no
    // copies at all — and no copies reads as "nothing can shadow".
    const layout = buildReviewLayout();
    makeUnlistable(plugins);

    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
    expect(row.message).not.toMatch(/clean/);
    expect(row.message).toContain(shown(plugins));

    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.message).not.toMatch(/nothing to move/);
    expect(fix.message).toContain(shown(plugins));
    expect(fs.existsSync(path.join(layout.backup, 'plugin.yaml'))).toBe(true);
  });

  itUnlessRoot('never reports clean for a copy directory it could not enter', async () => {
    // Mode `rw-` on a plugin directory: Hermes skips it as unreadable, so the
    // copy inside is invisible to discovery and to us. Neither of us can say
    // whether it declares our name.
    const layout = buildReviewLayout();
    chmodded.push({ dir: layout.backup, mode: fs.statSync(layout.backup).mode & 0o7777 });
    fs.chmodSync(layout.backup, 0o600);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).not.toMatch(/clean/);
    expect(row.message).toContain(shown(layout.backup));
  });

  it('still repairs an ordinary host, so the refusal is not blanket', () => {
    // The control: same layout minus the entanglement and minus any unreadable
    // path. A change that refuses everything would pass every case above.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    makePlugin(path.join(hermes, 'profiles', 'work', 'plugins'), 'shieldcortex');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect(fix.failed).toBe(false);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
  });
});

describeWithHermes('an unreadable path inside a copy refuses too (#569 r6)', () => {
  /** Canonical + backup, with a subdirectory inside the backup. */
  function buildWalkLayout(): { canonical: string; backup: string; inner: string } {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const inner = path.join(backup, 'inner');
    fs.mkdirSync(inner, { recursive: true });
    fs.writeFileSync(path.join(inner, 'keep'), 'x\n');
    return { canonical, backup, inner };
  }

  itUnlessRoot('refuses when the symlink walk of a backup copy hits EACCES (real chmod)', () => {
    const layout = buildWalkLayout();
    makeUnlistable(layout.inner);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fix.failed).toBe(true);
    const reasons = fix.refused.map((r) => r.reason).join(' ');
    expect(reasons).toMatch(/nothing was moved/);
    // The path that could not be read is named — not just "could not be checked".
    expect(reasons).toContain(shown(layout.inner));
    expect(reasons).toMatch(/EACCES/);
    expect(fs.existsSync(path.join(layout.backup, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('refuses when the walk is injected to fail on one directory', () => {
    const layout = buildWalkLayout();
    const real = fs.readdirSync;
    jest.spyOn(fs, 'readdirSync').mockImplementation(((target: fs.PathLike, options?: unknown) => {
      if (String(target) === layout.inner) {
        const err = new Error(`EACCES: permission denied, scandir '${layout.inner}'`);
        (err as NodeJS.ErrnoException).code = 'EACCES';
        throw err;
      }
      return (real as (...args: unknown[]) => unknown)(target, options);
    }) as typeof fs.readdirSync);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    const reasons = fix.refused.map((r) => r.reason).join(' ');
    expect(reasons).toContain(shown(layout.inner));
    expect(reasons).toMatch(/EACCES/);
  });

  it('refuses when a dependent install cannot be resolved', () => {
    // The plan preflight: `profiles/work/plugins/shieldcortex` is what another
    // root loads from, and a realpath that fails is the LEAST safe one to
    // treat as absent.
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const profileCanonical = makePlugin(
      path.join(hermes, 'profiles', 'work', 'plugins'),
      'shieldcortex',
    );
    const real = fs.realpathSync;
    jest.spyOn(fs, 'realpathSync').mockImplementation(((target: fs.PathLike, options?: unknown) => {
      if (String(target) === profileCanonical) {
        const err = new Error(`EACCES: permission denied, realpath '${profileCanonical}'`);
        (err as NodeJS.ErrnoException).code = 'EACCES';
        throw err;
      }
      return (real as (...args: unknown[]) => unknown)(target, options);
    }) as typeof fs.realpathSync);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused.map((r) => r.reason).join(' ')).toContain(shown(profileCanonical));
    expect(fs.existsSync(path.join(backup, 'plugin.yaml'))).toBe(true);
  });

  it('refuses the whole plan when the destination is not a directory', () => {
    // The destination check, before the first move rather than after it.
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    fs.writeFileSync(path.join(hermes, 'backups'), 'not a directory\n');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused.map((r) => r.reason).join(' ')).toMatch(/is not a directory/);
    expect(fs.existsSync(path.join(backup, 'plugin.yaml'))).toBe(true);
    expect(fs.readFileSync(path.join(hermes, 'backups'), 'utf8')).toBe('not a directory\n');
  });
});

describe('a home that cannot be statted is not an absent home (#569 r6)', () => {
  it('warns instead of reporting "Hermes not detected"', async () => {
    fs.mkdirSync(plugins, { recursive: true });
    const real = fs.statSync;
    jest.spyOn(fs, 'statSync').mockImplementation(((target: fs.PathLike, options?: unknown) => {
      if (String(target) === hermes) {
        const err = new Error(`EACCES: permission denied, stat '${hermes}'`);
        (err as NodeJS.ErrnoException).code = 'EACCES';
        throw err;
      }
      return (real as (...args: unknown[]) => unknown)(target, options);
    }) as typeof fs.statSync);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).not.toMatch(/not detected/);
    expect(row.message).toContain(shown(hermes));
    expect(row.message).toMatch(/EACCES/);
  });
});

describe('a probe that does not say what it could not read is not trusted (#569 r6)', () => {
  it('rejects an answer with no `undetermined` field at all', () => {
    // A stale interpreter, a half-applied upgrade, a probe replaced by
    // something else: silence on this question is not a clean bill of health.
    const fake = path.join(home, 'fake-python');
    fs.writeFileSync(
      fake,
      ['#!/bin/sh', 'echo \'{"ok": true, "activeHome": "/h", "root": "/h", "roots": []}\'', ''].join(
        '\n',
      ),
    );
    fs.chmodSync(fake, 0o755);
    fs.mkdirSync(plugins, { recursive: true });

    const probe = probeHermesDiscovery({ home, hermesHome: null }, { interpreter: fake });

    expect('error' in probe).toBe(true);
    if (!('error' in probe)) return;
    expect(probe.error).toMatch(/did not say which paths it could not read/);
  });

  it('accepts an answer that says it read everything', () => {
    const fake = path.join(home, 'fake-python');
    fs.writeFileSync(
      fake,
      [
        '#!/bin/sh',
        'echo \'{"ok": true, "activeHome": "/h", "root": "/h", "roots": [], "undetermined": [],' +
          ' "project": {"envSet": false, "enabled": false, "dir": null, "copies": [],' +
          ' "discovered": []}}\'',
        '',
      ].join('\n'),
    );
    fs.chmodSync(fake, 0o755);
    fs.mkdirSync(plugins, { recursive: true });

    const probe = probeHermesDiscovery({ home, hermesHome: null }, { interpreter: fake });

    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    expect(probe.undetermined).toEqual([]);
  });
});
