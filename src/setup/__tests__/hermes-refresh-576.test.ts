import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  hermesPluginCopyStale,
  hermesPluginSourceDir,
  refreshHermesPluginCopies,
} from '../hermes-refresh.js';
import { probeHermesDiscovery } from '../hermes-plugins.js';

/**
 * #576 — `shieldcortex update` upgraded the npm package and left
 * `~/.hermes/plugins/shieldcortex` on the previous release, so the gateway kept
 * running the old `pre_tool_call` gate. Observed 5.1.0 → 5.2.0: `__init__.py`
 * differed and `shadow.py` was not installed at all.
 *
 * Every case builds a fake home under a temp dir. The real `~/.hermes` is never
 * read and never written — `HERMES_HOME` and `HERMES_ENABLE_PROJECT_PLUGINS`
 * are scrubbed per test so a developer box that has either set cannot redirect
 * a refresh onto a live host.
 */
let home: string;
let hermes: string;
let plugins: string;
let installed: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedProjectPlugins = process.env.HERMES_ENABLE_PROJECT_PLUGINS;
const SOURCE = hermesPluginSourceDir();

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-refresh-'));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  installed = path.join(plugins, 'shieldcortex');
  fs.mkdirSync(plugins, { recursive: true });
  delete process.env.HERMES_HOME;
  delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedProjectPlugins === undefined) delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
  else process.env.HERMES_ENABLE_PROJECT_PLUGINS = savedProjectPlugins;
});

const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const STAMP = FROZEN.toISOString().replace(/[:.]/g, '-');

/** What `hermes install` puts on disk: the packaged tree minus `tests/`. */
function installCopy(dest: string = installed): void {
  fs.cpSync(SOURCE, dest, {
    recursive: true,
    filter: (src) => !['tests', '__pycache__', '.pytest_cache'].includes(path.basename(src)),
  });
}

/** The exact drift #576 reported: one file behind, one file absent. */
function makeStale(dir: string = installed): void {
  fs.writeFileSync(path.join(dir, '__init__.py'), '# shieldcortex 5.1.0\n');
  fs.rmSync(path.join(dir, 'shadow.py'), { force: true });
}

/** A second directory Hermes keys `shieldcortex`, sorting after the install. */
function makeShadow(name = 'shieldcortex.bak-x'): string {
  const dir = path.join(plugins, name);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'plugin.yaml'), 'name: shieldcortex\nkind: standalone\n');
  return dir;
}

/** Whether this box has a Hermes to ask. Resolved once, by asking. */
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

/** The one reserved backup directory under `<hermesHome>/backups`, if any. */
function backupDirs(): string[] {
  const root = path.join(hermes, 'backups');
  return fs.existsSync(root) ? fs.readdirSync(root).sort() : [];
}

describe('hermesPluginCopyStale — the comparator update and doctor share (#576)', () => {
  it('calls a byte-identical install current', () => {
    installCopy();
    const verdict = hermesPluginCopyStale(installed);
    expect(verdict).toMatchObject({ stale: false, comparable: true, differing: 0 });
  });

  it('is NOT stale over the packaged `tests/` the installer never copies', () => {
    installCopy();
    // The #576 report's own post-install state: "only tests/ differs".
    expect(fs.existsSync(path.join(SOURCE, 'tests'))).toBe(true);
    expect(fs.existsSync(path.join(installed, 'tests'))).toBe(false);
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
  });

  it('ignores __pycache__ the gateway leaves behind', () => {
    installCopy();
    fs.mkdirSync(path.join(installed, '__pycache__'));
    fs.writeFileSync(path.join(installed, '__pycache__', 'shadow.cpython-312.pyc'), 'x');
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
  });

  it('names the missing file — the `shadow.py` half of #576', () => {
    installCopy();
    fs.rmSync(path.join(installed, 'shadow.py'));
    const verdict = hermesPluginCopyStale(installed);
    expect(verdict.stale).toBe(true);
    expect(verdict.reason).toMatch(/shadow\.py is missing/);
  });

  it('catches a file that merely differs — the `__init__.py` half of #576', () => {
    installCopy();
    fs.writeFileSync(path.join(installed, '__init__.py'), '# shieldcortex 5.1.0\n');
    const verdict = hermesPluginCopyStale(installed);
    expect(verdict.stale).toBe(true);
    expect(verdict.differing).toBe(1);
    expect(verdict.reason).toMatch(/__init__\.py differs/);
  });

  it('claims nothing against a packaged source it cannot read', () => {
    installCopy();
    makeStale();
    const verdict = hermesPluginCopyStale(installed, path.join(home, 'no-such-package'));
    expect(verdict).toMatchObject({ stale: false, comparable: false });
  });
});

describeWithHermes('refreshHermesPluginCopies — what it writes (#576)', () => {
  it('refreshes the copy Hermes loads and keeps the old one in backups/', () => {
    installCopy();
    makeStale();

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('refreshed');
    expect(result.refreshed).toHaveLength(1);
    expect(result.refreshed[0].dir).toBe(installed);
    // The gate is current…
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
    expect(fs.readFileSync(path.join(installed, 'shadow.py'))).toEqual(
      fs.readFileSync(path.join(SOURCE, 'shadow.py')),
    );
    // …and the previous copy was MOVED, not deleted.
    expect(backupDirs()).toEqual([`shieldcortex-preupdate-${STAMP}`]);
    const kept = path.join(hermes, 'backups', `shieldcortex-preupdate-${STAMP}`, 'shieldcortex');
    expect(fs.readFileSync(path.join(kept, '__init__.py'), 'utf-8')).toBe('# shieldcortex 5.1.0\n');
    expect(result.summary).toMatch(/restart the Hermes gateway/);
  });

  it('never leaves a second `shieldcortex` copy inside a plugins root', () => {
    installCopy();
    makeStale();
    // The staging directory is the #569 hazard in miniature: a directory under
    // `plugins/` holding a `plugin.yaml` named `shieldcortex` IS a shadowing
    // copy while it exists. Prove where the new bytes were staged by watching
    // the rename that swapped them in.
    const real = fs.renameSync;
    const renames: Array<{ from: string; to: string }> = [];
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      renames.push({ from: String(from), to: String(to) });
      return real(from, to);
    });

    refreshHermesPluginCopies(home, { now: FROZEN });

    const swap = renames.find((r) => r.to === installed);
    expect(swap).toBeDefined();
    expect(swap!.from.startsWith(`${plugins}${path.sep}`)).toBe(false);
    expect(swap!.from.startsWith(`${hermes}${path.sep}`)).toBe(true);
    // And nothing of ours is left beside the install afterwards.
    expect(fs.readdirSync(plugins)).toEqual(['shieldcortex']);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-staging'))).toEqual([]);
  });

  it('leaves a current copy alone and creates no backups', () => {
    installCopy();
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('current');
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('never creates an install that was not there', () => {
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('not-installed');
    expect(fs.readdirSync(plugins)).toEqual([]);
  });

  it('writes nothing when a shadowing copy is in play, and says where to go', () => {
    installCopy();
    makeStale();
    const shadow = makeShadow();

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/--fix-hermes-plugin-copies/);
    expect(result.refreshed).toEqual([]);
    // The stale copy is still exactly as stale, and the shadow is untouched.
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
    expect(fs.existsSync(path.join(shadow, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
    // Nothing was written, so nothing is waiting for a restart: telling an
    // operator to bounce the gateway here is advice with no work behind it.
    expect([result.summary, ...result.detail].join('\n')).not.toMatch(/restart the Hermes gateway/);
  });

  it('writes nothing when a project plugin copy outranks the install', () => {
    installCopy();
    makeStale();
    const project = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-proj-'));
    const projectCopy = path.join(project, '.hermes', 'plugins', 'shieldcortex');
    fs.mkdirSync(projectCopy, { recursive: true });
    fs.writeFileSync(path.join(projectCopy, 'plugin.yaml'), 'name: shieldcortex\nkind: standalone\n');
    const savedCwd = process.cwd();
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(project);

    let result: ReturnType<typeof refreshHermesPluginCopies>;
    try {
      result = refreshHermesPluginCopies(home, { now: FROZEN });
    } finally {
      process.chdir(savedCwd);
      fs.rmSync(project, { recursive: true, force: true });
    }

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/project plugin copy/);
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('writes nothing when a discovered copy holds a symlink', () => {
    installCopy();
    makeStale();
    fs.symlinkSync(path.join(SOURCE, 'shadow.py'), path.join(installed, 'shadow-link.py'));

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/is a symlink/);
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('restores the previous copy when the swap fails part-way', () => {
    installCopy();
    makeStale();
    const real = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      // Let the backup move happen, and let the RESTORE happen; refuse only the
      // rename that installs the staged copy.
      if (String(to) === installed && String(from).includes('.shieldcortex-staging')) {
        throw Object.assign(new Error('EIO: simulated'), { code: 'EIO' });
      }
      return real(from, to);
    });

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(result.detail.join('\n')).toMatch(/previous copy was restored/);
    // Restored means restored: the operator's plugin directory is back, with
    // its old contents, and nothing is stranded in backups/.
    expect(fs.readFileSync(path.join(installed, '__init__.py'), 'utf-8')).toBe('# shieldcortex 5.1.0\n');
    expect(backupDirs()).toEqual([]);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-staging'))).toEqual([]);
  });

  it('says so loudly when even the restore fails, and names where the copy is', () => {
    installCopy();
    makeStale();
    const real = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      // Both directions of the swap refused: the worst case, and the one an
      // operator must not have to discover from an empty `plugins/` directory.
      if (String(to) === installed) throw Object.assign(new Error('EIO: simulated'), { code: 'EIO' });
      return real(from, to);
    });

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    const said = result.detail.join('\n');
    expect(said).toMatch(/could not be restored/);
    // The message names the exact path the copy is at, because that is the
    // whole remedy.
    const kept = path.join(hermes, 'backups', `shieldcortex-preupdate-${STAMP}`, 'shieldcortex');
    expect(said).toContain(kept);
    expect(fs.existsSync(path.join(kept, '__init__.py'))).toBe(true);
  });
});

describe('refreshHermesPluginCopies — when Hermes cannot be asked (#569 r4)', () => {
  const NO_HERMES = { interpreter: null } as const;

  it('warns and writes nothing when a copy is installed but discovery is unavailable', () => {
    installCopy();
    makeStale();

    const result = refreshHermesPluginCopies(home, { now: FROZEN, scan: NO_HERMES });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/could not determine which copy Hermes loads/);
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('is a quiet skip, not a warning, when there is no copy to refresh either', () => {
    const result = refreshHermesPluginCopies(home, { now: FROZEN, scan: NO_HERMES });
    expect(result.status).toBe('not-installed');
  });

  it('says nothing at all about a host with no Hermes home', () => {
    const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-bare-'));
    try {
      const result = refreshHermesPluginCopies(bare, { now: FROZEN, scan: NO_HERMES });
      expect(result.status).toBe('not-installed');
      expect(result.summary).toMatch(/Hermes not detected/);
    } finally {
      fs.rmSync(bare, { recursive: true, force: true });
    }
  });

  it('treats a home it could not stat as undetermined, not absent', () => {
    jest.spyOn(fs, 'statSync').mockImplementation((target) => {
      if (String(target) === hermes) throw Object.assign(new Error('EACCES'), { code: 'EACCES' });
      return jest.requireActual<typeof fs>('fs').statSync(target as string);
    });

    const result = refreshHermesPluginCopies(home, { now: FROZEN, scan: NO_HERMES });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/could not scan every plugin root/);
  });
});
