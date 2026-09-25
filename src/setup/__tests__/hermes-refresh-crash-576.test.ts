import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { hermesPluginCopyStale, hermesPluginSourceDir, refreshHermesPluginCopies } from '../hermes-refresh.js';
import { probeHermesDiscovery } from '../hermes-plugins.js';
import { journalPath, readJournal, writeJournal } from '../swap-journal.js';

/**
 * #576 round 2 — the two blockers the first review raised about the Hermes
 * refresh:
 *
 *   1. the swap could leave the host with NO installed plugin (crash between
 *      the two renames), and the next run reported "not installed" rather than
 *      recovering;
 *   4. the symlink preflight covered the CONTENTS of discovered copies but not
 *      the write path itself — a symlinked `backups/` or plugins root was
 *      followed.
 *
 * Every case is a fake home under a temp dir. The real `~/.hermes` is never
 * read or written; `HERMES_HOME` and `HERMES_ENABLE_PROJECT_PLUGINS` are
 * scrubbed per test.
 */
let home: string;
let hermes: string;
let plugins: string;
let installed: string;
let elsewhere: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedProjectPlugins = process.env.HERMES_ENABLE_PROJECT_PLUGINS;
const SOURCE = hermesPluginSourceDir();
const FROZEN = new Date('2026-09-24T12:34:56.789Z');

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-crash-'));
  elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-elsewhere-'));
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
  fs.rmSync(elsewhere, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedProjectPlugins === undefined) delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
  else process.env.HERMES_ENABLE_PROJECT_PLUGINS = savedProjectPlugins;
});

function installCopy(dest: string = installed): void {
  fs.cpSync(SOURCE, dest, {
    recursive: true,
    filter: (src) => !['tests', '__pycache__', '.pytest_cache'].includes(path.basename(src)),
  });
}

function makeStale(dir: string = installed): void {
  fs.writeFileSync(path.join(dir, '__init__.py'), '# shieldcortex 5.1.0\n');
  fs.rmSync(path.join(dir, 'shadow.py'), { force: true });
}

/**
 * How many directories under a plugins root Hermes would key `shieldcortex` —
 * the #569 count that must never exceed one, at any moment of a refresh.
 */
function shieldcortexDirsIn(root: string): string[] {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .filter((e) => {
      try {
        return /^name:\s*shieldcortex\s*$/m.test(
          fs.readFileSync(path.join(root, e.name, 'plugin.yaml'), 'utf-8'),
        );
      } catch {
        return false;
      }
    })
    .map((e) => e.name);
}

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

describeWithHermes('a crash between the two renames (r2 blocker 1)', () => {
  /**
   * Drive a real refresh to the exact state a SIGKILL after rename 1 leaves:
   * both the publish and the restore refuse, so the process "dies" with the
   * plugin directory gone.
   */
  function crashAfterFirstRename(): ReturnType<typeof refreshHermesPluginCopies> {
    const real = fs.renameSync;
    const spy = jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      if (String(to) === installed) throw Object.assign(new Error('EIO: simulated'), { code: 'EIO' });
      return real(from, to);
    });
    try {
      return refreshHermesPluginCopies(home, { now: FROZEN });
    } finally {
      spy.mockRestore();
    }
  }

  it('leaves a journal, the backup and the staged copy — and never deletes the replacement', () => {
    installCopy();
    makeStale();

    const result = crashAfterFirstRename();

    expect(result.status).toBe('warn');
    expect(fs.existsSync(installed)).toBe(false);
    // The three things recovery needs, all present.
    const journal = readJournal(hermes);
    expect('journal' in journal && journal.journal.target).toBe(installed);
    expect('journal' in journal && journal.journal.phase).toBe('publishing');
    expect(fs.existsSync(String('journal' in journal ? journal.journal.backup : ''))).toBe(true);
    expect(fs.existsSync(String('journal' in journal ? journal.journal.staged : ''))).toBe(true);
    // And the operator is told, in the step output, exactly what finishes it.
    expect(result.detail.join('\n')).toMatch(/shieldcortex update/);
    expect(result.detail.join('\n')).toContain(journalPath(hermes));
  });

  it('is recovered by the next `update`, which then completes the refresh', () => {
    installCopy();
    makeStale();
    crashAfterFirstRename();
    expect(fs.existsSync(installed)).toBe(false);

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    // The plugin is back AND current: recovery restored the previous copy, and
    // the refresh it was interrupted in the middle of then ran to completion.
    expect(fs.existsSync(path.join(installed, 'plugin.yaml'))).toBe(true);
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
    expect(result.status).toBe('refreshed');
    expect(result.detail.join('\n')).toMatch(/interrupted refresh was found/);
    // Resolved means resolved.
    expect(fs.existsSync(journalPath(hermes))).toBe(false);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-staging'))).toEqual([]);
    // Exactly one backup: the interrupted run's reservation was emptied by the
    // restore and given back, so `backups/` holds the copy this run displaced
    // and no empty directory beside it.
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toHaveLength(1);
  });

  it('never leaves two `shieldcortex` copies inside the plugins root, at any point', () => {
    installCopy();
    makeStale();
    const seen: string[][] = [];
    const real = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      seen.push(shieldcortexDirsIn(plugins));
      const out = real(from, to);
      seen.push(shieldcortexDirsIn(plugins));
      return out;
    });

    refreshHermesPluginCopies(home, { now: FROZEN });

    expect(seen.length).toBeGreaterThan(0);
    for (const state of seen) expect(state.length).toBeLessThanOrEqual(1);
    expect(shieldcortexDirsIn(plugins)).toEqual(['shieldcortex']);
  });

  it('recovers a crash after rename 2 by clearing the journal and keeping the backup', () => {
    installCopy();
    // The state a crash between "publish landed" and "journal deleted" leaves.
    const backupDir = path.join(hermes, 'backups', 'shieldcortex-preupdate-x');
    fs.mkdirSync(backupDir, { recursive: true });
    fs.mkdirSync(path.join(backupDir, 'shieldcortex'));
    fs.writeFileSync(path.join(backupDir, 'shieldcortex', '__init__.py'), '# shieldcortex 5.1.0\n');
    const stagingRoot = path.join(hermes, '.shieldcortex-staging-x');
    fs.mkdirSync(stagingRoot);
    writeJournal({
      version: 1,
      kind: 'hermes-plugin',
      root: hermes,
      target: installed,
      backup: path.join(backupDir, 'shieldcortex'),
      staged: path.join(stagingRoot, 'shieldcortex'),
      stagingRoot,
      packagedVersion: '5.2.0',
      phase: 'publishing',
      startedAt: FROZEN.toISOString(),
      pid: 1,
    });

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('current');
    expect(fs.existsSync(journalPath(hermes))).toBe(false);
    // The old copy stays in backups/ — nothing here ever deletes one.
    expect(fs.existsSync(path.join(backupDir, 'shieldcortex', '__init__.py'))).toBe(true);
    expect(fs.existsSync(stagingRoot)).toBe(false);
    expect(result.detail.join('\n')).toMatch(/interrupted refresh was found/);
  });

  it('writes nothing while an unresolvable journal is unresolved', () => {
    installCopy();
    makeStale();
    fs.writeFileSync(journalPath(hermes), '{ truncated');

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/interrupted Hermes plugin refresh could not be finished/);
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });
});

describeWithHermes('the write path is preflighted for symlinks (r2 blocker 4)', () => {
  it('refuses a symlinked `backups/` and writes nothing through it', () => {
    installCopy();
    makeStale();
    fs.symlinkSync(elsewhere, path.join(hermes, 'backups'));

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/is a symlink/);
    expect(result.summary).toContain(path.join(hermes, 'backups'));
    // Nothing followed the link, and the stale copy is exactly as stale.
    expect(fs.readdirSync(elsewhere)).toEqual([]);
    expect(fs.readFileSync(path.join(installed, '__init__.py'), 'utf-8')).toBe('# shieldcortex 5.1.0\n');
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-staging'))).toEqual([]);
    expect(fs.existsSync(journalPath(hermes))).toBe(false);
  });

  it('refuses a symlinked plugins root and writes nothing through it', () => {
    const real = path.join(hermes, 'real-plugins');
    fs.rmSync(plugins, { recursive: true, force: true });
    fs.mkdirSync(real, { recursive: true });
    fs.symlinkSync(real, plugins);
    installCopy(path.join(real, 'shieldcortex'));
    makeStale(path.join(real, 'shieldcortex'));

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/is a symlink/);
    expect(result.summary).toContain(plugins);
    expect(result.refreshed).toEqual([]);
    expect(fs.readFileSync(path.join(real, 'shieldcortex', '__init__.py'), 'utf-8'))
      .toBe('# shieldcortex 5.1.0\n');
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
    expect(fs.existsSync(journalPath(hermes))).toBe(false);
  });

  it('refuses a symlinked Hermes home itself', () => {
    installCopy();
    makeStale();
    // `HERMES_HOME` pointing at a link to the tree we just built: every write
    // path below it resolves through a component nobody declared.
    const linked = path.join(home, 'linked-hermes');
    fs.symlinkSync(hermes, linked);
    process.env.HERMES_HOME = linked;

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/is a symlink/);
    expect(result.summary).toContain(linked);
    expect(fs.readFileSync(path.join(installed, '__init__.py'), 'utf-8')).toBe('# shieldcortex 5.1.0\n');
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });
});
