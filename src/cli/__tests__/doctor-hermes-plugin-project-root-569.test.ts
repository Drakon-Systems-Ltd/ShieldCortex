import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { checkHermesPluginShadowing, fixHermesPluginShadowing } from '../doctor.js';
import { probeHermesDiscovery } from '../../setup/hermes-plugins.js';

/**
 * #569 round 9 — the project source and the plugins ROOTS can be the same
 * directory, and which one of them it is decides the verdict.
 *
 * Hermes' USER source is `get_hermes_home()/plugins` and nothing else. The
 * other roots this scan covers — `<root>/plugins` and every sibling profile's
 * `plugins/` — are roots a gateway *would* load from if it ran under that
 * profile; they are not sources of the gateway running now. So:
 *
 *  - `cwd=$HOME` with `HERMES_HOME=$HOME/.hermes` makes `<cwd>/.hermes/plugins`
 *    and the ACTIVE plugins root the same directory. Hermes scans it twice
 *    under two labels, the winner is the same either way, and reading it as a
 *    project override turns the operator's own plugins root into a directory
 *    this repair may not touch.
 *
 *  - `cwd=$HOME` with `HERMES_HOME=$HOME/.hermes/profiles/work` makes that same
 *    `$HOME/.hermes/plugins` a source Hermes reads as `project` ALONE — the
 *    user source is the work profile — so the default install wins the key over
 *    the profile's install. Suppressing it as "a root we already cover" is how
 *    the sibling Ekho change reported PASS on a host loading the other tree
 *    (ekho#85 r9 blocker C).
 *
 * Every case builds a fake home in a temp dir and runs the real probe; the real
 * `~/.hermes` is never read and never written.
 */
let home: string;
let hermes: string;
let plugins: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedProjectPlugins = process.env.HERMES_ENABLE_PROJECT_PLUGINS;
const savedCwd = process.cwd();

beforeEach(() => {
  home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-r9-')));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  delete process.env.HERMES_HOME;
  delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
});

afterEach(() => {
  jest.restoreAllMocks();
  process.chdir(savedCwd);
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedProjectPlugins === undefined) delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
  else process.env.HERMES_ENABLE_PROJECT_PLUGINS = savedProjectPlugins;
});

const FROZEN = new Date('2026-09-24T12:34:56.789Z');

/** Doctor prints paths tildified, and a CI temp dir can live under $HOME. */
function shown(target: string): string {
  const real = os.homedir();
  return target.startsWith(real) ? target.replace(real, '~') : target;
}

/** A plugin directory declaring `name: <manifestName>`. */
function makePlugin(root: string, dirName: string, manifestName = 'shieldcortex'): string {
  const dir = path.join(root, dirName);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'plugin.yaml'),
    `name: ${manifestName}\nkind: standalone\nversion: 0.1.0\n`,
  );
  return dir;
}

/** Whether this box has a Hermes to ask. Without one there is no verdict at all. */
const HAS_HERMES = (() => {
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-r9-probe-'));
  try {
    fs.mkdirSync(path.join(probeDir, '.hermes', 'plugins'), { recursive: true });
    return 'roots' in probeHermesDiscovery({ home: probeDir, hermesHome: null });
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();
const describeWithHermes = HAS_HERMES ? describe : describe.skip;

// ── The review's layout: a project dir that is an INACTIVE root ───────────

describeWithHermes('a project dir matching an INACTIVE root still takes precedence (#569 r9)', () => {
  /**
   * `cwd=$HOME`, `HERMES_HOME=$HOME/.hermes/profiles/work`, project plugins on,
   * an ordinary readable install in each of the two trees. Hermes reads the
   * work profile as `user` and `$HOME/.hermes/plugins` as `project`, so the
   * DEFAULT install is what loads — in the profile's gateway, not the default
   * root's.
   */
  function reviewLayout(): { defaultInstall: string; workInstall: string; workPlugins: string } {
    const defaultInstall = makePlugin(plugins, 'shieldcortex');
    const workPlugins = path.join(hermes, 'profiles', 'work', 'plugins');
    const workInstall = makePlugin(workPlugins, 'shieldcortex');
    process.env.HERMES_HOME = path.join(hermes, 'profiles', 'work');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(home);
    return { defaultInstall, workInstall, workPlugins };
  }

  it('warns and names the default install as the copy that loads, never PASS', async () => {
    const { defaultInstall, workInstall } = reviewLayout();

    const row = await checkHermesPluginShadowing(home);

    // Both installs are ordinary and each root holds exactly one canonical
    // copy, so every per-root question answers "clean" — and the host is not.
    expect(row.status).toBe('warn');
    expect(row.status).not.toBe('pass');
    expect(row.message).toContain('project plugin directory');
    expect(row.message).toContain(shown(plugins));
    // The effective winner is named, and it is the DEFAULT install.
    expect(row.message).toMatch(
      new RegExp(
        `${shown(defaultInstall).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} is what a\\s+gateway`,
      ),
    );
    // …and the profile's own install is never claimed to be what runs.
    expect(row.message).not.toMatch(
      new RegExp(`Hermes loads ${shown(workInstall).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
    );
    // The overlap is named rather than left to read as a contradiction: the
    // same directory appears both as a scanned root and as the project source.
    expect(row.message).toMatch(/itself one of the plugin roots above, but it is NOT the active/);
    expect(row.message).toContain(shown(path.dirname(workInstall)));
    expect(row.fix).toMatch(/never move anything from or into that directory/);
  });

  it('refuses the repair and moves nothing in either tree', () => {
    const { defaultInstall, workInstall } = reviewLayout();

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fix.refused.map((r) => r.dir)).toContain(defaultInstall);
    expect(fs.existsSync(path.join(defaultInstall, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(workInstall, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });
});

// ── The equality that IS a second scan of one root ────────────────────────

describeWithHermes('a project dir that IS the ACTIVE plugins root is that root (#569 r9)', () => {
  it('passes on a clean install with the doctor run from $HOME', async () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(home);

    const row = await checkHermesPluginShadowing(home);

    // Hermes scans `<cwd>/.hermes/plugins` a second time under the `project`
    // label: same directory, same manifest, same winner. Reporting the
    // operator's own plugins root as a project override would be a permanent
    // WARN on an ordinary host.
    expect(row.status).toBe('pass');
    expect(row.message).toContain('one canonical');
    expect(row.message).toContain(shown(canonical));
    // Said out loud rather than passed over in silence — the operator can see
    // the variable in their own environment — but as the one directory it is.
    expect(row.message).toMatch(/IS the active\s+plugins root/);
    expect(row.message).not.toMatch(/holds \d+ `shieldcortex` cop/);
    expect(row.message).not.toMatch(/is what a gateway started in that working directory loads/);
  });

  it('still repairs a backup in that root rather than refusing it', () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(home);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved.map((m) => m.from)).toEqual([backup]);
    expect(fix.failed).toBe(false);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(backup)).toBe(false);
  });

  it('is undetermined when the project dir cannot be resolved at all', async () => {
    makePlugin(plugins, 'shieldcortex');
    const project = path.join(home, 'proj');
    fs.mkdirSync(project, { recursive: true });
    // A self-referential link: every attempt to resolve `<cwd>/.hermes` is
    // ELOOP. "Is this the active root or a source that beats every root" has
    // no answer here, and neither answer may be guessed.
    fs.symlinkSync('.hermes', path.join(project, '.hermes'));
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(project);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/could not scan every plugin root/);
    expect(row.message).toMatch(/ELOOP|Too many levels of symbolic links/);
    expect(row.message).not.toMatch(/clean \(/);

    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
  });
});

// ── Labelling: only the effective winner is "loaded" ──────────────────────

describeWithHermes('per-root winners are not loading claims under an override (#569 r9)', () => {
  it('labels the user-root winner root-local when a project copy outranks it', async () => {
    makePlugin(plugins, 'shieldcortex');
    const rootBackup = makePlugin(plugins, 'shieldcortex.bak-x');
    const project = path.join(home, 'work');
    const projectCopy = makePlugin(path.join(project, '.hermes', 'plugins'), 'shieldcortex');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(project);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    // The root's own winner is still named — it is a real duplicate to clear
    // up — but it is not what runs, so it is not described as loaded.
    expect(row.message).toContain(shown(rootBackup));
    expect(row.message).toMatch(/root-local winner/);
    expect(row.message).not.toMatch(/Hermes loads/);
    expect(row.message).not.toMatch(/the installed copy is the one loaded/);
    // Exactly one loading claim, and it is the project copy.
    expect(row.message).toContain(`${shown(projectCopy)} is what a`);
  });

  it('keeps the plain loading claim when there is no project override', async () => {
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toMatch(
      new RegExp(`Hermes loads ${shown(backup).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`),
    );
    expect(row.message).not.toMatch(/root-local winner/);
  });
});
