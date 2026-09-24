import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { checkHermesPluginShadowing, fixHermesPluginShadowing } from '../doctor.js';
import { probeHermesDiscovery } from '../../setup/hermes-plugins.js';

/**
 * #569 round 7 — the two things the scan was not looking at.
 *
 *  1. THE COLLISION SET IS NOT THE PROTECTION SET. Only an exact `shieldcortex`
 *     key can collide with the installed plugin, so filtering discovery down to
 *     that key is right for deciding a winner — and wrong for deciding what a
 *     repair may move. `scan_directory` keys a manifest one level down as
 *     `<category>/<name>`, so
 *     `profiles/work/plugins/security/shieldcortex -> plugins/shieldcortex.bak-x`
 *     is a real, enabled installation that never entered the copy list, never
 *     entered the symlink walk, and never entered the dependent-path
 *     preflight. The repair moved the backup and left it dangling.
 *
 *  2. THE USER ROOTS ARE NOT THE WHOLE OF DISCOVERY.
 *     `collect_directory_manifests` scans `Path.cwd()/.hermes/plugins` as
 *     source `project` AFTER the user source when
 *     `HERMES_ENABLE_PROJECT_PLUGINS` is enabled, and `resolve_manifest_winners`
 *     lets the later source win. A canonical home install with an older copy in
 *     a project directory is a host running the old code, and the per-root
 *     winner called it clean.
 *
 * Every case builds a fake home in a temp dir; the real `~/.hermes` is never
 * read and never written.
 */
let home: string;
let hermes: string;
let plugins: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedProjectPlugins = process.env.HERMES_ENABLE_PROJECT_PLUGINS;
const savedCwd = process.cwd();

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-r7-'));
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
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-r7-probe-'));
  try {
    fs.mkdirSync(path.join(probeDir, '.hermes', 'plugins'), { recursive: true });
    return 'roots' in probeHermesDiscovery({ home: probeDir, hermesHome: null });
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();
const describeWithHermes = HAS_HERMES ? describe : describe.skip;

// ── Blocker 1: every discovered plugin path is protected ──────────────────

describeWithHermes('the repair protects plugin paths under every key (#569 r7)', () => {
  it('refuses when a CATEGORY install in a profile links to the backup', () => {
    // The reviewer's exact layout. Hermes discovers the profile's copy under
    // the key `security/shieldcortex`, which can never collide with ours — so
    // the probe dropped it, and with it went the only record that the backup
    // has a dependent. The main root then looks entirely ordinary.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    fs.writeFileSync(path.join(backup, 'marker'), 'the profile runs this\n');

    const category = path.join(hermes, 'profiles', 'work', 'plugins', 'security');
    fs.mkdirSync(category, { recursive: true });
    const categoryLink = path.join(category, 'shieldcortex');
    fs.symlinkSync(backup, categoryLink);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fix.failed).toBe(true);
    // The refusal names the dependent path, not just "something depends on it".
    const reasons = fix.refused.map((r) => r.reason).join(' ');
    expect(reasons).toMatch(/nothing was moved/);
    expect(reasons).toContain(shown(categoryLink));
    // Everything still resolves to its own bytes.
    expect(fs.readFileSync(path.join(categoryLink, 'marker'), 'utf8')).toBe(
      'the profile runs this\n',
    );
    expect(fs.existsSync(path.join(backup, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('refuses when a differently-KEYED flat plugin links into the backup', () => {
    // The same defect without a category: the profile's own plugin is not ours
    // at all (`name: other-plugin`), so it was never in the copy list either —
    // and its `lib` resolves into the directory this plan would move.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const vendored = path.join(backup, 'lib');
    fs.mkdirSync(vendored, { recursive: true });
    fs.writeFileSync(path.join(vendored, 'marker'), 'shared by the profile\n');

    const profilePlugins = path.join(hermes, 'profiles', 'work', 'plugins');
    const other = makePlugin(profilePlugins, 'other', 'other-plugin');
    const otherLink = path.join(other, 'lib');
    fs.symlinkSync(vendored, otherLink);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    const reasons = fix.refused.map((r) => r.reason).join(' ');
    expect(reasons).toMatch(/nothing was moved/);
    expect(reasons).toContain(shown(otherLink));
    expect(fs.readFileSync(path.join(otherLink, 'marker'), 'utf8')).toBe('shared by the profile\n');
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('refuses the flat `other -> …/shieldcortex.bak-x` link the review named', () => {
    // The link resolves onto the backup itself, so the profile's own copy IS
    // the backup. Whatever rule stops it, the outcome is the contract: nothing
    // moves, and the profile's plugin path still resolves to real bytes.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    fs.writeFileSync(path.join(backup, 'marker'), 'the profile runs this\n');

    const profilePlugins = path.join(hermes, 'profiles', 'work', 'plugins');
    fs.mkdirSync(profilePlugins, { recursive: true });
    const flatLink = path.join(profilePlugins, 'other');
    fs.symlinkSync(backup, flatLink);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fs.readFileSync(path.join(flatLink, 'marker'), 'utf8')).toBe('the profile runs this\n');
    expect(fs.existsSync(path.join(backup, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('still repairs an ordinary host whose other plugins hold no links', () => {
    // The protection must not freeze every host that has a second plugin.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    makePlugin(plugins, 'ekho', 'ekho');
    const category = path.join(hermes, 'profiles', 'work', 'plugins', 'security');
    makePlugin(category, 'shieldcortex');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.failed).toBe(false);
    expect(fix.refused).toEqual([]);
    expect(fix.moved.map((m) => m.from)).toEqual([backup]);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(category, 'shieldcortex', 'plugin.yaml'))).toBe(true);
  });
});

// ── Blocker 2: project plugins win, so they are looked at ─────────────────

/** A project tree at `<home>/<name>`, returned as its own working directory. */
function makeProjectDir(name = 'proj'): string {
  const dir = path.join(home, name);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

describeWithHermes('project plugins are part of the effective winner (#569 r7)', () => {
  it('warns and names the project copy that outranks the install', async () => {
    makePlugin(plugins, 'shieldcortex');
    const project = makeProjectDir();
    const projectCopy = makePlugin(path.join(project, '.hermes', 'plugins'), 'shieldcortex.bak-x');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(project);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toContain(shown(projectCopy));
    expect(row.message).toContain('HERMES_ENABLE_PROJECT_PLUGINS');
    expect(row.message).toContain('project plugin directory');
    expect(row.fix).toMatch(/never move anything from or into that directory/);
    // The caveat an operator needs: this reading is the DOCTOR's environment.
    expect(row.message).toMatch(/GATEWAY/);
  });

  it('refuses the fix, and moves nothing in the user roots either', () => {
    // The user root has an ordinary repairable backup. Moving it would not
    // change which copy runs while the project copy outranks them both, so a
    // "moved 1 copy" report there would be a repair report on a host that is
    // still loading the wrong plugin.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const userBackup = makePlugin(plugins, 'shieldcortex.bak-user');
    const project = makeProjectDir();
    const projectCopy = makePlugin(path.join(project, '.hermes', 'plugins'), 'shieldcortex.bak-x');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(project);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    // Moves that were ready to go did not happen, so the CLI exits non-zero.
    expect(fix.failed).toBe(true);
    expect(fix.refused.map((r) => r.dir)).toContain(projectCopy);
    expect(fix.refused.map((r) => r.dir)).toContain(userBackup);
    const reasons = fix.refused.map((r) => r.reason).join(' ');
    expect(reasons).toMatch(/nothing was moved/);
    expect(reasons).toContain(shown(path.join(project, '.hermes', 'plugins')));
    // Nothing was touched in either tree.
    expect(fs.existsSync(path.join(projectCopy, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(userBackup, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
    expect(fs.existsSync(path.join(project, '.hermes', 'backups'))).toBe(false);
  });

  it('passes when project plugins are enabled and the project directory is absent', async () => {
    makePlugin(plugins, 'shieldcortex');
    const project = makeProjectDir('empty-project');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    process.chdir(project);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('pass');
    expect(row.message).toContain('one canonical');
    // Still said out loud: the directory scanned here is the doctor's.
    expect(row.message).toContain('HERMES_ENABLE_PROJECT_PLUGINS');
  });

  it('passes — with the note — when the switch is off and a project copy is there', async () => {
    makePlugin(plugins, 'shieldcortex');
    const project = makeProjectDir();
    makePlugin(path.join(project, '.hermes', 'plugins'), 'shieldcortex.bak-x');
    process.chdir(project);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('pass');
    expect(row.message).toMatch(/Project plugins are off here/);
    expect(row.message).toContain('HERMES_ENABLE_PROJECT_PLUGINS');
    // And the copy is not reported as a shadow, because today it is not one.
    expect(row.message).not.toContain(shown(path.join(project, '.hermes', 'plugins')));

    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.failed).toBe(false);
    expect(fix.message).toMatch(/nothing to move/);
  });

  it('says so when the variable is set to a value Hermes does not read as enabled', async () => {
    makePlugin(plugins, 'shieldcortex');
    const project = makeProjectDir();
    makePlugin(path.join(project, '.hermes', 'plugins'), 'shieldcortex.bak-x');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '0';
    process.chdir(project);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('pass');
    expect(row.message).toMatch(/does not read its value as enabled/);
  });
});

/**
 * Whether the switch is on is Hermes' question, asked of Hermes' own helper.
 * When that helper cannot be reached the answer is not "off" — it is unknown,
 * and unknown with the variable set is a host that may be loading a copy this
 * scan never looked at.
 */
describeWithHermes('an unreachable `_env_enabled` is undetermined (#569 r7)', () => {
  const savedPythonPath = process.env.PYTHONPATH;
  let blocker: string;

  beforeEach(() => {
    blocker = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-r7-noenv-'));
    fs.writeFileSync(
      path.join(blocker, 'sitecustomize.py'),
      'import sys\n' +
      'class _Block:\n' +
      '    def find_spec(self, name, path=None, target=None):\n' +
      '        if name == "hermes_cli.plugins":\n' +
      '            raise ModuleNotFoundError("No module named %r (hidden for the r7 test)" % name)\n' +
      '        return None\n' +
      'sys.meta_path.insert(0, _Block())\n',
    );
    process.env.PYTHONPATH = blocker;
  });

  afterEach(() => {
    if (savedPythonPath === undefined) delete process.env.PYTHONPATH;
    else process.env.PYTHONPATH = savedPythonPath;
    fs.rmSync(blocker, { recursive: true, force: true });
  });

  it('gives no verdict at all when the variable is set', async () => {
    makePlugin(plugins, 'shieldcortex');
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toContain('could not determine which copy Hermes loads');
    expect(row.message).toContain('HERMES_ENABLE_PROJECT_PLUGINS is set');
    expect(row.status).not.toBe('pass');

    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
  });

  it('still answers normally when the variable is not set', async () => {
    // Fail closed on the question that was asked, not on every question. With
    // the switch absent there is no project source to miss, and refusing a
    // verdict here would cost every host a row it is entitled to.
    makePlugin(plugins, 'shieldcortex');

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('pass');
  });
});

// ── Nit 1: preflight the device, then stop at the first failure ───────────

describeWithHermes('cross-device moves are refused before anything moves (#569 r7)', () => {
  /** Report `target` as living on another filesystem, without moving it. */
  function stageForeignDevice(target: string): void {
    const realLstat = fs.lstatSync.bind(fs) as typeof fs.lstatSync;
    jest.spyOn(fs, 'lstatSync').mockImplementation(((p: fs.PathLike, o?: unknown) => {
      const stats = realLstat(p, o as never) as fs.Stats;
      if (String(p) === target) stats.dev += 1;
      return stats;
    }) as typeof fs.lstatSync);
  }

  it('refuses the WHOLE plan when one source is on another filesystem', () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const first = makePlugin(plugins, 'shieldcortex.bak-1');
    const second = makePlugin(plugins, 'shieldcortex.bak-2');
    fs.writeFileSync(path.join(first, 'marker'), 'ordinary\n');
    stageForeignDevice(second);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fix.failed).toBe(true);
    const reasons = fix.refused.map((r) => r.reason).join(' ');
    expect(reasons).toMatch(/nothing was moved/);
    expect(reasons).toMatch(/EXDEV/);
    expect(reasons).toContain(shown(second));
    // The copy that WOULD have moved is named too, and is still where it was.
    expect(fix.refused.map((r) => r.dir)).toContain(first);
    expect(fs.readFileSync(path.join(first, 'marker'), 'utf8')).toBe('ordinary\n');
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('stops at the first failed move and calls the result partial', () => {
    // Everything above this loop is designed so nothing gets here unless the
    // plan is safe — but the filesystem is not ours alone. When a move fails
    // anyway, the preflight that cleared the rest was run against a tree that
    // has since changed, so the rest is abandoned and said to be abandoned.
    makePlugin(plugins, 'shieldcortex');
    const first = makePlugin(plugins, 'shieldcortex.bak-1');
    const second = makePlugin(plugins, 'shieldcortex.bak-2');
    const third = makePlugin(plugins, 'shieldcortex.bak-3');
    fs.writeFileSync(path.join(third, 'marker'), 'never touched\n');

    const realRename = fs.renameSync.bind(fs) as typeof fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation(((from: fs.PathLike, to: fs.PathLike) => {
      if (String(from) === second) {
        const err: NodeJS.ErrnoException = new Error('EXDEV: cross-device link not permitted');
        err.code = 'EXDEV';
        throw err;
      }
      return realRename(from, to);
    }) as typeof fs.renameSync);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    // The first move really happened and is reported as such.
    expect(fix.moved.map((m) => m.from)).toEqual([first]);
    expect(fix.changed).toBe(true);
    expect(fix.failed).toBe(true);
    expect(fs.existsSync(first)).toBe(false);
    expect(fs.existsSync(fix.moved[0].to)).toBe(true);
    // The third was never attempted, and says so.
    expect(fs.readFileSync(path.join(third, 'marker'), 'utf8')).toBe('never touched\n');
    const notAttempted = fix.refused.find((r) => r.dir === third);
    expect(notAttempted?.reason).toMatch(/was not attempted/);
    expect(notAttempted?.reason).toContain(shown(second));
    // And the operator is not told the repair is done.
    expect(fix.message).toMatch(/partial/);
    expect(fix.message).not.toMatch(/^moved 1 shadowing copy/);
    expect(fs.existsSync(path.join(second, 'plugin.yaml'))).toBe(true);
  });
});

// ── Nit 2: a malformed probe answer is rejected whole ─────────────────────

describe('a malformed probe answer is rejected, never filtered (#569 r7)', () => {
  /** A fake interpreter that prints `payload` and exits 0. */
  function fakeProbe(payload: string): string {
    const fake = path.join(home, `fake-python-${Math.random().toString(36).slice(2)}`);
    fs.writeFileSync(fake, ['#!/bin/sh', `cat <<'JSON'\n${payload}\nJSON`, ''].join('\n'));
    fs.chmodSync(fake, 0o755);
    fs.mkdirSync(plugins, { recursive: true });
    return fake;
  }

  function errorFrom(payload: string): string {
    const probe = probeHermesDiscovery(
      { home, hermesHome: null },
      { interpreter: fakeProbe(payload) },
    );
    expect('error' in probe).toBe(true);
    return 'error' in probe ? probe.error : '';
  }

  const PROJECT = '"project": {"envSet": false, "enabled": false, "dir": null, "copies": [], ' +
    '"discovered": [], "sameAsActiveRoot": false}';

  it('rejects a top-level null instead of throwing on it', () => {
    // `JSON.parse("null")` is a perfectly successful parse, and reading `.ok`
    // off the result throws a TypeError out of a function whose whole contract
    // is to RETURN "no answer".
    expect(errorFrom('null')).toMatch(/no result object/);
  });

  it('rejects a top-level array', () => {
    expect(errorFrom('[]')).toMatch(/no result object/);
  });

  it('rejects a null root entry', () => {
    expect(
      errorFrom(`{"ok": true, "activeHome": "/h", "root": "/h", "roots": [null], ` +
        `"undetermined": [], ${PROJECT}}`),
    ).toMatch(/malformed root entry/);
  });

  it('rejects a root entry with a non-string in `copies`', () => {
    expect(
      errorFrom(
        `{"ok": true, "activeHome": "/h", "root": "/h", "roots": [{"root": "/h/plugins", ` +
        `"copies": ["/h/plugins/shieldcortex", 7], "discovered": [], "loaded": null, ` +
        `"effective": null, "effectiveSource": null}], "undetermined": [], ${PROJECT}}`,
      ),
    ).toMatch(/malformed root entry/);
  });

  it('rejects a root entry with a non-string in `discovered`', () => {
    expect(
      errorFrom(
        `{"ok": true, "activeHome": "/h", "root": "/h", "roots": [{"root": "/h/plugins", ` +
        `"copies": [], "discovered": [null], "loaded": null, "effective": null, ` +
        `"effectiveSource": null}], "undetermined": [], ${PROJECT}}`,
      ),
    ).toMatch(/malformed root entry/);
  });

  it('rejects a winner with no source, and a source with no winner', () => {
    const root = (loaded: string, effective: string, source: string): string =>
      `{"ok": true, "activeHome": "/h", "root": "/h", "roots": [{"root": "/h/plugins", ` +
      `"copies": [], "discovered": [], "loaded": ${loaded}, "effective": ${effective}, ` +
      `"effectiveSource": ${source}}], "undetermined": [], ${PROJECT}}`;
    expect(errorFrom(root('null', '"/h/plugins/x"', 'null'))).toMatch(/malformed root entry/);
    expect(errorFrom(root('null', 'null', '"project"'))).toMatch(/malformed root entry/);
    expect(errorFrom(root('null', '"/h/plugins/x"', '"elsewhere"'))).toMatch(
      /malformed root entry/,
    );
  });

  it('rejects a malformed undetermined entry', () => {
    expect(
      errorFrom(`{"ok": true, "activeHome": "/h", "root": "/h", "roots": [], ` +
        `"undetermined": [null], ${PROJECT}}`),
    ).toMatch(/malformed undetermined entry/);
  });

  it('rejects a missing or malformed project block', () => {
    expect(
      errorFrom('{"ok": true, "activeHome": "/h", "root": "/h", "roots": [], "undetermined": []}'),
    ).toMatch(/malformed project entry/);
    expect(
      errorFrom(
        '{"ok": true, "activeHome": "/h", "root": "/h", "roots": [], "undetermined": [], ' +
        '"project": {"envSet": false, "enabled": false, "dir": null, "copies": [3], ' +
        '"discovered": [], "sameAsActiveRoot": false}}',
      ),
    ).toMatch(/malformed project entry/);
    // Enabled, but unable to name the directory it says it scanned.
    expect(
      errorFrom(
        '{"ok": true, "activeHome": "/h", "root": "/h", "roots": [], "undetermined": [], ' +
        '"project": {"envSet": true, "enabled": true, "dir": null, "copies": [], ' +
        '"discovered": [], "sameAsActiveRoot": false}}',
      ),
    ).toMatch(/malformed project entry/);
    // A probe with no answer about the ACTIVE-root equality is not one that
    // found none (#569 r9): silence there is the difference between the
    // operator's own plugins root and a source this command may not touch.
    expect(
      errorFrom(
        '{"ok": true, "activeHome": "/h", "root": "/h", "roots": [], "undetermined": [], ' +
        '"project": {"envSet": false, "enabled": false, "dir": null, "copies": [], ' +
        '"discovered": []}}',
      ),
    ).toMatch(/malformed project entry/);
    expect(
      errorFrom(
        '{"ok": true, "activeHome": "/h", "root": "/h", "roots": [], "undetermined": [], ' +
        '"project": {"envSet": false, "enabled": false, "dir": null, "copies": [], ' +
        '"discovered": [], "sameAsActiveRoot": "no"}}',
      ),
    ).toMatch(/malformed project entry/);
  });

  it('accepts the shape the probe really emits', () => {
    const probe = probeHermesDiscovery(
      { home, hermesHome: null },
      {
        interpreter: fakeProbe(
          '{"ok": true, "activeHome": "/h", "root": "/h", "roots": [{"root": "/h/plugins", ' +
          '"copies": ["/h/plugins/shieldcortex"], "discovered": ["/h/plugins/shieldcortex"], ' +
          '"loaded": "/h/plugins/shieldcortex", "effective": "/h/plugins/shieldcortex", ' +
          `"effectiveSource": "user"}], "undetermined": [], ${PROJECT}}`,
        ),
      },
    );
    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    expect(probe.roots[0].discovered).toEqual(['/h/plugins/shieldcortex']);
    expect(probe.roots[0].effectiveSource).toBe('user');
    expect(probe.project.enabled).toBe(false);
    expect(probe.project.sameAsActiveRoot).toBe(false);
  });
});

// ── Nit 3: a duplicate that loses is a duplicate, not a downgrade ─────────

describeWithHermes('a backup that sorts FIRST is reported as a duplicate (#569 r7)', () => {
  it('does not claim Hermes is loading something else', async () => {
    // `old-shieldcortex` sorts BEFORE `shieldcortex`, so the installed copy
    // still wins. Warning about the duplicate is right; saying the gateway is
    // running the old code sends an operator hunting a fault that is not there.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const duplicate = makePlugin(plugins, 'old-shieldcortex');

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toContain('duplicate');
    expect(row.message).toContain(shown(duplicate));
    expect(row.message).not.toMatch(/Hermes is not loading the installed plugin/);
    expect(row.message).toContain(`Hermes loads ${shown(canonical)}`);
    expect(row.message).toContain('which IS the installed copy');
  });

  it('still moves the duplicate, because the winner does not change', async () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const duplicate = makePlugin(plugins, 'old-shieldcortex');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.failed).toBe(false);
    expect(fix.moved.map((m) => m.from)).toEqual([duplicate]);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect((await checkHermesPluginShadowing(home)).status).toBe('pass');
  });

  it('keeps the honest headline when a copy really does outrank the install', async () => {
    makePlugin(plugins, 'shieldcortex');
    makePlugin(plugins, 'old-shieldcortex');
    makePlugin(plugins, 'shieldcortex.bak-x');

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/Hermes is not loading the installed plugin/);
  });
});
