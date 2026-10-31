import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  hermesAskPlan,
  hermesHomeLauncher,
  probeHermesDiscovery,
  scanHermesPluginCopies,
  searchHermesInterpreter,
} from '../hermes-plugins.js';
import { hermesPluginSourceDir, refreshHermesPluginCopies } from '../hermes-refresh.js';

/**
 * #971 — `shieldcortex update` asked a leftover July `.venv/bin/python3`
 * before the live launcher at `hermes-agent/.hermes/bin/hermes`. The venv
 * existed as a file, so it won; it could not `import ruamel.yaml`, so the probe
 * failed; so nothing was written and Hermes kept the previous plugin copy.
 *
 * Every case builds a throwaway home under /tmp with a STUB install:
 *
 *   - a launcher that answers `--print-runtime-command` with a JSON argv and
 *     exits 97 on anything else, so a test fails loudly if it is ever spawned
 *     any other way (`hermes -c` is "resume a session", not Python `-c`);
 *   - a stub "bundled Python" that records its argv and prints a canned probe
 *     answer — the real one cannot be used against a fixture home, because
 *     Hermes' bootstrap prepares a full dependency set for any data root it has
 *     not seen;
 *   - a stub venv Python that answers exactly what the stale one did.
 *
 * PATH is pinned to an empty directory so the developer's own `hermes` is
 * never found, and `HERMES_HOME` / `HERMES_ENABLE_PROJECT_PLUGINS` are
 * scrubbed. Nothing reads or writes the operator's `~/.hermes`.
 */

const SOURCE = hermesPluginSourceDir();
const FROZEN = new Date('2026-10-31T07:00:00.000Z');
const JULY = new Date('2026-07-15T00:00:00.000Z');
const OCTOBER = new Date('2026-10-23T05:40:00.000Z');
const RUAMEL = "ModuleNotFoundError: No module named 'ruamel'";

const saved = {
  PATH: process.env.PATH,
  HERMES_HOME: process.env.HERMES_HOME,
  HERMES_ENABLE_PROJECT_PLUGINS: process.env.HERMES_ENABLE_PROJECT_PLUGINS,
};

let home: string;
let hermes: string;
let agent: string;
let plugins: string;
let installed: string;
let bin: string;
let logs: string;

beforeEach(() => {
  // /tmp, not os.tmpdir(): macOS tmpdir is /var/folders, and nothing here
  // needs it to be anywhere special.
  home = fs.mkdtempSync(path.join('/tmp', 'sc-hermes-971-'));
  hermes = path.join(home, '.hermes');
  agent = path.join(hermes, 'hermes-agent');
  plugins = path.join(hermes, 'plugins');
  installed = path.join(plugins, 'shieldcortex');
  bin = path.join(home, 'empty-bin');
  logs = path.join(home, 'logs');
  for (const dir of [agent, plugins, bin, logs]) fs.mkdirSync(dir, { recursive: true });
  process.env.PATH = bin;
  delete process.env.HERMES_HOME;
  delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/** Single-quote a string for /bin/sh. */
function sq(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** What Hermes' probe prints when it answers: the install, winning its root. */
function answer(): string {
  return JSON.stringify({
    ok: true,
    activeHome: hermes,
    root: hermes,
    roots: [{
      root: plugins,
      copies: [installed],
      discovered: [installed],
      loaded: installed,
      effective: installed,
      effectiveSource: 'user',
    }],
    project: { envSet: false, enabled: false, dir: null, copies: [], discovered: [], sameAsActiveRoot: false },
    undetermined: [],
  });
}

/** What a Python that cannot see Hermes' dependencies prints. */
function cannotImport(why = RUAMEL): string {
  return JSON.stringify({ ok: false, error: why });
}

/**
 * A stub interpreter: records every argv element NUL-separated in
 * `logs/<name>.argv`, then prints `reply`.
 */
function stubPython(file: string, name: string, reply: string): string {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const replyFile = path.join(logs, `${name}.reply`);
  fs.writeFileSync(replyFile, reply);
  fs.writeFileSync(
    file,
    '#!/bin/sh\n' +
      `for a in "$@"; do printf '%s\\0' "$a"; done > ${sq(path.join(logs, `${name}.argv`))}\n` +
      `/bin/cat ${sq(replyFile)}\n`,
    { mode: 0o755 },
  );
  return file;
}

function argvOf(name: string): string[] | null {
  const file = path.join(logs, `${name}.argv`);
  if (!fs.existsSync(file)) return null;
  return fs.readFileSync(file, 'utf8').split('\0').slice(0, -1);
}

/**
 * The live launcher's shape: a `#!/bin/sh` that answers
 * `--print-runtime-command` with `[<bundled python>, "-I", "-c", <bootstrap>]`.
 */
function makeLauncher(opts: { reply?: string; bootstrapRoot?: string | null; mtime?: Date } = {}): string {
  const python = stubPython(
    path.join(hermes, 'tools', 'python-3.14', 'bin', 'python3'),
    'bundled',
    opts.reply ?? answer(),
  );
  const root = opts.bootstrapRoot === undefined ? agent : opts.bootstrapRoot;
  const bootstrap = 'import os, sys, runpy; ' +
    "os.environ.pop('PYTHONHOME', None); os.environ.pop('PYTHONPATH', None); " +
    (root === null ? '' : `sys.path.insert(0, '${root}'); `) +
    "sys._hermes_pin_default_home = True; import hermes_bootstrap; " +
    "runpy.run_module('hermes_cli.main', run_name='__main__', alter_sys=True)";
  const runtime = path.join(logs, 'runtime.json');
  fs.writeFileSync(runtime, JSON.stringify([python, '-I', '-c', bootstrap]) + '\n');
  const launcher = hermesHomeLauncher(hermes);
  fs.mkdirSync(path.dirname(launcher), { recursive: true });
  fs.writeFileSync(
    launcher,
    '#!/bin/sh\n' +
      `printf '%s\\n' "$*" >> ${sq(path.join(logs, 'launcher.calls'))}\n` +
      'if [ "$1" = "--print-runtime-command" ]; then\n' +
      `  /bin/cat ${sq(runtime)}\n` +
      '  exit 0\n' +
      'fi\n' +
      'echo "unexpected launch: $*" >&2\n' +
      'exit 97\n',
    { mode: 0o755 },
  );
  const when = opts.mtime ?? OCTOBER;
  fs.utimesSync(launcher, when, when);
  return launcher;
}

/** The leftover venv Python, answering `reply`, last touched at `mtime`. */
function makeVenv(opts: { reply?: string; mtime?: Date } = {}): string {
  const py = stubPython(path.join(agent, '.venv', 'bin', 'python3'), 'venv', opts.reply ?? cannotImport());
  const when = opts.mtime ?? JULY;
  fs.utimesSync(py, when, when);
  return py;
}

function launcherCalls(): string[] {
  const file = path.join(logs, 'launcher.calls');
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter((l) => l !== '') : [];
}

/** What `hermes install` puts on disk, then the #576 drift. */
function installStaleCopy(dest: string = installed): void {
  fs.cpSync(SOURCE, dest, {
    recursive: true,
    filter: (src) => !['tests', '__pycache__', '.pytest_cache'].includes(path.basename(src)),
  });
  fs.writeFileSync(path.join(dest, '__init__.py'), '# shieldcortex 5.16.0\n');
}

/** A Hermes config with the plugin NOT enabled; it must come out byte-identical. */
function writeConfig(): { file: string; bytes: string } {
  const file = path.join(hermes, 'config.yaml');
  const bytes = 'plugins:\n  enabled: []\n';
  fs.writeFileSync(file, bytes);
  return { file, bytes };
}

function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      const rel = path.relative(dir, full);
      if (entry.isDirectory() && !entry.isSymbolicLink()) {
        out.push(`${rel}/`);
        walk(full);
      } else {
        out.push(`${rel}=${entry.isSymbolicLink() ? `->${fs.readlinkSync(full)}` : fs.readFileSync(full, 'utf8')}`);
      }
    }
  };
  walk(dir);
  return out.sort();
}

describe('which Hermes to ask (#971)', () => {
  it('prefers hermes-agent/.hermes/bin/hermes over a present .venv/bin/python3', () => {
    const launcher = makeLauncher();
    makeVenv({ mtime: new Date(OCTOBER.getTime() + 60_000) }); // newer: not stale
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'found', interpreter: launcher });
    const plan = hermesAskPlan(hermes);
    expect(plan.launchers).toEqual([{ kind: 'launcher', path: launcher }]);
    // Still a fallback, after the launcher — never ahead of it.
    expect(plan.venvs.map((v) => v.path)).toEqual([path.join(agent, '.venv', 'bin', 'python3')]);
  });

  it('a venv older than the launcher is stale: named, never a candidate', () => {
    const launcher = makeLauncher();
    const venv = makeVenv();
    const plan = hermesAskPlan(hermes);
    expect(plan.venvs).toEqual([]);
    expect(plan.stale).toEqual([{ path: venv, launcher }]);
  });

  it('with no launcher at all, the venv is still asked (legacy installs)', () => {
    const venv = makeVenv({ reply: answer() });
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'found', interpreter: venv });
    expect(hermesAskPlan(hermes).stale).toEqual([]);
  });

  it('a PATH `#!/bin/sh` wrapper is no longer a dead end when the home launcher exists', () => {
    const launcher = makeLauncher();
    fs.writeFileSync(path.join(bin, 'hermes'), `#!/bin/sh\nexec ${launcher} "$@"\n`, { mode: 0o755 });
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'found', interpreter: launcher });
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.fromHermes).toBe(true);
    expect(scan.copies.map((c) => c.dir)).toEqual([installed]);
  });

  it('control (#651): the same PATH wrapper alone is still undetermined, and is never run', () => {
    const wrapper = path.join(bin, 'hermes');
    fs.writeFileSync(wrapper, `#!/bin/sh\necho ran > ${sq(path.join(logs, 'wrapper.ran'))}\n`, { mode: 0o755 });
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'undetermined', path: wrapper });
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.fromHermes).toBe(false);
    expect(scan.noInterpreter).toBe(false);
    expect(fs.existsSync(path.join(logs, 'wrapper.ran'))).toBe(false);
  });

  it('control (#651): a dangling hermes-agent link is undetermined, not absent', () => {
    fs.rmSync(agent, { recursive: true });
    fs.symlinkSync(path.join(home, 'moved-away'), agent);
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'undetermined', path: hermesHomeLauncher(hermes) });
    expect(scanHermesPluginCopies({ home, hermesHome: null }).noInterpreter).toBe(false);
  });

  it('control (#651): nothing anywhere is still confirmed absence', () => {
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'absent' });
    expect(scanHermesPluginCopies({ home, hermesHome: null }).noInterpreter).toBe(true);
  });
});

describe('asking Hermes through the launcher closure (#971)', () => {
  it('runs the launcher only with --print-runtime-command, then its Python with -I and the closure', () => {
    makeLauncher();
    makeVenv();
    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('error' in probe).toBe(false);
    expect(launcherCalls()).toEqual(['--print-runtime-command']);
    // The stale venv was never asked.
    expect(argvOf('venv')).toBeNull();

    const argv = argvOf('bundled')!;
    expect(argv[0]).toBe('-I');
    expect(argv[1]).toBe('-c');
    const script = argv[2];
    const insert = script.indexOf(`_sc_sys.path.insert(0, ${JSON.stringify(agent)})`);
    const bootstrap = script.indexOf('import hermes_bootstrap');
    const probeBody = script.indexOf('_payload = json.loads(sys.argv[1])');
    expect(script.indexOf('_sc_os.environ.pop("PYTHONHOME", None)')).toBeGreaterThan(-1);
    expect(script.indexOf('_sc_os.environ.pop("PYTHONPATH", None)')).toBeGreaterThan(-1);
    expect(insert).toBeGreaterThan(-1);
    expect(bootstrap).toBeGreaterThan(insert);
    expect(probeBody).toBeGreaterThan(bootstrap);
    // Never the install-root pin: the probe answers for the HOME it was given.
    expect(script).not.toContain('_hermes_pin_default_home');
    expect(JSON.parse(argv[3]).importRoots).toEqual([agent]);
  });

  it('derives hermes-agent from the launcher path when the printed -c names no checkout', () => {
    makeLauncher({ bootstrapRoot: null });
    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('error' in probe).toBe(false);
    expect(argvOf('bundled')![2]).toContain(`_sc_sys.path.insert(0, ${JSON.stringify(agent)})`);
  });

  it('a candidate that cannot import Hermes hands over to the next one', () => {
    // The launcher's Python cannot import Hermes; a venv NEWER than the
    // launcher (so not stale) can. The launcher is asked first, then the venv.
    makeLauncher({ reply: cannotImport("ModuleNotFoundError: No module named 'hermes_bootstrap'") });
    makeVenv({ reply: answer(), mtime: new Date(OCTOBER.getTime() + 60_000) });
    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('error' in probe).toBe(false);
    expect(argvOf('bundled')).not.toBeNull();
    expect(argvOf('venv')).not.toBeNull();
  });

  it('a .venv python3 whose probe says No module named ruamel is skipped for the launcher', () => {
    // No home launcher here: the venv is first, fails exactly as #971 saw,
    // and a launcher on PATH answers.
    const venv = makeVenv({ mtime: OCTOBER });
    const launcher = makeLauncher({ mtime: JULY });
    const onPath = path.join(bin, 'hermes');
    fs.renameSync(launcher, onPath);
    expect(hermesAskPlan(hermes).launchers).toEqual([{ kind: 'launcher', path: onPath }]);
    // The PATH launcher is older than the venv, so the venv is not stale —
    // and it is still asked only AFTER the launcher.
    expect(hermesAskPlan(hermes).venvs).toEqual([{ kind: 'python', path: venv }]);
    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('error' in probe).toBe(false);
    expect(argvOf('venv')).toBeNull();

    // And when the launcher is the one that fails to import, the venv is next.
    fs.writeFileSync(path.join(logs, 'bundled.reply'), cannotImport());
    fs.writeFileSync(path.join(logs, 'venv.reply'), answer());
    expect('error' in probeHermesDiscovery({ home, hermesHome: null })).toBe(false);
    expect(argvOf('venv')).not.toBeNull();
  });

  it('an error that is Hermes answering stops the search', () => {
    makeLauncher({ reply: JSON.stringify({ ok: false, error: 'ValueError: bad HERMES_HOME' }) });
    makeVenv({ reply: answer(), mtime: new Date(OCTOBER.getTime() + 60_000) });
    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('error' in probe).toBe(true);
    expect(argvOf('venv')).toBeNull();
  });

  it('names every candidate tried, in order, and the stale venv it skipped', () => {
    const launcher = makeLauncher({ reply: cannotImport() });
    const venv = makeVenv();
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.fromHermes).toBe(false);
    const reason = scan.undeterminedReason!;
    expect(reason).toContain(launcher);
    expect(reason).toContain(RUAMEL);
    expect(reason).toContain(venv);
    expect(reason).toMatch(/stale venv: older than the launcher/);
    expect(reason.indexOf(launcher)).toBeLessThan(reason.indexOf(venv));
  });

  it('a --print-runtime-command that fails is named, and the next candidate is asked', () => {
    const launcher = makeLauncher();
    fs.writeFileSync(path.join(logs, 'runtime.json'), 'not json\n');
    const venv = makeVenv({ reply: cannotImport(), mtime: new Date(OCTOBER.getTime() + 60_000) });
    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('error' in probe).toBe(true);
    if ('error' in probe) {
      expect(probe.error).toContain(`${launcher} (--print-runtime-command printed no JSON argv)`);
      expect(probe.error).toContain(venv);
      expect(probe.error.indexOf(launcher)).toBeLessThan(probe.error.indexOf(venv));
    }
  });

  it('the opts.interpreter seam accepts a launcher and still never runs it with -c', () => {
    const launcher = makeLauncher();
    const probe = probeHermesDiscovery({ home, hermesHome: null }, { interpreter: launcher });
    expect('error' in probe).toBe(false);
    expect(launcherCalls()).toEqual(['--print-runtime-command']);
  });
});

describe('refreshHermesPluginCopies on a launcher install with a stale venv (#971)', () => {
  it('updates $HERMES_HOME/plugins/shieldcortex through the launcher; old copy to backups/', () => {
    makeLauncher();
    makeVenv();
    installStaleCopy();
    const config = writeConfig();

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('refreshed');
    expect(result.refreshed.map((r) => r.dir)).toEqual([installed]);
    expect(fs.readFileSync(path.join(installed, '__init__.py'))).toEqual(
      fs.readFileSync(path.join(SOURCE, '__init__.py')),
    );
    const backup = result.refreshed[0].backup!;
    expect(backup.startsWith(path.join(hermes, 'backups') + path.sep)).toBe(true);
    expect(fs.readFileSync(path.join(backup, '__init__.py'), 'utf8')).toBe('# shieldcortex 5.16.0\n');
    expect(fs.readdirSync(plugins)).toEqual(['shieldcortex']);
    expect(fs.readFileSync(config.file, 'utf8')).toBe(config.bytes);
    expect(argvOf('venv')).toBeNull();
  });

  it('discovery cannot be asked + the one conventional copy: refreshes that copy', () => {
    makeLauncher({ reply: cannotImport() });
    makeVenv();
    installStaleCopy();
    const config = writeConfig();

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('refreshed');
    expect(result.refreshed.map((r) => r.dir)).toEqual([installed]);
    expect(result.refreshed[0].backup!.startsWith(path.join(hermes, 'backups') + path.sep)).toBe(true);
    expect(fs.readdirSync(plugins)).toEqual(['shieldcortex']);
    expect(fs.readFileSync(path.join(installed, '__init__.py'))).toEqual(
      fs.readFileSync(path.join(SOURCE, '__init__.py')),
    );
    expect(result.detail.join('\n')).toMatch(/could not be asked/);
    expect(fs.readFileSync(config.file, 'utf8')).toBe(config.bytes);
  });

  it('discovery cannot be asked + TWO copies: writes nothing (#569)', () => {
    makeLauncher({ reply: cannotImport() });
    makeVenv();
    installStaleCopy();
    const extra = path.join(plugins, 'shieldcortex.bak-x');
    fs.mkdirSync(extra);
    fs.writeFileSync(path.join(extra, 'plugin.yaml'), 'name: shieldcortex\n');
    writeConfig();
    const before = snapshot(hermes);

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(result.summary).toMatch(/nothing written/);
    expect(snapshot(hermes)).toEqual(before);
  });

  it('discovery cannot be asked + escaped-name second copy: writes nothing', () => {
    makeLauncher({ reply: cannotImport() });
    installStaleCopy();
    const extra = path.join(plugins, 'zz-old');
    fs.mkdirSync(extra);
    fs.writeFileSync(path.join(extra, 'plugin.yaml'), 'name: "shieldcorte\\u0078"\n');
    const before = snapshot(hermes);
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(snapshot(hermes)).toEqual(before);
  });

  it('discovery cannot be asked + any other manifest-bearing plugin: writes nothing', () => {
    makeLauncher({ reply: cannotImport() });
    installStaleCopy();
    const extra = path.join(plugins, 'ekho');
    fs.mkdirSync(extra);
    fs.writeFileSync(path.join(extra, 'plugin.yaml'), 'name: ekho\n');
    const before = snapshot(hermes);
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(snapshot(hermes)).toEqual(before);
  });

  it('discovery cannot be asked + a second copy in a profile: writes nothing', () => {
    makeLauncher({ reply: cannotImport() });
    installStaleCopy();
    installStaleCopy(path.join(hermes, 'profiles', 'work', 'plugins', 'shieldcortex'));
    const before = snapshot(hermes);
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('warn');
    expect(snapshot(hermes)).toEqual(before);
  });

  it('discovery cannot be asked + the conventional copy is a symlink: writes nothing', () => {
    makeLauncher({ reply: cannotImport() });
    const real = path.join(home, 'elsewhere', 'shieldcortex');
    installStaleCopy(real);
    fs.symlinkSync(real, installed);
    const before = snapshot(hermes);
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(snapshot(hermes)).toEqual(before);
  });

  it('discovery cannot be asked + a symlink inside the copy: writes nothing', () => {
    makeLauncher({ reply: cannotImport() });
    installStaleCopy();
    fs.symlinkSync(path.join(home, 'elsewhere'), path.join(installed, 'link'));
    const before = snapshot(hermes);
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('warn');
    expect(snapshot(hermes)).toEqual(before);
  });

  it('discovery cannot be asked + project plugins may be on: writes nothing', () => {
    makeLauncher({ reply: cannotImport() });
    installStaleCopy();
    process.env.HERMES_ENABLE_PROJECT_PLUGINS = '1';
    const before = snapshot(hermes);
    const result = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(result.status).toBe('warn');
    expect(snapshot(hermes)).toEqual(before);
  });
});
