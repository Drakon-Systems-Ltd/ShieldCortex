import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkHermesPluginShadowing, fixHermesPluginShadowing } from '../doctor.js';
import { probeHermesDiscovery } from '../../setup/hermes-plugins.js';

/**
 * #569 r8 — a manifest read failure Hermes WRAPPED is still a read failure.
 *
 * The layout is the one the review reproduced, and it is an ordinary portable
 * backup rather than a hostile construction:
 *
 *     plugins/shieldcortex                the installed plugin
 *     plugins/shieldcortex.bak-portable   a VALID portable package —
 *                                         plugin.json declaring `shieldcortex`,
 *                                         plus plugin.py
 *
 * Readable, that is a WARN: `shieldcortex.bak-portable` sorts after
 * `shieldcortex`, so it is what the gateway loads. With `plugin.json` at a mode
 * this process cannot read — 0600 owned by the service account in the field,
 * `chmod 000` here — it became a PASS reading "clean", because:
 *
 *   - the pre-verdict child check STATTED the manifest and stopped there, and
 *     stat and open are two different permissions;
 *   - Hermes' own read then failed, and `agent_plugins._read_json_object`
 *     turns that PermissionError into an `AgentPluginError` — a ValueError —
 *     with `raise ... from exc`. `plugins_discovery` logs the wrapper, which
 *     judged on its own type is indistinguishable from a schema rejection, and
 *     a schema rejection is an ANSWER: "this is not a plugin".
 *
 * So the host whose gateway loads the backup was certified clean, and
 * `--fix-hermes-plugin-copies` exited 0 saying there was nothing to move.
 *
 * Both legs are driven separately on purpose. The real-mode case is the host
 * condition itself and exercises the pre-read. The injected case leaves the
 * file perfectly readable and makes HERMES fail on it, so nothing but the
 * cause chain can catch it. The control is a portable manifest Hermes rejects
 * for its schema, with no OSError anywhere in the chain: that is a verdict,
 * and it must still produce a PASS for the canonical copy.
 */
let home: string;
let hermes: string;
let plugins: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedPythonPath = process.env.PYTHONPATH;
const savedWrap = process.env.SC569_WRAP_PERM;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-wrapped-'));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  fs.mkdirSync(plugins, { recursive: true });
  delete process.env.HERMES_HOME;
});

afterEach(() => {
  // Modes go back before the tree does: a file left at 000 inside a directory
  // this suite is about is still removable, but a restored tree is what the
  // next case and any post-mortem need.
  restoreModes();
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedPythonPath === undefined) delete process.env.PYTHONPATH;
  else process.env.PYTHONPATH = savedPythonPath;
  if (savedWrap === undefined) delete process.env.SC569_WRAP_PERM;
  else process.env.SC569_WRAP_PERM = savedWrap;
});

/** Paths whose mode this suite changed, and what it was. */
const chmodded: Array<{ target: string; mode: number }> = [];

function makeUnreadable(target: string): void {
  chmodded.push({ target, mode: fs.statSync(target).mode & 0o7777 });
  fs.chmodSync(target, 0o000);
}

function restoreModes(): void {
  while (chmodded.length > 0) {
    const entry = chmodded.pop()!;
    try {
      fs.chmodSync(entry.target, entry.mode);
    } catch {
      /* the tree is about to go anyway */
    }
  }
}

const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const PORTABLE_SCHEMA = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json';

/** Doctor prints paths tildified; a temp dir can itself live under $HOME. */
function shown(target: string): string {
  const real = os.homedir();
  return target.startsWith(real) ? target.replace(real, '~') : target;
}

/** The installed plugin: a YAML manifest keyed `shieldcortex`. */
function makeCanonical(): string {
  const dir = path.join(plugins, 'shieldcortex');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'plugin.yaml'),
    'name: shieldcortex\nkind: standalone\nversion: 5.1.0\n',
  );
  fs.writeFileSync(path.join(dir, 'marker'), 'installed\n');
  return dir;
}

/**
 * A portable backup beside it: a real Agent Plugins package, which is how a
 * `plugin.json` copy is written and is why the file is the only thing that
 * decides the key.
 */
function makePortableBackup(schema: string = PORTABLE_SCHEMA): { dir: string; manifest: string } {
  const dir = path.join(plugins, 'shieldcortex.bak-portable');
  fs.mkdirSync(dir, { recursive: true });
  const manifest = path.join(dir, 'plugin.json');
  fs.writeFileSync(
    manifest,
    `${JSON.stringify({ $schema: schema, name: 'shieldcortex', version: '1.0.0' })}\n`,
  );
  fs.writeFileSync(path.join(dir, 'plugin.py'), 'def register(*a, **k):\n    pass\n');
  fs.writeFileSync(path.join(dir, 'marker'), 'the gateway runs this\n');
  return { dir, manifest };
}

/**
 * Make Hermes itself fail on ONE plugin directory the way the field does,
 * without touching a single mode: a `sitecustomize` module on `PYTHONPATH`
 * pre-imports `plugins_discovery` and replaces `portable_plugin_manifest` with
 * one that raises `AgentPluginError(...) from PermissionError` — the exact
 * shape `agent_plugins._read_json_object` produces.
 *
 * The manifest stays fully readable, so the pre-read finds nothing at all and
 * the ONLY thing that can notice is the cause chain. It also reaches the
 * branch on a box where a real mode change cannot be staged (running as root,
 * or a filesystem that ignores modes).
 */
function injectWrappedPermissionError(target: string): void {
  const hookDir = path.join(home, 'probe-hook');
  fs.mkdirSync(hookDir, { recursive: true });
  fs.writeFileSync(
    path.join(hookDir, 'sitecustomize.py'),
    [
      'import os',
      '_want = os.environ.get("SC569_WRAP_PERM")',
      'if _want:',
      '    try:',
      '        from hermes_cli import plugins_discovery as _pd',
      '        from hermes_cli.agent_plugins import AgentPluginError',
      '',
      '        _real = _pd.portable_plugin_manifest',
      '',
      '        def _portable(child, source, prefix):',
      '            if os.fspath(child) == _want:',
      '                try:',
      '                    raise PermissionError(13, "injected: refusing to read")',
      '                except PermissionError as _exc:',
      '                    raise AgentPluginError(',
      '                        "plugin.json is not valid readable JSON: injected"',
      '                    ) from _exc',
      '            return _real(child, source, prefix)',
      '',
      '        _pd.portable_plugin_manifest = _portable',
      '    except Exception:',
      '        pass',
      '',
    ].join('\n'),
  );
  process.env.PYTHONPATH =
    savedPythonPath === undefined ? hookDir : `${hookDir}${path.delimiter}${savedPythonPath}`;
  process.env.SC569_WRAP_PERM = target;
}

/** Whether this box can be asked at all — see the sibling suites' note. */
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

describeWithHermes('a wrapped manifest read failure is never a clean PASS (#569 r8)', () => {
  it('warns that the portable backup is what loads while it IS readable', async () => {
    // The premise of the whole case: readable, this layout is a shadow, and
    // the row says so. If this stopped being true the unreadable case below
    // would be asserting nothing.
    makeCanonical();
    const backup = makePortableBackup();

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).toContain(shown(backup.dir));
    expect(row.message).toMatch(/Hermes loads/);
  });

  itUnlessRoot('refuses to answer when the portable manifest cannot be read (real chmod)', async () => {
    const canonical = makeCanonical();
    const backup = makePortableBackup();
    makeUnreadable(backup.manifest);

    // The premise: the directory lists and the manifest stats, and only the
    // READ fails. That is what made the old stat-only check report clean.
    expect(fs.readdirSync(backup.dir)).toContain('plugin.json');
    expect(fs.statSync(backup.manifest).isFile()).toBe(true);
    expect(() => fs.readFileSync(backup.manifest)).toThrow(/EACCES/);

    const row = await checkHermesPluginShadowing(home);

    expect(row.status).toBe('warn');
    expect(row.message).not.toMatch(/clean/);
    expect(row.message).toContain(shown(backup.manifest));
    expect(row.message).toMatch(/Permission denied|EACCES/);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    // Non-zero, and nothing moved — including the canonical copy, which was
    // never a candidate but shares the refusal.
    expect(fix.failed).toBe(true);
    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fix.message).not.toMatch(/nothing to move/);
    expect(fix.message).toContain(shown(backup.manifest));
    expect(fs.readFileSync(path.join(canonical, 'marker'), 'utf8')).toBe('installed\n');
    expect(fs.readFileSync(path.join(backup.dir, 'marker'), 'utf8')).toBe('the gateway runs this\n');
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  itUnlessRoot('reports the uncertainty even though the plan is EMPTY (real chmod)', () => {
    // The shape that made this a false PASS rather than a partial repair:
    // Hermes drops the manifest it could not read, so it discovers ONE copy,
    // and one copy is no collision and no plan. An empty plan used to be
    // reported as "nothing to move" and exit 0.
    makeCanonical();
    const backup = makePortableBackup();
    makeUnreadable(backup.manifest);

    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    // Hermes really did come back with nothing to move…
    expect(probe.roots.flatMap((r) => r.copies)).toEqual([path.join(plugins, 'shieldcortex')]);
    // …and the read failure is carried out anyway, naming the file.
    expect(probe.undetermined).toContainEqual({
      path: backup.manifest,
      error: expect.stringContaining('PermissionError') as unknown as string,
    });

    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.failed).toBe(true);
    expect(fix.moved).toEqual([]);
  });

  it('follows the cause chain when Hermes wraps the error (injected, file readable)', async () => {
    const canonical = makeCanonical();
    const backup = makePortableBackup();
    injectWrappedPermissionError(backup.dir);

    // No chmod anywhere: our own pre-read of this manifest succeeds, so the
    // cause chain is the only thing that can catch this.
    expect(fs.readFileSync(backup.manifest, 'utf8')).toContain('shieldcortex');

    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    expect(probe.undetermined).toEqual([
      {
        path: backup.manifest,
        error: expect.stringContaining('injected: refusing to read') as unknown as string,
      },
    ]);
    expect(probe.undetermined[0].error).toMatch(/PermissionError/);

    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
    expect(row.message).not.toMatch(/clean/);
    expect(row.message).toContain(shown(backup.manifest));

    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.failed).toBe(true);
    expect(fix.moved).toEqual([]);
    expect(fs.readFileSync(path.join(canonical, 'marker'), 'utf8')).toBe('installed\n');
  });

  itUnlessRoot('reports a second candidate Hermes never opened (pre-read only)', async () => {
    // The leg that does NOT depend on Hermes logging anything. `plugin.yaml`
    // is readable, so `scan_directory` selects it, parses it and says nothing
    // at all — `plugin.json` beside it is never opened, and the cause chain
    // has no record to classify. The pre-read opens EVERY candidate that is
    // there, which is what makes this check independent of Hermes' own log
    // wording, log level, and of which of the three names a given Hermes
    // version selects.
    const canonical = makeCanonical();
    const second = path.join(canonical, 'plugin.json');
    fs.writeFileSync(
      second,
      `${JSON.stringify({ $schema: PORTABLE_SCHEMA, name: 'shieldcortex', version: '1.0.0' })}\n`,
    );
    makeUnreadable(second);

    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    // Hermes read the YAML and found the copy — it never met an error at all.
    expect(probe.roots.flatMap((r) => r.copies)).toEqual([canonical]);
    expect(probe.undetermined).toEqual([
      {
        path: second,
        error: expect.stringContaining('PermissionError') as unknown as string,
      },
    ]);

    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
    expect(row.message).toContain(shown(second));
  });

  it('still answers for a manifest Hermes rejects on its schema (control)', async () => {
    // The other half of the fix: an ordinary rejection has no OSError anywhere
    // in its chain. Hermes' answer there is "this is not a plugin", which is a
    // VERDICT and not a gap, and the canonical copy must still come back PASS.
    const canonical = makeCanonical();
    const backup = makePortableBackup('https://example.invalid/not-the-schema.json');

    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    // Hermes logged its rejection of the backup, and it is not a read failure.
    expect(probe.undetermined).toEqual([]);
    expect(probe.roots.flatMap((r) => r.copies)).toEqual([canonical]);

    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('pass');
    expect(row.message).toMatch(/clean/);
    expect(row.message).toContain(shown(canonical));
    expect(fs.existsSync(path.join(backup.dir, 'plugin.json'))).toBe(true);
  });

  it('still repairs an ordinary shadowed host, so the refusal is not blanket', () => {
    // The control for the control: everything readable, nothing wrapped, a
    // plain YAML backup. A change that refused everything would pass every
    // case above.
    const canonical = makeCanonical();
    const backup = path.join(plugins, 'shieldcortex.bak-x');
    fs.mkdirSync(backup, { recursive: true });
    fs.writeFileSync(path.join(backup, 'plugin.yaml'), 'name: shieldcortex\nversion: 0.1.0\n');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.failed).toBe(false);
    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
  });
});

describeWithHermes('an OSError Hermes logged directly is undetermined too (#569 r8)', () => {
  it('reports a manifest candidate that is a directory, which the pre-read never opens', async () => {
    // Two halves of the same rule meeting on one path.
    //
    // The PRE-READ does not open a candidate that is not a regular file: it
    // takes a byte out of manifests, and a `plugin.yaml` that is a DIRECTORY
    // (or a FIFO) answers an open with a block or an error that says nothing
    // about who can read what.
    //
    // The CAUSE CHAIN still reports it, because Hermes met an OSError of its
    // own reading it and logged it — here directly rather than wrapped. The
    // rule is the same either way: an OSError that is not FileNotFoundError
    // means the manifest was not read, so no copy in this root can be ruled in
    // or out and nothing may be moved anywhere.
    makeCanonical();
    const odd = path.join(plugins, 'not-a-plugin');
    const candidate = path.join(odd, 'plugin.yaml');
    fs.mkdirSync(candidate, { recursive: true });

    const probe = probeHermesDiscovery({ home, hermesHome: null });
    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    expect(probe.undetermined).toEqual([
      {
        path: candidate,
        error: expect.stringContaining('IsADirectoryError') as unknown as string,
      },
    ]);

    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
    expect(row.message).toContain(shown(candidate));
  });
});
