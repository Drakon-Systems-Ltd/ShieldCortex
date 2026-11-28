import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkOpenClawManagedPinDrift } from '../cli/doctor.js';

/**
 * Guards the v4.33.0 detection for OpenClaw's EOVERRIDE trap (openclaw#91772):
 * a managed-peer dependency pin that has drifted to a different version than the
 * imported workspace override for the same package will throw `EOVERRIDE` on the
 * next `openclaw update` and OpenClaw silently disables the plugin. The check
 * surfaces both the pre-failure drift (warn) and the already-disabled state (fail).
 */
describe('doctor — OpenClaw managed-pin drift / disabled realtime plugin', () => {
  let home: string;
  const HASH = 'abc123';

  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocpins-')); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  function projectRoot(): string {
    return path.join(home, '.openclaw', 'npm', 'projects', `drakon-systems-shieldcortex-realtime-${HASH}`);
  }
  /** Write the generated project manifest + the nested plugin package (so the
   * install resolves) — the shape OpenClaw creates on disk. */
  function install(manifest: Record<string, unknown>): void {
    const root = projectRoot();
    const pkgDir = path.join(root, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '4.32.8' }));
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest, null, 2));
    // #260 r12: OpenClaw's install record names this copy, so it is the copy
    // OpenClaw selected and the repair's target check accepts this project.
    const plugins = path.join(home, '.openclaw', 'plugins');
    fs.mkdirSync(plugins, { recursive: true });
    fs.writeFileSync(path.join(plugins, 'installs.json'), JSON.stringify({ installRecords: { 'shieldcortex-realtime': { version: '4.32.8', installPath: pkgDir } } }));
  }
  function setEnabled(enabled: boolean): void {
    const dir = path.join(home, '.openclaw');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'openclaw.json'), JSON.stringify({ plugins: { entries: { 'shieldcortex-realtime': { enabled } } } }, null, 2));
  }

  it('skips (info) when ~/.openclaw does not exist', async () => {
    const r = await checkOpenClawManagedPinDrift(path.join(home, 'nope'));
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/skipped/i);
  });

  it('skips (info) when the realtime plugin is not installed', async () => {
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not installed/i);
  });

  it('passes when deps and overrides agree and the plugin is enabled', async () => {
    install({ dependencies: { hono: '4.12.21', shieldcortex: '4.32.8' }, overrides: { hono: '4.12.21' } });
    setEnabled(true);
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('pass');
  });

  it('warns when a managed pin has drifted from its override (pre-failure)', async () => {
    install({ dependencies: { hono: '4.12.23', shieldcortex: '4.32.8' }, overrides: { hono: '4.12.21' } });
    setEnabled(true);
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/EOVERRIDE/);
    expect(r.message).toContain('hono');
    expect(r.fix).toMatch(/shieldcortex openclaw repair/);
  });

  it('fails when the plugin has been auto-disabled', async () => {
    install({ dependencies: { hono: '4.12.23' }, overrides: { hono: '4.12.21' } });
    setEnabled(false);
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/disabled/i);
    expect(r.fix).toMatch(/shieldcortex openclaw repair/);
  });
});

/**
 * #260 r12 (Sol): the pin-drift row recommended `shieldcortex openclaw repair`
 * where that repair's own target check refuses. Doctor now asks the SAME
 * function (`managedManifestTarget`); when it refuses, the row gives
 * diagnostic advice only — no repair command, no host path.
 */
describe('#260 r12: doctor offers the managed-pin repair only where its target check accepts', () => {
  const ID = 'shieldcortex-realtime';
  const PKG = '@drakon-systems/shieldcortex-realtime';
  let home: string;
  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocpins-r12-')); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  const put = (file: string, text: string): void => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
  };
  /** A managed project holding the plugin at `version`, its manifest drifting (`peer` 1.0.0 vs override 2.0.0). */
  function project(name: string, version: string): { root: string; dir: string } {
    const root = path.join(home, '.openclaw', 'npm', 'projects', name);
    const dir = path.join(root, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    put(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version, main: './dist/index.js' }));
    put(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version }));
    put(path.join(dir, 'dist', 'index.js'), '');
    put(path.join(root, 'package.json'), JSON.stringify({ dependencies: { peer: '1.0.0' }, overrides: { peer: '2.0.0' } }));
    return { root, dir };
  }
  function indexSelects(selected: string, version: string): void {
    const dbPath = path.join(home, '.openclaw', 'state', 'openclaw.sqlite');
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    const db = new Database(dbPath);
    try {
      db.prepare('CREATE TABLE config_machine_state (state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)').run();
      db.prepare('INSERT INTO config_machine_state VALUES (?, ?, 1)').run('plugins.installedIndex', JSON.stringify({
        revision: 1,
        index: { generatedAtMs: 1, installRecords: { [ID]: { source: 'npm', version, installPath: selected } }, plugins: [{ pluginId: ID, enabled: true, rootDir: selected }] },
      }));
    } finally {
      db.close();
    }
  }
  function config(installsPath: string, enabled = true): void {
    put(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { allow: [ID], entries: { [ID]: { enabled } } } }));
    put(path.join(home, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({ installRecords: { [ID]: { version: '5.22.1', installPath: installsPath } } }));
  }
  const expectDiagnosticOnly = (fix: string | undefined, why: RegExp): void => {
    expect(fix).toBeDefined();
    expect(fix).not.toMatch(/shieldcortex openclaw repair/);
    expect(fix).toMatch(/Check it: `shieldcortex openclaw status`/);
    expect(fix).toMatch(why);
    expect(fix).not.toContain(home);
  };

  it('Sol\'s mismatch fixture (empty installs.json path; the index selects 5.22.1, the resolver a 5.23.0 project) — warn, no repair command', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', '5.22.1');
    project('drakon-systems-shieldcortex-realtime-bbb', '5.23.0');
    indexSelects(selected.dir, '5.22.1');
    config('');

    const r = await checkOpenClawManagedPinDrift(home);

    expect(r.status).toBe('warn');
    expectDiagnosticOnly(r.fix, /not the one holding the copy OpenClaw selected/);
    expect(r.needsOpenClawCli).toBeUndefined();
  });

  it('the same mismatch with the plugin disabled — fail, no repair command', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', '5.22.1');
    project('drakon-systems-shieldcortex-realtime-bbb', '5.23.0');
    indexSelects(selected.dir, '5.22.1');
    config('', false);

    const r = await checkOpenClawManagedPinDrift(home);

    expect(r.status).toBe('fail');
    expectDiagnosticOnly(r.fix, /not the one holding the copy OpenClaw selected/);
  });

  it('the verified project\'s package.json is a symlink into another project — warn, no repair command', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', '5.22.1');
    const other = project('other-managed-project', '5.23.0');
    fs.unlinkSync(path.join(selected.root, 'package.json'));
    fs.symlinkSync(path.join(other.root, 'package.json'), path.join(selected.root, 'package.json'));
    indexSelects(selected.dir, '5.22.1');
    config(selected.dir);

    const r = await checkOpenClawManagedPinDrift(home);

    expect(r.status).toBe('warn');
    expectDiagnosticOnly(r.fix, /package\.json is not a plain file/);
  });

  it('no record selects any copy — warn, no repair command (the repair refuses: no verified copy)', async () => {
    project('drakon-systems-shieldcortex-realtime-aaa', '5.22.1');
    put(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { allow: [ID], entries: { [ID]: { enabled: true } } } }));

    const r = await checkOpenClawManagedPinDrift(home);

    expect(r.status).toBe('warn');
    expectDiagnosticOnly(r.fix, /not the one holding the copy OpenClaw selected/);
  });

  it('matching control: the index and the resolver name the same project — the repair command is still offered', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', '5.22.1');
    indexSelects(selected.dir, '5.22.1');
    config(selected.dir);

    const r = await checkOpenClawManagedPinDrift(home);

    expect(r.status).toBe('warn');
    expect(r.fix).toMatch(/shieldcortex openclaw repair/);
    expect(r.needsOpenClawCli).toEqual({ subcommand: 'plugins' });
  });
});
