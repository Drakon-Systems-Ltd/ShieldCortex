/**
 * #260 round 11 (Sol): `repairOpenClawManagedPins` rewrites the managed
 * project manifest the DISK RESOLVER chose (`resolveRealtimeProjectDir`), but
 * its replacement preflight approves the copy OpenClaw SELECTED. With an empty
 * installs.json `installPath`, the SQLite index selected the current copy and
 * the resolver chose a different, newer project — whose package.json the
 * repair then backed up and rewrote.
 *
 * The write target is now bound to the copy the preflight verified (real
 * paths compared): a disagreement, or no verified copy in a managed project,
 * refuses with nothing written. Both SQLite index layouts.
 *
 * Nothing here runs `openclaw`: PATH is an empty folder, so a repair that
 * proceeds stops at "`openclaw` is not on PATH", after its manifest writes.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import semver from 'semver';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { repairOpenClawManagedPins } from '../openclaw.js';

const ID = 'shieldcortex-realtime';
const PKG = '@drakon-systems/shieldcortex-realtime';
const SELF = (): string => JSON.parse(
  fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
).version;

let home: string;
let prevPath: string | undefined;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-260-pins-'));
  prevPath = process.env.PATH;
  const emptyBin = path.join(home, 'empty-bin');
  fs.mkdirSync(emptyBin);
  process.env.PATH = emptyBin;
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  process.env.PATH = prevPath;
  fs.rmSync(home, { recursive: true, force: true });
});

const put = (file: string, text: string): void => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
};
const projects = (): string => path.join(home, '.openclaw', 'npm', 'projects');

/** A managed project holding the plugin at `version`; returns its plugin dir. */
function project(name: string, version: string, peer: string): { root: string; dir: string } {
  const root = path.join(projects(), name);
  const dir = path.join(root, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
  put(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version, main: './dist/index.js' }));
  put(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version }));
  put(path.join(dir, 'dist', 'index.js'), '');
  // A peer pin co-present in overrides, so the heal has work (`peer: '1.0.0'` also drifts).
  put(path.join(root, 'package.json'), JSON.stringify({ dependencies: { peer }, overrides: { peer: '2.0.0' } }));
  return { root, dir };
}

function writeIndex(layout: 'new' | 'legacy', selected: string, version: string): void {
  const dbPath = path.join(home, '.openclaw', 'state', 'openclaw.sqlite');
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const records = { [ID]: { source: 'npm', version, installPath: selected } };
  const plugins = [{ pluginId: ID, enabled: true, rootDir: selected }];
  const db = new Database(dbPath);
  try {
    if (layout === 'new') {
      db.prepare('CREATE TABLE config_machine_state (state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)').run();
      db.prepare('INSERT INTO config_machine_state VALUES (?, ?, 1)')
        .run('plugins.installedIndex', JSON.stringify({ revision: 1, index: { generatedAtMs: 1, installRecords: records, plugins } }));
    } else {
      db.prepare('CREATE TABLE installed_plugin_index (index_key TEXT PRIMARY KEY, generated_at_ms INTEGER, install_records_json TEXT, plugins_json TEXT, warning TEXT)').run();
      db.prepare('INSERT INTO installed_plugin_index VALUES (?, 1, ?, ?, NULL)')
        .run('installed-plugin-index', JSON.stringify(records), JSON.stringify(plugins));
    }
  } finally {
    db.close();
  }
}

function baseConfig(installsPath?: string): void {
  put(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { allow: [ID], entries: { [ID]: { enabled: true } } } }));
  if (installsPath !== undefined) {
    put(path.join(home, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({ installRecords: { [ID]: { version: SELF(), installPath: installsPath } } }));
  }
}

const backups = (root: string): string[] => fs.readdirSync(root).filter((f) => f.includes('.repair-backup-'));

describe.each(['new', 'legacy'] as const)('#260 r11: managed-pin repair writes only the verified copy\'s project (%s index layout)', (layout) => {
  it('Sol repro: empty installs.json path, the index selects the current copy, the resolver a newer project — refused, nothing written', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '2.0.0');
    const newer = project('drakon-systems-shieldcortex-realtime-bbb', semver.inc(SELF(), 'minor')!, '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig('');
    const before = [selected.root, newer.root].map((r) => fs.readFileSync(path.join(r, 'package.json')));

    const result = await repairOpenClawManagedPins(home);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/plugin folders disagree/);
    expect(result.message).toMatch(/nothing was changed/);
    // Round 8: no raw path in the guidance.
    expect(result.message).not.toContain(home);
    expect([selected.root, newer.root].map((r) => fs.readFileSync(path.join(r, 'package.json')))).toEqual(before);
    expect(backups(selected.root)).toEqual([]);
    expect(backups(newer.root)).toEqual([]);
  });

  it('control: the resolver and the index name the same project — the repair proceeds as before', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);

    const result = await repairOpenClawManagedPins(home);

    // It rewrote the manifest (co-present pin stripped, backup kept), then
    // stopped only because no `openclaw` is on this test's PATH.
    expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
    expect(backups(selected.root)).toHaveLength(1);
    const after = JSON.parse(fs.readFileSync(path.join(selected.root, 'package.json'), 'utf-8')) as { dependencies: Record<string, string> };
    expect(after.dependencies.peer).toBeUndefined();
  });

  it('control: the index names the copy through a symlink to that same folder — the repair proceeds', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    const link = path.join(home, 'linked-copy');
    fs.symlinkSync(selected.dir, link);
    writeIndex(layout, link, SELF());
    baseConfig();

    const result = await repairOpenClawManagedPins(home);

    expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
    expect(backups(selected.root)).toHaveLength(1);
  });

  it('control: a symlinked HOME — both sides compared as real paths — the repair proceeds', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const aliasHome = path.join(os.tmpdir(), `${path.basename(home)}-alias`);
    fs.symlinkSync(home, aliasHome);
    try {
      const result = await repairOpenClawManagedPins(aliasHome);
      expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
      expect(backups(selected.root)).toHaveLength(1);
    } finally {
      fs.unlinkSync(aliasHome);
    }
  });
});

describe('#260 r11: no verified copy in a managed project — refused, nothing written', () => {
  it('no record selects a copy (preflight: none), a managed project on disk — refused', async () => {
    const onlyOnDisk = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    baseConfig();
    const before = fs.readFileSync(path.join(onlyOnDisk.root, 'package.json'));

    const result = await repairOpenClawManagedPins(home);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/plugin folders disagree/);
    expect(fs.readFileSync(path.join(onlyOnDisk.root, 'package.json'))).toEqual(before);
    expect(backups(onlyOnDisk.root)).toEqual([]);
  });

  it('the selected copy lives outside every managed project — refused', async () => {
    const managed = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    const elsewhere = path.join(home, 'elsewhere', 'shieldcortex-realtime');
    put(path.join(elsewhere, 'package.json'), JSON.stringify({ name: PKG, version: SELF(), main: './dist/index.js' }));
    put(path.join(elsewhere, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: SELF() }));
    put(path.join(elsewhere, 'dist', 'index.js'), '');
    writeIndex('new', elsewhere, SELF());
    baseConfig();

    const result = await repairOpenClawManagedPins(home);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/plugin folders disagree/);
    expect(backups(managed.root)).toEqual([]);
  });
});
