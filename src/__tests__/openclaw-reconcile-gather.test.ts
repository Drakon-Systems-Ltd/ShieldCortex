import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import {
  gatherReconcileInput,
  readPluginInstallIndex,
  readPluginInstallIndexState,
  reconcilePluginState,
} from '../integrations/openclaw-plugin-index.js';

/**
 * Disk-level tests for the reconciler's input gathering — fully isolated in a
 * temp HOME (never ~/.openclaw). Proves the gatherer reads the three layers
 * off disk and that the SQLite reader parses a real index row, then that the
 * end-to-end (gather → reconcile) reproduces the #74 silent-drop verdict.
 */
const PLUGIN = 'shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');

let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-reconcile-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function writeConfig(enabled: boolean | null, inAllow: boolean): void {
  const dir = path.join(home, '.openclaw');
  fs.mkdirSync(dir, { recursive: true });
  const entries: Record<string, unknown> = {};
  if (enabled !== null) entries[PLUGIN] = { enabled };
  fs.writeFileSync(
    path.join(dir, 'openclaw.json'),
    JSON.stringify({ plugins: { entries, allow: inAllow ? [PLUGIN] : [] } }),
  );
}

function writeInstallsJson(version: string, installPath: string): void {
  const dir = path.join(home, '.openclaw', 'plugins');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'installs.json'),
    JSON.stringify({ installRecords: { [PLUGIN]: { version, installPath } } }),
  );
}

function writeProjectDir(dirName: string, version: string): string {
  const pkgDir = path.join(home, '.openclaw', 'npm', 'projects', dirName, PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version }));
  return pkgDir;
}

function writeIndex(row: {
  installRecords: Record<string, unknown>;
  plugins: unknown[];
  warning?: string | null;
  generatedAtMs?: number;
}): void {
  const stateDir = path.join(home, '.openclaw', 'state');
  fs.mkdirSync(stateDir, { recursive: true });
  const db = new Database(path.join(stateDir, 'openclaw.sqlite'));
  db.exec(`CREATE TABLE installed_plugin_index (
    index_key TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL,
    host_contract_version TEXT NOT NULL, compat_registry_version TEXT NOT NULL,
    migration_version INTEGER NOT NULL, policy_hash TEXT NOT NULL,
    generated_at_ms INTEGER NOT NULL, refresh_reason TEXT,
    install_records_json TEXT NOT NULL, plugins_json TEXT NOT NULL,
    diagnostics_json TEXT NOT NULL, warning TEXT, updated_at_ms INTEGER NOT NULL);`);
  db.prepare(
    `INSERT INTO installed_plugin_index VALUES (@k,1,'2026.6.11','x',1,'h',@g,'r',@ir,@pj,'[]',@w,@g)`,
  ).run({
    k: 'installed-plugin-index',
    g: row.generatedAtMs ?? 1752230565000,
    ir: JSON.stringify(row.installRecords),
    pj: JSON.stringify(row.plugins),
    w: row.warning ?? null,
  });
  db.close();
}

describe('readPluginInstallIndex — parses the latest SQLite row', () => {
  it('reads install records + loaded roster from a real index DB', () => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2', installPath: '/x' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      warning: 'DO NOT EDIT',
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.installRecords[PLUGIN]?.version).toBe('4.47.2');
    expect(idx!.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
  });

  it('returns the most recent row when several exist', () => {
    writeIndex({ installRecords: {}, plugins: [{ pluginId: PLUGIN, enabled: false }], generatedAtMs: 1000 });
    const db = new Database(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'));
    db.prepare(`INSERT INTO installed_plugin_index VALUES ('newer',1,'v','x',1,'h',9999,'r',@ir,@pj,'[]',NULL,9999)`)
      .run({ ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: '4.47.2' } }), pj: JSON.stringify([{ pluginId: PLUGIN, enabled: true }]) });
    db.close();
    const idx = readPluginInstallIndex(home);
    expect(idx!.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
  });

  it('returns null when no DB exists', () => {
    expect(readPluginInstallIndex(home)).toBeNull();
  });
});

/**
 * OpenClaw 2026.11.x layout (#260): the index is one `config_machine_state`
 * row, `plugins.installedIndex`, whose value_json is `{ revision, index }`.
 * The migration that writes it DROPS `installed_plugin_index`. `valueJson`
 * overrides the stored text (malformed / wrong-shape rows); `null` writes the
 * table with no index row.
 */
function writeMachineStateIndex(
  row: { installRecords: unknown; plugins: unknown; warning?: string | null; generatedAtMs?: number } | null,
  valueJson?: string,
): void {
  const stateDir = path.join(home, '.openclaw', 'state');
  fs.mkdirSync(stateDir, { recursive: true });
  const db = new Database(path.join(stateDir, 'openclaw.sqlite'));
  db.exec(`CREATE TABLE IF NOT EXISTS config_machine_state (
    state_key TEXT NOT NULL PRIMARY KEY, value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL);`);
  db.prepare(`INSERT INTO config_machine_state VALUES ('some.other.state', '{"revision":1}', 1)`).run();
  if (row !== null || valueJson !== undefined) {
    const g = row?.generatedAtMs ?? 1763000000000;
    const value =
      valueJson ??
      JSON.stringify({
        revision: g,
        index: {
          version: 1,
          ...(row!.warning != null ? { warning: row!.warning } : {}),
          hostContractVersion: '2026.11.10',
          compatRegistryVersion: 'x',
          migrationVersion: 1,
          policyHash: 'h',
          generatedAtMs: g,
          installRecords: row!.installRecords,
          plugins: row!.plugins,
          diagnostics: [],
        },
      });
    db.prepare(`INSERT INTO config_machine_state VALUES ('plugins.installedIndex', ?, ?)`).run(value, g);
  }
  db.close();
}

describe('#260 — the install index in config_machine_state (OpenClaw 2026.11.x)', () => {
  it('migrated layout (no legacy table): both readers return the index', () => {
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: '/x' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      warning: 'DO NOT EDIT',
      generatedAtMs: 1763111111111,
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).toEqual({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: '/x' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      warning: 'DO NOT EDIT',
      generatedAtMs: 1763111111111,
    });
    expect(readPluginInstallIndexState(home)).toEqual({ state: 'ok', row: idx });
  });

  it('no warning in the stored index reads as null', () => {
    writeMachineStateIndex({ installRecords: {}, plugins: [] });
    expect(readPluginInstallIndex(home)!.warning).toBeNull();
  });

  it('both layouts present (mid-migration): config_machine_state wins', () => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2' } },
      plugins: [{ pluginId: PLUGIN, enabled: false }],
    });
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
    });
    expect(readPluginInstallIndex(home)!.installRecords[PLUGIN]?.version).toBe('5.22.1');
    const st = readPluginInstallIndexState(home);
    expect(st.state).toBe('ok');
    expect(st.state === 'ok' && st.row.plugins[0]?.enabled).toBe(true);
  });

  it('config_machine_state without the index row falls back to the legacy table', () => {
    writeIndex({ installRecords: { [PLUGIN]: { version: '4.47.2' } }, plugins: [{ pluginId: PLUGIN, enabled: true }] });
    writeMachineStateIndex(null);
    expect(readPluginInstallIndex(home)!.installRecords[PLUGIN]?.version).toBe('4.47.2');
    expect(readPluginInstallIndexState(home).state).toBe('ok');
  });

  it('config_machine_state without the index row and no legacy table: null / absent', () => {
    writeMachineStateIndex(null);
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toEqual({ state: 'absent' });
  });

  it.each([
    ['malformed JSON', '{"revision": 1, "index": {'],
    ['no index object', JSON.stringify({ revision: 1 })],
    ['a non-object value', JSON.stringify('nope')],
    ['installRecords is an array', JSON.stringify({ revision: 1, index: { installRecords: [], plugins: [] } })],
    ['installRecords is missing', JSON.stringify({ revision: 1, index: { plugins: [] } })],
    ['plugins is not an array', JSON.stringify({ revision: 1, index: { installRecords: {}, plugins: {} } })],
  ])('an index row with %s is unreadable, never absent and never an empty index', (_label, valueJson) => {
    writeMachineStateIndex(null, valueJson);
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toMatchObject({ state: 'unreadable', why: expect.any(String) });
  });

  it('a malformed new row is not papered over by a leftover legacy table', () => {
    writeIndex({ installRecords: { [PLUGIN]: { version: '4.47.2' } }, plugins: [{ pluginId: PLUGIN, enabled: true }] });
    writeMachineStateIndex(null, 'not json');
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
  });

  it('reading never writes to the state DB', () => {
    writeMachineStateIndex({ installRecords: {}, plugins: [] });
    const dbPath = path.join(home, '.openclaw', 'state', 'openclaw.sqlite');
    const before = fs.readFileSync(dbPath);
    readPluginInstallIndex(home);
    readPluginInstallIndexState(home);
    expect(fs.readFileSync(dbPath).equals(before)).toBe(true);
  });

  it('end-to-end on a migrated macOS-like host (no live roster): NOT index-unreadable', () => {
    writeConfig(true, true);
    const canonical = 'drakon-systems-shieldcortex-realtime-abc';
    const installPath = writeProjectDir(canonical, '5.22.1');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.index).not.toBeNull();
    const verdict = reconcilePluginState(input);
    expect(verdict.state).not.toBe('index-unreadable');
    expect(verdict.indexReadable).toBe(true);
    expect(verdict.loadedInIndex).toBe(true);
  });
});

describe('gatherReconcileInput — reads all three layers off disk', () => {
  it('assembles config + installs.json + on-disk version + project dirs + index', () => {
    writeConfig(true, true);
    const canonical = 'drakon-systems-shieldcortex-realtime-abc';
    const installPath = writeProjectDir(canonical, '4.47.2');
    writeInstallsJson('4.47.2', installPath);
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2', installPath } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
    });

    const input = gatherReconcileInput(home, { expectedVersion: '4.47.2' });
    expect(input.config.enabled).toBe(true);
    expect(input.config.inAllow).toBe(true);
    expect(input.installsJson?.version).toBe('4.47.2');
    expect(input.onDiskVersion).toBe('4.47.2');
    expect(input.projectDirs).toContain(canonical);
    expect(input.index?.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
  });

  it('end-to-end reproduces the #74 silent drop: enabled in config, absent from roster', () => {
    writeConfig(true, true);
    const canonical = 'drakon-systems-shieldcortex-realtime-abc';
    const installPath = writeProjectDir(canonical, '4.47.2');
    writeInstallsJson('4.47.2', installPath);
    // Roster omits shieldcortex-realtime — the drop.
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2', installPath } },
      plugins: [{ pluginId: 'brave', enabled: true }],
    });

    const unread = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '4.47.2', readLiveRoster: () => null }));
    expect(unread.state).toBe('load-unproven');
    expect(unread.severity).toBe('warn');
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '4.47.2', readLiveRoster: () => ['brave'] }));
    expect(verdict.state).toBe('enabled-not-loaded');
    expect(verdict.severity).toBe('fail');
    expect(verdict.recommendedAction).toBe('update-openclaw-tracked');
  });
});
