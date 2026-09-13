import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import {
  gatherReconcileInput,
  readPluginInstallIndex,
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

/**
 * OpenClaw 2026.9.4 layout: migration `state-consolidation-v13` moved the
 * index into `config_machine_state` under `plugins.installedIndex` and
 * dropped `installed_plugin_index`. `value_json` wraps the old row's fields
 * in `{ revision, index: {...} }`.
 */
function writeMigratedIndex(row: {
  installRecords: Record<string, unknown>;
  plugins: unknown[];
  warning?: string | null;
  generatedAtMs?: number;
  updatedAtMs?: number;
}): void {
  const stateDir = path.join(home, '.openclaw', 'state');
  fs.mkdirSync(stateDir, { recursive: true });
  const db = new Database(path.join(stateDir, 'openclaw.sqlite'));
  db.exec(`CREATE TABLE IF NOT EXISTS config_machine_state (
    state_key TEXT NOT NULL PRIMARY KEY, value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL);`);
  const updatedAtMs = row.updatedAtMs ?? 1757980800000;
  const index: Record<string, unknown> = {
    version: 1,
    warning: row.warning ?? null,
    hostContractVersion: '2026.9.4',
    compatRegistryVersion: 'x',
    migrationVersion: 13,
    policyHash: 'h',
    workspaceDir: '/w',
    refreshReason: 'r',
    installRecords: row.installRecords,
    plugins: row.plugins,
    diagnostics: [],
  };
  if (row.generatedAtMs !== undefined) index.generatedAtMs = row.generatedAtMs;
  db.prepare(`INSERT INTO config_machine_state VALUES ('plugins.installedIndex', @v, @u)`).run({
    v: JSON.stringify({ revision: updatedAtMs, index }),
    u: updatedAtMs,
  });
  db.close();
}

/** Write a raw `plugins.installedIndex` row so malformed shapes can be exercised. */
function writeMigratedRaw(valueJson: string, updatedAtMs = 2000): void {
  const stateDir = path.join(home, '.openclaw', 'state');
  fs.mkdirSync(stateDir, { recursive: true });
  const db = new Database(path.join(stateDir, 'openclaw.sqlite'));
  db.exec(`CREATE TABLE IF NOT EXISTS config_machine_state (
    state_key TEXT NOT NULL PRIMARY KEY, value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL);`);
  db.prepare(`INSERT INTO config_machine_state VALUES ('plugins.installedIndex', @v, @u)`).run({ v: valueJson, u: updatedAtMs });
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

  it('legacy layout: a DB with ONLY installed_plugin_index still reads the row', () => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: '/legacy' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      warning: 'legacy-warning',
      generatedAtMs: 4242,
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.installRecords[PLUGIN]?.installPath).toBe('/legacy');
    expect(idx!.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
    expect(idx!.warning).toBe('legacy-warning');
    expect(idx!.generatedAtMs).toBe(4242);
  });

  it('OpenClaw 2026.9.4: reads the migrated config_machine_state row when installed_plugin_index is gone', () => {
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: '/migrated' } },
      plugins: [{ pluginId: PLUGIN, enabled: true, origin: 'npm' }],
      warning: 'migrated-warning',
      generatedAtMs: 5151,
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.installRecords[PLUGIN]?.version).toBe('5.0.0');
    expect(idx!.installRecords[PLUGIN]?.installPath).toBe('/migrated');
    expect(idx!.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
    expect(idx!.warning).toBe('migrated-warning');
    expect(idx!.generatedAtMs).toBe(5151);
  });

  it('OpenClaw 2026.9.4: falls back to updated_at_ms when the migrated index carries no generatedAtMs', () => {
    writeMigratedIndex({ installRecords: {}, plugins: [{ pluginId: PLUGIN, enabled: true }], updatedAtMs: 6161 });
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.generatedAtMs).toBe(6161);
    expect(idx!.warning).toBeNull();
  });

  it('both layouts present: the migrated config_machine_state row wins', () => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2', installPath: '/legacy' } },
      plugins: [{ pluginId: PLUGIN, enabled: false }],
      generatedAtMs: 9999999,
    });
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: '/migrated' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      generatedAtMs: 1,
    });
    const idx = readPluginInstallIndex(home);
    expect(idx!.installRecords[PLUGIN]?.installPath).toBe('/migrated');
    expect(idx!.installRecords[PLUGIN]?.version).toBe('5.0.0');
    expect(idx!.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
    expect(idx!.generatedAtMs).toBe(1);
  });

  const MALFORMED: Array<[string, string]> = [
    ['index is an array', JSON.stringify({ revision: 2000, index: [] })],
    ['index is a string', JSON.stringify({ revision: 2000, index: 'bad' })],
    ['plugins is not an array', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: 'bad' } })],
    ['installRecords is an array', JSON.stringify({ revision: 2000, index: { installRecords: [], plugins: [] } })],
    ['warning has the wrong type', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [], warning: 7 } })],
    ['generatedAtMs has the wrong type', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [], generatedAtMs: 'x' } })],
    ['value_json is not JSON', '{not json'],
  ];

  it.each(MALFORMED)('malformed migrated row (%s) alongside a valid legacy row → legacy row is read, not a readable empty index', (_label, valueJson) => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2', installPath: '/legacy' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      generatedAtMs: 4242,
    });
    writeMigratedRaw(valueJson);
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.installRecords[PLUGIN]?.installPath).toBe('/legacy');
    expect(idx!.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
    expect(idx!.generatedAtMs).toBe(4242);
  });

  it.each(MALFORMED)('malformed migrated row (%s) with no legacy table → null (unreadable), never an empty index', (_label, valueJson) => {
    writeMigratedRaw(valueJson);
    expect(readPluginInstallIndex(home)).toBeNull();
  });

  it('malformed migrated-only row reconciles to index-unreadable (warn), never enabled-not-loaded (fail)', () => {
    writeConfig(true, true);
    const canonical = 'drakon-systems-shieldcortex-realtime-abc';
    writeProjectDir(canonical, '5.0.0');
    writeMigratedRaw(JSON.stringify({ revision: 2000, index: [] }));
    const verdict = reconcilePluginState(
      gatherReconcileInput(home, { expectedVersion: '5.0.0', readLiveRoster: () => null }),
    );
    expect(verdict.indexReadable).toBe(false);
    expect(verdict.state).toBe('index-unreadable');
    expect(verdict.severity).toBe('warn');
    expect(verdict.state).not.toBe('enabled-not-loaded');
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

    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '4.47.2' }));
    expect(verdict.state).toBe('enabled-not-loaded');
    expect(verdict.severity).toBe('fail');
    expect(verdict.recommendedAction).toBe('update-openclaw-tracked');
  });
});
