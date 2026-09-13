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

/** A host-valid roster entry: OpenClaw 2026.9.4 requires enabled, origin and rootDir. */
function entry(pluginId: string, enabled: boolean, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { pluginId, enabled, origin: 'global', rootDir: `/fixture/extensions/${pluginId}`, ...extra };
}

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
      plugins: [entry(PLUGIN, true)],
      warning: 'DO NOT EDIT',
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.installRecords[PLUGIN]?.version).toBe('4.47.2');
    expect(idx!.plugins.find((p) => p.pluginId === PLUGIN)?.enabled).toBe(true);
  });

  it('returns the most recent row when several exist', () => {
    writeIndex({ installRecords: {}, plugins: [entry(PLUGIN, false)], generatedAtMs: 1000 });
    const db = new Database(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'));
    db.prepare(`INSERT INTO installed_plugin_index VALUES ('newer',1,'v','x',1,'h',9999,'r',@ir,@pj,'[]',NULL,9999)`)
      .run({ ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: '4.47.2' } }), pj: JSON.stringify([entry(PLUGIN, true)]) });
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
      plugins: [entry(PLUGIN, true)],
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
      plugins: [entry(PLUGIN, true, { origin: 'npm' })],
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
    writeMigratedIndex({ installRecords: {}, plugins: [entry(PLUGIN, true)], updatedAtMs: 6161 });
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.generatedAtMs).toBe(6161);
    expect(idx!.warning).toBeNull();
  });

  it('both layouts present: the migrated config_machine_state row wins', () => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2', installPath: '/legacy' } },
      plugins: [entry(PLUGIN, false)],
      generatedAtMs: 9999999,
    });
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: '/migrated' } },
      plugins: [entry(PLUGIN, true)],
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
    // Nested entries — OpenClaw's parser validates every element; so do we for every field we read.
    ['plugin entry is null', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [null] } })],
    ['plugin entry is an array', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [[]] } })],
    ['plugin pluginId is a number', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [{ pluginId: 1 }] } })],
    ['plugin pluginId missing', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [{ enabled: true }] } })],
    ['plugin enabled is the string "true"', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [{ pluginId: 'shieldcortex-realtime', enabled: 'true' }] } })],
    ['plugin rootDir is a number', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [entry(PLUGIN, true, { rootDir: 7 })] } })],
    // Host-REQUIRED fields (OpenClaw 2026.9.4 InstalledPluginIndexRecordSchema): absent is invalid, not "unset".
    ['plugin enabled missing', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [{ pluginId: PLUGIN, origin: 'global', rootDir: '/r' }] } })],
    ['plugin origin missing', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [{ pluginId: PLUGIN, enabled: true, rootDir: '/r' }] } })],
    ['plugin rootDir missing', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [{ pluginId: PLUGIN, enabled: true, origin: 'global' }] } })],
    ['plugin origin is a number', JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [entry(PLUGIN, true, { origin: 1 })] } })],
    ['install record is null', JSON.stringify({ revision: 2000, index: { installRecords: { 'shieldcortex-realtime': null }, plugins: [] } })],
    ['install record is an array', JSON.stringify({ revision: 2000, index: { installRecords: { 'shieldcortex-realtime': [] }, plugins: [] } })],
    ['install record version is a number', JSON.stringify({ revision: 2000, index: { installRecords: { 'shieldcortex-realtime': { source: 'npm', version: 5 } }, plugins: [] } })],
    ['install record installPath is an object', JSON.stringify({ revision: 2000, index: { installRecords: { 'shieldcortex-realtime': { source: 'npm', installPath: {} } }, plugins: [] } })],
    // `source` is required and an enum (PluginInstallSourceSchema); it routes remediation.
    ['install record source missing', JSON.stringify({ revision: 2000, index: { installRecords: { 'shieldcortex-realtime': { version: '5.0.0' } }, plugins: [] } })],
    ['install record source outside the host enum', JSON.stringify({ revision: 2000, index: { installRecords: { 'shieldcortex-realtime': { source: 'npmjs', version: '5.0.0' } }, plugins: [] } })],
    ['install record source is a number', JSON.stringify({ revision: 2000, index: { installRecords: { 'shieldcortex-realtime': { source: 1 } }, plugins: [] } })],
    // Raw JSON: a `__proto__` record is an ordinary id and is validated like any other.
    ['__proto__ install record missing source', '{"revision":2000,"index":{"installRecords":{"__proto__":{"version":"5.0.0"}},"plugins":[]}}'],
  ];

  it.each(MALFORMED)('malformed migrated row (%s) alongside a valid legacy row → legacy row is read, not a readable empty index', (_label, valueJson) => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2', installPath: '/legacy' } },
      plugins: [entry(PLUGIN, true)],
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

  it('migrated-only `plugins:[null]` does not throw in the reconciler and is index-unreadable, not FAIL', () => {
    writeConfig(true, true);
    writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.0.0');
    writeMigratedRaw(JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [null] } }));
    const verdict = reconcilePluginState(
      gatherReconcileInput(home, { expectedVersion: '5.0.0', readLiveRoster: () => null }),
    );
    expect(verdict.indexReadable).toBe(false);
    expect(verdict.state).toBe('index-unreadable');
  });

  it('migrated-only `enabled:"true"` is not read as "present but disabled" → never enabled-not-loaded', () => {
    writeConfig(true, true);
    writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.0.0');
    writeMigratedRaw(
      JSON.stringify({ revision: 2000, index: { installRecords: {}, plugins: [{ pluginId: PLUGIN, enabled: 'true' }] } }),
    );
    const verdict = reconcilePluginState(
      gatherReconcileInput(home, { expectedVersion: '5.0.0', readLiveRoster: () => null }),
    );
    expect(verdict.state).toBe('index-unreadable');
    expect(verdict.recommendedAction).not.toBe('reinstall-pinned');
  });

  it('legacy row with malformed nested entries is unreadable too (same projection on both layouts)', () => {
    writeIndex({
      installRecords: { [PLUGIN]: null as unknown as Record<string, unknown> },
      plugins: [null, entry(PLUGIN, true)],
      generatedAtMs: 4242,
    });
    expect(readPluginInstallIndex(home)).toBeNull();
  });

  it('well-formed entries survive the projection with every consumed field intact', () => {
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', resolvedVersion: '5.0.0', installPath: '/p', extra: 1 } },
      plugins: [{ pluginId: PLUGIN, enabled: true, origin: 'global', rootDir: '/p', manifestPath: '/m' }],
      generatedAtMs: 77,
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).toEqual({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', resolvedVersion: '5.0.0', installPath: '/p' } },
      plugins: [{ pluginId: PLUGIN, enabled: true, origin: 'global', rootDir: '/p' }],
      warning: null,
      generatedAtMs: 77,
    });
  });

  const LEGACY_INVALID: Array<[string, Record<string, unknown>, unknown[]]> = [
    ['plugin enabled missing', { [PLUGIN]: { source: 'npm' } }, [{ pluginId: PLUGIN, origin: 'global', rootDir: '/r' }]],
    ['plugin origin missing', { [PLUGIN]: { source: 'npm' } }, [{ pluginId: PLUGIN, enabled: true, rootDir: '/r' }]],
    ['plugin rootDir missing', { [PLUGIN]: { source: 'npm' } }, [{ pluginId: PLUGIN, enabled: true, origin: 'global' }]],
    ['install record source missing', { [PLUGIN]: { version: '5.0.0' } }, [entry(PLUGIN, true)]],
    ['install record source outside the host enum', { [PLUGIN]: { source: 'registry' } }, [entry(PLUGIN, true)]],
  ];

  it.each(LEGACY_INVALID)('legacy-only row with %s → null (unreadable), same contract as the migrated row', (_label, installRecords, plugins) => {
    writeIndex({ installRecords, plugins, generatedAtMs: 4242 });
    expect(readPluginInstallIndex(home)).toBeNull();
  });

  it.each(['npm', 'archive', 'path', 'clawhub', 'git', 'marketplace'])('accepts host install source %s', (source) => {
    writeMigratedIndex({ installRecords: { [PLUGIN]: { source } }, plugins: [entry(PLUGIN, true)], generatedAtMs: 1 });
    expect(readPluginInstallIndex(home)?.installRecords[PLUGIN]).toEqual({ source });
  });

  it('accepts what the host accepts: empty pluginId, any origin string, unknown host metadata', () => {
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { source: 'npm', spec: 'x', integrity: 'sha', acceptedSurface: { channels: [] } } },
      plugins: [
        entry('', false),
        entry(PLUGIN, true, { origin: 'workspace-custom', manifestPath: '/m', startup: { sidecar: false }, compat: [] }),
      ],
      generatedAtMs: 1,
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.plugins.map((p) => p.pluginId)).toEqual(['', PLUGIN]);
    expect(idx!.plugins[1]).toEqual({ pluginId: PLUGIN, enabled: true, origin: 'workspace-custom', rootDir: `/fixture/extensions/${PLUGIN}` });
    expect(idx!.installRecords[PLUGIN]).toEqual({ source: 'npm' });
  });

  it('migrated-only row missing plugin `enabled` reconciles to index-unreadable (warn), never enabled-not-loaded (fail)', () => {
    writeConfig(true, true);
    writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.0.0');
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0' } },
      plugins: [{ pluginId: PLUGIN, origin: 'global', rootDir: '/r' }],
      generatedAtMs: 1,
    });
    const verdict = reconcilePluginState(
      gatherReconcileInput(home, { expectedVersion: '5.0.0', readLiveRoster: () => null }),
    );
    expect(verdict.indexReadable).toBe(false);
    expect(verdict.state).toBe('index-unreadable');
    expect(verdict.recommendedAction).toBe('none');
  });

  it('migrated-only record missing `source` is unreadable, not a readable untracked record routed to reinstall', () => {
    writeConfig(true, true);
    writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.0.0');
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { version: '5.0.0' } },
      plugins: [entry('brave', true)],
      generatedAtMs: 1,
    });
    const verdict = reconcilePluginState(
      gatherReconcileInput(home, { expectedVersion: '5.0.0', readLiveRoster: () => null }),
    );
    expect(verdict.state).toBe('index-unreadable');
    expect(verdict.recommendedAction).not.toBe('reinstall-pinned');
  });

  it('migrated row missing `enabled` + valid legacy row → the legacy row decides the verdict', () => {
    writeConfig(true, true);
    writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.0.0');
    writeIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0' } }, plugins: [entry(PLUGIN, true)], generatedAtMs: 4242 });
    writeMigratedIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0' } },
      plugins: [{ pluginId: PLUGIN, origin: 'global', rootDir: '/r' }],
      generatedAtMs: 1,
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.0.0', readLiveRoster: () => null });
    expect(input.index?.generatedAtMs).toBe(4242);
    const verdict = reconcilePluginState(input);
    expect(verdict.indexReadable).toBe(true);
    expect(verdict.loadedInIndex).toBe(true);
    expect(verdict.state).toBe('healthy');
  });

  describe('reserved plugin ids are ordinary own keys', () => {
    const rec = (v: string): string => `{"source":"npm","version":"${v}","installPath":"/p/${v}"}`;
    const plug = (id: string): string => JSON.stringify(entry(id, true));
    // Raw JSON text: an object literal `{ __proto__: … }` would not create an own key.
    const RESERVED_ROW =
      `{"revision":1,"index":{"generatedAtMs":5,"installRecords":{"__proto__":${rec('1.0.0')},"constructor":${rec('2.0.0')},"toString":${rec('3.0.0')}},` +
      `"plugins":[${plug('__proto__')},${plug('constructor')},${plug('toString')}]}}`;

    it('__proto__/constructor/toString records round-trip as own enumerable keys without touching the prototype', () => {
      writeMigratedRaw(RESERVED_ROW);
      const idx = readPluginInstallIndex(home);
      expect(idx).not.toBeNull();
      const records = idx!.installRecords;
      expect(Object.getPrototypeOf(records)).toBeNull();
      expect(Object.keys(records)).toEqual(['__proto__', 'constructor', 'toString']);
      expect(Object.keys(records).map((k) => records[k].version)).toEqual(['1.0.0', '2.0.0', '3.0.0']);
      expect(JSON.stringify(records)).toContain('"__proto__":{"source":"npm","version":"1.0.0"');
      expect(idx!.plugins.map((p) => p.pluginId)).toEqual(['__proto__', 'constructor', 'toString']);
    });

    it('end-to-end: an installed `__proto__` plugin reads its own record and verdict', () => {
      writeMigratedRaw(RESERVED_ROW);
      const verdict = reconcilePluginState({
        ...gatherReconcileInput(home, { pluginId: '__proto__', expectedVersion: '1.0.0', readLiveRoster: () => null }),
        config: { enabled: true, inAllow: true },
      });
      expect(verdict.indexReadable).toBe(true);
      expect(verdict.openClawTracked).toBe(true);
      expect(verdict.indexVersion).toBe('1.0.0');
      expect(verdict.state).toBe('healthy');
    });

    it('absent reserved ids never resolve to an inherited phantom record', () => {
      writeMigratedIndex({ installRecords: { [PLUGIN]: { source: 'npm' } }, plugins: [entry(PLUGIN, true)], generatedAtMs: 1 });
      const records = readPluginInstallIndex(home)!.installRecords;
      for (const id of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
        expect(records[id]).toBeUndefined();
      }
    });

    it.each(['constructor', 'toString', '__proto__'])(
      'reconciler: config enables absent `%s` with nothing installed → enabled-not-installed, not a phantom-installed FAIL',
      (id) => {
        const verdict = reconcilePluginState({
          pluginId: id,
          expectedVersion: '5.0.0',
          config: { enabled: true, inAllow: true },
          installsJson: null,
          // An ordinary object, as injected indexes are.
          index: { installRecords: {}, plugins: [] },
          onDiskVersion: null,
          liveRoster: null,
        });
        expect(verdict.state).toBe('enabled-not-installed');
        expect(verdict.recommendedAction).toBe('install');
      },
    );

    it('gather: installs.json and openclaw.json lookups for an absent `constructor` find nothing', () => {
      fs.mkdirSync(path.join(home, '.openclaw', 'plugins'), { recursive: true });
      fs.writeFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({ installRecords: {} }));
      fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { entries: {}, allow: [] } }));
      const input = gatherReconcileInput(home, { pluginId: 'constructor', expectedVersion: '5.0.0', readLiveRoster: () => null });
      expect(input.installsJson).toBeNull();
      expect(input.config.enabled).toBeNull();
    });
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
      plugins: [entry(PLUGIN, true)],
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
      plugins: [entry('brave', true)],
    });

    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '4.47.2' }));
    expect(verdict.state).toBe('enabled-not-loaded');
    expect(verdict.severity).toBe('fail');
    expect(verdict.recommendedAction).toBe('update-openclaw-tracked');
  });
});
