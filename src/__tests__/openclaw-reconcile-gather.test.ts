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

/**
 * A host-valid roster entry. OpenClaw 2026.9.4 `InstalledPluginIndexRecordSchema`
 * REQUIRES pluginId, manifestPath, manifestHash, rootDir, origin, enabled, startup
 * (sidecar, memory, agentHarnesses) and compat; everything else is optional.
 */
function entry(pluginId: string, enabled: boolean, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    pluginId,
    enabled,
    origin: 'global',
    rootDir: `/fixture/extensions/${pluginId}`,
    manifestPath: `/fixture/extensions/${pluginId}/openclaw.plugin.json`,
    manifestHash: 'sha256:m',
    startup: { sidecar: false, memory: false, agentHarnesses: [] },
    compat: [],
    ...extra,
  };
}

/**
 * A host-valid 2026.9.4 index object (`InstalledPluginIndexSchema`): version and
 * migrationVersion are literal 1; hostContractVersion, compatRegistryVersion,
 * policyHash, generatedAtMs, plugins and diagnostics are required; warning is an
 * optional STRING (null is rejected). Tests break exactly one field at a time.
 */
function hostIndex(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    warning: 'DO NOT EDIT',
    hostContractVersion: '2026.9.4',
    compatRegistryVersion: 'x',
    migrationVersion: 1,
    policyHash: 'h',
    generatedAtMs: 5,
    workspaceDir: '/w',
    refreshReason: 'r',
    installRecords: {},
    plugins: [],
    diagnostics: [],
    ...overrides,
  };
}

/** Host `InstalledPluginIndexContributionSchema`: eight string arrays + `contracts` record. */
const CONTRIBUTIONS_EMPTY = {
  channels: [],
  channelConfigs: [],
  providers: [],
  modelCatalogProviders: [],
  modelSupportPrefixes: [],
  modelSupportPatterns: [],
  autoEnableProviderIds: [],
  commandAliases: [],
  contracts: {},
};

/** Host `acceptedSurface` is `.strict()`: all ten arrays, nothing else. */
const FULL_ACCEPTED_SURFACE = {
  channels: [],
  providers: [],
  tools: [],
  contracts: [],
  hooks: [],
  mcpServers: [],
  cliCommands: [],
  cliBackends: [],
  skills: [],
  dangerousConfigFlags: [],
};

/** A host-valid `config_machine_state` wrapper: numeric `revision` + `index`. */
function wrap(index: unknown, revision: unknown = 2000): string {
  return JSON.stringify({ revision, index });
}

/** `hostIndex()` with one key removed. */
function hostIndexWithout(key: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const idx = hostIndex(overrides);
  delete idx[key];
  return idx;
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
  // Host-valid wrapper (the live 2026.9.4 row: version 1, migrationVersion 1,
  // warning a string when present, generatedAtMs always a number).
  const index = hostIndex({
    installRecords: row.installRecords,
    plugins: row.plugins,
    generatedAtMs: row.generatedAtMs ?? 1757980800000,
  });
  if (typeof row.warning === 'string') index.warning = row.warning;
  else delete index.warning;
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

  it('OpenClaw 2026.9.4: a migrated index without generatedAtMs is host-invalid → unreadable, not "fall back to updated_at_ms"', () => {
    writeMigratedRaw(wrap(hostIndexWithout('generatedAtMs', { plugins: [entry(PLUGIN, true)] })), 6161);
    expect(readPluginInstallIndex(home)).toBeNull();
  });

  it('OpenClaw 2026.9.4: an index with no `warning` key reads with warning null', () => {
    writeMigratedRaw(wrap(hostIndexWithout('warning', { plugins: [entry(PLUGIN, true)], generatedAtMs: 6161 })));
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    expect(idx!.generatedAtMs).toBe(6161);
    expect(idx!.warning).toBeNull();
  });

  it('OpenClaw 2026.9.4: no `installRecords` key → records rebuilt from each plugin `installRecord` (host fallback)', () => {
    writeMigratedRaw(
      wrap(
        hostIndexWithout('installRecords', {
          plugins: [entry(PLUGIN, true, { installRecord: { source: 'npm', version: '5.0.0', installPath: ' /p ' } })],
        }),
      ),
    );
    const idx = readPluginInstallIndex(home);
    expect(idx).not.toBeNull();
    // Host normalisation trims string fields.
    expect(idx!.installRecords[PLUGIN]).toEqual({ source: 'npm', version: '5.0.0', installPath: '/p' });
  });

  it('OpenClaw 2026.9.4: no `installRecords` key + an invalid plugin `installRecord` → unreadable', () => {
    writeMigratedRaw(
      wrap(hostIndexWithout('installRecords', { plugins: [entry(PLUGIN, true, { installRecord: { version: '5.0.0' } })] })),
    );
    expect(readPluginInstallIndex(home)).toBeNull();
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
    // ---- Full host contract (OpenClaw v2026.9.4 parser), one layer / one field at a time ----
    // The review probe: no wrapper revision, index missing every host-required field.
    ['review probe: no revision + host-required index fields missing', JSON.stringify({ index: { installRecords: {}, plugins: [], generatedAtMs: 1 } })],
    // Wrapper (`readPersistedInstalledPluginIndexSync`).
    ['wrapper: revision missing', JSON.stringify({ index: hostIndex() })],
    ['wrapper: revision is a string', wrap(hostIndex(), '2000')],
    ['wrapper: revision is null', wrap(hostIndex(), null)],
    ['wrapper: index key absent', JSON.stringify({ revision: 2000 })],
    ['wrapper: is an array', JSON.stringify([{ revision: 2000, index: hostIndex() }])],
    // Index (`InstalledPluginIndexSchema`).
    ['index: version is 2', wrap(hostIndex({ version: 2 }))],
    ['index: version missing', wrap(hostIndexWithout('version'))],
    ['index: migrationVersion is 13', wrap(hostIndex({ migrationVersion: 13 }))],
    ['index: migrationVersion missing', wrap(hostIndexWithout('migrationVersion'))],
    ['index: warning is null', wrap(hostIndex({ warning: null }))],
    ['index: hostContractVersion missing', wrap(hostIndexWithout('hostContractVersion'))],
    ['index: hostContractVersion is a number', wrap(hostIndex({ hostContractVersion: 2026 }))],
    ['index: compatRegistryVersion missing', wrap(hostIndexWithout('compatRegistryVersion'))],
    ['index: policyHash missing', wrap(hostIndexWithout('policyHash'))],
    ['index: generatedAtMs missing', wrap(hostIndexWithout('generatedAtMs'))],
    ['index: plugins missing', wrap(hostIndexWithout('plugins'))],
    ['index: diagnostics missing', wrap(hostIndexWithout('diagnostics'))],
    ['index: diagnostics is not an array', wrap(hostIndex({ diagnostics: {} }))],
    ['index: diagnostic level outside warn|error', wrap(hostIndex({ diagnostics: [{ level: 'info', message: 'm' }] }))],
    ['index: diagnostic message missing', wrap(hostIndex({ diagnostics: [{ level: 'warn' }] }))],
    ['index: workspaceDir is a number', wrap(hostIndex({ workspaceDir: 1 }))],
    ['index: refreshReason is an object', wrap(hostIndex({ refreshReason: {} }))],
    ['index: installRecords is null', wrap(hostIndex({ installRecords: null }))],
    ['index: installRecords is a string', wrap(hostIndex({ installRecords: 'x' }))],
    // Plugin entry (`InstalledPluginIndexRecordSchema`).
    ['plugin: manifestPath missing', wrap(hostIndex({ plugins: [(() => { const e = entry(PLUGIN, true); delete e.manifestPath; return e; })()] }))],
    ['plugin: manifestHash missing', wrap(hostIndex({ plugins: [(() => { const e = entry(PLUGIN, true); delete e.manifestHash; return e; })()] }))],
    ['plugin: startup missing', wrap(hostIndex({ plugins: [(() => { const e = entry(PLUGIN, true); delete e.startup; return e; })()] }))],
    ['plugin: compat missing', wrap(hostIndex({ plugins: [(() => { const e = entry(PLUGIN, true); delete e.compat; return e; })()] }))],
    ['plugin: startup.memory missing', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { startup: { sidecar: false, agentHarnesses: [] } })] }))],
    ['plugin: startup.sidecar is a string', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { startup: { sidecar: 'no', memory: false, agentHarnesses: [] } })] }))],
    ['plugin: startup.agentHarnesses holds a number', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { startup: { sidecar: false, memory: false, agentHarnesses: [1] } })] }))],
    ['plugin: startup.configPaths is a string', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { startup: { sidecar: false, memory: false, agentHarnesses: [], configPaths: 'x' } })] }))],
    ['plugin: compat holds a number', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { compat: [1] })] }))],
    ['plugin: manifestPath is a number', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { manifestPath: 1 })] }))],
    ['plugin: installOwnerAmbiguous is false', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { installOwnerAmbiguous: false })] }))],
    ['plugin: packageJson missing hash', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { packageJson: { path: '/p' } })] }))],
    ['plugin: manifestFile.size is a string', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { manifestFile: { size: '1', mtimeMs: 1 } })] }))],
    ['plugin: enabledByDefault is a string', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { enabledByDefault: 'yes' })] }))],
    ['plugin: contributions missing contracts', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { contributions: { channels: [], channelConfigs: [], providers: [], modelCatalogProviders: [], modelSupportPrefixes: [], modelSupportPatterns: [], autoEnableProviderIds: [], commandAliases: [] } })] }))],
    ['plugin: installRecord source missing', wrap(hostIndex({ plugins: [entry(PLUGIN, true, { installRecord: { version: '1' } })] }))],
    // Install record (`PluginInstallRecordShape`): optional fields are still typed.
    ['record: spec is a number', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'npm', spec: 1 } } }))],
    ['record: clawhubFamily outside the enum', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'clawhub', clawhubFamily: 'skill' } } }))],
    ['record: clawhubChannel outside the enum', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'clawhub', clawhubChannel: 'beta' } } }))],
    ['record: clawhubTrustReasons holds a number', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'clawhub', clawhubTrustReasons: [1] } } }))],
    ['record: clawpackSize negative', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'archive', clawpackSize: -1 } } }))],
    ['record: clawpackSpecVersion fractional', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'archive', clawpackSpecVersion: 1.5 } } }))],
    ['record: artifactKind outside the enum', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'archive', artifactKind: 'tar' } } }))],
    ['record: acceptedSurface missing keys', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'npm', acceptedSurface: { channels: [] } } } }))],
    ['record: acceptedSurface has an unknown key (strict)', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'npm', acceptedSurface: { ...FULL_ACCEPTED_SURFACE, extra: [] } } } }))],
    ['record: acceptedSurface.tools holds an empty string', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'npm', acceptedSurface: { ...FULL_ACCEPTED_SURFACE, tools: [''] } } } }))],
    ['record: one valid + one invalid → whole map rejected', wrap(hostIndex({ installRecords: { [PLUGIN]: { source: 'npm' }, other: { source: 'nope' } } }))],
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
      plugins: [entry(PLUGIN, true, { rootDir: '/p', manifestPath: '/m', packageName: '@x/y' })],
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
      installRecords: {
        [PLUGIN]: { source: 'npm', spec: 'x', integrity: 'sha', acceptedSurface: FULL_ACCEPTED_SURFACE, unknownHostField: { a: 1 } },
      },
      plugins: [
        entry('', false),
        entry(PLUGIN, true, {
          origin: 'workspace-custom',
          manifestPath: '/m',
          startup: { sidecar: true, memory: true, agentHarnesses: ['claude'], configPaths: ['/c'] },
          compat: ['2026.9'],
          contributions: { ...CONTRIBUTIONS_EMPTY, providers: ['p'] },
          diagnosticsIgnoredUnknownKey: 1,
        }),
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
    // Host-valid index around the reserved ids; `installRecords` spliced in as raw text.
    const RESERVED_ROW = wrap(
      hostIndex({ installRecords: '__RAW_RECORDS__', plugins: [] }),
      1,
    )
      .replace('"__RAW_RECORDS__"', `{"__proto__":${rec('1.0.0')},"constructor":${rec('2.0.0')},"toString":${rec('3.0.0')}}`)
      .replace('"plugins":[]', `"plugins":[${plug('__proto__')},${plug('constructor')},${plug('toString')}]`);

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
