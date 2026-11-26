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
    expect(input.indexInstallPathExists).toBe(true);
    const verdict = reconcilePluginState(input);
    expect(verdict.state).toBe('healthy');
    expect(verdict.severity).toBe('ok');
    expect(verdict.indexReadable).toBe(true);
    expect(verdict.loadedInIndex).toBe(true);
  });
});

/**
 * #260 round 2 — one bad entry makes the whole index unreadable, in both
 * layouts (OpenClaw's own parsePluginInstallRecordMap rejects the whole map).
 */
describe('#260 r2 — install-index ENTRIES are validated, not just their containers', () => {
  const BAD_ENTRIES: Array<[string, { installRecords: Record<string, unknown>; plugins: unknown[] }]> = [
    ['a null install record', { installRecords: { [PLUGIN]: null }, plugins: [] }],
    ['a string install record', { installRecords: { other: 'npm' }, plugins: [] }],
    ['an array install record', { installRecords: { [PLUGIN]: [] }, plugins: [] }],
    ['a null plugins entry', { installRecords: {}, plugins: [null] }],
    ['a plugins entry with no pluginId', { installRecords: {}, plugins: [{ enabled: true }] }],
    ['a plugins entry with a non-string pluginId', { installRecords: {}, plugins: [{ pluginId: 7 }] }],
    // #260 r3: a field we select on, present with the wrong type (OpenClaw's
    // record schema is string().optional() for each).
    ['a numeric installPath', { installRecords: { [PLUGIN]: { source: 'npm', installPath: 37, version: '6.0.0' } }, plugins: [] }],
    ['a null installPath', { installRecords: { [PLUGIN]: { source: 'npm', installPath: null } }, plugins: [] }],
    ['an object version', { installRecords: { [PLUGIN]: { source: 'npm', version: { major: 6 } } }, plugins: [] }],
    ['a numeric resolvedVersion', { installRecords: { [PLUGIN]: { source: 'npm', resolvedVersion: 6 } }, plugins: [] }],
    ['a numeric source', { installRecords: { [PLUGIN]: { source: 1, version: '6.0.0' } }, plugins: [] }],
    ['a null source', { installRecords: { [PLUGIN]: { source: null } }, plugins: [] }],
    ['an array sourcePath', { installRecords: { [PLUGIN]: { source: 'path', sourcePath: ['/x'] } }, plugins: [] }],
    ['a bad field on ANOTHER plugin\'s record', { installRecords: { [PLUGIN]: { source: 'npm' }, other: { source: 'npm', installPath: 37 } }, plugins: [] }],
  ];

  it('string-typed and absent record fields stay readable', () => {
    writeMachineStateIndex({
      installRecords: {
        [PLUGIN]: { source: 'npm', installPath: '/x', version: '5.22.1', resolvedVersion: '5.22.1' },
        bare: {},
        linked: { source: 'path', sourcePath: '/y', somethingElse: 3 },
      },
      plugins: [],
    });
    expect(readPluginInstallIndexState(home).state).toBe('ok');
    expect(readPluginInstallIndex(home)).not.toBeNull();
  });

  it.each(BAD_ENTRIES)('new layout: %s ⇒ null / unreadable (never ok, never absent)', (_label, row) => {
    writeMachineStateIndex(row);
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toMatchObject({ state: 'unreadable', why: expect.any(String) });
  });

  it.each(BAD_ENTRIES)('legacy layout: %s ⇒ null / unreadable (never ok, never absent)', (_label, row) => {
    writeIndex(row);
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toMatchObject({ state: 'unreadable', why: expect.any(String) });
  });

  it('legacy layout: a column that does not parse still reads as empty for the diagnosis reader (unchanged)', () => {
    writeIndex({ installRecords: { [PLUGIN]: { version: '4.47.2' } }, plugins: [] });
    const db = new Database(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'));
    db.exec(`UPDATE installed_plugin_index SET plugins_json = 'not json'`);
    db.close();
    const idx = readPluginInstallIndex(home);
    expect(idx!.plugins).toEqual([]);
    expect(idx!.installRecords[PLUGIN]?.version).toBe('4.47.2');
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
  });

  it('a null realtime record on a host with config enabled is a diagnostic gap, not a crash and not a verdict', () => {
    writeConfig(true, true);
    writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1');
    writeMachineStateIndex({ installRecords: { [PLUGIN]: null }, plugins: [null] });
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null }));
    expect(verdict.state).toBe('index-unreadable');
    expect(verdict.severity).toBe('warn');
  });
});

/**
 * #260 round 2 — an index record is a claim. When the directory it names is
 * gone and nothing else is on disk, it must not read as an installed plugin.
 */
describe('#260 r2 — a stale index record does not prove an installation', () => {
  const gone = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'reaped', PKG_SUBPATH);
  const staleRow = () => ({
    installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: gone() } },
    plugins: [{ pluginId: PLUGIN, enabled: true }],
  });

  it.each([
    ['config_machine_state', (): void => writeMachineStateIndex(staleRow())],
    ['legacy table', (): void => writeIndex(staleRow())],
  ])('%s: config enabled, no live roster, recorded path gone, no other build ⇒ load-unproven / warn (never healthy, never a fail)', (_label, write) => {
    writeConfig(true, true);
    write();
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.index!.installRecords[PLUGIN]?.installPath).toBe(gone());
    expect(input.indexInstallPathExists).toBe(false);
    const verdict = reconcilePluginState(input);
    expect(verdict.state).toBe('load-unproven');
    expect(verdict.severity).toBe('warn');
    expect(verdict.recommendedAction).toBe('none');
    expect(verdict.indexPathMissing).toBe(true);
    expect(verdict.reasons.join(' ')).toContain(gone());
  });

  // #260 r3 (Astra r2 blocker): a real copy in a layout this gather does not
  // read — the packaged extension layout with dist/index.js and no root
  // index.js. The stale record must not convict it as uninstalled.
  it('stale path + a real extension copy with dist/index.js (no root index.js) ⇒ not a fail', () => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    const ext = path.join(home, '.openclaw', 'extensions', PLUGIN);
    fs.mkdirSync(path.join(ext, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(ext, 'dist', 'index.js'), '');
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexInstallPathExists).toBe(false);
    const verdict = reconcilePluginState(input);
    expect(verdict.severity).not.toBe('fail');
    expect(verdict.state).not.toBe('enabled-not-installed');
    expect(verdict.state).not.toBe('healthy');
  });

  // #260 r3: an EMPTY directory left at the recorded path is not an install.
  it('stale path + an empty directory at the recorded path ⇒ missing ⇒ warn, not healthy', () => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    fs.mkdirSync(gone(), { recursive: true });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexInstallPathExists).toBe(false);
    expect(reconcilePluginState(input)).toMatchObject({ state: 'load-unproven', severity: 'warn', indexPathMissing: true });
  });

  it.each(['package.json', 'openclaw.plugin.json'])('a recorded directory holding %s counts as there', (marker) => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    fs.mkdirSync(gone(), { recursive: true });
    fs.writeFileSync(path.join(gone(), marker), '{}');
    expect(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null }).indexInstallPathExists).toBe(true);
  });

  // #260 r3 (C): the roster proves it loaded, not which version loaded.
  it('path gone + live roster names the plugin + stale record 4.0.0 ⇒ not version-regressed', () => {
    writeConfig(true, true);
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.0.0', installPath: gone() } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => [PLUGIN] });
    expect(input.indexInstallPathExists).toBe(false);
    expect(input.onDiskVersion).toBeNull();
    const verdict = reconcilePluginState(input);
    expect(verdict.state).not.toBe('version-regressed');
    expect(verdict.state).not.toBe('enabled-not-installed');
    expect(verdict.severity).not.toBe('fail');
    // #260 r4: load proven, version not — healthy, and it says so.
    expect(verdict).toMatchObject({ state: 'healthy', severity: 'ok', versionUnverified: true });
    expect(verdict.reasons.join(' ')).not.toMatch(/versions agree/);
  });

  // #260 r4 (Astra r3 BLOCKER 1): the install location is uncertain; the load
  // result is not. A readable roster that omits the plugin still convicts.
  it('empty recorded dir + a readable live roster that OMITS the plugin, no registration after boot ⇒ enabled-not-loaded / fail', () => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    fs.mkdirSync(gone(), { recursive: true });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => ['brave'] });
    expect(input.indexInstallPathExists).toBe(false);
    expect(input.registrationSeenAfterBoot).not.toBe(true);
    const verdict = reconcilePluginState(input);
    expect(verdict.loadedInLiveRoster).toBe(false);
    expect(verdict).toMatchObject({ state: 'enabled-not-loaded', severity: 'fail' });
  });

  it('gone recorded dir + a readable live roster that OMITS the plugin ⇒ enabled-not-loaded / fail', () => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => ['brave'] }));
    expect(verdict).toMatchObject({ state: 'enabled-not-loaded', severity: 'fail' });
  });

  // #260 r4 (Astra r3 BLOCKER 2): the #214 wipe shape behind a stale path.
  it('no config entry / not allow-listed + stale path + a real packaged extension at the roster rootDir ⇒ installed-not-enabled, never not-installed', () => {
    writeConfig(null, false);
    const ext = path.join(home, '.openclaw', 'extensions', PLUGIN);
    fs.mkdirSync(path.join(ext, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(ext, 'dist', 'index.js'), '');
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: gone() } },
      plugins: [{ pluginId: PLUGIN, enabled: true, rootDir: ext }],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexInstallPathExists).toBe(false);
    const verdict = reconcilePluginState(input);
    expect(verdict.state).not.toBe('not-installed');
    expect(verdict).toMatchObject({ state: 'installed-not-enabled', severity: 'fail', recommendedAction: 're-register' });
  });

  it('the stale record beside a real build elsewhere: the build decides (version from disk, not the record)', () => {
    writeConfig(true, true);
    writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexInstallPathExists).toBe(false);
    expect(input.onDiskVersion).toBe('5.22.1');
    expect(reconcilePluginState(input)).toMatchObject({ state: 'healthy', severity: 'ok' });
  });

  it('a record with no installPath, or a relative one, is "not checked" — never "missing"', () => {
    writeConfig(true, true);
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1' } }, plugins: [] });
    expect(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null }).indexInstallPathExists).toBeNull();
    fs.rmSync(path.join(home, '.openclaw', 'state'), { recursive: true });
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', installPath: 'relative/dir' } }, plugins: [] });
    expect(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null }).indexInstallPathExists).toBeNull();
  });
});

/**
 * #260 round 2 — both layout probes read ONE snapshot. A WAL fixture, a
 * second (writer) connection, and the migration committed between the
 * reader's two probes: without a read transaction the reader finds neither
 * copy and says "absent" about an index that existed before and after.
 *
 * The seam is the prepare() of the reader's second sqlite_master probe — the
 * exact gap the bug lives in — so the timing is deterministic.
 */
describe('#260 r2 — the two layout probes share one SQLite snapshot', () => {
  it('a migration committing between the probes never reads as absent', () => {
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
    });
    const dbPath = path.join(home, '.openclaw', 'state', 'openclaw.sqlite');
    const writer = new Database(dbPath);
    writer.pragma('journal_mode = WAL');
    const migrated = JSON.stringify({
      revision: 2,
      index: { installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1' } }, plugins: [{ pluginId: PLUGIN, enabled: true }] },
    });
    const migrate = (): void => {
      writer.exec(`BEGIN;
        CREATE TABLE config_machine_state (state_key TEXT NOT NULL PRIMARY KEY, value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL);
        INSERT INTO config_machine_state VALUES ('plugins.installedIndex', '${migrated}', 2);
        DROP TABLE installed_plugin_index;
        COMMIT;`);
    };

    const proto = Database.prototype as unknown as { prepare: (this: { readonly: boolean }, sql: string) => unknown };
    const realPrepare = proto.prepare;
    const run = (): { result: ReturnType<typeof readPluginInstallIndexState>; migrations: number } => {
      let probes = 0;
      let migrations = 0;
      proto.prepare = function (sql: string) {
        if (this.readonly && sql.includes('sqlite_master') && ++probes === 2) {
          migrate();
          migrations += 1;
        }
        return realPrepare.call(this, sql);
      };
      try {
        return { result: readPluginInstallIndexState(home), migrations };
      } finally {
        proto.prepare = realPrepare;
      }
    };

    try {
      const { result, migrations } = run();
      expect(migrations).toBe(1); // the migration really landed inside the read
      expect(result.state).toBe('ok');
      // …and it was one consistent copy: the pre-migration snapshot.
      expect(result.state === 'ok' && result.row.installRecords[PLUGIN]?.version).toBe('4.47.2');
      // The next read sees the migrated row.
      const after = readPluginInstallIndexState(home);
      expect(after.state === 'ok' && after.row.installRecords[PLUGIN]?.version).toBe('5.22.1');
    } finally {
      writer.close();
    }
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
