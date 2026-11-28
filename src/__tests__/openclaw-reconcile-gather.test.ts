import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import {
  gatherReconcileInput,
  planReconcileActions,
  readPluginInstallIndex,
  readPluginInstallIndexState,
  reconcilePluginState,
} from '../integrations/openclaw-plugin-index.js';
import { checkOpenClawPluginLoadState, renderPluginLoadVerdict } from '../cli/doctor.js';
import { extractFixCommands, formatDoctorReport, nextCommandForFailures, sanitiseDoctorRowsForDisplay } from '../cli/doctor-report.js';
import { assessRealtimeReplacement, REALTIME_PLUGIN_PACKAGE } from '../setup/openclaw-plugin-spec.js';
import { readRealtimeReplacementEvidence } from '../integrations/openclaw-realtime-install.js';

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

/** The npm package layout OpenClaw loads: package.json `main`, the manifest naming the plugin, the entry point. */
function writeRealBuild(dir: string, version: string): string {
  fs.mkdirSync(path.join(dir, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version, main: './dist/index.js' }));
  fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version }));
  fs.writeFileSync(path.join(dir, 'dist', 'index.js'), '');
  return dir;
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

/**
 * A plugins entry shaped the way OpenClaw 2026.11.x writes it — every field
 * its `InstalledPluginIndexRecordSchema` requires (pluginId, manifestPath,
 * manifestHash, rootDir, origin, enabled, startup, compat). The reader
 * requires string `rootDir` and boolean `enabled` in this layout (#260, Sol
 * finding 1), so the valid controls use the real shape, not a partial one.
 */
function upstreamEntry(rootDir: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    pluginId: PLUGIN,
    manifestPath: path.join(rootDir, 'openclaw.plugin.json'),
    manifestHash: 'h',
    rootDir,
    origin: 'global',
    enabled: true,
    startup: { sidecar: false, memory: false, agentHarnesses: [] },
    compat: [],
    ...over,
  };
}

describe('#260 — the install index in config_machine_state (OpenClaw 2026.11.x)', () => {
  it('migrated layout (no legacy table): both readers return the index', () => {
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: '/x' } },
      plugins: [upstreamEntry('/x')],
      warning: 'DO NOT EDIT',
      generatedAtMs: 1763111111111,
    });
    const idx = readPluginInstallIndex(home);
    expect(idx).toEqual({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: '/x' } },
      plugins: [upstreamEntry('/x')],
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
      plugins: [upstreamEntry('/x')],
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
    const installPath = writeRealBuild(writeProjectDir(canonical, '5.22.1'), '5.22.1');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath } },
      plugins: [upstreamEntry(installPath)],
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
 * #260 Sol finding 1 — the migrated envelope and the SELECTION fields are
 * validated the way OpenClaw 2026.11.7+ validates them before either reader
 * says `ok`: a numeric `revision`, and on every plugins entry a string
 * `rootDir` and a boolean `enabled`.
 */
describe('#260 Sol-1 — envelope + selection fields validated as OpenClaw does', () => {
  const index = (plugins: unknown[]) => ({
    version: 1, hostContractVersion: '2026.11.10', compatRegistryVersion: 'x', migrationVersion: 1, policyHash: 'h',
    generatedAtMs: 5, diagnostics: [], installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1' } }, plugins,
  });
  it.each([
    ['no revision', { index: index([upstreamEntry('/x')]) }],
    ['a string revision', { revision: '5', index: index([upstreamEntry('/x')]) }],
    ['a null revision', { revision: null, index: index([upstreamEntry('/x')]) }],
    ['an entry with a numeric rootDir', { revision: 5, index: index([upstreamEntry('/x', { rootDir: 42 })]) }],
    ['an entry with no rootDir', { revision: 5, index: index([{ pluginId: PLUGIN, enabled: true }]) }],
    ['an entry with a string enabled', { revision: 5, index: index([upstreamEntry('/x', { enabled: 'true' })]) }],
    ['an entry with no enabled', { revision: 5, index: index([{ pluginId: PLUGIN, rootDir: '/x' }]) }],
    ['ANOTHER plugin\'s entry with no rootDir', { revision: 5, index: index([upstreamEntry('/x'), { pluginId: 'other', enabled: true }]) }],
  ])('new layout: %s ⇒ null / unreadable', (_label, value) => {
    writeMachineStateIndex(null, JSON.stringify(value));
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toMatchObject({ state: 'unreadable', why: expect.any(String) });
  });

  it('control: the upstream-shaped row reads ok in both readers', () => {
    writeMachineStateIndex(null, JSON.stringify({ revision: 5, index: index([upstreamEntry('/x')]) }));
    expect(readPluginInstallIndexState(home).state).toBe('ok');
    expect(readPluginInstallIndex(home)!.plugins[0]?.rootDir).toBe('/x');
  });

  it('legacy layout: a present rootDir / enabled must be typed right; an absent one is still read (pre-2026.11 rows)', () => {
    writeIndex({ installRecords: {}, plugins: [{ pluginId: PLUGIN, rootDir: 42, enabled: true }] });
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
    expect(readPluginInstallIndex(home)).toBeNull();
    fs.rmSync(path.join(home, '.openclaw', 'state'), { recursive: true });
    writeIndex({ installRecords: {}, plugins: [{ pluginId: PLUGIN, rootDir: '/x', enabled: 'yes' }] });
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
    fs.rmSync(path.join(home, '.openclaw', 'state'), { recursive: true });
    writeIndex({ installRecords: {}, plugins: [{ pluginId: PLUGIN }] });
    expect(readPluginInstallIndexState(home).state).toBe('ok');
  });
});

/**
 * #260 Case non-blocking — the stored JSON is size-capped before JSON.parse,
 * and when both layouts hold a row the fresher one wins.
 */
describe('#260 Case — value_json size cap and the fresher layout', () => {
  const CAP = 16 * 1024 * 1024;

  it('new layout: a row over the cap is unreadable (never absent, never parsed)', () => {
    writeMachineStateIndex(null, JSON.stringify({ revision: 1, index: { pad: 'x'.repeat(CAP) } }));
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toMatchObject({ state: 'unreadable', why: expect.stringMatching(/over the .*-byte cap/) });
  });

  it('legacy layout: a row over the cap is unreadable in BOTH readers (not the lenient "empty column")', () => {
    writeIndex({ installRecords: { [PLUGIN]: { version: '5.22.1', pad: 'x'.repeat(CAP) } }, plugins: [] });
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toMatchObject({ state: 'unreadable', why: expect.stringMatching(/over the .*-byte cap/) });
  });

  // Case r2 (non-blocking): with one column SQL NULL, `a + b` was NULL, the
  // oversized other column was cut to NULL by its CASE, and the lenient
  // reader returned an EMPTY index instead of "could not read".
  it('legacy layout, one column NULL and the other over the cap: unreadable in BOTH readers, never an empty index', () => {
    const stateDir = path.join(home, '.openclaw', 'state');
    fs.mkdirSync(stateDir, { recursive: true });
    const db = new Database(path.join(stateDir, 'openclaw.sqlite'));
    // A schema without NOT NULL, so either column can be SQL NULL.
    db.exec('CREATE TABLE installed_plugin_index (index_key TEXT PRIMARY KEY, generated_at_ms INTEGER, install_records_json TEXT, plugins_json TEXT, warning TEXT)');
    db.prepare('INSERT INTO installed_plugin_index VALUES (?, ?, ?, ?, NULL)').run('k', 1, null, JSON.stringify([{ pluginId: PLUGIN, pad: 'x'.repeat(CAP) }]));
    db.close();
    expect(readPluginInstallIndex(home)).toBeNull();
    expect(readPluginInstallIndexState(home)).toMatchObject({ state: 'unreadable', why: expect.stringMatching(/over the .*-byte cap/) });
  });

  it('control: a row just under the cap reads ok', () => {
    const pad = 'x'.repeat(CAP - 4096);
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1' } }, plugins: [upstreamEntry('/x', { pad })] });
    expect(readPluginInstallIndexState(home).state).toBe('ok');
  });

  it('downgrade: a legacy row NEWER than the leftover config_machine_state row wins', () => {
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1' } },
      plugins: [upstreamEntry('/x')],
      generatedAtMs: 1763000000000,
    });
    writeIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.20.0' } },
      plugins: [{ pluginId: PLUGIN, enabled: false }],
      generatedAtMs: 1764000000000,
    });
    expect(readPluginInstallIndex(home)!.installRecords[PLUGIN]?.version).toBe('5.20.0');
    const st = readPluginInstallIndexState(home);
    expect(st.state === 'ok' && st.row.generatedAtMs).toBe(1764000000000);
  });

  it('equal timestamps: the config_machine_state row wins', () => {
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { version: '5.22.1' } }, plugins: [upstreamEntry('/x')], generatedAtMs: 1763000000000 });
    writeIndex({ installRecords: { [PLUGIN]: { version: '5.20.0' } }, plugins: [], generatedAtMs: 1763000000000 });
    expect(readPluginInstallIndex(home)!.installRecords[PLUGIN]?.version).toBe('5.22.1');
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
    plugins: [upstreamEntry(gone())],
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

  // Sol finding 3: a marker that EXISTS is not a build. Only a manifest that
  // names the plugin plus an entry point file counts.
  const manifest = JSON.stringify({ id: PLUGIN, version: '5.22.1' });
  const BUILD_SHAPES: Array<[string, (d: string) => void, boolean]> = [
    ['package.json only (leftover metadata)', (d) => fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ name: 'x', version: '5.22.1' })), false],
    ['an empty-object openclaw.plugin.json only', (d) => fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), '{}'), false],
    ['a DIRECTORY named openclaw.plugin.json + dist/index.js', (d) => { fs.mkdirSync(path.join(d, 'openclaw.plugin.json')); fs.mkdirSync(path.join(d, 'dist')); fs.writeFileSync(path.join(d, 'dist', 'index.js'), ''); }, false],
    ['a DIRECTORY named package.json', (d) => fs.mkdirSync(path.join(d, 'package.json')), false],
    ['the manifest, no entry point', (d) => fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), manifest), false],
    ['the manifest + a DIRECTORY named index.js', (d) => { fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), manifest); fs.mkdirSync(path.join(d, 'index.js')); }, false],
    ['a manifest for ANOTHER plugin + dist/index.js', (d) => { fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), JSON.stringify({ id: 'other' })); fs.mkdirSync(path.join(d, 'dist')); fs.writeFileSync(path.join(d, 'dist', 'index.js'), ''); }, false],
    ['an unparseable manifest + index.js', (d) => { fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), '{'); fs.writeFileSync(path.join(d, 'index.js'), ''); }, false],
    ['a package.json `main` escaping the directory', (d) => { fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), manifest); fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ main: '../../../../../../../../etc/hostname' })); }, false],
    ['the manifest + index.js (trusted-local copy)', (d) => { fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), manifest); fs.writeFileSync(path.join(d, 'index.js'), ''); }, true],
    ['the manifest + dist/index.js (no package.json)', (d) => { fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), manifest); fs.mkdirSync(path.join(d, 'dist')); fs.writeFileSync(path.join(d, 'dist', 'index.js'), ''); }, true],
    ['the npm package layout (package.json main ./dist/index.js)', (d) => { writeRealBuild(d, '5.22.1'); }, true],
    ['the manifest + package.json main lib/entry.mjs', (d) => { fs.writeFileSync(path.join(d, 'openclaw.plugin.json'), manifest); fs.writeFileSync(path.join(d, 'package.json'), JSON.stringify({ main: 'lib/entry.mjs' })); fs.mkdirSync(path.join(d, 'lib')); fs.writeFileSync(path.join(d, 'lib', 'entry.mjs'), ''); }, true],
  ];
  it.each(BUILD_SHAPES.map(([label, make, expected]) => [label, expected, make] as const))('a recorded directory holding %s ⇒ indexInstallPathExists %s', (_label, expected, make) => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    fs.mkdirSync(gone(), { recursive: true });
    make(gone());
    expect(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null }).indexInstallPathExists).toBe(expected);
  });

  it('a recorded path that is a FILE, not a directory ⇒ false', () => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    fs.mkdirSync(path.dirname(gone()), { recursive: true });
    fs.writeFileSync(gone(), '');
    expect(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null }).indexInstallPathExists).toBe(false);
  });

  // #260 r3 (C): the roster proves it loaded, not which version loaded.
  // r4c (owner ruling on jarvis r3): was "not version-regressed" + healthy.
  // No build is on disk anywhere, so main weighs the record (Case r5 keeps
  // this residual): its 4.0.0 is below expected and fails as on main — named
  // as the record's claim, never as the version that loaded.
  it('path gone + live roster names the plugin + stale record 4.0.0, no build anywhere ⇒ version-regressed on the RECORD\'s claim (r4c residual)', () => {
    writeConfig(true, true);
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.0.0', installPath: gone() } },
      plugins: [upstreamEntry(gone())],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => [PLUGIN] });
    expect(input.indexInstallPathExists).toBe(false);
    expect(input.onDiskVersion).toBeNull();
    const verdict = reconcilePluginState(input);
    expect(verdict.state).not.toBe('enabled-not-installed');
    expect(verdict).toMatchObject({
      state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
      versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'index-record',
    });
    expect(verdict.reasons.join(' ')).toMatch(/holds no plugin build, and OpenClaw's install record says v4\.0\.0/);
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
      plugins: [upstreamEntry(ext)],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexInstallPathExists).toBe(false);
    const verdict = reconcilePluginState(input);
    expect(verdict.state).not.toBe('not-installed');
    expect(verdict).toMatchObject({ state: 'installed-not-enabled', severity: 'fail', recommendedAction: 're-register' });
  });

  // Sol finding 3: this test used to assert a FALSE green. The other copy
  // proves an install, not that OpenClaw selected it; the only "enabled"
  // evidence is the stale row.
  // r6 owner ruling (jarvis 6095709381, meeting Case 6095672540's three
  // conditions): r4c failed this as version-regressed on the record's 5.0.0;
  // Case r5 made it warn. It FAILS — on the STALE INDEX RECORD (the indexed
  // folders hold no build, the record is older than expected), not as a
  // measured regression: neither 5.0.0 nor 5.22.1 is reported as running, and
  // repair reinstalls pinned to expected, rewriting the record.
  const staleRecordBesideCurrentBuild = (): void => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } },
      plugins: [upstreamEntry(gone())],
    });
  };

  // The pinned reinstall rewrites the stale record; it pins the EXPECTED
  // version (never the record's 5.0.0, never the disk build's).
  const pinnedToExpected = (verdict: ReturnType<typeof reconcilePluginState>): void => {
    const plan = planReconcileActions(verdict, { pluginId: PLUGIN, packageName: REALTIME_PLUGIN_PACKAGE, expectedVersion: '5.22.1' });
    expect(plan.map((x) => x.kind)).toEqual(['openclaw-install-pinned', 'gateway-reload', 'self-check']);
    expect(plan[0].command!.join(' ')).toContain('@5.22.1');
    expect(plan[0].command!.join(' ')).not.toContain('5.0.0');
  };

  it('the stale record (5.0.0) beside a real build elsewhere (5.22.1), roster unread ⇒ stale-index-record / FAIL / reinstall-pinned — on the stale record, never a measured regression (r6 owner ruling)', () => {
    staleRecordBesideCurrentBuild();
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexInstallPathExists).toBe(false);
    expect(input.indexRootDirExists).toBe(false);
    expect(input.onDiskVersion).toBe('5.22.1');
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({
      state: 'stale-index-record', severity: 'fail', recommendedAction: 'reinstall-pinned', indexPathMissing: true,
      versionUnverified: true, installedVersion: null, installedVersionSource: null,
    });
    expect(verdict.reasons.join(' ')).toMatch(/holds no plugin build \(stale index record\)/);
    expect(verdict.reasons.join(' ')).not.toMatch(/v5\.0\.0|regressed/);
    pinnedToExpected(verdict);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('fail');
    expect(rendered.message).toMatch(/OpenClaw's plugin index points to folders that hold no build \(stale index record\).*; running version unknown/);
    expect(rendered.message).not.toMatch(/running stale|regressed|as on main|v5\.0\.0|v5\.22\.1/);
    expect(rendered.fix).toMatch(/shieldcortex repair.*pinned to v5\.22\.1.*rewrites OpenClaw's stale index record/);
  });

  // Sol r2 (r3 change): the load is proven; the scan's build elsewhere is not
  // the selected copy, so its version is not claimed as the one that loaded.
  // r6 owner ruling (was Case r5 version-unverified / warn): the roster proves
  // a load, not which copy — the same stale-record FAIL.
  it('the same host with a live roster naming the plugin ⇒ stale-index-record / FAIL — never the scan\'s or the record\'s version (r6 owner ruling)', () => {
    staleRecordBesideCurrentBuild();
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => [PLUGIN] }));
    expect(verdict).toMatchObject({
      state: 'stale-index-record', severity: 'fail', recommendedAction: 'reinstall-pinned', onDiskVersion: '5.22.1',
      versionUnverified: true, installedVersion: null, installedVersionSource: null,
    });
    pinnedToExpected(verdict);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('fail');
    expect(rendered.message).toMatch(/stale index record.*running version unknown\. The running gateway loaded a copy, but nothing shows which one/);
    expect(rendered.message).not.toMatch(/running stale|regressed|as on main|v5\.0\.0|v5\.22\.1/);
  });

  // Positive control: a rootDir verified as the real 5.22.1 build is MEASURED
  // and decides — the stale 5.0.0 record beside it does not fail the host.
  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('positive control (%s): the index rootDir IS the 5.22.1 build (record 5.0.0, path gone) ⇒ healthy, measured', (_l, roster) => {
    writeConfig(true, true);
    const real = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } },
      plugins: [upstreamEntry(real)],
    });
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => (roster ? [...roster] : null) }));
    expect(verdict).toMatchObject({ state: 'healthy', severity: 'ok', installedVersion: '5.22.1', installedVersionSource: 'selected-build' });
    expect(renderPluginLoadVerdict(verdict).status).toBe('pass');
  });

  it('the same host with a READ roster that omits the plugin ⇒ enabled-not-loaded / FAIL (confirmed non-load, unchanged)', () => {
    staleRecordBesideCurrentBuild();
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => ['brave'] }));
    expect(verdict).toMatchObject({ state: 'enabled-not-loaded', severity: 'fail' });
  });

  it('the same host with a #142 registration sighted after boot ⇒ the #142 warn, no action (unchanged)', () => {
    staleRecordBesideCurrentBuild();
    const input = { ...gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => ['brave'] }), registrationSeenAfterBoot: true };
    expect(reconcilePluginState(input)).toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none' });
  });

  it('…but a disk build BELOW expected still fails on the scan\'s claim, as on main (record at expected)', () => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '4.0.0'), '4.0.0');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: gone() } },
      plugins: [upstreamEntry(gone())],
    });
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null }));
    expect(verdict).toMatchObject({
      state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
      versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'disk',
    });
    expect(renderPluginLoadVerdict(verdict).message).toMatch(/the build on disk is v4\.0\.0, older than expected v5\.22\.1; running version unknown/);
  });

  it('positive control (Sol 3): the index SELECTS the real build (rootDir verified) though the record path is stale ⇒ ordinary rules, healthy', () => {
    writeConfig(true, true);
    const real = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: gone() } },
      plugins: [upstreamEntry(real)],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexInstallPathExists).toBe(false);
    expect(input.indexRootDirExists).toBe(true);
    expect(reconcilePluginState(input)).toMatchObject({ state: 'healthy', severity: 'ok', indexPathMissing: false });
  });

  it('…and a rootDir holding only leftover metadata is no selection proof', () => {
    writeConfig(true, true);
    const leftover = writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1');
    writeMachineStateIndex({
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: gone() } },
      plugins: [upstreamEntry(leftover)],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexRootDirExists).toBe(false);
    expect(reconcilePluginState(input)).toMatchObject({ state: 'load-unproven', indexPathMissing: true });
  });

  // Case #1 / Sol finding 2 through the real gather: a READ live roster that
  // lacks the plugin on a stale-path host — non-null rosters, both shapes.
  it.each([
    ['a roster naming other plugins', ['brave']],
    ['an empty roster', [] as string[]],
  ])('stale-path host + %s, no race ⇒ enabled-not-loaded / FAIL / update-openclaw-tracked (as on main)', (_label, roster) => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => roster });
    expect(input.liveRoster).toEqual(roster);
    expect(input.indexInstallPathExists).toBe(false);
    expect(reconcilePluginState(input)).toMatchObject({
      state: 'enabled-not-loaded', severity: 'fail', recommendedAction: 'update-openclaw-tracked', indexPathMissing: false,
    });
  });

  it.each([
    ['a roster naming other plugins', ['brave']],
    ['an empty roster', [] as string[]],
  ])('stale-path host + %s + a #142 registration sighted after boot ⇒ the #142 warn, no action', (_label, roster) => {
    writeConfig(true, true);
    writeMachineStateIndex(staleRow());
    // The race flag is only produced by the production log reader (needs a
    // real boot line); everything else here is the real gather.
    const input = { ...gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => roster }), registrationSeenAfterBoot: true };
    expect(reconcilePluginState(input)).toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: false });
  });

  // Case r2 (non-blocking): the recorded paths are normalised before the
  // entry-point containment check — `..`, `//` and `.` segments used to make
  // a real build read as "no build".
  it.each([
    ['a `..` segment', (d: string) => [path.dirname(d), '..', path.basename(path.dirname(d)), path.basename(d)].join(path.sep)],
    ['a doubled separator', (d: string) => d.replace(`${path.sep}node_modules${path.sep}`, `${path.sep}node_modules${path.sep}${path.sep}`)],
    ['a `.` segment and a trailing separator', (d: string) => `${path.dirname(d)}${path.sep}.${path.sep}${path.basename(d)}${path.sep}`],
  ])('a selected rootDir / record path written with %s still verifies as the build it is', (_l, spell) => {
    writeConfig(true, true);
    const real = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    const odd = spell(real);
    expect(odd).not.toBe(real);
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: odd } }, plugins: [upstreamEntry(odd)] });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input).toMatchObject({ indexInstallPathExists: true, indexRootDirExists: true, selectedVersion: '5.22.1' });
    expect(reconcilePluginState(input)).toMatchObject({ state: 'healthy', indexPathMissing: false, installedVersion: '5.22.1' });
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
 * #260 r3 — Case r2 #1 / Sol r2: selection, build and version are verified
 * SEPARATELY. When the record path is gone and the selected `rootDir` is a
 * verified build, its OWN package.json version is the version — so a
 * regression is still caught even outside every place the disk scan looks —
 * and an unreadable one is "version unverified", never the expected pin. A
 * stale selection, or an equal-version record elsewhere, is not the selected
 * build; a disk scan is not a measured version.
 */
describe('#260 r3 — the selected build is measured, not assumed', () => {
  const gone = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'reaped', PKG_SUBPATH);
  /** A linked/path build outside installs.json, npm/projects and extensions — out of the disk scan. */
  const outOfScan = (): string => path.join(home, 'src', 'realtime');
  const row = (rootDir: string, recordVersion: string, installPath: string = gone()) => ({
    installRecords: { [PLUGIN]: { source: 'npm', version: recordVersion, installPath } },
    plugins: [upstreamEntry(rootDir)],
  });
  const gather = (roster: string[] | null) =>
    gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => roster });

  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('out-of-scan rootDir at 4.0.0, record path gone (%s) ⇒ version-regressed / fail at the measured 4.0.0', (_l, roster) => {
    writeConfig(true, true);
    writeRealBuild(outOfScan(), '4.0.0');
    writeMachineStateIndex(row(outOfScan(), '4.0.0'));
    const input = gather(roster ? [...roster] : null);
    expect(input).toMatchObject({ indexInstallPathExists: false, indexRootDirExists: true, onDiskVersion: null, selectedVersion: '4.0.0' });
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({
      state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
      installedVersion: '4.0.0', installedVersionSource: 'selected-build',
    });
    expect(verdict.reasons.join(' ')).toMatch(/the build OpenClaw selected is v4\.0\.0, older than expected 5\.22\.1/);
  });

  it.each([
    ['roster unread', '5.22.1', null],
    ['roster-proven', '5.22.1', [PLUGIN]],
    // A version different from the pin proves the number is read, not assumed.
    ['roster unread', '5.23.0', null],
    ['roster-proven', '5.23.0', [PLUGIN]],
  ] as const)('out-of-scan rootDir, record path gone (%s, v%s) ⇒ healthy at the MEASURED version', (_l, version, roster) => {
    writeConfig(true, true);
    writeRealBuild(outOfScan(), version);
    writeMachineStateIndex(row(outOfScan(), '4.0.0'));
    const verdict = reconcilePluginState(gather(roster ? [...roster] : null));
    expect(verdict).toMatchObject({
      state: 'healthy', severity: 'ok', installedVersion: version, installedVersionSource: 'selected-build', indexPathMissing: false,
    });
    expect(verdict.versionUnverified).toBeUndefined();
  });

  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('verified rootDir whose version cannot be read (%s) + a scan build elsewhere at 4.0.0 ⇒ version-regressed / fail, as on main (jarvis r3)', (_l, roster) => {
    writeConfig(true, true);
    writeRealBuild(outOfScan(), '5.22.1');
    fs.writeFileSync(path.join(outOfScan(), 'package.json'), JSON.stringify({ main: './dist/index.js', version: 'not-a-version' }));
    // r6: and no version in its own manifest either (that would be read).
    fs.writeFileSync(path.join(outOfScan(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-old', '4.0.0'), '4.0.0');
    writeMachineStateIndex(row(outOfScan(), '5.22.1'));
    const input = gather(roster ? [...roster] : null);
    expect(input).toMatchObject({ indexRootDirExists: true, selectedVersion: null, onDiskVersion: '4.0.0' });
    const verdict = reconcilePluginState(input);
    // Was `healthy / ok` at 2e119972 — the fail-open jarvis r3 blocked.
    expect(verdict).toMatchObject({
      state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
      versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'disk',
    });
    expect(verdict.reasons.join(' ')).not.toMatch(/versions agree/);
  });

  // r6 (jarvis 6095709381): was "the record speaks for it" — the same-dir
  // record stood in for the build's version, and so acquitted at or above
  // expected. It is a claim: below expected it convicts, flagged unverified.
  it('unreadable selected version, record naming THAT SAME verified directory at 4.0.0 ⇒ the record convicts (version-regressed, unverified), never stands in as measured', () => {
    writeConfig(true, true);
    const selected = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-a', '4.0.0'), '4.0.0');
    fs.writeFileSync(path.join(selected, 'package.json'), '{ nope');
    fs.writeFileSync(path.join(selected, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    writeMachineStateIndex(row(selected, '4.0.0', selected));
    const verdict = reconcilePluginState(gather(null));
    expect(verdict).toMatchObject({ state: 'version-regressed', installedVersion: '4.0.0', installedVersionSource: 'index-record', versionUnverified: true });
  });

  // CASE's onDiskVersion note: the scan's NEWEST build is not the selected copy.
  it('the selected build is older than the newest build the scan finds ⇒ version-regressed on the SELECTED copy', () => {
    writeConfig(true, true);
    const selected = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-a', '4.0.0'), '4.0.0');
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-b', '5.22.1'), '5.22.1');
    writeMachineStateIndex(row(selected, '4.0.0', selected));
    const input = gather([PLUGIN]);
    expect(input).toMatchObject({ onDiskVersion: '5.22.1', selectedVersion: '4.0.0', indexInstallPathExists: true, indexRootDirExists: true });
    expect(reconcilePluginState(input)).toMatchObject({ state: 'version-regressed', severity: 'fail', installedVersion: '4.0.0' });
  });

  it.each([
    ['5.22.1', 'healthy', 'ok'],
    ['4.0.0', 'version-regressed', 'fail'],
  ] as const)('roster-only verified root (plugins entry, no install record, out of scan) at v%s ⇒ %s — never "not installed"', (version, state, severity) => {
    writeConfig(true, true);
    writeRealBuild(outOfScan(), version);
    writeMachineStateIndex({ installRecords: {}, plugins: [upstreamEntry(outOfScan())] });
    const verdict = reconcilePluginState(gather(null));
    expect(verdict).toMatchObject({ state, severity, installedVersion: version, installedVersionSource: 'selected-build' });
  });

  it('roster-only root that is NOT a build, nothing else on disk ⇒ the confirmed absence it is (enabled-not-installed)', () => {
    writeConfig(true, true);
    fs.mkdirSync(outOfScan(), { recursive: true });
    writeMachineStateIndex({ installRecords: {}, plugins: [upstreamEntry(outOfScan())] });
    expect(reconcilePluginState(gather(null))).toMatchObject({ state: 'enabled-not-installed', severity: 'fail' });
  });

  // Sol r2: a stale SELECTION is not rescued by an equal-version record elsewhere.
  it.each([
    ['roster unread', null, { state: 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: true }],
    // r4c: was `healthy / ok`; an unmeasured version never passes.
    ['roster-proven', [PLUGIN], { state: 'version-unverified', severity: 'warn', versionUnverified: true, installedVersion: null }],
  ] as const)('stale selection (rootDir holds no build) + an equal-version build at the record path (%s) ⇒ never the record\'s version', (_l, roster, expected) => {
    writeConfig(true, true);
    const recordBuild = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-rec', '5.22.1'), '5.22.1');
    // Named off the plugin id so the duplicate-dir rule stays out of this row.
    const staleRoot = path.join(home, '.openclaw', 'npm', 'projects', 'selected-but-emptied', PKG_SUBPATH);
    fs.mkdirSync(staleRoot, { recursive: true });
    writeMachineStateIndex(row(staleRoot, '5.22.1', recordBuild));
    const input = gather(roster ? [...roster] : null);
    expect(input).toMatchObject({ indexInstallPathExists: true, indexRootDirExists: false });
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject(expected);
    expect(verdict.reasons.join(' ')).toContain(staleRoot);
  });

  // Sol r2: a stale RECORD with no selection at all, and a scan build elsewhere.
  it.each([
    ['roster unread', null, { state: 'load-unproven', severity: 'warn' }],
    // r4c: was `healthy / ok`; an unmeasured version never passes.
    ['roster-proven', [PLUGIN], { state: 'version-unverified', severity: 'warn', versionUnverified: true, installedVersion: null }],
  ] as const)('stale-record-only (no plugins entry, record path gone) + a scan build elsewhere (%s) ⇒ no pass on the scan\'s version', (_l, roster, expected) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-x', '5.22.1'), '5.22.1');
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: gone() } }, plugins: [] });
    const input = gather(roster ? [...roster] : null);
    expect(input).toMatchObject({ indexInstallPathExists: false, onDiskVersion: '5.22.1' });
    expect(input.indexRootDirExists).toBeNull();
    expect(reconcilePluginState(input)).toMatchObject(expected);
  });
});

/**
 * #260 jarvis r3 (BLOCKING) — the selected build is verified but its version
 * cannot be read. A version check that cannot measure never reports a pass.
 * Case r5: the claim weighed is main's — the disk scan's build, else the
 * install record — and it fails only when below expected; a stale record
 * below expected beside a current scan build is `version-unverified` (warn),
 * as is every other unmeasured case. Both index
 * layouts, roster unread and roster proven, through gather → reconcile →
 * doctor's renderer.
 */
describe('#260 jarvis r3 — unreadable selected version is never a pass', () => {
  const gone = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'reaped', PKG_SUBPATH);
  const outOfScan = (): string => path.join(home, 'src', 'realtime');
  const LAYOUTS = [
    ['legacy installed_plugin_index', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeIndex(r)],
    ['config_machine_state', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeMachineStateIndex(r)],
  ] as const;
  const ROSTERS = [['roster unread', null], ['roster-proven', [PLUGIN]]] as const;
  // r6: the build's own manifest is read when package.json gives no version,
  // so "unreadable" means neither file carries one.
  const corrupt = (): void => {
    fs.writeFileSync(path.join(outOfScan(), 'package.json'), '{ not json');
    fs.writeFileSync(path.join(outOfScan(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
  };
  const noVersion = (): void => {
    fs.writeFileSync(path.join(outOfScan(), 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', main: './dist/index.js' }));
    fs.writeFileSync(path.join(outOfScan(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
  };
  type Row = {
    id: string;
    damage: () => void;
    record: { version: string; installPath: () => string } | null;
    scanAt: string | null;
    expect: 'fail' | 'warn';
    source?: 'index-record' | 'disk';
  };
  const ROWS: Row[] = [
    { id: 'a. corrupt package.json, record says 4.0.0 (record path gone)', damage: corrupt, record: { version: '4.0.0', installPath: gone }, scanAt: null, expect: 'fail', source: 'index-record' },
    { id: 'b. no version anywhere, record says 4.0.0 (record path gone)', damage: noVersion, record: { version: '4.0.0', installPath: gone }, scanAt: null, expect: 'fail', source: 'index-record' },
    { id: 'c. corrupt package.json, disk scan holds 4.0.0 elsewhere', damage: corrupt, record: { version: '5.22.1', installPath: gone }, scanAt: '4.0.0', expect: 'fail', source: 'disk' },
    { id: 'd1. corrupt package.json, record at expected, nothing on disk', damage: corrupt, record: { version: '5.22.1', installPath: gone }, scanAt: null, expect: 'warn' },
    { id: 'd2. corrupt package.json, no record, scan at expected', damage: corrupt, record: null, scanAt: '5.22.1', expect: 'warn' },
    { id: 'd3. no version anywhere, record NEWER than expected (5.23.0), scan at expected', damage: noVersion, record: { version: '5.23.0', installPath: gone }, scanAt: '5.22.1', expect: 'warn' },
    // Case r5: main's precedence — the scan's current build outranks the stale
    // record, so the record's 4.0.0 convicts nothing (r4c's lowest claim did).
    { id: 'e1. corrupt package.json, record 4.0.0 (path gone), scan at expected', damage: corrupt, record: { version: '4.0.0', installPath: gone }, scanAt: '5.22.1', expect: 'warn' },
    { id: 'e2. no version anywhere, record 4.0.0 (path gone), scan NEWER (5.23.0)', damage: noVersion, record: { version: '4.0.0', installPath: gone }, scanAt: '5.23.0', expect: 'warn' },
    // …and a scan build below expected still fails, whatever the record says.
    { id: 'e3. corrupt package.json, record NEWER (5.23.0), scan 4.0.0', damage: corrupt, record: { version: '5.23.0', installPath: gone }, scanAt: '4.0.0', expect: 'fail', source: 'disk' },
  ];
  const cases = ROWS.flatMap((r) => LAYOUTS.flatMap(([layout, write]) => ROSTERS.map(([rl, roster]) => [`${r.id} — ${layout}, ${rl}`, r, write, roster] as const)));

  it.each(cases)('%s', (_title, r, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(outOfScan(), '5.22.1');
    r.damage();
    if (r.scanAt) writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-scan', r.scanAt), r.scanAt);
    write({
      installRecords: r.record ? { [PLUGIN]: { source: 'npm', version: r.record.version, installPath: r.record.installPath() } } : {},
      plugins: [upstreamEntry(outOfScan())],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => (roster ? [...roster] : null) });
    expect(input).toMatchObject({ indexRootDirExists: true, selectedVersion: null, onDiskVersion: r.scanAt });
    const verdict = reconcilePluginState(input);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(verdict.versionUnverified).toBe(true);
    expect(verdict.severity).not.toBe('ok');
    expect(rendered.status).not.toBe('pass');
    if (r.expect === 'fail') {
      expect(verdict).toMatchObject({
        state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
        installedVersion: '4.0.0', installedVersionSource: r.source,
      });
      expect(verdict.reasons.join(' ')).toMatch(/the build OpenClaw selected has no readable version, and .*v4\.0\.0, older than expected 5\.22\.1/);
      expect(rendered.status).toBe('fail');
      // Case r5: a claim, not a measurement — whose claim, and no "running stale".
      expect(rendered.message).toMatch(r.source === 'disk'
        ? /the build on disk is v4\.0\.0, older than expected v5\.22\.1; running version unknown/
        : /OpenClaw's install record says v4\.0\.0, older than expected v5\.22\.1; running version unknown/);
      expect(rendered.message).not.toMatch(/running stale|regressed to/);
    } else {
      expect(verdict).toMatchObject({
        state: 'version-unverified', severity: 'warn', recommendedAction: 'none',
        installedVersion: null, installedVersionSource: null, indexPathMissing: false,
      });
      expect(rendered.status).toBe('warn');
      expect(rendered.message).toMatch(/version unverified/);
      // Never the expected version printed as if measured.
      expect(rendered.message).not.toMatch(/v5\.22\.1/);
      expect(rendered.message).toMatch(roster ? /the running gateway loaded it/ : /load is not confirmed either/);
    }
  });

  it('control: the same verified rootDir with a READABLE version at expected still passes (the warn is only for the unread version)', () => {
    writeConfig(true, true);
    writeRealBuild(outOfScan(), '5.22.1');
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '4.0.0', installPath: gone() } }, plugins: [upstreamEntry(outOfScan())] });
    const verdict = reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => [PLUGIN] }));
    expect(verdict).toMatchObject({ state: 'healthy', severity: 'ok', installedVersion: '5.22.1', installedVersionSource: 'selected-build' });
    expect(renderPluginLoadVerdict(verdict).status).toBe('pass');
  });
});

/**
 * #260 r6 (jarvis review 6095709381, BLOCKING) — the same-dir record never
 * acquits. A verified selected build in the normal npm layout whose own
 * version cannot be read, with OpenClaw's install record naming THAT SAME
 * folder. The record is a claim about the build, not a reading of it: below
 * expected it convicts (named as the record's, running version unknown);
 * otherwise the row is `version-unverified` (warn) and never prints the
 * record's version. When package.json yields no version, the build's own
 * openclaw.plugin.json is read: that IS a measurement of the selected build.
 * Both index layouts, roster unread and roster proven, gather → reconcile →
 * doctor's renderer.
 */
describe('#260 r6 — a same-dir install record only convicts, never acquits', () => {
  const LAYOUTS = [
    ['legacy installed_plugin_index', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeIndex(r)],
    ['config_machine_state', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeMachineStateIndex(r)],
  ] as const;
  const ROSTERS = [['roster unread', null], ['roster-proven', [PLUGIN]]] as const;
  const selectedDir = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-a', PKG_SUBPATH);
  const manifest = (version?: string): void =>
    fs.writeFileSync(path.join(selectedDir(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, ...(version ? { version } : {}) }));
  const pkg = (body: string): void => fs.writeFileSync(path.join(selectedDir(), 'package.json'), body);
  const corrupt = (): void => pkg('{ not json');
  type Row = {
    id: string;
    damage: () => void;
    record: string;
    expect: 'warn' | 'record-fail' | 'measured-fail' | 'pass';
    measured?: string;
  };
  const ROWS: Row[] = [
    { id: 'a. corrupt package.json, no manifest version, record 5.22.1', damage: () => { corrupt(); manifest(); }, record: '5.22.1', expect: 'warn' },
    { id: 'b1. package.json with no version, no manifest version, record 5.22.1', damage: () => { pkg(JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', main: './dist/index.js' })); manifest(); }, record: '5.22.1', expect: 'warn' },
    { id: 'b2. package.json version "latest", no manifest version, record 5.22.1', damage: () => { pkg(JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: 'latest', main: './dist/index.js' })); manifest(); }, record: '5.22.1', expect: 'warn' },
    { id: 'c. corrupt package.json, no manifest version, record NEWER (5.23.0)', damage: () => { corrupt(); manifest(); }, record: '5.23.0', expect: 'warn' },
    { id: 'd. corrupt package.json, the build\'s own manifest says 4.0.0, record 5.22.1', damage: () => { corrupt(); manifest('4.0.0'); }, record: '5.22.1', expect: 'measured-fail', measured: '4.0.0' },
    { id: 'd2. package.json version "latest", the build\'s own manifest says 4.0.0, record 5.22.1', damage: () => { pkg(JSON.stringify({ version: 'latest', main: './dist/index.js' })); manifest('4.0.0'); }, record: '5.22.1', expect: 'measured-fail', measured: '4.0.0' },
    { id: 'd3 (control). corrupt package.json, the build\'s own manifest says 5.23.0, record 4.0.0', damage: () => { corrupt(); manifest('5.23.0'); }, record: '4.0.0', expect: 'pass', measured: '5.23.0' },
    { id: 'e. corrupt package.json, no manifest version, record BELOW expected (4.0.0)', damage: () => { corrupt(); manifest(); }, record: '4.0.0', expect: 'record-fail' },
  ];
  const cases = ROWS.flatMap((r) => LAYOUTS.flatMap(([layout, write]) => ROSTERS.map(([rl, roster]) => [`${r.id} — ${layout}, ${rl}`, r, write, roster] as const)));

  it.each(cases)('%s', (_title, r, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(selectedDir(), '5.22.1');
    r.damage();
    write({
      installRecords: { [PLUGIN]: { source: 'npm', version: r.record, installPath: selectedDir() } },
      plugins: [upstreamEntry(selectedDir())],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => (roster ? [...roster] : null) });
    expect(input).toMatchObject({ indexRootDirExists: true, indexInstallPathExists: true, selectedVersion: r.measured ?? null });
    const verdict = reconcilePluginState(input);
    const rendered = renderPluginLoadVerdict(verdict);
    if (r.expect === 'pass') {
      expect(verdict).toMatchObject({ state: 'healthy', severity: 'ok', installedVersion: r.measured, installedVersionSource: 'selected-build' });
      expect(verdict.versionUnverified).toBeUndefined();
      expect(rendered.status).toBe('pass');
      expect(rendered.message).toContain(`v${r.measured}`);
      return;
    }
    expect(verdict.severity).not.toBe('ok');
    expect(rendered.status).not.toBe('pass');
    if (r.expect === 'measured-fail') {
      // The build's own manifest is a reading of the selected build: measured.
      expect(verdict).toMatchObject({
        state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
        installedVersion: '4.0.0', installedVersionSource: 'selected-build',
      });
      expect(verdict.versionUnverified).toBeUndefined();
      expect(rendered.message).toMatch(/regressed to v4\.0\.0 \(older than expected v5\.22\.1\) — running stale/);
      expect(rendered.message).not.toMatch(/v5\.22\.1 \(|install record/);
    } else if (r.expect === 'record-fail') {
      expect(verdict).toMatchObject({
        state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
        versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'index-record',
      });
      expect(verdict.reasons.join(' ')).toMatch(/the build OpenClaw selected has no readable version, and OpenClaw's install record says v4\.0\.0, older than expected 5\.22\.1/);
      expect(rendered.status).toBe('fail');
      expect(rendered.message).toMatch(/OpenClaw's install record says v4\.0\.0, older than expected v5\.22\.1; running version unknown/);
      expect(rendered.message).not.toMatch(/running stale|regressed to/);
    } else {
      expect(verdict).toMatchObject({
        state: 'version-unverified', severity: 'warn', recommendedAction: 'none',
        versionUnverified: true, installedVersion: null, installedVersionSource: null,
      });
      expect(rendered.status).toBe('warn');
      expect(rendered.message).toMatch(/could not be read \(version unverified\)/);
      // The record's version is never printed as if measured.
      expect(rendered.message).not.toMatch(new RegExp(`v${r.record.replace(/\./g, '\\.')}`));
      expect(rendered.message).toMatch(roster ? /the running gateway loaded it/ : /load is not confirmed either/);
    }
  });
});

/**
 * #260 r4c (owner ruling on jarvis r3: every path, not only a verified
 * rootDir) — the index-selected folder AND the record's folder are gone, so
 * nothing on the host measures the copy that runs. With no build anywhere, a
 * record below expected fails as on main (main weighs the record only when no
 * build is on disk), named as the record's claim; otherwise it is never a
 * pass: `version-unverified` (warn) when the running gateway proves the load,
 * the stale-path `load-unproven` warn when it does not. Both index layouts,
 * roster unread and roster proven, gather → reconcile → doctor's renderer.
 */
describe('#260 r4c — gone selected + record folders: an unmeasured version is never a pass', () => {
  const gone = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'reaped', PKG_SUBPATH);
  const LAYOUTS = [
    ['legacy installed_plugin_index', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeIndex(r)],
    ['config_machine_state', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeMachineStateIndex(r)],
  ] as const;
  const ROSTERS = [['roster unread', null], ['roster-proven', [PLUGIN]]] as const;
  const RECORDS = [['record 4.0.0', '4.0.0'], ['record at expected 5.22.1', '5.22.1'], ['record with no version', null]] as const;
  const cases = RECORDS.flatMap(([rl, v]) => LAYOUTS.flatMap(([layout, write]) => ROSTERS.map(([ro, roster]) => [`${rl} — ${layout}, ${ro}`, v, write, roster] as const)));

  it.each(cases)('%s', (_title, recordVersion, write, roster) => {
    writeConfig(true, true);
    write({
      installRecords: { [PLUGIN]: { source: 'npm', ...(recordVersion ? { version: recordVersion } : {}), installPath: gone() } },
      plugins: [upstreamEntry(gone())],
    });
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => (roster ? [...roster] : null) });
    expect(input).toMatchObject({ indexInstallPathExists: false, indexRootDirExists: false, onDiskVersion: null });
    const verdict = reconcilePluginState(input);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(verdict.severity).not.toBe('ok');
    expect(rendered.status).not.toBe('pass');
    if (recordVersion === '4.0.0') {
      expect(verdict).toMatchObject({
        state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
        versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'index-record',
      });
      expect(verdict.reasons.join(' ')).toMatch(/holds no plugin build, and OpenClaw's install record says v4\.0\.0, older than expected 5\.22\.1/);
      expect(rendered.status).toBe('fail');
      expect(rendered.message).toMatch(/OpenClaw's install record says v4\.0\.0, older than expected v5\.22\.1; running version unknown/);
      expect(rendered.message).not.toMatch(/running stale|regressed to/);
      return;
    }
    expect(rendered.status).toBe('warn');
    // Never the expected version printed as if measured.
    expect(rendered.message).not.toMatch(/v5\.22\.1/);
    if (roster) {
      expect(verdict).toMatchObject({
        state: 'version-unverified', severity: 'warn', recommendedAction: 'none',
        versionUnverified: true, installedVersion: null, installedVersionSource: null,
      });
      expect(verdict.reasons.join(' ')).toMatch(/load proven by the running gateway; the installed version could not be verified/);
      expect(rendered.message).toMatch(/version unverified\) — the running gateway loaded it/);
    } else {
      expect(verdict).toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: true });
    }
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
      index: { generatedAtMs: 2, installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1' } }, plugins: [upstreamEntry('/x')] },
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

/**
 * #260 Sol finding 4 through the real gather: an index that is there but
 * cannot be read reaches the reconciler as exactly that — with NO on-disk copy
 * (the case the earlier malformed-index test, which seeded a copy, could not
 * catch) — and a confirmed absence still fails.
 */
describe('#260 Sol-4 — gather carries present-but-unreadable', () => {
  it.each([
    ['a malformed migrated row', (): void => writeMachineStateIndex(null, '{"revision": 1, "index": {')],
    ['a migrated row with a bad plugins entry', (): void => writeMachineStateIndex({ installRecords: {}, plugins: [{ pluginId: PLUGIN, rootDir: 7, enabled: true }] })],
    ['a legacy row with a column that does not parse', (): void => {
      writeIndex({ installRecords: {}, plugins: [] });
      const db = new Database(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'));
      db.exec(`UPDATE installed_plugin_index SET install_records_json = 'not json'`);
      db.close();
    }],
    ['a state DB that is not a database', (): void => {
      fs.mkdirSync(path.join(home, '.openclaw', 'state'), { recursive: true });
      fs.writeFileSync(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'), 'not a sqlite database');
    }],
  ])('%s, config enabled, NO on-disk copy ⇒ index-unreadable / warn / none (never enabled-not-installed)', (_label, write) => {
    writeConfig(true, true);
    write();
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.index).toBeNull();
    expect(input.indexUnreadable).toBe(true);
    expect(input.onDiskVersion).toBeNull();
    expect(input.onDiskInstallPath).toBeNull();
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({ state: 'index-unreadable', severity: 'warn', recommendedAction: 'none' });
  });

  it.each([
    ['no state DB at all', (): void => undefined],
    ['a migrated DB with no index row', (): void => writeMachineStateIndex(null)],
    ['a readable index with no record for the plugin', (): void => writeMachineStateIndex({ installRecords: {}, plugins: [] })],
  ])('confirmed-absence control: %s + config enabled + no copy ⇒ enabled-not-installed / fail / install', (_label, write) => {
    writeConfig(true, true);
    write();
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null });
    expect(input.indexUnreadable).toBe(false);
    expect(reconcilePluginState(input)).toMatchObject({ state: 'enabled-not-installed', severity: 'fail', recommendedAction: 'install' });
  });

  it('a read live roster without the plugin still convicts over an unreadable index', () => {
    writeConfig(true, true);
    writeMachineStateIndex(null, 'not json');
    expect(reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => ['brave'] })))
      .toMatchObject({ state: 'enabled-not-loaded', severity: 'fail' });
  });

  it('an injected readIndex keeps its old meaning (indexUnreadable unset)', () => {
    writeConfig(true, true);
    const input = gatherReconcileInput(home, { expectedVersion: '5.22.1', readIndex: () => null, readLiveRoster: () => null });
    expect(input.indexUnreadable).toBeUndefined();
  });
});

/**
 * #260 r7 (Sol review at 7c5a9714). Both index layouts, roster unread and
 * roster-proven, gather → reconcile → doctor's renderer, plus the #1109
 * preflight repair would run (`assessRealtimeReplacement`).
 */
describe('#260 r7 — unreadable selected copy, diagnostic-only warns, record-path build', () => {
  const LAYOUTS = [
    ['legacy installed_plugin_index', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeIndex(r)],
    ['config_machine_state', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeMachineStateIndex(r)],
  ] as const;
  const ROSTERS = [['roster unread', null], ['roster-proven', [PLUGIN]]] as const;
  const MATRIX = LAYOUTS.flatMap(([layout, write]) => ROSTERS.map(([rl, roster]) => [`${layout}, ${rl}`, write, roster] as const));
  const gone = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'reaped', PKG_SUBPATH);
  /** A linked/path build outside every place the disk scan looks. */
  const selected = (): string => path.join(home, 'linked', 'shieldcortex-realtime');
  const gather = (roster: readonly string[] | null) =>
    gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => (roster ? [...roster] : null) });
  const preflight = () => assessRealtimeReplacement(readRealtimeReplacementEvidence(home), '5.22.1');
  const noInstallAdvice = (fix: string | undefined): void => {
    expect(fix ?? '').not.toMatch(/plugins install|--force|shieldcortex repair/);
  };
  // Permission rows need a non-root uid: root reads a mode-0 file.
  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const permIt = asRoot ? it.skip : it;

  /** The selected copy: own manifest at `manifestVersion`, package.json unreadable by permission. */
  const unreadableSelected = (manifestVersion: string | undefined, opts: { manifestUnreadable?: boolean } = {}): void => {
    writeRealBuild(selected(), '5.22.1');
    fs.writeFileSync(path.join(selected(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, ...(manifestVersion ? { version: manifestVersion } : {}) }));
    fs.chmodSync(path.join(selected(), 'package.json'), 0);
    if (opts.manifestUnreadable) fs.chmodSync(path.join(selected(), 'openclaw.plugin.json'), 0);
  };

  // FINDING 1 (Sol BLOCKER): at 7c5a9714 an EACCES package.json made the
  // build check return "not checked" before the manifest was read, and the
  // current 5.22.1 copy elsewhere passed the row (roster-confirmed PASS at
  // v5.22.1). Now it takes the corrupt path: the manifest is read — 4.0.0 is
  // a measured regression.
  permIt.each(MATRIX)('F1: package.json unreadable (EACCES), own manifest 4.0.0, a current 5.22.1 copy elsewhere ⇒ measured regression, never a pass — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    unreadableSelected('4.0.0');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: selected() } }, plugins: [upstreamEntry(selected())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: true, selectedVersion: '4.0.0', onDiskVersion: '5.22.1' });
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({
      state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned',
      installedVersion: '4.0.0', installedVersionSource: 'selected-build',
    });
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('fail');
    expect(rendered.message).toMatch(/regressed to v4\.0\.0/);
  });

  permIt.each(MATRIX)('F1: package.json unreadable (EACCES), manifest carries no version ⇒ version-unverified / warn, the other copy never clears it — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    unreadableSelected(undefined);
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: selected() } }, plugins: [upstreamEntry(selected())] });
    const verdict = reconcilePluginState(gather(roster));
    expect(verdict).toMatchObject({ state: 'version-unverified', severity: 'warn', recommendedAction: 'none', installedVersion: null, versionUnverified: true });
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('warn');
    expect(rendered.message).not.toMatch(/v5\.22\.1/);
    noInstallAdvice(rendered.fix);
  });

  // Same class: package.json AND manifest unreadable — the build check itself
  // cannot run (null). A named rootDir that could not be checked is an
  // unmeasured selected copy: another copy may convict, never clear.
  permIt.each(MATRIX)('F1: package.json and manifest both unreadable (check cannot run), a current copy elsewhere ⇒ version-unverified / warn, never a pass — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    unreadableSelected('5.22.1', { manifestUnreadable: true });
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: selected() } }, plugins: [upstreamEntry(selected())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: null, indexRootDirUnreadable: true, onDiskVersion: '5.22.1' });
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({ state: 'version-unverified', severity: 'warn', recommendedAction: 'none', installedVersion: null, versionUnverified: true });
    expect(verdict.reasons.join(' ')).toMatch(/could not be read \(permission or I\/O error\)/);
    expect(renderPluginLoadVerdict(verdict).status).toBe('warn');
  });

  permIt.each(MATRIX)('F1: both files unreadable, the copy elsewhere is 4.0.0 ⇒ that claim convicts (versionUnverified), running version unknown — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '4.0.0'), '4.0.0');
    unreadableSelected('5.22.1', { manifestUnreadable: true });
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: selected() } }, plugins: [upstreamEntry(selected())] });
    const verdict = reconcilePluginState(gather(roster));
    expect(verdict).toMatchObject({ state: 'version-regressed', severity: 'fail', versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'disk' });
    expect(renderPluginLoadVerdict(verdict).message).toMatch(/running version unknown/);
  });

  // FINDING 2 (general rule): doctor never offers a repair that repair's own
  // preflight refuses. The measured regression above is a real FAIL, but the
  // preflight will not replace a copy whose package.json it cannot read — so
  // doctor says so instead of "Run `shieldcortex repair`".
  permIt('F2: doctor does not offer repair when the preflight would refuse it (unreadable package.json, measured 4.0.0)', async () => {
    writeConfig(true, true);
    unreadableSelected('4.0.0');
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: selected() } }, plugins: [upstreamEntry(selected())] });
    expect(preflight()).toMatchObject({ replace: false, why: 'unknown' });
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/regressed to v4\.0\.0/);
    noInstallAdvice(r.fix);
    expect(r.fix).toMatch(/^Check it: `shieldcortex openclaw status`\. Repair will not reinstall the plugin here: /);
    expect(r.needsOpenClawCli).toBeUndefined();
  });

  // FINDING 2 (Sol BLOCKER): version-unverified has no action, so its fix is
  // diagnostic only. Sol's probe row: selected rootDir missing, a real 5.23.0
  // build at the record's path — at 7c5a9714 the fix offered
  // `openclaw plugins install --force …@5.22.1`, which the preflight refuses.
  it.each(MATRIX)('F2: selected rootDir missing, newer 5.23.0 build at the record path (record 5.22.1) ⇒ warn, no action, no install command — %s', async (_t, write, roster) => {
    writeConfig(true, true);
    const atRecord = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.23.0'), '5.23.0');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: atRecord } }, plugins: [upstreamEntry(gone())] });
    const verdict = reconcilePluginState(gather(roster));
    expect(verdict).toMatchObject({ state: roster ? 'version-unverified' : 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: true });
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('warn');
    noInstallAdvice(rendered.fix);
    expect(rendered.fix).toMatch(/^Check it: `shieldcortex openclaw status`/);
    expect(preflight().replace).toBe(false);
    if (!roster) noInstallAdvice((await checkOpenClawPluginLoadState(home, '5.22.1')).fix);
  });

  it.each(MATRIX)('F2: verified selected build, corrupt package.json, no version anywhere ⇒ version-unverified fix is diagnostic only — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(selected(), '5.22.1');
    fs.writeFileSync(path.join(selected(), 'package.json'), '{ not json');
    fs.writeFileSync(path.join(selected(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: selected() } }, plugins: [upstreamEntry(selected())] });
    const verdict = reconcilePluginState(gather(roster));
    expect(verdict).toMatchObject({ state: 'version-unverified', recommendedAction: 'none' });
    const rendered = renderPluginLoadVerdict(verdict);
    noInstallAdvice(rendered.fix);
    expect(rendered.fix).toMatch(/package\.json and openclaw\.plugin\.json can be read and carry an exact version/);
    expect(rendered.needsOpenClawCli).toBeUndefined();
    expect(preflight().replace).toBe(false);
  });

  // FINDING 3a (Sol SHOULD-FIX): only the SELECTED folder is empty — the
  // record's own path holds a verified 5.22.1 build, which refutes the
  // record's 5.0.0. At 7c5a9714 this failed as stale-index-record ("folders
  // that hold no build") and promised a repair the preflight refuses (record
  // 5.0.0 vs copy 5.22.1 ⇒ unknown). The preflight's refusal stands (#1109:
  // conflicting evidence never authorises a forced install), so the verdict no
  // longer promises it: the empty selection still blocks a pass, as a warn
  // with no action that names the selected folder.
  it.each(MATRIX)('F3a: selected rootDir empty, verified 5.22.1 build at the record path, record 5.0.0 ⇒ warn, no action, names the selected folder — %s', async (_t, write, roster) => {
    writeConfig(true, true);
    const atRecord = writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: atRecord } }, plugins: [upstreamEntry(gone())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: false, indexInstallPathExists: true });
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({
      state: roster ? 'version-unverified' : 'load-unproven', severity: 'warn', recommendedAction: 'none',
      indexPathMissing: true, installedVersion: null,
    });
    expect(verdict.reasons.join(' ')).toContain(`selects the plugin at ${gone()}, which holds no plugin build`);
    expect(verdict.reasons.join(' ')).not.toMatch(/stale index record|v5\.0\.0/);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.message).toMatch(/points to a folder that holds no (plugin )?build/);
    expect(rendered.message).not.toMatch(/folders that hold no build|v5\.0\.0|v5\.22\.1/);
    noInstallAdvice(rendered.fix);
    expect(preflight()).toMatchObject({ replace: false, why: 'unknown' });
    if (!roster) noInstallAdvice((await checkOpenClawPluginLoadState(home, '5.22.1')).fix);
  });

  // Positive control: both indexed folders empty (the ruled case) still fails
  // as stale-index-record, and doctor still offers repair — the preflight
  // allows that pinned reinstall.
  it('F3a control: both indexed folders empty, record 5.0.0, current build elsewhere ⇒ stale-index-record FAIL, doctor offers repair, preflight allows it', async () => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } }, plugins: [upstreamEntry(gone())] });
    expect(preflight()).toEqual({ replace: true });
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/stale index record/);
    expect(r.fix).toMatch(/shieldcortex repair.*pinned to v5\.22\.1/);
  });

  // FINDING 3b (Sol SHOULD-FIX), decided: KEEP the warn. On main, an index
  // entry that is not enabled with the roster unread is rule 4
  // (load-unproven / warn), which runs BEFORE the version rule — main warns
  // there even on a measured regression. The stale-record fail is a
  // version-tier rule and keeps main's order. A read roster still decides
  // (naming it ⇒ the stale-record FAIL; omitting it ⇒ enabled-not-loaded).
  it.each(LAYOUTS)('F3b: both indexed folders empty + index entry enabled:false + roster unread ⇒ load-unproven / warn, as main does for that entry (%s)', (_l, write) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } }, plugins: [upstreamEntry(gone(), { enabled: false })] });
    expect(reconcilePluginState(gather(null))).toMatchObject({ state: 'load-unproven', severity: 'warn' });
    expect(reconcilePluginState(gather([PLUGIN]))).toMatchObject({ state: 'stale-index-record', severity: 'fail' });
    expect(reconcilePluginState(gather([]))).toMatchObject({ state: 'enabled-not-loaded', severity: 'fail' });
  });
});

/**
 * #260 r8 (Sol delta review at 62323dc6). The record's folder is tri-state —
 * a build, no build, not read — and a build there is a measured copy that may
 * convict, never clear. Doctor's preflight-aware fix keeps host text off
 * command lines and out of the NEXT parser, and the human report shows why
 * repair refuses.
 */
describe('#260 r8 — record-path tri-state, record-path build convicts, preflight fix host text', () => {
  const LAYOUTS = [
    ['legacy installed_plugin_index', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeIndex(r)],
    ['config_machine_state', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeMachineStateIndex(r)],
  ] as const;
  const ROSTERS = [['roster unread', null], ['roster-proven', [PLUGIN]]] as const;
  const MATRIX = LAYOUTS.flatMap(([layout, write]) => ROSTERS.map(([rl, roster]) => [`${layout}, ${rl}`, write, roster] as const));
  const gone = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'reaped', PKG_SUBPATH);
  /** The record's folder: outside every place the disk scan looks. */
  const recordCopy = (): string => path.join(home, 'record-copy', 'shieldcortex-realtime');
  const gather = (roster: readonly string[] | null) =>
    gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => (roster ? [...roster] : null) });
  const preflight = () => assessRealtimeReplacement(readRealtimeReplacementEvidence(home), '5.22.1');
  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const permIt = asRoot ? it.skip : it;

  // FINDING 1a (Sol BLOCKER): at 62323dc6 a record folder that could not be
  // read counted as one that "holds no build", so the stale-record rule
  // failed on folders it never checked. Unread is not empty.
  permIt.each(MATRIX)('F1a: selected rootDir gone, record folder unreadable (check cannot run), record 5.0.0, current build elsewhere ⇒ warn, never "holds no build" for that folder, never a pass — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeRealBuild(recordCopy(), '5.0.0');
    fs.chmodSync(path.join(recordCopy(), 'openclaw.plugin.json'), 0);
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: recordCopy() } }, plugins: [upstreamEntry(gone())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: false, indexInstallPathExists: null, indexInstallPathUnreadable: true, onDiskVersion: '5.22.1' });
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({
      state: roster ? 'version-unverified' : 'load-unproven', severity: 'warn', recommendedAction: 'none',
      indexPathMissing: true, installedVersion: null,
    });
    const why = verdict.reasons.join(' ');
    expect(why).toContain(`(${recordCopy()}) could not be checked (permission or I/O error)`);
    expect(why).not.toContain(`${recordCopy()}, which holds no plugin build`);
    expect(why).not.toMatch(/stale index record/);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('warn');
    expect(rendered.message).not.toMatch(/folders that hold no build|v5\.(0\.0|22\.1)/);
  });

  // "If the other evidence already convicts, still fail."
  permIt.each(MATRIX)('F1a: record folder unreadable, but the build elsewhere is 4.0.0 ⇒ that claim still convicts — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '4.0.0'), '4.0.0');
    writeRealBuild(recordCopy(), '5.0.0');
    fs.chmodSync(path.join(recordCopy(), 'openclaw.plugin.json'), 0);
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: recordCopy() } }, plugins: [upstreamEntry(gone())] });
    const verdict = reconcilePluginState(gather(roster));
    expect(verdict).toMatchObject({ state: 'version-regressed', severity: 'fail', versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'disk' });
  });

  // Control: the ruled case — both indexed folders confirmed empty — still
  // fails on the stale record.
  it.each(MATRIX)('F1a control: both indexed folders confirmed empty, record 5.0.0, current build elsewhere ⇒ stale-index-record FAIL — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } }, plugins: [upstreamEntry(gone())] });
    const input = gather(roster);
    expect(input.indexInstallPathExists).toBe(false);
    expect(input.indexInstallPathUnreadable).toBeUndefined();
    expect(reconcilePluginState(input)).toMatchObject({ state: 'stale-index-record', severity: 'fail' });
  });

  // FINDING 1b (Sol BLOCKER): at 62323dc6 any verified build at the record's
  // folder suppressed the failure without a version comparison — a 5.0.0
  // build there warned beside a current scan. It is a measured copy: older
  // than expected, it convicts; running version unknown.
  it.each(MATRIX)('F1b: selected rootDir gone, verified 5.0.0 build at the record folder, current build elsewhere ⇒ fails on that copy, running version unknown — %s', async (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeRealBuild(recordCopy(), '5.0.0');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: recordCopy() } }, plugins: [upstreamEntry(gone())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: false, indexInstallPathExists: true, recordPathVersion: '5.0.0', onDiskVersion: '5.22.1' });
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({
      state: 'version-regressed', severity: 'fail', recommendedAction: 'reinstall-pinned', versionUnverified: true,
      installedVersion: '5.0.0', installedVersionSource: 'record-path-build',
    });
    expect(verdict.reasons.join(' ')).toContain(`the build in the folder OpenClaw's install record names (${recordCopy()}) is v5.0.0`);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('fail');
    expect(rendered.message).toMatch(/the build in the folder OpenClaw's install record names is v5\.0\.0, older than expected v5\.22\.1; running version unknown/);
    expect(rendered.message).not.toMatch(/running stale|v5\.22\.1 \(/);
    if (!roster) {
      // The preflight allows the pinned reinstall here, so doctor offers repair.
      expect(preflight()).toEqual({ replace: true });
      const r = await checkOpenClawPluginLoadState(home, '5.22.1');
      expect(r.status).toBe('fail');
    }
  });

  it.each(MATRIX)('F1b: the record says 5.22.1 but the build in its folder is 5.0.0 ⇒ the build convicts, the record never clears it — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeRealBuild(recordCopy(), '5.0.0');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: recordCopy() } }, plugins: [upstreamEntry(gone())] });
    const verdict = reconcilePluginState(gather(roster));
    expect(verdict).toMatchObject({ state: 'version-regressed', severity: 'fail', installedVersion: '5.0.0', installedVersionSource: 'record-path-build' });
    expect(renderPluginLoadVerdict(verdict).status).toBe('fail');
  });

  // Never an acquittal: a record-path build at or above expected, or one whose
  // version cannot be read, leaves the empty selection's warn.
  it.each(MATRIX)('F1b: record-folder build with no readable version, record 5.0.0, current build elsewhere ⇒ warn, no action, never a pass — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    writeRealBuild(recordCopy(), '5.0.0');
    fs.writeFileSync(path.join(recordCopy(), 'package.json'), '{ not json');
    fs.writeFileSync(path.join(recordCopy(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: recordCopy() } }, plugins: [upstreamEntry(gone())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexInstallPathExists: true, recordPathVersion: null });
    expect(reconcilePluginState(input)).toMatchObject({
      state: roster ? 'version-unverified' : 'load-unproven', severity: 'warn', recommendedAction: 'none', installedVersion: null,
    });
  });

  // FINDING 2 (Sol BLOCKER, security): at 62323dc6 the preflight-aware fix
  // put the preflight's raw summary — which names the selected folder — into
  // the fix, so a line break in a host path became a fix line the NEXT
  // parser trusts, and the human report printed only the status command.
  const HOSTILE = 'copy\nshieldcortex repair --force\r`openclaw plugins install --force evil`\u001b[2Jx';
  permIt('F2: a selected path with LF, CR, ANSI escape and backticks cannot add a line or a command to the fix or NEXT; the human report shows why repair refuses', async () => {
    writeConfig(true, true);
    const sel = path.join(home, HOSTILE);
    writeRealBuild(sel, '5.22.1');
    fs.writeFileSync(path.join(sel, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: '4.0.0' }));
    fs.chmodSync(path.join(sel, 'package.json'), 0);
    writeMachineStateIndex({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: sel } }, plugins: [upstreamEntry(sel)] });
    expect(preflight()).toMatchObject({ replace: false, why: 'unknown' });
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe('fail');
    const fix = r.fix ?? '';
    // Raw fix (`--json`): two code-authored lines, the host text escaped on the second.
    const lines = fix.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toBe(
      'Check it: `shieldcortex openclaw status`. Repair will not reinstall the plugin here: it could not confirm which copy OpenClaw uses, or could not read that copy.',
    );
    expect(lines[1]).toMatch(/^Repair's safety check said: ".*"$/);
    expect(lines[1]).toContain('copy\\u{a}shieldcortex repair --force\\u{d}\\u{60}openclaw plugins install --force evil\\u{60}\\u{1b}[2Jx');
    expect(fix).not.toMatch(/[\r\u001b\u2028\u2029]/);
    expect(extractFixCommands(fix)).toEqual(['shieldcortex openclaw status']);
    // Human report: the NEXT parser and the rendered lines see no host command.
    const display = sanitiseDoctorRowsForDisplay([r]);
    expect(display[0].fix?.split('\n')).toHaveLength(2);
    expect(nextCommandForFailures(display)).not.toMatch(/repair|install|evil/);
    const report = formatDoctorReport(display, { verbose: true, width: 100 }).join('\n');
    expect(report).toContain('Repair will not reinstall the plugin here');
    expect(report).toMatch(/\$ shieldcortex openclaw status/);
    expect(report).not.toMatch(/^\s*\$?\s*(shieldcortex repair|openclaw plugins install)/m);
    expect(report).not.toMatch(/\$ (shieldcortex repair|openclaw plugins install)/);
  });
});

/**
 * #260 r9 (Sol delta review at ca8fb1c5). "Not checked" is not "empty" for a
 * RELATIVE path either: the build check returns null for one (it is resolved
 * against OpenClaw's own working directory, never here), and at ca8fb1c5 that
 * null still counted as a folder that holds no build — a stale-index-record
 * FAIL and a scheduled reinstall on a folder no one looked at. The stale
 * record now needs absence CONFIRMED for every indexed folder; an unchecked
 * one is named as such and schedules nothing. Repair's preflight no longer
 * stats a relative path against this process's cwd as if it were "not there".
 */
describe('#260 r9 — a relative indexed path is unchecked, never empty', () => {
  const LAYOUTS = [
    ['legacy installed_plugin_index', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeIndex(r)],
    ['config_machine_state', (r: { installRecords: Record<string, unknown>; plugins: unknown[] }) => writeMachineStateIndex(r)],
  ] as const;
  const ROSTERS = [['roster unread', null], ['roster-proven', [PLUGIN]]] as const;
  const MATRIX = LAYOUTS.flatMap(([layout, write]) => ROSTERS.map(([rl, roster]) => [`${layout}, ${rl}`, write, roster] as const));
  const gone = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'reaped', PKG_SUBPATH);
  /** Relative to nothing this process knows: OpenClaw resolves it against its own cwd. */
  const REL_RECORD = path.join('record-copy', 'shieldcortex-realtime');
  const REL_ROOT = path.join('selected-copy', 'shieldcortex-realtime');
  const unreadableCopy = (): string => {
    const dir = writeRealBuild(path.join(home, 'unreadable-copy', 'shieldcortex-realtime'), '5.0.0');
    fs.chmodSync(path.join(dir, 'openclaw.plugin.json'), 0);
    return dir;
  };
  const gather = (roster: readonly string[] | null) =>
    gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => (roster ? [...roster] : null) });
  const preflight = () => assessRealtimeReplacement(readRealtimeReplacementEvidence(home), '5.22.1');
  const installSteps = (v: ReturnType<typeof reconcilePluginState>) =>
    planReconcileActions(v, { expectedVersion: '5.22.1', pluginId: PLUGIN, packageName: REALTIME_PLUGIN_PACKAGE })
      .filter((s) => s.kind === 'openclaw-install' || s.kind === 'openclaw-install-pinned');
  const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const permIt = asRoot ? it.skip : it;
  /** Every unchecked row: a warn, no action, no reinstall, never the stale-record wording. */
  const expectUncheckedWarn = (verdict: ReturnType<typeof reconcilePluginState>, state: string) => {
    expect(verdict).toMatchObject({ state, severity: 'warn', recommendedAction: 'none', installedVersion: null });
    expect(verdict.reasons.join(' ')).not.toMatch(/stale index record/);
    expect(installSteps(verdict)).toEqual([]);
    const rendered = renderPluginLoadVerdict(verdict);
    expect(rendered.status).toBe('warn');
    expect(rendered.message).not.toMatch(/folders that hold no build|stale index record/);
    expect(rendered.fix ?? '').not.toMatch(/shieldcortex repair|plugins install/);
  };

  // (i) Sol's first fixture.
  it.each(MATRIX)('(i) relative record installPath, selected rootDir gone, record 5.0.0, current build elsewhere ⇒ warn, the record folder "could not be checked", no reinstall — %s', async (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: REL_RECORD } }, plugins: [upstreamEntry(gone())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: false, indexInstallPathExists: null, indexInstallPathUnreadable: true, onDiskVersion: '5.22.1' });
    const verdict = reconcilePluginState(input);
    expectUncheckedWarn(verdict, roster ? 'version-unverified' : 'load-unproven');
    const why = verdict.reasons.join(' ');
    expect(why).toContain(`(${REL_RECORD}) could not be checked (not an absolute path`);
    expect(why).not.toContain(`${REL_RECORD}, which holds no plugin build`);
    // Repair's preflight does not read the relative folder as "not there".
    expect(preflight()).toMatchObject({ replace: false, why: 'unknown' });
    if (!roster) {
      const r = await checkOpenClawPluginLoadState(home, '5.22.1');
      expect(r.status).toBe('warn');
      expect(r.fix ?? '').not.toMatch(/shieldcortex repair|plugins install/);
    }
  });

  // (ii) Sol's second fixture.
  it.each(MATRIX)('(ii) relative selected rootDir, record installPath gone, record 5.0.0, current build elsewhere ⇒ warn, the selected copy "could not be checked", no reinstall — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } }, plugins: [upstreamEntry(REL_ROOT)] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: null, indexRootDirUnreadable: true, indexInstallPathExists: false, onDiskVersion: '5.22.1' });
    const verdict = reconcilePluginState(input);
    expectUncheckedWarn(verdict, 'version-unverified');
    expect(verdict.reasons.join(' ')).toContain(`the copy OpenClaw selected (${REL_ROOT}) could not be checked (not an absolute path`);
    expect(preflight()).toMatchObject({ replace: false, why: 'unknown' });
  });

  it.each(MATRIX)('both indexed paths relative, record 5.0.0, current build elsewhere ⇒ warn, never a pass, no reinstall — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: REL_RECORD } }, plugins: [upstreamEntry(REL_ROOT)] });
    const input = gather(roster);
    expect(input).toMatchObject({
      indexRootDirExists: null, indexRootDirUnreadable: true, indexInstallPathExists: null, indexInstallPathUnreadable: true,
    });
    expectUncheckedWarn(reconcilePluginState(input), 'version-unverified');
    expect(preflight()).toMatchObject({ replace: false, why: 'unknown' });
  });

  permIt.each(MATRIX)('relative selected rootDir + record folder unreadable (permission) ⇒ warn, no reinstall — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    const copy = unreadableCopy();
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: copy } }, plugins: [upstreamEntry(REL_ROOT)] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: null, indexRootDirUnreadable: true, indexInstallPathExists: null, indexInstallPathUnreadable: true });
    expectUncheckedWarn(reconcilePluginState(input), 'version-unverified');
  });

  permIt.each(MATRIX)('selected rootDir unreadable (permission) + relative record installPath ⇒ warn, no reinstall — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    const copy = unreadableCopy();
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: REL_RECORD } }, plugins: [upstreamEntry(copy)] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: null, indexRootDirUnreadable: true, indexInstallPathExists: null, indexInstallPathUnreadable: true });
    const verdict = reconcilePluginState(input);
    expectUncheckedWarn(verdict, 'version-unverified');
    expect(verdict.reasons.join(' ')).toContain(`(${copy}) could not be read (permission or I/O error)`);
  });

  // Measured-elsewhere evidence still convicts: the unchecked folder never acquits.
  it.each(MATRIX)('relative record installPath, selected rootDir gone, the build elsewhere is 4.0.0 ⇒ that claim still convicts — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '4.0.0'), '4.0.0');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: REL_RECORD } }, plugins: [upstreamEntry(gone())] });
    expect(reconcilePluginState(gather(roster))).toMatchObject({ state: 'version-regressed', severity: 'fail', installedVersion: '4.0.0', installedVersionSource: 'disk' });
  });

  // The reconciler does not lean on the gatherer's flag: a record that names
  // a folder whose check returned null is unchecked even when a caller passes
  // no `indexInstallPathUnreadable`.
  it.each(MATRIX)('reconciler: a named record folder with a null check and no flag is still not "confirmed empty" — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: REL_RECORD } }, plugins: [upstreamEntry(gone())] });
    const { indexInstallPathUnreadable: _flag, ...input } = gather(roster);
    void _flag;
    expect(input.indexInstallPathExists).toBeNull();
    const verdict = reconcilePluginState(input);
    expectUncheckedWarn(verdict, roster ? 'version-unverified' : 'load-unproven');
    expect(verdict.reasons.join(' ')).toContain(`(${REL_RECORD}) could not be checked (not an absolute path`);
  });

  it.each(MATRIX)('reconciler: a named selected rootDir with a null check and no flag is still not "confirmed empty" — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } }, plugins: [upstreamEntry(REL_ROOT)] });
    const { indexRootDirUnreadable: _flag, ...input } = gather(roster);
    void _flag;
    expect(input).toMatchObject({ indexRootDirExists: null, indexInstallPathExists: false });
    expectUncheckedWarn(reconcilePluginState(input), roster ? 'version-unverified' : 'load-unproven');
  });

  // Control: both indexed paths absolute and confirmed empty ⇒ still the stale-record FAIL.
  it.each(MATRIX)('control: both indexed paths absolute and confirmed empty, record 5.0.0, current build elsewhere ⇒ stale-index-record FAIL — %s', (_t, write, roster) => {
    writeConfig(true, true);
    writeRealBuild(writeProjectDir('drakon-systems-shieldcortex-realtime-abc', '5.22.1'), '5.22.1');
    write({ installRecords: { [PLUGIN]: { source: 'npm', version: '5.0.0', installPath: gone() } }, plugins: [upstreamEntry(gone())] });
    const input = gather(roster);
    expect(input).toMatchObject({ indexRootDirExists: false, indexInstallPathExists: false });
    expect(input.indexInstallPathUnreadable).toBeUndefined();
    expect(input.indexRootDirUnreadable).toBeUndefined();
    const verdict = reconcilePluginState(input);
    expect(verdict).toMatchObject({ state: 'stale-index-record', severity: 'fail', recommendedAction: 'reinstall-pinned' });
    expect(installSteps(verdict).length).toBeGreaterThan(0);
    expect(renderPluginLoadVerdict(verdict)).toMatchObject({ status: 'fail', message: expect.stringMatching(/folders that hold no build/) });
    expect(preflight()).toEqual({ replace: true });
  });
});
