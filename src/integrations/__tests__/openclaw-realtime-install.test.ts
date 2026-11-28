/**
 * #1109 round 2 — which realtime install is linked, and which copy OpenClaw
 * selected, read from OpenClaw's own files (Astra P1 ×2).
 *
 *  - A link is identified by what is AT a `plugins.load.paths` entry (its
 *    package.json name or openclaw.plugin.json id) and by path-source install
 *    records — openclaw.json, installs.json AND the SQLite install index. Not
 *    by the path string: a checkout's `plugins/openclaw` has no plugin id in
 *    its name.
 *  - The post-install check reads the copy OpenClaw SELECTED. A leftover copy
 *    at the pin next to an older selected copy is not success.
 *  - Unreadable or conflicting evidence is "unknown", never "absent"/success.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import {
  readLinkedRealtimeInstall,
  readRealtimeReplacementEvidence,
  readSelectedRealtimeInstall,
  readSelectedRealtimePluginVersion,
  readSelectedRealtimePluginVersionDetail,
} from '../openclaw-realtime-install.js';
import { readPluginInstallIndexState, type PluginInstallIndexState } from '../openclaw-plugin-index.js';
import { assessRealtimeReplacement } from '../../setup/openclaw-plugin-spec.js';

const ID = 'shieldcortex-realtime';
const PKG = '@drakon-systems/shieldcortex-realtime';
let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1109-r2-'));
  fs.mkdirSync(path.join(home, '.openclaw', 'plugins'), { recursive: true });
});
afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

/**
 * OpenClaw's SQLite install index, as its reader returns it. Injected through
 * the readers' `readIndex` seam: the real reader is exercised below on a file
 * it cannot open (the unreadable case); a real DB fixture is not written here.
 */
const index = (installRecords: Record<string, unknown>, plugins: unknown[] = []) =>
  ({ readIndex: (): PluginInstallIndexState => ({ state: 'ok', row: { installRecords, plugins } as never }) });
const unreadableIndex = { readIndex: (): PluginInstallIndexState => ({ state: 'unreadable', why: 'the install index row is not valid JSON' }) };

/** An npm project dir holding the realtime package at `version`; returns the package dir. */
const writeRealtimeProject = (projectName: string, version: string): string => {
  const dir = path.join(home, '.openclaw', 'npm', 'projects', projectName, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version }));
  return dir;
};

const writeJson = (rel: string, v: unknown): void => {
  fs.mkdirSync(path.dirname(path.join(home, '.openclaw', rel)), { recursive: true });
  fs.writeFileSync(path.join(home, '.openclaw', rel), JSON.stringify(v));
};
/** A checkout of this repo's plugin: `<root>/plugins/openclaw` with the real package name. */
const checkout = (version = '5.20.2'): string => {
  const dir = path.join(home, 'src', 'ShieldCortex', 'plugins', 'openclaw');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version }));
  fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version }));
  return dir;
};

describe('readLinkedRealtimeInstall — identity from what is at the path', () => {
  it('a load.paths link to a dir named plugins/openclaw is linked (package.json name)', () => {
    const dir = checkout();
    expect(dir).not.toContain(ID);
    writeJson('openclaw.json', { plugins: { load: { paths: [dir] } } });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'linked', at: dir });
  });

  it('a load.paths link identified by the manifest id alone', () => {
    const dir = path.join(home, 'work', 'plugin');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID }));
    writeJson('openclaw.json', { plugins: { load: { paths: ['~/work/plugin'] } } });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'linked', at: '~/work/plugin' });
  });

  it('a load.paths entry whose path NAMES the plugin but holds another plugin is not our link', () => {
    const dir = path.join(home, 'shieldcortex-realtime-fork');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: '@someone/else' }));
    writeJson('openclaw.json', { plugins: { load: { paths: [dir, '/nonexistent/shieldcortex-realtime'] } } });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'absent' });
  });

  it('a path-source record in the SQLite install index is linked', () => {
    const opts = index({ [ID]: { source: 'path', sourcePath: '/dev/sc', installPath: '/dev/sc' } });
    expect(readLinkedRealtimeInstall(home, opts)).toEqual({ state: 'linked', at: '/dev/sc' });
  });

  it('path-source records in installs.json and openclaw.json plugins.installs are linked', () => {
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'path', sourcePath: '/dev/a' } } });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'linked', at: '/dev/a' });
    fs.rmSync(path.join(home, '.openclaw', 'plugins', 'installs.json'));
    writeJson('openclaw.json', { plugins: { installs: { [ID]: { source: 'path', installPath: '/dev/b' } } } });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'linked', at: '/dev/b' });
  });

  it.each(['npm', 'clawhub', undefined])('a `%s` record is not linked', (source) => {
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source, installPath: '/x' } } });
    expect(readLinkedRealtimeInstall(home, index({ [ID]: { source, installPath: '/x' } }))).toEqual({ state: 'absent' });
  });

  it('no files at all is absent', () => {
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'absent' });
  });

  it.each([
    ['openclaw.json is JSON5', 'openclaw.json', '{ plugins: { load: { paths: [] } } } // json5'],
    ['installs.json is truncated', 'plugins/installs.json', '{"installRecords": {'],
  ])('UNKNOWN, not absent, when %s', (_label, rel, body) => {
    fs.writeFileSync(path.join(home, '.openclaw', rel), body);
    expect(readLinkedRealtimeInstall(home)).toMatchObject({ state: 'unknown', why: expect.stringMatching(/not strict JSON/) });
  });

  it('UNKNOWN when the SQLite index cannot be read (the real reader, on a file that is not a database)', () => {
    fs.mkdirSync(path.join(home, '.openclaw', 'state'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'), 'not a sqlite database at all, just text');
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
    expect(readLinkedRealtimeInstall(home).state).toBe('unknown');
    expect(readSelectedRealtimeInstall(home).state).toBe('unknown');
  });

  it('no DB file is absent, not unreadable', () => {
    expect(readPluginInstallIndexState(home)).toEqual({ state: 'absent' });
  });

  // #260: OpenClaw 2026.11.x moved the index into a config_machine_state row
  // and dropped the old table. These use the REAL reader on a real fixture DB:
  // "absent" here would let a forced install treat a recorded install as none.
  const writeMigratedStateDb = (valueJson: string | null): void => {
    const dir = path.join(home, '.openclaw', 'state');
    fs.mkdirSync(dir, { recursive: true });
    const db = new Database(path.join(dir, 'openclaw.sqlite'));
    db.exec('CREATE TABLE config_machine_state (state_key TEXT NOT NULL PRIMARY KEY, value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL)');
    if (valueJson !== null) db.prepare("INSERT INTO config_machine_state VALUES ('plugins.installedIndex', ?, 1)").run(valueJson);
    db.close();
  };

  it('#260: a migrated host (index in config_machine_state, no legacy table) is ok — and its record selects', () => {
    const dir = writeRealtimeProject('drakon-systems-shieldcortex-realtime-abc', '5.22.1');
    writeMigratedStateDb(JSON.stringify({
      revision: 7,
      index: {
        version: 1, generatedAtMs: 7, diagnostics: [],
        installRecords: { [ID]: { source: 'npm', version: '5.22.1', installPath: dir } },
        plugins: [{ pluginId: ID, enabled: true, rootDir: dir }],
      },
    }));
    const st = readPluginInstallIndexState(home);
    expect(st.state).toBe('ok');
    expect(st.state === 'ok' && st.row.installRecords[ID]?.version).toBe('5.22.1');
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'selected', version: '5.22.1' });
  });

  // #260 (Sol finding 1): selection evidence that OpenClaw itself would
  // reject must refuse the forced replacement. An index OpenClaw 2026.11.7+
  // would discard (non-numeric revision, a plugins entry without a string
  // rootDir or a boolean enabled) used to read as `ok`; with the realtime
  // record naming no path the bad rootDir was then dropped, selection fell
  // through to `none`, and `none` permits replacement.
  const upstreamIndex = (over: { revision?: unknown; entry?: Record<string, unknown>; record?: Record<string, unknown> } = {}, dir = '/nowhere'): string => {
    const entry = {
      pluginId: ID, manifestPath: path.join(dir, 'openclaw.plugin.json'), manifestHash: 'h', rootDir: dir, origin: 'global',
      enabled: true, startup: { sidecar: false, memory: false, agentHarnesses: [] }, compat: [], ...over.entry,
    };
    for (const [k, v] of Object.entries(over.entry ?? {})) if (v === undefined) delete (entry as Record<string, unknown>)[k];
    return JSON.stringify({
      ...('revision' in over ? (over.revision === undefined ? {} : { revision: over.revision }) : { revision: 7 }),
      index: {
        version: 1, hostContractVersion: '2026.11.10', compatRegistryVersion: 'x', migrationVersion: 1, policyHash: 'h',
        generatedAtMs: 7, diagnostics: [],
        installRecords: { [ID]: { source: 'npm', ...(over.record ?? { version: '5.22.1', installPath: dir }) } },
        plugins: [entry],
      },
    });
  };

  it.each([
    ['a numeric rootDir (and no install path on the record)', { entry: { rootDir: 42 }, record: { version: '6.0.0' } }],
    ['no rootDir at all (and no install path on the record)', { entry: { rootDir: undefined }, record: { version: '6.0.0' } }],
    ['a string enabled', { entry: { enabled: 'yes' } }],
    ['no enabled', { entry: { enabled: undefined } }],
    ['no revision', { revision: undefined }],
    ['a string revision', { revision: '7' }],
  ])('#260 Sol-1: a migrated index with %s ⇒ unreadable ⇒ selected unknown ⇒ the forced replacement is REFUSED', (_label, over) => {
    writeMigratedStateDb(upstreamIndex(over as never));
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
    const evidence = readRealtimeReplacementEvidence(home);
    expect(evidence.selected.state).toBe('unknown');
    expect(evidence.selected.state).not.toBe('none');
    expect(assessRealtimeReplacement(evidence, '5.22.1')).toMatchObject({ replace: false, why: 'unknown' });
  });

  it('#260 Sol-1 control: an upstream-shaped migrated index (every field OpenClaw 2026.11.x writes) selects its copy and allows the pinned replacement', () => {
    const dir = writeRealtimeProject('drakon-systems-shieldcortex-realtime-abc', '5.22.1');
    writeMigratedStateDb(upstreamIndex({}, dir));
    const st = readPluginInstallIndexState(home);
    expect(st.state).toBe('ok');
    const evidence = readRealtimeReplacementEvidence(home);
    expect(evidence.selected).toMatchObject({ state: 'selected', version: '5.22.1', dir });
    expect(assessRealtimeReplacement(evidence, '5.22.1')).toEqual({ replace: true });
  });

  it('#260 Sol-1 control: an upstream-shaped index whose copy is gone and that no other copy backs is still `none` (nothing to lose)', () => {
    writeMigratedStateDb(upstreamIndex({}, path.join(home, 'gone')));
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'none', dangling: expect.any(String) });
  });

  it.each([
    ['an empty rootDir', { rootDir: '' }],
    ['a blank rootDir', { rootDir: '   ' }],
    ['no rootDir (a legacy row, which the reader does not require it on)', {}],
  ])('#260 Sol-1: a roster entry for the plugin with %s ⇒ unknown, never none', (_label, extra) => {
    const s = readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', version: '6.0.0' } }, [{ pluginId: ID, enabled: true, ...extra }]));
    expect(s).toMatchObject({ state: 'unknown', why: expect.stringMatching(/no usable rootDir/) });
  });

  it('#260: a migrated state DB with no index row is absent', () => {
    writeMigratedStateDb(null);
    expect(readPluginInstallIndexState(home)).toEqual({ state: 'absent' });
  });

  it.each([
    ['malformed JSON', '{"index": '],
    ['the wrong shape', JSON.stringify({ revision: 1, index: { installRecords: [], plugins: 'x' } })],
  ])('#260: a migrated index row with %s is unreadable ⇒ the selected copy is unknown', (_label, valueJson) => {
    writeMigratedStateDb(valueJson);
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
    expect(readSelectedRealtimeInstall(home).state).toBe('unknown');
  });

  // #260 round 2 (Astra): a corrupt RECORD inside a well-formed index. Read as
  // `ok`, the null record names no copy, selection says `none`, and the forced
  // install is allowed to replace an install it never looked at.
  it.each([
    ['a null realtime install record', { installRecords: { [ID]: null }, plugins: [] }],
    ['a null plugins entry', { installRecords: {}, plugins: [null] }],
    // #260 r3: an object record, with a field we select on mistyped. Read as
    // `ok` it names no path ⇒ `none` ⇒ replacing a 6.0.0 install is allowed.
    ['a realtime record with a numeric installPath', { installRecords: { [ID]: { source: 'npm', installPath: 37, version: '6.0.0' } }, plugins: [] }],
    ['a realtime record with a null version', { installRecords: { [ID]: { source: 'npm', version: null } }, plugins: [] }],
    ['a realtime record with a numeric resolvedVersion', { installRecords: { [ID]: { source: 'npm', resolvedVersion: 6 } }, plugins: [] }],
    ['a realtime record with an object source', { installRecords: { [ID]: { source: {}, version: '6.0.0' } }, plugins: [] }],
    ['a realtime record with a numeric sourcePath', { installRecords: { [ID]: { source: 'path', sourcePath: 1 } }, plugins: [] }],
  ])('#260 r2: %s ⇒ unreadable ⇒ selected unknown ⇒ the forced replacement is REFUSED', (_label, idx) => {
    writeMigratedStateDb(JSON.stringify({ revision: 7, index: { version: 1, generatedAtMs: 7, diagnostics: [], ...idx } }));
    expect(readPluginInstallIndexState(home).state).toBe('unreadable');
    const evidence = readRealtimeReplacementEvidence(home);
    expect(evidence.selected.state).toBe('unknown');
    expect(assessRealtimeReplacement(evidence, '5.22.1')).toMatchObject({ replace: false, why: 'unknown' });
  });

  it('UNKNOWN when a load.paths entry\'s package.json cannot be parsed', () => {
    const dir = path.join(home, 'work', 'x');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{ broken');
    writeJson('openclaw.json', { plugins: { load: { paths: [dir] } } });
    expect(readLinkedRealtimeInstall(home).state).toBe('unknown');
  });

  it('linked evidence wins over an unreadable source elsewhere', () => {
    const dir = checkout();
    writeJson('openclaw.json', { plugins: { load: { paths: [dir] } } });
    fs.writeFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), '{ broken');
    expect(readLinkedRealtimeInstall(home).state).toBe('linked');
  });
});

describe('readSelectedRealtimeInstall — the copy OpenClaw selected, not the highest on disk', () => {
  it('two installs: a leftover at the pin + the SELECTED older copy ⇒ the older one', () => {
    writeRealtimeProject('drakon-systems-shieldcortex-realtime-new', '5.20.2');
    const selected = writeRealtimeProject('drakon-systems-shieldcortex-realtime-old', '5.17.3');
    const opts = index(
      { [ID]: { source: 'npm', resolvedVersion: '5.17.3', installPath: selected } },
      [{ pluginId: ID, enabled: true, rootDir: selected }],
    );
    expect(readSelectedRealtimeInstall(home, opts)).toMatchObject({ state: 'selected', dir: selected, version: '5.17.3' });
    expect(readSelectedRealtimePluginVersion(home, opts)).toEqual({ version: '5.17.3' });
  });

  it('the index record alone (no roster entry) selects', () => {
    const p = writeRealtimeProject('proj', '5.20.2');
    expect(readSelectedRealtimePluginVersion(home, index({ [ID]: { source: 'npm', installPath: p } }))).toEqual({ version: '5.20.2' });
  });

  it('CONFLICT: the record says one version, the copy it names says another ⇒ unknown', () => {
    const p = writeRealtimeProject('proj', '5.17.3');
    expect(readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', resolvedVersion: '5.20.2', installPath: p } })))
      .toMatchObject({ state: 'unknown', why: expect.stringContaining('says v5.20.2') });
  });

  it('CONFLICT: the roster and the record name copies at different versions ⇒ unknown', () => {
    const a = writeRealtimeProject('a', '5.20.2');
    const b = writeRealtimeProject('b', '5.17.3');
    expect(readSelectedRealtimeInstall(home, index(
      { [ID]: { source: 'npm', installPath: a } },
      [{ pluginId: ID, enabled: true, rootDir: b }],
    )).state).toBe('unknown');
  });

  it('#1109 round 4: the copy the index names is NOT ON DISK ⇒ none (dangling), never the leftover and never a version', () => {
    writeRealtimeProject('leftover', '5.20.2');
    const gone = path.join(home, 'gone');
    const s = readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', installPath: gone } }, [{ pluginId: ID, rootDir: gone }]));
    expect(s).toEqual({ state: 'none', dangling: `the copy OpenClaw's install index roster and install index record name is not on disk (${gone})`, danglingDirs: [gone, gone] });
    expect(readSelectedRealtimePluginVersion(home, index({ [ID]: { source: 'npm', installPath: gone } })))
      .toEqual({ version: null, reason: `the copy OpenClaw's install index record names is not on disk (${gone})` });
  });

  it('#1109 round 4: a named directory holding neither package.json nor openclaw.plugin.json is not on disk either', () => {
    const empty = path.join(home, '.openclaw', 'npm', 'projects', 'reaped', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(empty, { recursive: true });
    expect(readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', installPath: empty } })).state).toBe('none');
  });

  it('#1109 round 4: a dangling record falls through to what OpenClaw discovers (a newer extension copy is still seen)', () => {
    const ext = path.join(home, '.openclaw', 'extensions', ID);
    fs.mkdirSync(ext, { recursive: true });
    fs.writeFileSync(path.join(ext, 'index.js'), '');
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: '5.22.0' }));
    expect(readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', installPath: path.join(home, 'gone') } })))
      .toMatchObject({ state: 'selected', dir: ext, version: '5.22.0', evidence: 'extensions directory' });
  });

  it.each([
    ['unparseable package.json', (dir: string) => fs.writeFileSync(path.join(dir, 'package.json'), '{ nope')],
    ['package.json with no exact version', (dir: string) => fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version: 'latest' }))],
  ])('#1109 round 4: a named copy that EXISTS but is unreadable (%s) is still unknown', (_label, write) => {
    const dir = path.join(home, '.openclaw', 'npm', 'projects', 'broken', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(dir, { recursive: true });
    write(dir);
    expect(readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', installPath: dir } })).state).toBe('unknown');
    writeJson('plugins/installs.json', { installRecords: { [ID]: { installPath: dir } } });
    expect(readSelectedRealtimeInstall(home).state).toBe('unknown');
  });

  it('#1109 round 4: no index — installs.json naming a copy that is gone is none (dangling)', () => {
    const gone = path.join(home, '.openclaw', 'npm', 'projects', 'gone', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'npm', installPath: gone } } });
    expect(readSelectedRealtimeInstall(home)).toEqual({ state: 'none', dangling: `the copy installs.json names is not on disk (${gone})`, danglingDirs: [gone] });
  });

  it('#1109 round 4 (npm provenance): a selected copy whose record says ClawHub is never a post-install version', () => {
    const p = writeRealtimeProject('proj', '5.20.2');
    const viaIndex = index({ [ID]: { source: 'clawhub', installPath: p } }, [{ pluginId: ID, rootDir: p }]);
    expect(readSelectedRealtimeInstall(home, viaIndex)).toMatchObject({ state: 'selected', version: '5.20.2', source: 'clawhub' });
    expect(readSelectedRealtimePluginVersion(home, viaIndex))
      .toEqual({ version: null, reason: 'the copy OpenClaw selected (v5.20.2) was installed from clawhub, not npm' });
    // A pre-2026.6.1 host (OpenClaw <= 2026.4.25 is one) records it in installs.json.
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'clawhub', installPath: p } } });
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
    // npm and a local path (a linked development install) are fine; a record that names no source says nothing.
    for (const source of ['npm', 'path', undefined]) {
      writeJson('plugins/installs.json', { installRecords: { [ID]: { ...(source ? { source } : {}), installPath: p } } });
      expect(readSelectedRealtimePluginVersion(home)).toEqual({ version: '5.20.2' });
    }
  });

  it('#1109 round 4 (npm provenance): the replacement decision still SEES a ClawHub copy (so it can be replaced)', () => {
    const p = writeRealtimeProject('proj', '5.17.3');
    const e = readRealtimeReplacementEvidence(home, index({ [ID]: { source: 'clawhub', installPath: p } }, [{ pluginId: ID, rootDir: p }]));
    expect(e.selected).toMatchObject({ state: 'selected', version: '5.17.3', source: 'clawhub' });
  });

  it('an unreadable index is unknown', () => {
    expect(readSelectedRealtimeInstall(home, unreadableIndex)).toMatchObject({ state: 'unknown', why: expect.stringContaining('not valid JSON') });
  });

  it('no index: installs.json\'s installPath selects (pre-2026.6.1 hosts)', () => {
    writeRealtimeProject('leftover', '5.20.2');
    const p = writeRealtimeProject('recorded', '5.17.3');
    writeJson('plugins/installs.json', { installRecords: { [ID]: { installPath: p, version: '5.20.2' } } });
    expect(readSelectedRealtimePluginVersion(home)).toEqual({ version: '5.17.3' });
  });

  it('no records: a linked load.paths copy, or the local extension copy, is what OpenClaw discovers', () => {
    const dir = checkout('5.20.2');
    writeJson('openclaw.json', { plugins: { load: { paths: [dir] } } });
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'selected', dir, version: '5.20.2' });
  });

  it('no records: the local extension copy (version in its manifest) is selected', () => {
    const ext = path.join(home, '.openclaw', 'extensions', ID);
    fs.mkdirSync(ext, { recursive: true });
    fs.writeFileSync(path.join(ext, 'index.js'), '');
    fs.writeFileSync(path.join(ext, 'package.json'), JSON.stringify({ name: 'shieldcortex-realtime-local', type: 'module', private: true }));
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: '5.20.2' }));
    expect(readSelectedRealtimePluginVersion(home)).toEqual({ version: '5.20.2' });
  });

  it('nothing recorded and nothing discovered is none — and none is not a version', () => {
    writeRealtimeProject('unrecorded', '5.20.2');
    expect(readSelectedRealtimeInstall(home)).toEqual({ state: 'none' });
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
  });
});

describe('#1109 round 3 — readRealtimeReplacementEvidence: what a forced install must know first', () => {
  it('an index-only install newer than a stale npm project is what is selected (the stale project does not hide it)', () => {
    writeRealtimeProject('drakon-systems-shieldcortex-realtime-stale', '5.17.3');
    const live = path.join(home, 'elsewhere', 'shieldcortex-realtime');
    fs.mkdirSync(live, { recursive: true });
    fs.writeFileSync(path.join(live, 'package.json'), JSON.stringify({ name: PKG, version: '5.21.0' }));
    const e = readRealtimeReplacementEvidence(home, index({ [ID]: { source: 'npm', installPath: live } }, [{ pluginId: ID, rootDir: live }]));
    expect(e.selected).toMatchObject({ state: 'selected', version: '5.21.0' });
    expect(e.linked).toEqual({ state: 'absent' });
    expect(e.deleting).toEqual([]);
  });

  it('reads every copy scheduled for deletion: a version, unknown for an unreadable one, nothing for an empty dir', () => {
    const newer = path.join(home, 'a');
    fs.mkdirSync(newer);
    fs.writeFileSync(path.join(newer, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: '5.22.0' }));
    const broken = path.join(home, 'b');
    fs.mkdirSync(broken);
    fs.writeFileSync(path.join(broken, 'openclaw.plugin.json'), '{ nope');
    const empty = path.join(home, 'c');
    fs.mkdirSync(empty);
    const e = readRealtimeReplacementEvidence(home, { deleting: [newer, broken, empty, path.join(home, 'missing')] });
    expect(e.deleting).toEqual([
      { dir: newer, state: 'ok', version: '5.22.0' },
      { dir: broken, state: 'unknown', why: expect.stringContaining('not strict JSON') },
    ]);
  });

  it('an unreadable index makes the selected copy unknown', () => {
    expect(readRealtimeReplacementEvidence(home, unreadableIndex).selected.state).toBe('unknown');
  });
});

/**
 * #1110 — OpenClaw <= 2026.4.24 has no installs.json and no SQLite index: its
 * install record is openclaw.json `plugins.installs`, and the copy is the npm
 * package under ~/.openclaw/extensions (`dist/index.js`, no root index.js).
 * Temp-directory JSON only; the index is the injectable reader or simply absent.
 */
describe('#1110 — a native install recorded in openclaw.json plugins.installs', () => {
  const PIN = '5.20.3';
  const ext = (): string => path.join(home, '.openclaw', 'extensions', ID);
  /** The published package layout: package.json + manifest + dist/index.js, NO root index.js. */
  const nativeCopy = (version: string, dir = ext()): string => {
    fs.mkdirSync(path.join(dir, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'dist', 'index.js'), '');
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version, main: './dist/index.js' }));
    fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version }));
    return dir;
  };
  const record = (rec: Record<string, unknown>): void => writeJson('openclaw.json', { plugins: { installs: { [ID]: rec } } });
  const decide = () => assessRealtimeReplacement(readRealtimeReplacementEvidence(home), PIN);

  it('a NEWER native copy is selected, with its source, and a forced install is refused', () => {
    const dir = nativeCopy('999.0.0');
    record({ source: 'npm', spec: PKG, installPath: dir, version: '999.0.0' });
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'selected', dir, version: '999.0.0', evidence: 'openclaw.json plugins.installs record', source: 'npm',
    });
    expect(decide()).toMatchObject({ replace: false, why: 'newer' });
  });

  it('an exact-pin native copy verifies; an OLDER one may be replaced', () => {
    const dir = nativeCopy(PIN);
    record({ source: 'npm', installPath: dir, version: PIN });
    expect(readSelectedRealtimePluginVersion(home)).toEqual({ version: PIN });
    nativeCopy('5.17.3');
    record({ source: 'npm', installPath: dir, version: '5.17.3' });
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'selected', version: '5.17.3' });
    expect(decide()).toEqual({ replace: true });
  });

  it('a record with no installPath names the extensions directory (a `~/` path resolves too)', () => {
    nativeCopy(PIN);
    record({ source: 'npm', version: PIN });
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'selected', dir: ext(), version: PIN, source: 'npm' });
    record({ source: 'npm', installPath: `~/.openclaw/extensions/${ID}` });
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'selected', dir: ext(), version: PIN });
  });

  it.each(['clawhub', 'archive'])('a `%s` record is not pinned npm provenance — but the replacement decision still sees the copy', (source) => {
    const dir = nativeCopy(PIN);
    record({ source, installPath: dir, version: PIN });
    expect(readSelectedRealtimePluginVersion(home))
      .toEqual({ version: null, reason: `the copy OpenClaw selected (v${PIN}) was installed from ${source}, not npm` });
    expect(readRealtimeReplacementEvidence(home).selected).toMatchObject({ state: 'selected', version: PIN, source });
  });

  it.each([
    ['unparseable package.json', (dir: string) => fs.writeFileSync(path.join(dir, 'package.json'), '{ nope')],
    ['no exact version', (dir: string) => fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version: 'latest' }))],
  ])('a recorded copy that EXISTS but is unreadable (%s) is unknown, and a forced install is refused', (_label, write) => {
    const dir = nativeCopy('999.0.0');
    fs.rmSync(path.join(dir, 'openclaw.plugin.json'));
    write(dir);
    record({ source: 'npm', installPath: dir });
    expect(readSelectedRealtimeInstall(home).state).toBe('unknown');
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
    expect(decide()).toMatchObject({ replace: false, why: 'unknown' });
  });

  it('CONFLICT: the record says one version, the copy it names another ⇒ unknown', () => {
    const dir = nativeCopy('5.17.3');
    record({ source: 'npm', installPath: dir, version: PIN });
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'unknown', why: `openclaw.json plugins.installs says v${PIN}, but the copy it names is v5.17.3`,
    });
    expect(decide()).toMatchObject({ replace: false, why: 'unknown' });
  });

  it('CONFLICT: installs.json and openclaw.json name copies at different versions ⇒ unknown; the same version is not a conflict', () => {
    const dir = nativeCopy('999.0.0');
    record({ source: 'npm', installPath: dir });
    const p = writeRealtimeProject('recorded', PIN);
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'npm', installPath: p } } });
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'unknown', why: `installs.json and openclaw.json name two copies (v${PIN}, v999.0.0)`,
    });
    nativeCopy(PIN);
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'selected', dir: p, version: PIN, evidence: 'installs.json record' });
  });

  it('a DANGLING record (its copy is gone) is none, says so, and does not block a reinstall', () => {
    const gone = path.join(home, '.openclaw', 'extensions', ID);
    record({ source: 'npm', installPath: gone, version: '999.0.0' });
    expect(readSelectedRealtimeInstall(home))
      .toEqual({ state: 'none', dangling: `the copy openclaw.json plugins.installs names is not on disk (${gone})`, danglingDirs: [gone] });
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
    expect(decide()).toEqual({ replace: true });
  });

  it('the index, when OpenClaw has one, still wins over a leftover openclaw.json record', () => {
    const dir = nativeCopy('999.0.0');
    record({ source: 'npm', installPath: dir });
    const p = writeRealtimeProject('indexed', PIN);
    expect(readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', installPath: p } })))
      .toMatchObject({ state: 'selected', dir: p, version: PIN, evidence: 'install index record' });
  });

  it('NO record at all: the native layout in the extensions directory is still discovered (newer ⇒ kept)', () => {
    const dir = nativeCopy('999.0.0');
    expect(readSelectedRealtimeInstall(home)).toEqual({ state: 'selected', dir, version: '999.0.0', evidence: 'extensions directory' });
    expect(decide()).toMatchObject({ replace: false, why: 'newer' });
    // …and after a dangling index record, too.
    expect(readSelectedRealtimeInstall(home, index({ [ID]: { source: 'npm', installPath: path.join(home, 'gone') } })))
      .toMatchObject({ state: 'selected', dir, version: '999.0.0' });
  });

  it('NO record: a native-layout copy whose package.json cannot be parsed is unknown, never none', () => {
    const dir = nativeCopy('999.0.0');
    fs.rmSync(path.join(dir, 'openclaw.plugin.json'));
    fs.writeFileSync(path.join(dir, 'package.json'), '{ nope');
    expect(readSelectedRealtimeInstall(home).state).toBe('unknown');
  });

  it('the direct install\'s deletion evidence: a newer extension copy no reader selects still refuses the install', () => {
    // No record, no dist/index.js, no root index.js — only a package.json.
    fs.mkdirSync(ext(), { recursive: true });
    fs.writeFileSync(path.join(ext(), 'package.json'), JSON.stringify({ name: PKG, version: '999.0.0' }));
    expect(readSelectedRealtimeInstall(home)).toEqual({ state: 'none' });
    expect(assessRealtimeReplacement(readRealtimeReplacementEvidence(home, { deleting: [ext()] }), PIN))
      .toMatchObject({ replace: false, why: 'newer' });
  });

  it('unchanged: a path record is the linked reader\'s, and a bare extensions directory is still not an install', () => {
    record({ source: 'path', installPath: '/dev/b' });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'linked', at: '/dev/b' });
    fs.rmSync(path.join(home, '.openclaw', 'openclaw.json'));
    fs.mkdirSync(path.join(ext(), 'dist'), { recursive: true });
    expect(readSelectedRealtimeInstall(home)).toEqual({ state: 'none' });
    fs.writeFileSync(path.join(ext(), 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: '999.0.0' }));
    expect(readSelectedRealtimeInstall(home)).toEqual({ state: 'none' });
  });

  // #1110 round 2: OpenClaw ranks a `plugins.load.paths` copy above a
  // record-matched extension copy, so the record alone cannot claim the pin.
  const recordAndLoadPath = (loadVersion: string, recordVersion = PIN): { dir: string; linked: string } => {
    const dir = nativeCopy(recordVersion);
    const linked = checkout(loadVersion);
    writeJson('openclaw.json', { plugins: { load: { paths: [linked] }, installs: { [ID]: { source: 'npm', version: recordVersion } } } });
    return { dir, linked };
  };

  it('CONFLICT: a load-path copy and a record copy at DIFFERENT versions ⇒ unknown, never the record copy', () => {
    const { linked } = recordAndLoadPath('5.17.3');
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'unknown',
      why: `a plugins.load.paths copy (v5.17.3, ${linked}) and the openclaw.json plugins.installs record copy (v${PIN}) disagree`,
    });
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
    expect(decide()).toMatchObject({ replace: false });
  });

  it('CONFLICT survives a whitespace-padded load path (OpenClaw trims it and loads the copy)', () => {
    const dir = nativeCopy(PIN);
    const linked = checkout('5.17.3');
    writeJson('openclaw.json', { plugins: { load: { paths: [`  ${linked}  `] }, installs: { [ID]: { source: 'npm', version: PIN } } } });
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'unknown',
      why: `a plugins.load.paths copy (v5.17.3, ${linked}) and the openclaw.json plugins.installs record copy (v${PIN}) disagree`,
    });
    expect(readSelectedRealtimeInstall(home)).not.toMatchObject({ state: 'selected', dir });
    expect(decide()).toMatchObject({ replace: false });
  });

  it('round 3: an installs.json record at the pin + a whitespace-padded OLDER load path ⇒ unknown, never the record\'s pin', () => {
    const rec = writeRealtimeProject('drakon-systems-shieldcortex-realtime', PIN);
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'npm', installPath: rec, version: PIN } } });
    const linked = checkout('5.17.3');
    writeJson('openclaw.json', { plugins: { load: { paths: [`  ${linked}  `] } } });
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'unknown',
      why: `a plugins.load.paths copy (v5.17.3, ${linked}) and the installs.json record copy (v${PIN}) disagree`,
    });
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
    expect(assessRealtimeReplacement(readRealtimeReplacementEvidence(home), PIN)).toMatchObject({ replace: false });
  });

  it('round 3: the linked reader reports the trimmed load path — one identity for discovery and version reading', () => {
    const linked = checkout('5.17.3');
    writeJson('openclaw.json', { plugins: { load: { paths: [`\t ${linked} \n`] } } });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'linked', at: linked });
  });

  it('round 3: a path record whose identity cannot be read beside a record copy ⇒ unknown, not the record\'s pin', () => {
    const rec = writeRealtimeProject('drakon-systems-shieldcortex-realtime', PIN);
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'npm', installPath: rec, version: PIN } } });
    const bad = path.join(home, 'dev', 'plugin');
    fs.mkdirSync(bad, { recursive: true });
    fs.writeFileSync(path.join(bad, 'package.json'), '{ not json');
    writeJson('openclaw.json', { plugins: { installs: { [ID]: { source: 'path', sourcePath: bad } } } });
    expect(readLinkedRealtimeInstall(home)).toEqual({ state: 'linked', at: bad });
    expect(readSelectedRealtimeInstall(home).state).toBe('unknown');
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
  });

  it('a load-path copy whose version cannot be read beside a record copy ⇒ unknown', () => {
    const { linked } = recordAndLoadPath(PIN);
    fs.writeFileSync(path.join(linked, 'package.json'), JSON.stringify({ name: PKG, version: 'latest' }));
    expect(readSelectedRealtimeInstall(home).state).toBe('unknown');
  });

  it('a load-path copy and a record copy at the SAME version stay selected (the record copy)', () => {
    const { dir } = recordAndLoadPath(PIN);
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'selected', dir, version: PIN, evidence: 'openclaw.json plugins.installs record', source: 'npm',
    });
  });
});

/**
 * #260 r10 (Sol delta review at a524cf60): a record's `installPath` that is
 * there but empty, blank or not a string is unknown — never "names no path".
 * At a524cf60 an empty one was dropped, the selection fell through to `none`,
 * and a forced install was allowed to replace whatever was there. Only an
 * absent field is absent.
 */
describe('#260 r10 — a present but unusable installPath refuses the replacement', () => {
  const BAD = [['empty', ''], ['blank', '   '], ['non-string', 42]] as const;
  const decide = () => assessRealtimeReplacement(readRealtimeReplacementEvidence(home), '5.22.1');

  it.each(BAD)('the index record\'s installPath is %s (no roster entry) ⇒ unknown, refused', (_t, value) => {
    writeRealtimeProject('drakon-systems-shieldcortex-realtime-abc', '5.22.1');
    const opts = index({ [ID]: { source: 'npm', version: '5.0.0', installPath: value } });
    expect(readSelectedRealtimeInstall(home, opts)).toMatchObject({ state: 'unknown', why: expect.stringContaining('installPath') });
    expect(assessRealtimeReplacement(readRealtimeReplacementEvidence(home, opts), '5.22.1')).toMatchObject({ replace: false, why: 'unknown' });
  });

  it.each(BAD)('the index roster\'s rootDir is %s ⇒ unknown, refused', (_t, value) => {
    const opts = index({}, [{ pluginId: ID, enabled: true, rootDir: value }]);
    expect(readSelectedRealtimeInstall(home, opts)).toMatchObject({ state: 'unknown', why: expect.stringContaining('no usable rootDir') });
  });

  it.each(BAD)('no index: installs.json installPath is %s ⇒ unknown, refused', (_t, value) => {
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'npm', version: '5.0.0', installPath: value } } });
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'unknown', why: expect.stringContaining('installs.json names: its installPath') });
    expect(decide()).toMatchObject({ replace: false, why: 'unknown' });
  });

  it.each(BAD)('no index: openclaw.json plugins.installs installPath is %s ⇒ unknown, refused (not the extensions default)', (_t, value) => {
    writeJson('openclaw.json', { plugins: { installs: { [ID]: { source: 'npm', version: '5.0.0', installPath: value } } } });
    expect(readSelectedRealtimeInstall(home)).toMatchObject({ state: 'unknown', why: expect.stringContaining('openclaw.json plugins.installs names: its installPath') });
    expect(decide()).toMatchObject({ replace: false, why: 'unknown' });
  });

  it('control: no index, installs.json record with NO installPath and nothing on disk ⇒ none, replacement allowed (as before)', () => {
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'npm', version: '5.0.0' } } });
    expect(readSelectedRealtimeInstall(home)).toEqual({ state: 'none' });
    expect(decide()).toEqual({ replace: true });
  });
});

/**
 * #1179 r3 (Astra 3, adjudication OBS-1): an install record's `source` is the
 * selected copy's provenance only when that record names the same physical
 * folder (by real path). A record for another folder at the same version is
 * marked `sourceUnbound`: the version check still refuses it (never success),
 * but the detail says provenance unverified, not a known wrong source.
 * `state`, `dir`, `version` and `evidence` are what they were.
 */
describe('#1179 r3 — a recorded source binds only to the folder its record names', () => {
  const PIN = '5.22.1';
  const UNBOUND = new RegExp(`an install record says the plugin was installed from clawhub, but it names a different folder from the copy OpenClaw selected \\(both v${PIN.replace(/\./g, '\\.')}\\)`);

  it('roster A / record B / same version / ClawHub on B: selected A as before, the source unbound; the public reader still refuses', () => {
    const a = writeRealtimeProject('a', PIN);
    const b = writeRealtimeProject('b', PIN);
    const opts = index({ [ID]: { source: 'clawhub', installPath: b } }, [{ pluginId: ID, enabled: true, rootDir: a }]);
    expect(readSelectedRealtimeInstall(home, opts)).toEqual({
      state: 'selected', dir: a, version: PIN, evidence: 'install index roster', source: 'clawhub', sourceUnbound: true,
    });
    const pub = readSelectedRealtimePluginVersion(home, opts);
    expect(pub).toEqual({ version: null, reason: expect.stringMatching(UNBOUND) });
    expect(readSelectedRealtimePluginVersionDetail(home, opts)).toEqual({
      version: null, reason: expect.stringMatching(UNBOUND), provenanceUnverified: true, measuredVersion: PIN,
    });
    // The replacement decision sees the same selected copy it saw before.
    expect(readRealtimeReplacementEvidence(home, opts).selected).toMatchObject({ state: 'selected', dir: a, version: PIN });
  });

  it('the same folder by real path (the record names a symlink to the roster\'s folder): bound — a known wrong source', () => {
    const a = writeRealtimeProject('a', PIN);
    const link = path.join(home, 'link-to-a');
    fs.symlinkSync(a, link, 'dir');
    const opts = index({ [ID]: { source: 'clawhub', installPath: link } }, [{ pluginId: ID, enabled: true, rootDir: a }]);
    const s = readSelectedRealtimeInstall(home, opts);
    expect(s).toMatchObject({ state: 'selected', dir: a, version: PIN, source: 'clawhub' });
    expect(s).not.toHaveProperty('sourceUnbound');
    expect(readSelectedRealtimePluginVersionDetail(home, opts)).toEqual({
      version: null, reason: `the copy OpenClaw selected (v${PIN}) was installed from clawhub, not npm`, wrongSource: true, measuredVersion: PIN,
    });
  });

  it('a record-only selection names its own folder: bound — a known wrong source, with the version it read', () => {
    const p = writeRealtimeProject('hub', '5.23.0');
    const opts = index({ [ID]: { source: 'clawhub', installPath: p } });
    expect(readSelectedRealtimeInstall(home, opts)).not.toHaveProperty('sourceUnbound');
    expect(readSelectedRealtimePluginVersionDetail(home, opts)).toMatchObject({ version: null, wrongSource: true, measuredVersion: '5.23.0' });
  });

  it('OBS-1: no index, an installs.json ClawHub record copy beside a linked load-path copy at the same version: unbound, still refused', () => {
    const rec = writeRealtimeProject('drakon-systems-shieldcortex-realtime', PIN);
    writeJson('plugins/installs.json', { installRecords: { [ID]: { source: 'clawhub', installPath: rec } } });
    const linked = checkout(PIN);
    writeJson('openclaw.json', { plugins: { load: { paths: [linked] } } });
    expect(readSelectedRealtimeInstall(home)).toEqual({
      state: 'selected', dir: rec, version: PIN, evidence: 'installs.json record', source: 'clawhub', sourceUnbound: true,
    });
    expect(readSelectedRealtimePluginVersion(home).version).toBeNull();
    expect(readSelectedRealtimePluginVersionDetail(home)).toEqual({
      version: null, reason: expect.stringMatching(UNBOUND), provenanceUnverified: true, measuredVersion: PIN,
    });
  });
});
