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
 * Nothing here can run a native process (#260 r15, Jarvis 1). The repair
 * takes its `openclaw` lookup and runner as an explicit parameter, and every
 * call here passes a recording fake (by default: "no openclaw", so a repair
 * that proceeds stops at "`openclaw` is not on PATH", after its manifest
 * writes). `child_process` is mocked as a tripwire: every launcher throws and
 * is asserted unused — `which openclaw` included. The environment is scrubbed
 * of OpenClaw/ShieldCortex/multi-clawd/Claude variables and HOME is a temp
 * dir. PATH deliberately still reaches the host's own (so an installed
 * OpenClaw stays findable) behind a stub `openclaw` that records any run —
 * the injected fake and the tripwire, not PATH, are the isolation.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import semver from 'semver';
import Database from 'better-sqlite3';
import type { SpawnSyncReturns } from 'child_process';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { expectNoLaunch, installLaunchTripwire, isolateHostEnv } from '../../__tests__/support/openclaw-host-isolation.js';

const tripwire = installLaunchTripwire();

const { repairOpenClawManagedPins } = await import('../openclaw.js');
const { realtimePluginInstallArgs } = await import('../openclaw-plugin-spec.js');
const { checkOpenClawManagedPinDrift } = await import('../../cli/doctor.js');
const { findEoverrideRiskPins } = await import('../../integrations/openclaw-plugin-state.js');

/** The recording fake every repair here gets: `bin` null = no openclaw. */
const fake = {
  bin: null as string | null,
  lookups: 0,
  runs: [] as string[][],
  deps: {
    resolveOpenClawBin: (): string | null => {
      fake.lookups += 1;
      return fake.bin;
    },
    runOpenClaw: (_bin: string, args: string[]): SpawnSyncReturns<string> => {
      fake.runs.push(args);
      return { pid: 0, output: [], stdout: '', stderr: '', status: 0, signal: null };
    },
  },
};

const ID = 'shieldcortex-realtime';
const PKG = '@drakon-systems/shieldcortex-realtime';
const SELF = (): string => JSON.parse(
  fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
).version;

let home: string;
let restoreEnv: () => void;
let stubRan: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-260-pins-'));
  const hostPath = process.env.PATH;
  restoreEnv = isolateHostEnv(home);
  const stubBin = path.join(home, 'stub-bin');
  stubRan = path.join(home, 'stub-openclaw-ran');
  fs.mkdirSync(stubBin);
  fs.writeFileSync(path.join(stubBin, 'openclaw'), `#!/bin/sh\necho ran >> '${stubRan}'\n`, { mode: 0o755 });
  process.env.PATH = [stubBin, hostPath].filter(Boolean).join(path.delimiter);
  tripwire.reset();
  fake.bin = null;
  fake.lookups = 0;
  fake.runs = [];
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  try {
    // No real launcher at all — not even the `which openclaw` lookup.
    expectNoLaunch(tripwire);
    expect(fs.existsSync(stubRan)).toBe(false);
  } finally {
    jest.restoreAllMocks();
    restoreEnv();
    fs.rmSync(home, { recursive: true, force: true });
  }
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

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

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

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    // It rewrote the manifest (co-present pin stripped, backup kept), then
    // stopped only because this suite's mocked lookup finds no `openclaw`.
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

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

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
      const result = await repairOpenClawManagedPins(aliasHome, undefined, fake.deps);
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

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    // r15 (Jarvis 4b): refused as before; the reason is now "no record" (see the r15 no-record tests).
    expect(result.message).toMatch(/No install record names the managed project/);
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

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/plugin folders disagree/);
    expect(backups(managed.root)).toEqual([]);
  });
});

/**
 * #260 r12 (Sol): the folder check did not bind the FILE. A package.json that
 * is a link into another project passed it and was written through; and a
 * manifest removed or replaced after the last check still reached the write.
 * Now the manifest must be a regular file in the verified folder, every write
 * is a new file created there, and the manifest is replaced by rename after a
 * re-check — any doubt refuses, nothing left behind.
 */
describe.each(['new', 'legacy'] as const)('#260 r12: managed-pin repair writes only the verified FILE (%s index layout)', (layout) => {
  const leftovers = (root: string): string[] => fs.readdirSync(root).filter((f) => f.includes('.repair-backup-') || f.endsWith('.tmp'));

  it('the verified project\'s package.json is a symlink into a different project — refused, both manifests byte-identical, no backup or tmp', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    const other = project('other-managed-project', semver.inc(SELF(), 'minor')!, '1.0.0');
    fs.unlinkSync(path.join(selected.root, 'package.json'));
    fs.symlinkSync(path.join(other.root, 'package.json'), path.join(selected.root, 'package.json'));
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const otherBefore = fs.readFileSync(path.join(other.root, 'package.json'));

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/package\.json is not a plain file/);
    expect(result.message).toMatch(/nothing was changed/);
    expect(result.message).not.toContain(home);
    expect(fs.lstatSync(path.join(selected.root, 'package.json')).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(path.join(other.root, 'package.json'))).toEqual(otherBefore);
    expect(leftovers(selected.root)).toEqual([]);
    expect(leftovers(other.root)).toEqual([]);
  });

  it('the manifest entry is not a regular file — refused, nothing written', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    // The resolver and reader still see a file; only the repair's own lstat of
    // the target reports a non-regular entry (a FIFO here would block the read).
    const real = fs.lstatSync;
    jest.spyOn(fs, 'lstatSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const st = (real as (...a: unknown[]) => fs.Stats)(p, ...rest);
      if (String(p) === path.join(selected.root, 'package.json')) return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { isFile: () => false });
      return st;
    }) as typeof fs.lstatSync);
    const before = fs.readFileSync(path.join(selected.root, 'package.json'));

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/package\.json is not a plain file/);
    expect(fs.readFileSync(path.join(selected.root, 'package.json'))).toEqual(before);
    expect(leftovers(selected.root)).toEqual([]);
  });

  /** Run the repair with `swap` applied to the manifest once the replacement tmp file is created. */
  async function raceAtTmp(root: string, swap: (manifest: string) => void): Promise<Awaited<ReturnType<typeof repairOpenClawManagedPins>>> {
    const open = fs.openSync;
    let raced = false;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (open as (...a: unknown[]) => number)(p, ...rest);
      if (!raced && String(p).endsWith('.tmp')) {
        raced = true;
        swap(path.join(root, 'package.json'));
      }
      return fd;
    }) as typeof fs.openSync);
    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);
    expect(raced).toBe(true);
    return result;
  }

  it('package.json removed between the last check and the rename — refused, no tmp left', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);

    const result = await raceAtTmp(selected.root, (m) => fs.unlinkSync(m));

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/changed while this repair was running/);
    expect(result.message).not.toMatch(/shieldcortex openclaw repair/);
    expect(fs.existsSync(path.join(selected.root, 'package.json'))).toBe(false);
    expect(fs.readdirSync(selected.root).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });

  it('package.json replaced by a link into another project between the last check and the rename — refused, other manifest untouched, no tmp left', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    const other = project('other-managed-project', semver.inc(SELF(), 'minor')!, '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const otherBefore = fs.readFileSync(path.join(other.root, 'package.json'));

    const result = await raceAtTmp(selected.root, (m) => {
      fs.unlinkSync(m);
      fs.symlinkSync(path.join(other.root, 'package.json'), m);
    });

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/changed while this repair was running/);
    expect(fs.lstatSync(path.join(selected.root, 'package.json')).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(path.join(other.root, 'package.json'))).toEqual(otherBefore);
    expect(fs.readdirSync(selected.root).filter((f) => f.endsWith('.tmp'))).toEqual([]);
    expect(leftovers(other.root)).toEqual([]);
  });

  it('the rename itself throws — refused with a plain message, no tmp left, no direct-write fallback', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const before = fs.readFileSync(path.join(selected.root, 'package.json'));
    jest.spyOn(fs, 'renameSync').mockImplementation(() => { throw new Error('fixture: rename refused'); });
    const write = jest.spyOn(fs, 'writeFileSync');

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/Could not write the project manifest \(fixture: rename refused\)/);
    expect(fs.readFileSync(path.join(selected.root, 'package.json'))).toEqual(before);
    expect(fs.readdirSync(selected.root).filter((f) => f.endsWith('.tmp'))).toEqual([]);
    // Only file-descriptor writes (the exclusive-create helper); never a path.
    expect(write.mock.calls.every(([target]) => typeof target === 'number')).toBe(true);
  });

  it('control: a regular package.json — the repair proceeds and the manifest content is as before (pin stripped, mode kept, no tmp)', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    fs.chmodSync(manifest, 0o640);
    const original = JSON.parse(fs.readFileSync(manifest, 'utf-8')) as Record<string, unknown>;

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
    expect(fs.lstatSync(manifest).isFile()).toBe(true);
    expect(fs.statSync(manifest).mode & 0o777).toBe(0o640);
    expect(fs.readFileSync(manifest, 'utf-8')).toBe(JSON.stringify({ dependencies: {}, overrides: { peer: '2.0.0' } }, null, 2) + '\n');
    const [backup] = backups(selected.root);
    expect(fs.readFileSync(path.join(selected.root, backup), 'utf-8')).toBe(JSON.stringify(original, null, 2));
    expect(fs.readdirSync(selected.root).filter((f) => f.endsWith('.tmp'))).toEqual([]);
  });
});

/**
 * #260 round 13 (Sol): the r12 re-check bound the file's TYPE, not its
 * identity. A package.json replaced by a different regular file (a new inode),
 * or the same inode rewritten, between the read and the rename was still
 * replaced with bytes derived from the original — a lost update. The read is
 * now bound (one no-follow descriptor: dev, inode, size, mtime and a sha256 of
 * the bytes parsed), and the backup and the rename each require the file to be
 * that same file with those same bytes.
 */
describe.each(['new', 'legacy'] as const)('#260 r13: managed-pin repair rewrites only the manifest it read (%s index layout)', (layout) => {
  const leftovers = (root: string): string[] => fs.readdirSync(root).filter((f) => f.includes('.repair-backup-') || f.endsWith('.tmp'));
  const tmps = (root: string): string[] => fs.readdirSync(root).filter((f) => f.endsWith('.tmp'));
  const REPLACEMENT = JSON.stringify({ dependencies: { peer: '1.0.0', added: '9.9.9' }, overrides: { peer: '2.0.0' } });

  /** Run the repair, applying `swap` to the manifest once `when` first matches an openSync call. */
  async function raceAt(
    root: string,
    when: (p: string, flags: unknown) => boolean,
    swap: (manifest: string) => void,
  ): Promise<Awaited<ReturnType<typeof repairOpenClawManagedPins>>> {
    const open = fs.openSync;
    let raced = false;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (open as (...a: unknown[]) => number)(p, ...rest);
      if (!raced && when(String(p), rest[0])) {
        raced = true;
        swap(path.join(root, 'package.json'));
      }
      return fd;
    }) as typeof fs.openSync);
    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);
    expect(raced).toBe(true);
    return result;
  }
  const atTmp = (p: string): boolean => p.endsWith('.tmp');
  /**
   * #1179: a refusal AFTER the safety backup was written names that backup and
   * never says "nothing was changed" — the backup is a file this repair wrote.
   */
  const refusedAfterBackup = (root: string, message: string, original: unknown): void => {
    const found = backups(root);
    expect(found).toHaveLength(1);
    expect(message).toMatch(/package\.json changed while this repair was running, so it was not rewritten\. A safety backup of the contents read earlier was written first and is left at /);
    expect(message).toContain(found[0]);
    expect(message).not.toMatch(/nothing was changed/i);
    expect(JSON.parse(fs.readFileSync(path.join(root, found[0]), 'utf-8'))).toEqual(original);
  };
  /** A different regular file (new inode) renamed over the manifest. */
  const replaceWithNewInode = (m: string): void => {
    const side = `${m}.fixture-replacement`;
    fs.writeFileSync(side, REPLACEMENT);
    fs.renameSync(side, m);
  };

  it('replaced by a different regular file (new inode) before the rename — refused, the replacement intact, no tmp', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    const inodeBefore = fs.lstatSync(manifest).ino;
    const original: unknown = JSON.parse(fs.readFileSync(manifest, 'utf-8'));

    const result = await raceAt(selected.root, atTmp, replaceWithNewInode);

    expect(result.status).toBe('failed');
    refusedAfterBackup(selected.root, result.message, original);
    expect(fs.lstatSync(manifest).ino).not.toBe(inodeBefore);
    expect(fs.readFileSync(manifest, 'utf-8')).toBe(REPLACEMENT);
    expect(tmps(selected.root)).toEqual([]);
  });

  it('the same inode rewritten with different content before the rename — refused, the rewrite intact, no tmp', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    const inodeBefore = fs.lstatSync(manifest).ino;
    const original: unknown = JSON.parse(fs.readFileSync(manifest, 'utf-8'));

    const result = await raceAt(selected.root, atTmp, (m) => fs.writeFileSync(m, REPLACEMENT));

    expect(result.status).toBe('failed');
    refusedAfterBackup(selected.root, result.message, original);
    expect(fs.lstatSync(manifest).ino).toBe(inodeBefore);
    expect(fs.readFileSync(manifest, 'utf-8')).toBe(REPLACEMENT);
    expect(tmps(selected.root)).toEqual([]);
  });

  it('the same inode rewritten with same-size bytes while its metadata reads unchanged — the content hash refuses it', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    const original = fs.readFileSync(manifest, 'utf-8');
    const sameSize = original.replace('"1.0.0"', '"1.0.1"');
    expect(sameSize).not.toBe(original);
    expect(sameSize.length).toBe(original.length);
    // Every later lstat of the manifest reports the stat from before the
    // rewrite, so only the bytes can tell the files apart.
    const frozen = fs.lstatSync(manifest);
    const realLstat = fs.lstatSync;
    let rewritten = false;
    jest.spyOn(fs, 'lstatSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => (
      rewritten && String(p) === manifest ? frozen : (realLstat as (...a: unknown[]) => fs.Stats)(p, ...rest)
    )) as typeof fs.lstatSync);

    const result = await raceAt(selected.root, atTmp, (m) => {
      fs.writeFileSync(m, sameSize);
      rewritten = true;
    });

    expect(result.status).toBe('failed');
    refusedAfterBackup(selected.root, result.message, JSON.parse(original));
    expect(fs.readFileSync(manifest, 'utf-8')).toBe(sameSize);
    expect(tmps(selected.root)).toEqual([]);
  });

  it('replaced by a different regular file before the safety backup — refused, no backup and no tmp, the replacement intact', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');

    // Swap right after the repair's own no-follow descriptor on the manifest
    // opens (numeric flags; a plain path read passes a string flag). The
    // repair opens the verified folder's realpath, which differs from the
    // tmpdir spelling on macOS (/var -> /private/var), so match either.
    const realManifest = fs.realpathSync(manifest);
    const result = await raceAt(selected.root, (p, flags) => (p === manifest || p === realManifest) && typeof flags === 'number', replaceWithNewInode);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/package\.json changed while this repair was running; nothing was changed/);
    expect(fs.readFileSync(manifest, 'utf-8')).toBe(REPLACEMENT);
    expect(leftovers(selected.root)).toEqual([]);
  });

  it('control: the race hook fires but nothing changes — the repair proceeds and rewrites the manifest', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    const original = JSON.parse(fs.readFileSync(manifest, 'utf-8')) as Record<string, unknown>;

    const result = await raceAt(selected.root, atTmp, () => {});

    expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
    expect(fs.readFileSync(manifest, 'utf-8')).toBe(JSON.stringify({ dependencies: {}, overrides: { peer: '2.0.0' } }, null, 2) + '\n');
    const [backup] = backups(selected.root);
    expect(fs.readFileSync(path.join(selected.root, backup), 'utf-8')).toBe(JSON.stringify(original, null, 2));
    expect(tmps(selected.root)).toEqual([]);
  });
});

/**
 * #260 r15 (Jarvis 1): this suite once ran a REAL `openclaw` with a forced
 * install — emptying PATH did not stop `which openclaw` finding it. The
 * repair's lookup and runner are now an explicit parameter; the fake given
 * here is the only thing it can launch.
 */
describe.each(['new', 'legacy'] as const)('#260 r15: the managed-pin repair launches only the runner it is given (%s index layout)', (layout) => {
  it('a full heal: the lookup and the pinned reinstall go through the injected fake, nothing real runs', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    fake.bin = path.join(home, 'fake-bin', 'openclaw');

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('healed');
    expect(fake.lookups).toBe(1);
    expect(fake.runs).toEqual([realtimePluginInstallArgs(SELF())]);
  });

  it('tripwire: a recording `openclaw` first on PATH is never run when the repair reaches its launch step', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    // The suite's own setup put the recorder first on PATH.
    expect(process.env.PATH?.split(path.delimiter)[0]).toBe(path.join(home, 'stub-bin'));

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    // It got as far as looking for `openclaw` (the manifest was rewritten)…
    expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
    expect(fake.lookups).toBe(1);
    // …and neither the recorder on PATH nor any real launcher ran.
    expect(fs.existsSync(stubRan)).toBe(false);
    expectNoLaunch(tripwire);
  });
});

/**
 * #260 r15 (Jarvis 2): the r12 replace (exclusive create + rename) gave the
 * new package.json the WRITER's uid:gid — measured gid 4 → 1001 on head,
 * kept on main; under sudo the manifest became root-owned 0600, unreadable by
 * OpenClaw. The backup and the replacement now get the original owner, read
 * from the bound read's descriptor, by fchown on their own descriptor before
 * the rename; if that fails, nothing is rewritten.
 */
describe.each(['new', 'legacy'] as const)('#260 r15: the managed-pin repair keeps the manifest\'s owner (%s index layout)', (layout) => {
  const tmps = (root: string): string[] => fs.readdirSync(root).filter((f) => f.endsWith('.tmp'));
  /** Record the fd each `.tmp` / backup create returns. */
  function trackCreates(): { tmpFd: () => number | undefined; backupFd: () => number | undefined } {
    const open = fs.openSync;
    let tmpFd: number | undefined;
    let backupFd: number | undefined;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (open as (...a: unknown[]) => number)(p, ...rest);
      if (String(p).endsWith('.tmp')) tmpFd = fd;
      if (String(p).includes('.repair-backup-')) backupFd = fd;
      return fd;
    }) as typeof fs.openSync);
    return { tmpFd: () => tmpFd, backupFd: () => backupFd };
  }

  it('the new manifest and the backup get the ORIGINAL uid:gid by fchown on their own descriptors, before the rename', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    const st = fs.statSync(manifest);
    const created = trackCreates();
    // Recorded, not performed: this proves which owner is asked for, whoever runs the test.
    const fchown = jest.spyOn(fs, 'fchownSync').mockImplementation(() => {});
    const rename = jest.spyOn(fs, 'renameSync');

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
    expect(fchown.mock.calls).toEqual([
      [created.backupFd(), st.uid, st.gid],
      [created.tmpFd(), st.uid, st.gid],
    ]);
    expect(rename).toHaveBeenCalledTimes(1);
    expect(fchown.mock.invocationCallOrder[1]).toBeLessThan(rename.mock.invocationCallOrder[0]);
  });

  it('fchown of the replacement fails (EPERM) — refused, manifest bytes and inode unchanged, no tmp left, the cause named', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    const bytes = fs.readFileSync(manifest);
    const ino = fs.statSync(manifest).ino;
    const created = trackCreates();
    const real = fs.fchownSync;
    jest.spyOn(fs, 'fchownSync').mockImplementation(((fd: number, uid: number, gid: number) => {
      if (fd === created.tmpFd()) throw Object.assign(new Error('EPERM: operation not permitted, fchown'), { code: 'EPERM' });
      return real(fd, uid, gid);
    }) as typeof fs.fchownSync);
    const rename = jest.spyOn(fs, 'renameSync');

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/Could not write the project manifest \(could not keep the original owner \d+:\d+ \(EPERM/);
    expect(rename).not.toHaveBeenCalled();
    expect(fs.readFileSync(manifest)).toEqual(bytes);
    expect(fs.statSync(manifest).ino).toBe(ino);
    expect(tmps(selected.root)).toEqual([]);
    expect(fake.lookups).toBe(0);
  });

  it('fchown of the backup fails — refused before anything is written, no backup or tmp left', async () => {
    const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    writeIndex(layout, selected.dir, SELF());
    baseConfig(selected.dir);
    const manifest = path.join(selected.root, 'package.json');
    const bytes = fs.readFileSync(manifest);
    jest.spyOn(fs, 'fchownSync').mockImplementation(() => {
      throw Object.assign(new Error('EPERM: operation not permitted, fchown'), { code: 'EPERM' });
    });

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/Could not write a safety backup .*could not keep the original owner.*so nothing was changed/);
    expect(fs.readFileSync(manifest)).toEqual(bytes);
    expect(fs.readdirSync(selected.root).filter((f) => f.includes('.repair-backup-') || f.endsWith('.tmp'))).toEqual([]);
  });

  // A real group, where the test user has one besides its primary (CI-safe skip otherwise).
  const supplementary = typeof process.getgroups === 'function'
    ? process.getgroups().find((g) => g !== process.getgid?.())
    : undefined;
  (supplementary === undefined ? it.skip : it)(
    supplementary === undefined
      ? 'real-gid fixture SKIPPED: the test user has no supplementary group to chgrp the manifest to'
      : `real-gid fixture: a manifest in supplementary group ${supplementary} keeps that group after the heal`,
    async () => {
      const selected = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
      writeIndex(layout, selected.dir, SELF());
      baseConfig(selected.dir);
      const manifest = path.join(selected.root, 'package.json');
      fs.chownSync(manifest, fs.statSync(manifest).uid, supplementary!);
      const before = fs.statSync(manifest);

      const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

      expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
      const after = fs.statSync(manifest);
      expect(after.ino).not.toBe(before.ino);
      expect([after.uid, after.gid]).toEqual([before.uid, supplementary]);
      const [backup] = backups(selected.root);
      expect(fs.statSync(path.join(selected.root, backup)).gid).toBe(supplementary);
    },
  );
});

/**
 * #260 r15 (Jarvis 4, OWNER RULINGS). Main healed both of these; head refused.
 *  (a) a DANGLING record — the index names the managed project, its plugin
 *      build is gone, its package.json is left — HEALS again: the record binds
 *      the project, when its real path is the resolver's and the manifest
 *      passes the same plain-file and bound-read checks.
 *  (b) NO record — still REFUSED (owner decision: writing a project no record
 *      names is the r11 fail-open), but with a door that works: a reinstall
 *      alone keeps the drifted pin, so the advice names the pins and the file.
 */
describe.each(['new', 'legacy'] as const)('#260 r15: dangling record heals, no record refuses with a working door (%s index layout)', (layout) => {
  const leftovers = (root: string): string[] => fs.readdirSync(root).filter((f) => f.includes('.repair-backup-') || f.endsWith('.tmp'));
  /** The project's plugin build is removed; its package.json (drifting `peer`) is left. */
  function dangling(name: string): { root: string; dir: string } {
    const p = project(name, SELF(), '1.0.0');
    fs.rmSync(path.join(p.root, 'node_modules'), { recursive: true, force: true });
    return p;
  }
  const supplementary = typeof process.getgroups === 'function'
    ? process.getgroups().find((g) => g !== process.getgid?.())
    : undefined;

  it('(a) dangling record naming the managed project, drifted pins — healed: pins stripped, backup kept, owner and mode kept', async () => {
    const p = dangling('drakon-systems-shieldcortex-realtime-aaa');
    writeIndex(layout, p.dir, SELF());
    baseConfig();
    const manifest = path.join(p.root, 'package.json');
    fs.chmodSync(manifest, 0o640);
    if (supplementary !== undefined) fs.chownSync(manifest, fs.statSync(manifest).uid, supplementary);
    const before = fs.statSync(manifest);

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    // Healed, then stopped only because this suite's fake finds no `openclaw`.
    expect(result.message).toMatch(/Manifest reconciled, but `openclaw` is not on PATH/);
    const after = fs.statSync(manifest);
    expect((JSON.parse(fs.readFileSync(manifest, 'utf-8')) as { dependencies: Record<string, string> }).dependencies.peer).toBeUndefined();
    expect([after.uid, after.gid, after.mode & 0o777]).toEqual([before.uid, before.gid, 0o640]);
    expect(fs.readdirSync(p.root).filter((f) => f.includes('.repair-backup-'))).toHaveLength(1);
    // Doctor agrees: the repair is offered where the repair heals.
    expect((await checkOpenClawManagedPinDrift(home)).status).toBe('pass');
  });

  it('(a) doctor offers the repair for a dangling record before it runs', async () => {
    const p = dangling('drakon-systems-shieldcortex-realtime-aaa');
    writeIndex(layout, p.dir, SELF());
    baseConfig();

    const row = await checkOpenClawManagedPinDrift(home);

    expect(row.status).toBe('warn');
    expect(row.fix).toMatch(/shieldcortex openclaw repair/);
  });

  it('(a\') dangling record naming a DIFFERENT project than the resolver\'s — refused, nothing written in either', async () => {
    const named = dangling('drakon-systems-shieldcortex-realtime-aaa');
    const other = project('drakon-systems-shieldcortex-realtime-bbb', SELF(), '1.0.0');
    writeIndex(layout, named.dir, SELF());
    // installs.json points the disk resolver at the other project.
    baseConfig(other.dir);
    const before = [named.root, other.root].map((r) => fs.readFileSync(path.join(r, 'package.json')));

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/plugin folders disagree/);
    expect([named.root, other.root].map((r) => fs.readFileSync(path.join(r, 'package.json')))).toEqual(before);
    expect(leftovers(named.root)).toEqual([]);
    expect(leftovers(other.root)).toEqual([]);
    const row = await checkOpenClawManagedPinDrift(home);
    expect(row.fix).not.toMatch(/shieldcortex openclaw repair/);
  });

  it('(a\') dangling record whose package.json is a link — refused by the same plain-file check', async () => {
    const named = dangling('drakon-systems-shieldcortex-realtime-aaa');
    const other = project('other-managed-project', SELF(), '1.0.0');
    fs.unlinkSync(path.join(named.root, 'package.json'));
    fs.symlinkSync(path.join(other.root, 'package.json'), path.join(named.root, 'package.json'));
    writeIndex(layout, named.dir, SELF());
    baseConfig();
    const otherBefore = fs.readFileSync(path.join(other.root, 'package.json'));

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/package\.json is not a plain file/);
    expect(fs.readFileSync(path.join(other.root, 'package.json'))).toEqual(otherBefore);
    expect(leftovers(named.root)).toEqual([]);
  });

  it('(b) no record at all — refused, nothing written; the advice names the pins and the file, not "the install heals it"; doctor gives the same door', async () => {
    const p = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    baseConfig();
    if (layout === 'new') {
      // An index that records nothing for the plugin (the legacy variant has no index at all).
      const dbPath = path.join(home, '.openclaw', 'state', 'openclaw.sqlite');
      fs.mkdirSync(path.dirname(dbPath), { recursive: true });
      const db = new Database(dbPath);
      db.prepare('CREATE TABLE config_machine_state (state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)').run();
      db.prepare('INSERT INTO config_machine_state VALUES (?, ?, 1)').run('plugins.installedIndex', JSON.stringify({ revision: 1, index: { generatedAtMs: 1, installRecords: {}, plugins: [] } }));
      db.close();
    }
    const manifest = path.join(p.root, 'package.json');
    const before = fs.readFileSync(manifest);

    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);

    expect(result.status).toBe('failed');
    expect(fs.readFileSync(manifest)).toEqual(before);
    expect(leftovers(p.root)).toEqual([]);
    expect(fake.lookups).toBe(0);
    expect(result.message).toMatch(/No install record names the managed project .*an owner decision.*a reinstall alone keeps them/);
    expect(result.message).toMatch(/Remove dependencies\.peer /);
    expect(result.message).toMatch(/then `shieldcortex doctor` to confirm/);
    expect(result.message).not.toMatch(/reinstall (it )?cleanly|re-deriv|heals?\b/i);
    // The path is on its own detail line, `~`-relative; never on the command line.
    const lines = result.message.split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toBe('File: ~/.openclaw/npm/projects/drakon-systems-shieldcortex-realtime-aaa/package.json');
    expect(lines[0]).not.toContain('.openclaw/npm');
    expect(result.message).not.toContain(home);
    // Doctor's advice is the same door.
    expect((await checkOpenClawManagedPinDrift(home)).fix).toBe(result.message);
  });

  it('(b) measured with the injected fake: running only the suggested install leaves the drifted pin; doing what the door says clears doctor', async () => {
    const p = project('drakon-systems-shieldcortex-realtime-aaa', SELF(), '1.0.0');
    baseConfig();
    const manifest = path.join(p.root, 'package.json');
    const result = await repairOpenClawManagedPins(home, undefined, fake.deps);
    const command = /`(openclaw plugins install [^`]+)`/.exec(result.message)?.[1];
    expect(command).toBe(`openclaw ${realtimePluginInstallArgs(SELF()).join(' ')}`);

    // The operator runs the install alone (through the fake): the pin is still there.
    fake.deps.runOpenClaw('openclaw', command!.split(' ').slice(1));
    expect(findEoverrideRiskPins(JSON.parse(fs.readFileSync(manifest, 'utf-8')))).toEqual([{ name: 'peer', dependencyVersion: '1.0.0', overrideVersion: '2.0.0' }]);
    expect((await checkOpenClawManagedPinDrift(home)).status).toBe('warn');

    // Doing what the door says first — remove the named pin from that file — clears the row.
    const m = JSON.parse(fs.readFileSync(manifest, 'utf-8')) as { dependencies: Record<string, string> };
    delete m.dependencies.peer;
    fs.writeFileSync(manifest, JSON.stringify(m));
    expect((await checkOpenClawManagedPinDrift(home)).status).toBe('pass');
  });
});
