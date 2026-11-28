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

    const result = await repairOpenClawManagedPins(home);

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

    const result = await repairOpenClawManagedPins(home);

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
    const result = await repairOpenClawManagedPins(home);
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

    const result = await repairOpenClawManagedPins(home);

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

    const result = await repairOpenClawManagedPins(home);

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
    const result = await repairOpenClawManagedPins(home);
    expect(raced).toBe(true);
    return result;
  }
  const atTmp = (p: string): boolean => p.endsWith('.tmp');
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

    const result = await raceAt(selected.root, atTmp, replaceWithNewInode);

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/package\.json changed while this repair was running; nothing was changed/);
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

    const result = await raceAt(selected.root, atTmp, (m) => fs.writeFileSync(m, REPLACEMENT));

    expect(result.status).toBe('failed');
    expect(result.message).toMatch(/package\.json changed while this repair was running; nothing was changed/);
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
    expect(result.message).toMatch(/package\.json changed while this repair was running; nothing was changed/);
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
