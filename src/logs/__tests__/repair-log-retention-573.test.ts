/**
 * #573 — retention for `project-key-repair-*.json`.
 *
 * The incident: 3,508 repair logs in `~/.shieldcortex/logs`, up to 357 in a
 * single day, and nothing anywhere that ever deleted one. This module is the
 * bound. It is deliberately ONLY about that one plane — the realtime audit
 * ledger under `~/.shieldcortex/audit/` is a different problem (writer races,
 * an unread projector queue, stop-hook recovery) and is tracked separately in
 * #579; nothing here reads, writes or removes an audit file.
 *
 * The rules under test, in the order they matter:
 *   - newest N survive, N is a strict integer >= 1 from the environment;
 *   - only `project-key-repair-*.json`, only directly in the logs dir, only
 *     regular files (lstat, so a symlink with that name is never followed);
 *   - a plane reachable through a symlink refuses the whole pass;
 *   - deletion re-checks with lstat immediately before unlink, so a file
 *     swapped for a symlink mid-pass is left alone.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  DEFAULT_REPAIR_LOG_KEEP,
  pruneRepairLogs,
  repairLogDirForDb,
  resolveRepairLogKeep,
} from '../retention.js';

let root: string;
let logsDir: string;

/** `project-key-repair-<iso>.json`, oldest first, with distinct mtimes. */
function seedLogs(count: number, dir = logsDir): string[] {
  fs.mkdirSync(dir, { recursive: true });
  const names: string[] = [];
  for (let i = 0; i < count; i++) {
    const name = `project-key-repair-2026-01-01T00-00-${String(i).padStart(2, '0')}-000Z.json`;
    const full = path.join(dir, name);
    fs.writeFileSync(full, JSON.stringify({ n: i }));
    // Distinct, ordered mtimes — "newest" must not depend on write speed.
    fs.utimesSync(full, new Date(1_700_000_000_000 + i * 1000), new Date(1_700_000_000_000 + i * 1000));
    names.push(name);
  }
  return names;
}

const listed = (dir = logsDir): string[] => fs.readdirSync(dir).sort();

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-retention-'));
  logsDir = path.join(root, '.shieldcortex', 'logs');
  fs.mkdirSync(logsDir, { recursive: true });
});

afterEach(() => {
  jest.restoreAllMocks();
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
});

describe('#573 pruneRepairLogs keeps the newest N', () => {
  it('deletes everything past the newest N and reports what it freed', () => {
    const names = seedLogs(25);

    const result = pruneRepairLogs({ dir: logsDir, keep: 5, execute: true });

    expect(result.dryRun).toBe(false);
    expect(result.matched).toBe(25);
    expect(result.kept).toBe(5);
    expect(result.deleted).toHaveLength(20);
    expect(result.freedBytes).toBeGreaterThan(0);
    expect(listed()).toEqual(names.slice(-5).sort());
  });

  it('is a dry run by default — same plan, nothing removed', () => {
    const names = seedLogs(25);

    const result = pruneRepairLogs({ dir: logsDir, keep: 5 });

    expect(result.dryRun).toBe(true);
    expect(result.deleted).toHaveLength(20);
    expect(result.freedBytes).toBeGreaterThan(0);
    expect(listed()).toEqual([...names].sort());
  });

  it('keeps the newest by mtime, not by directory order', () => {
    seedLogs(3);
    // Make the lexically-first name the newest file on disk.
    const bumped = path.join(logsDir, 'project-key-repair-2026-01-01T00-00-00-000Z.json');
    fs.utimesSync(bumped, new Date(1_800_000_000_000), new Date(1_800_000_000_000));

    pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(listed()).toEqual([path.basename(bumped)]);
  });

  it('does nothing when there are fewer files than the keep count', () => {
    const names = seedLogs(3);
    const result = pruneRepairLogs({ dir: logsDir, keep: 20, execute: true });
    expect(result.deleted).toEqual([]);
    expect(result.kept).toBe(3);
    expect(listed()).toEqual([...names].sort());
  });

  it('treats a missing logs directory as nothing to do', () => {
    const absent = path.join(root, '.shieldcortex', 'nope');
    const result = pruneRepairLogs({ dir: absent, keep: 1, execute: true });
    expect(result.matched).toBe(0);
    expect(result.deleted).toEqual([]);
    expect(result.refused).toBeNull();
    expect(result.errors).toEqual([]);
  });
});

describe('#573 pruneRepairLogs only ever touches repair logs', () => {
  it('ignores every other name in the directory', () => {
    seedLogs(25);
    const bystanders = [
      'project-key-repair.json',              // no timestamp segment
      'project-key-repair-2026-01-01.json.gz', // not the .json suffix
      'project-key-repair-2026-01-01.txt',
      'PROJECT-KEY-REPAIR-2026-01-01.json',    // case matters
      'denials.jsonl',
      'worker.json',
    ];
    for (const name of bystanders) fs.writeFileSync(path.join(logsDir, name), 'keep me');

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(result.matched).toBe(25);
    for (const name of bystanders) {
      expect(fs.existsSync(path.join(logsDir, name))).toBe(true);
    }
  });

  it('does not descend into subdirectories', () => {
    seedLogs(25);
    const nested = path.join(logsDir, 'archive');
    const nestedNames = seedLogs(5, nested);

    pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(listed(nested)).toEqual([...nestedNames].sort());
  });

  it('never unlinks a symlink that happens to carry the name', () => {
    seedLogs(25);
    const canary = path.join(root, 'precious.json');
    fs.writeFileSync(canary, 'do not delete me');
    // Old, deliberately: a `stat` (rather than `lstat`) implementation reads the
    // TARGET's timestamp, so the link has to look like the oldest file in the
    // directory for that mistake to select it for deletion at all.
    fs.utimesSync(canary, new Date(1_600_000_000_000), new Date(1_600_000_000_000));
    const link = path.join(logsDir, 'project-key-repair-1999-01-01T00-00-00-000Z.json');
    fs.symlinkSync(canary, link);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    // Not counted, not deleted, and the target survives.
    expect(result.deleted.map((d) => d.path)).not.toContain(link);
    expect(fs.existsSync(canary)).toBe(true);
    expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);
  });

  it('never removes a directory that happens to carry the name', () => {
    seedLogs(25);
    const dirNamedLikeALog = path.join(logsDir, 'project-key-repair-1999-01-01T00-00-00-000Z.json');
    fs.mkdirSync(dirNamedLikeALog);

    pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(fs.statSync(dirNamedLikeALog).isDirectory()).toBe(true);
  });
});

describe('#573 pruneRepairLogs refuses a plane reachable through a symlink', () => {
  it('refuses when the logs directory itself is a symlink', () => {
    const real = path.join(root, 'elsewhere');
    seedLogs(25, real);
    const linked = path.join(root, '.shieldcortex', 'logs-link');
    fs.symlinkSync(real, linked);

    const result = pruneRepairLogs({ dir: linked, keep: 1, execute: true });

    expect(result.refused).toMatch(/symlink/i);
    expect(result.deleted).toEqual([]);
    expect(fs.readdirSync(real)).toHaveLength(25);
  });

  it('refuses when a component below .shieldcortex is a symlink', () => {
    const real = path.join(root, 'real-sc');
    fs.mkdirSync(path.join(real, 'logs'), { recursive: true });
    seedLogs(25, path.join(real, 'logs'));
    const link = path.join(root, '.shieldcortex', 'sub');
    fs.symlinkSync(real, link);

    const result = pruneRepairLogs({ dir: path.join(link, 'logs'), keep: 1, execute: true });

    expect(result.refused).toMatch(/symlink/i);
    expect(result.deleted).toEqual([]);
    expect(fs.readdirSync(path.join(real, 'logs'))).toHaveLength(25);
  });

  it('refuses when the logs path is not a directory at all', () => {
    const asFile = path.join(root, '.shieldcortex', 'logs-file');
    fs.writeFileSync(asFile, 'not a directory');
    const result = pruneRepairLogs({ dir: asFile, keep: 1, execute: true });
    expect(result.refused).toMatch(/not a directory/i);
    expect(fs.existsSync(asFile)).toBe(true);
  });
});

describe('#573 deletion re-checks the file immediately before unlinking', () => {
  it('leaves a doomed file that became a symlink mid-pass alone', () => {
    // The TOCTOU the recheck exists for: the plan is built, and between
    // building it and acting on it a doomed name is replaced by a symlink to
    // something that must not be deleted. Listing-time lstat cannot see that;
    // only a recheck at the unlink can.
    const names = seedLogs(3);
    const victim = path.join(logsDir, names[1]);
    const canary = path.join(root, 'precious.json');
    fs.writeFileSync(canary, 'do not delete me');

    const realUnlink = fs.unlinkSync.bind(fs);
    let swapped = false;
    jest.spyOn(fs, 'unlinkSync').mockImplementation(((target: fs.PathLike) => {
      realUnlink(target);
      if (!swapped) {
        swapped = true;
        realUnlink(victim);
        fs.symlinkSync(canary, victim);
      }
    }) as typeof fs.unlinkSync);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(swapped).toBe(true);
    expect(fs.existsSync(canary)).toBe(true);
    expect(fs.lstatSync(victim).isSymbolicLink()).toBe(true);
    expect(result.deleted.map((d) => path.basename(d.path))).not.toContain(names[1]);
  });
});

describe('#573 resolveRepairLogKeep is strict about its integer', () => {
  it('defaults to 20', () => {
    const { keep, warnings } = resolveRepairLogKeep({});
    expect(keep).toBe(DEFAULT_REPAIR_LOG_KEEP);
    expect(keep).toBe(20);
    expect(warnings).toEqual([]);
  });

  it('accepts a whole number >= 1', () => {
    expect(resolveRepairLogKeep({ SHIELDCORTEX_REPAIR_LOG_KEEP: '3' }).keep).toBe(3);
    expect(resolveRepairLogKeep({ SHIELDCORTEX_REPAIR_LOG_KEEP: ' 7 ' }).keep).toBe(7);
    expect(resolveRepairLogKeep({ SHIELDCORTEX_REPAIR_LOG_KEEP: '1' }).keep).toBe(1);
  });

  it('treats an unset or blank-exported variable as unset, with no warning', () => {
    expect(resolveRepairLogKeep({}).warnings).toEqual([]);
    expect(resolveRepairLogKeep({ SHIELDCORTEX_REPAIR_LOG_KEEP: '' }).warnings).toEqual([]);
  });

  // `Number(' ')` is 0 and 0 means "delete every repair log": a stray space in
  // a unit file must never be able to express that.
  it.each(['  ', '0', '-1', '3.5', '1e3', '0x10', 'twenty', 'Infinity', 'NaN'])(
    'rejects %p and warns, falling back to the default',
    (raw) => {
      const { keep, warnings } = resolveRepairLogKeep({ SHIELDCORTEX_REPAIR_LOG_KEEP: raw });
      expect(keep).toBe(DEFAULT_REPAIR_LOG_KEEP);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain('SHIELDCORTEX_REPAIR_LOG_KEEP');
    },
  );

  it('refuses to express "keep nothing" even when a caller passes keep: 0', () => {
    seedLogs(3);
    const result = pruneRepairLogs({ dir: logsDir, keep: 0, execute: true });
    expect(result.kept).toBe(1);
    expect(listed()).toHaveLength(1);
  });

  it('is what pruneRepairLogs uses when no keep is passed', () => {
    seedLogs(25);
    const result = pruneRepairLogs({
      dir: logsDir,
      execute: true,
      env: { SHIELDCORTEX_REPAIR_LOG_KEEP: '2' },
    });
    expect(result.keep).toBe(2);
    expect(listed()).toHaveLength(2);
  });

  it('surfaces the rejection warning through the prune result', () => {
    seedLogs(3);
    const result = pruneRepairLogs({
      dir: logsDir,
      execute: false,
      env: { SHIELDCORTEX_REPAIR_LOG_KEEP: ' ' },
    });
    expect(result.keep).toBe(DEFAULT_REPAIR_LOG_KEEP);
    expect(result.errors.join(' ')).toContain('SHIELDCORTEX_REPAIR_LOG_KEEP');
  });
});

describe('#573 the repair log belongs beside the database it describes', () => {
  it('resolves <db-dir>/logs', () => {
    expect(repairLogDirForDb('/var/tmp/scratch/memories.db'))
      .toBe(path.join('/var/tmp/scratch', 'logs'));
  });

  it('resolves the documented ~/.shieldcortex/logs for the default database', () => {
    const home = os.homedir();
    expect(repairLogDirForDb(path.join(home, '.shieldcortex', 'memories.db')))
      .toBe(path.join(home, '.shieldcortex', 'logs'));
  });

  it('resolves a relative db path against the cwd rather than guessing', () => {
    expect(repairLogDirForDb('memories.db')).toBe(path.join(process.cwd(), 'logs'));
  });
});
