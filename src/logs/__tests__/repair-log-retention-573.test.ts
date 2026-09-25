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
 *   - the directory is fully resolved before anything is listed, and a plane
 *     that resolves into the realtime audit ledger refuses the whole pass;
 *   - deletion re-checks with lstat immediately before unlink, so a file
 *     swapped for a symlink mid-pass is left alone.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  DEFAULT_REPAIR_LOG_KEEP,
  defaultRepairLogDir,
  pruneRepairLogs,
  REPAIR_LOG_MIN_AGE_MS,
  repairLogDbId,
  repairLogDirForDb,
  repairLogName,
  resolveRepairLogKeep,
} from '../retention.js';

let root: string;
let logsDir: string;
let auditDir: string;
let auditBefore: string | undefined;

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
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-retention-')));
  logsDir = path.join(root, '.shieldcortex', 'logs');
  fs.mkdirSync(logsDir, { recursive: true });
  // The audit plane this module must never touch, moved inside the sandbox:
  // the refusal is measured against a directory this test owns, and the real
  // ~/.shieldcortex/audit is never even stat'ed.
  auditDir = path.join(root, '.shieldcortex', 'audit');
  fs.mkdirSync(auditDir, { recursive: true });
  auditBefore = process.env.SHIELDCORTEX_AUDIT_DIR;
  process.env.SHIELDCORTEX_AUDIT_DIR = auditDir;
});

afterEach(() => {
  jest.restoreAllMocks();
  if (auditBefore === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
  else process.env.SHIELDCORTEX_AUDIT_DIR = auditBefore;
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
      // Round-3 blocker 4. Under the old `.+` stand-in for the timestamp these
      // were records — an operator's configuration and notes, deleted with
      // errors=[] and counted as retention doing its job.
      'project-key-repair-config.json',
      'project-key-repair-notes.json',
      'project-key-repair-.json',
      'project-key-repair-2026-01-01.json',    // a date is not the writer's stamp
      'project-key-repair-2026-01-01T00-00-00-000Z.json.bak',
    ];
    for (const name of bystanders) fs.writeFileSync(path.join(logsDir, name), 'keep me');

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(result.matched).toBe(25);
    for (const name of bystanders) {
      expect(fs.existsSync(path.join(logsDir, name))).toBe(true);
    }
  });

  it('leaves an operator file beside an older record, even at keep 1', () => {
    // The reviewer's exact reproduction: `project-key-repair-config.json`, OLDER
    // than the one real record, with keep=1 and execute=true. The name check
    // accepted it, the age rule did not save it, and it was unlinked.
    const config = path.join(logsDir, 'project-key-repair-config.json');
    fs.writeFileSync(config, '{"operator":"settings"}');
    fs.utimesSync(config, new Date(1_600_000_000_000), new Date(1_600_000_000_000));
    seedLogs(2);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(result.matched).toBe(2);
    expect(result.deleted).toHaveLength(1);
    expect(fs.readFileSync(config, 'utf-8')).toBe('{"operator":"settings"}');
  });

  it('bounds both name shapes the writer produces, suffixed collisions included', () => {
    // The other side of the grammar: tightening it must not withdraw retention
    // from a record the writer really wrote. `-<n>` is `writeRepairLogRecord`'s
    // collision suffix, which a stamp-only grammar would exclude.
    const names = [
      'project-key-repair-2026-01-01T00-00-00-000Z.json',
      'project-key-repair-2026-01-01T00-00-00-000Z-1.json',
      'project-key-repair-0123456789ab-2026-01-01T00-00-01-000Z.json',
      'project-key-repair-0123456789ab-2026-01-01T00-00-01-000Z-2.json',
    ];
    names.forEach((name, i) => {
      const full = path.join(logsDir, name);
      fs.writeFileSync(full, '{}');
      fs.utimesSync(full, new Date(1_700_000_000_000 + i * 1000), new Date(1_700_000_000_000 + i * 1000));
    });

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(result.matched).toBe(4);
    expect(result.databases).toBe(2);   // one legacy group, one id-bearing
    expect(listed()).toEqual([names[1], names[3]].sort());
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

describe('#573 pruneRepairLogs settles its directory before it lists anything', () => {
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

  it('refuses when the logs path is not a directory at all', () => {
    const asFile = path.join(root, '.shieldcortex', 'logs-file');
    fs.writeFileSync(asFile, 'not a directory');
    const result = pruneRepairLogs({ dir: asFile, keep: 1, execute: true });
    expect(result.refused).toMatch(/not a directory/i);
    expect(fs.existsSync(asFile)).toBe(true);
  });

  it('acts on the RESOLVED directory, so a symlinked ancestor cannot redirect it', () => {
    // A link above the logs directory is not itself a refusal — it just does
    // not get to decide anything. Everything from the listing to the unlink
    // uses the resolved path, and that is what the result reports.
    const real = path.join(root, 'real-sc', 'logs');
    seedLogs(25, real);
    const link = path.join(root, '.shieldcortex', 'sub');
    fs.symlinkSync(path.join(root, 'real-sc'), link);

    const result = pruneRepairLogs({ dir: path.join(link, 'logs'), keep: 1, execute: true });

    expect(result.refused).toBeNull();
    expect(result.dir).toBe(real);
    expect(result.deleted).toHaveLength(24);
    expect(fs.readdirSync(real)).toHaveLength(1);
  });
});

/**
 * Round-2 blocker 1 / round-3 blocker 1 — the realtime audit plane (#579's) is
 * reachable through a planted symlink, and must be refused wherever the link
 * sits. The boundary used to be chosen by basename: `lastIndexOf('.shieldcortex')`
 * picked the INNERMOST `.shieldcortex` component and never looked at anything
 * above it, so both layouts below pruned inside the audit directory with
 * `refused: null` and `errors: []`.
 */
describe('#573 blocker 1 — no path resolves into the realtime audit plane', () => {
  /** Byte-for-byte evidence that #579's plane was not touched. */
  function auditManifest(): Array<[string, string]> {
    return fs.readdirSync(auditDir, { recursive: true } as never)
      .map((n) => path.join(auditDir, n as string))
      .filter((f) => fs.statSync(f).isFile())
      .map((f) => [path.relative(auditDir, f), fs.readFileSync(f, 'utf-8')] as [string, string])
      .sort();
  }

  it('refuses a logs directory whose parent is a link to the audit plane', () => {
    // The reviewer's first layout: HOME/db-link -> .shieldcortex/audit, with
    // the repair logs written at db-link/logs. Nothing in the supplied path
    // contains `.shieldcortex` at all.
    const inside = path.join(auditDir, 'logs');
    seedLogs(3, inside);
    fs.writeFileSync(path.join(auditDir, 'realtime-2026-01-01.jsonl'), '{"event":"blocked"}\n');
    const before = auditManifest();
    fs.symlinkSync(auditDir, path.join(root, 'db-link'));

    const result = pruneRepairLogs({
      dir: path.join(root, 'db-link', 'logs'), keep: 1, execute: true,
    });

    expect(result.refused).toMatch(/audit/i);
    expect(result.deleted).toEqual([]);
    expect(result.errors).toEqual([]);
    expect(auditManifest()).toEqual(before);
  });

  it('refuses a nested .shieldcortex reached through a link to the audit plane', () => {
    // The reviewer's second layout: .shieldcortex/alias/.shieldcortex/logs with
    // alias -> the audit directory. Picking the LAST `.shieldcortex` component
    // as the trusted root skipped `alias` entirely.
    const inside = path.join(auditDir, '.shieldcortex', 'logs');
    seedLogs(3, inside);
    const before = auditManifest();
    fs.symlinkSync(auditDir, path.join(root, '.shieldcortex', 'alias'));

    const result = pruneRepairLogs({
      dir: path.join(root, '.shieldcortex', 'alias', '.shieldcortex', 'logs'),
      keep: 1,
      execute: true,
    });

    expect(result.refused).toMatch(/audit/i);
    expect(result.deleted).toEqual([]);
    expect(result.errors).toEqual([]);
    expect(auditManifest()).toEqual(before);
  });

  it('refuses the audit directory itself, named directly', () => {
    seedLogs(3, auditDir);
    const before = auditManifest();
    const result = pruneRepairLogs({ dir: auditDir, keep: 1, execute: true });
    expect(result.refused).toMatch(/audit/i);
    expect(auditManifest()).toEqual(before);
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
    // A warning, not an error: the pass ran to completion at the default, so
    // the command still exits 0 (see the exit-status case in logs-prune-573).
    expect(result.warnings.join(' ')).toContain('SHIELDCORTEX_REPAIR_LOG_KEEP');
    expect(result.errors).toEqual([]);
  });
});

describe('#573 the repair log belongs beside the database it describes', () => {
  it('resolves <db-dir>/logs', () => {
    const scratch = path.join(root, 'scratch');
    fs.mkdirSync(scratch);
    expect(repairLogDirForDb(path.join(scratch, 'memories.db'))).toBe(path.join(scratch, 'logs'));
  });

  it('resolves the documented ~/.shieldcortex/logs for the default database', () => {
    // A home this test owns, not the developer's: the formula is what is under
    // test, and it must agree with `defaultRepairLogDir()` for the default DB.
    const home = path.join(root, 'home');
    fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
    jest.spyOn(os, 'homedir').mockReturnValue(home);

    expect(repairLogDirForDb(path.join(home, '.shieldcortex', 'memories.db')))
      .toBe(path.join(home, '.shieldcortex', 'logs'));
    expect(defaultRepairLogDir()).toBe(path.join(home, '.shieldcortex', 'logs'));
  });

  it('resolves a relative db path against the cwd rather than guessing', () => {
    expect(repairLogDirForDb('memories.db'))
      .toBe(path.join(fs.realpathSync(process.cwd()), 'logs'));
  });

  it('resolves every symlink above the database, so no link picks the destination', () => {
    const realDbDir = path.join(root, 'real-db-dir');
    fs.mkdirSync(realDbDir);
    fs.symlinkSync(realDbDir, path.join(root, 'db-alias'));
    expect(repairLogDirForDb(path.join(root, 'db-alias', 'memories.db')))
      .toBe(path.join(realDbDir, 'logs'));
  });
});

// ── Round-2 blockers ──────────────────────────────────────────────────────

describe('#573 blocker 3 — the bound is per database, not per directory', () => {
  /** One record per database, all in the shared logs directory they resolve to. */
  function seedForDbs(dbs: string[], perDb = 1): Map<string, string[]> {
    fs.mkdirSync(logsDir, { recursive: true });
    const byDb = new Map<string, string[]>();
    let tick = 0;
    for (const db of dbs) {
      const names: string[] = [];
      for (let i = 0; i < perDb; i++) {
        const name = repairLogName(db, new Date(1_700_000_000_000 + tick * 1000));
        const full = path.join(logsDir, name);
        fs.writeFileSync(full, JSON.stringify({ dbPath: db, i }));
        const when = new Date(1_700_000_000_000 + tick * 1000);
        fs.utimesSync(full, when, when);
        names.push(name);
        tick++;
      }
      byDb.set(db, names);
    }
    return byDb;
  }

  it('keeps every database\'s only record when three share one logs directory', () => {
    // The reviewer's fixture: three databases in one parent, so
    // repairLogDirForDb gives all three the SAME logs directory. With keep=1 a
    // per-directory bound deleted two databases' sole repair record.
    const dbs = ['a.db', 'b.db', 'c.db'].map((n) => path.join(root, '.shieldcortex', n));
    expect(new Set(dbs.map(repairLogDirForDb))).toEqual(new Set([logsDir]));
    seedForDbs(dbs);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(result.databases).toBe(3);
    expect(result.deleted).toEqual([]);
    expect(listed()).toHaveLength(3);
  });

  it('applies the keep count within each database independently', () => {
    const dbs = ['busy.db', 'quiet.db'].map((n) => path.join(root, '.shieldcortex', n));
    const byDb = seedForDbs(dbs, 4);
    // Give `quiet.db` only one record; `busy.db` keeps its four.
    for (const name of byDb.get(dbs[1])!.slice(1)) fs.unlinkSync(path.join(logsDir, name));

    const result = pruneRepairLogs({ dir: logsDir, keep: 2, execute: true });

    // Two of busy's four go; quiet's single record is untouched.
    expect(result.deleted.map((d) => path.basename(d.path)).sort())
      .toEqual(byDb.get(dbs[0])!.slice(0, 2).sort());
    expect(fs.existsSync(path.join(logsDir, byDb.get(dbs[1])![0]))).toBe(true);
  });

  it('groups records written before #573 together as one legacy set', () => {
    // No id in the name, so they cannot be attributed to a database — one
    // group, bounded as a whole, which is the only honest reading.
    const legacy = seedLogs(5);
    const withId = seedForDbs([path.join(root, '.shieldcortex', 'x.db')], 3);

    const result = pruneRepairLogs({ dir: logsDir, keep: 2, execute: true });

    expect(result.databases).toBe(2);
    const gone = result.deleted.map((d) => path.basename(d.path));
    expect(gone).toEqual(expect.arrayContaining(legacy.slice(0, 3)));
    expect(gone).toContain(withId.get(path.join(root, '.shieldcortex', 'x.db'))![0]);
    expect(gone).toHaveLength(4);
  });

  it('names the database in the filename the writer produces', () => {
    const a = repairLogName(path.join(root, 'a.db'), new Date(0));
    const b = repairLogName(path.join(root, 'b.db'), new Date(0));
    expect(a).not.toBe(b);
    expect(a).toMatch(/^project-key-repair-[0-9a-f]{12}-1970-01-01T00-00-00-000Z\.json$/);
    // Stable across calls and independent of how the path was spelled.
    expect(repairLogDbId(path.join(root, 'a.db')))
      .toBe(repairLogDbId(path.join(root, '.', 'a.db')));
  });
});

describe('#573 blocker 2 — a record younger than an hour is never a candidate', () => {
  it('spares every record in a burst that is still inside the hour', () => {
    // The reviewer's case is a record a writer has open. The rule that makes
    // one ineligible AT ALL is its age: three repairs inside a few minutes put
    // two past a keep of 1, and one of those two may be the log currently
    // being serialised. None of them are candidates yet.
    const names = seedLogs(3);
    const now = 1_700_000_002_000 + 60_000; // newest record is a minute old

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true, nowMs: now });

    expect(result.tooYoung).toBe(2);
    expect(result.deleted).toEqual([]);
    expect(listed()).toEqual([...names].sort());
  });

  it('spares the young ones and deletes the old ones in the same pass', () => {
    const now = 1_700_000_000_000 + 3 * REPAIR_LOG_MIN_AGE_MS;
    /** One record at a chosen age, named for its age so failures read plainly. */
    const at = (label: string, ageMs: number): string => {
      const name = `project-key-repair-2026-01-01T00-00-00-${label}Z.json`;
      const full = path.join(logsDir, name);
      fs.writeFileSync(full, 'x');
      fs.utimesSync(full, new Date(now - ageMs), new Date(now - ageMs));
      return name;
    };
    const oldest = at('001', 2 * REPAIR_LOG_MIN_AGE_MS);
    const older = at('002', REPAIR_LOG_MIN_AGE_MS + 1000);
    const young = at('003', 60_000);
    const youngest = at('004', 1000);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true, nowMs: now });

    // Three are past a keep of 1; the one inside the hour is spared.
    expect(result.tooYoung).toBe(1);
    expect(result.deleted.map((d) => path.basename(d.path))).toEqual([oldest, older]);
    expect(listed()).toEqual([young, youngest].sort());
  });

  it('deletes the same record once it is over an hour old', () => {
    const names = seedLogs(2);
    const mtime = 1_700_000_001_000;
    const result = pruneRepairLogs({
      dir: logsDir, keep: 1, execute: true, nowMs: mtime + REPAIR_LOG_MIN_AGE_MS,
    });
    expect(result.tooYoung).toBe(0);
    expect(result.deleted.map((d) => path.basename(d.path))).toEqual([names[0]]);
  });

  it('leaves a record that changed between selection and unlink', () => {
    // Identity, not just "is it still a regular file": a candidate an
    // appending writer touched mid-pass is no longer the file that was chosen.
    const names = seedLogs(3);
    const victim = path.join(logsDir, names[1]);
    const realUnlink = fs.unlinkSync.bind(fs);
    let touched = false;
    jest.spyOn(fs, 'unlinkSync').mockImplementation(((target: fs.PathLike) => {
      realUnlink(target);
      if (!touched) {
        touched = true;
        fs.appendFileSync(victim, 'appended by a live writer');
      }
    }) as typeof fs.unlinkSync);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(touched).toBe(true);
    expect(fs.existsSync(victim)).toBe(true);
    expect(result.errors.join('\n')).toMatch(/changed since it was selected/);
  });

  it('leaves a record that is hard-linked somewhere else', () => {
    const names = seedLogs(3);
    const linked = path.join(logsDir, names[0]);
    fs.linkSync(linked, path.join(root, 'kept-by-someone-else.json'));

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(fs.existsSync(linked)).toBe(true);
    // Deliberately left in place, so it is a warning: nothing failed.
    expect(result.warnings.join('\n')).toMatch(/hard links/);
    expect(result.errors).toEqual([]);
    expect(result.deleted.map((d) => path.basename(d.path))).toEqual([names[1]]);
  });
});

describe('#573 blocker 1 — a replaced logs directory stops the pass', () => {
  it('deletes nothing more once the directory is no longer the one listed', () => {
    // The reviewer's traversal: the validated directory is swapped for a
    // symlink to ANOTHER database's logs directory after the listing. Checking
    // only the final file component cannot see that; the directory's pinned
    // (dev, ino) can.
    const names = seedLogs(4);
    const otherDbLogs = path.join(root, 'other', 'logs');
    const otherNames = seedLogs(2, otherDbLogs);

    const realUnlink = fs.unlinkSync.bind(fs);
    let swapped = false;
    jest.spyOn(fs, 'unlinkSync').mockImplementation(((target: fs.PathLike) => {
      realUnlink(target);
      if (!swapped) {
        swapped = true;
        for (const n of fs.readdirSync(logsDir)) realUnlink(path.join(logsDir, n));
        fs.rmdirSync(logsDir);
        fs.symlinkSync(otherDbLogs, logsDir);
      }
    }) as typeof fs.unlinkSync);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(swapped).toBe(true);
    // The other database's records are all still there.
    expect(fs.readdirSync(otherDbLogs).sort()).toEqual([...otherNames].sort());
    expect(result.errors.join('\n')).toMatch(/no longer the directory that was listed/);
    expect(result.deleted.map((d) => path.basename(d.path))).toEqual([names[0]]);
  });

  it('stops when the directory is replaced by a different real directory', () => {
    const names = seedLogs(4);
    const decoy = path.join(root, 'decoy-logs');
    const decoyNames = seedLogs(3, decoy);

    const realUnlink = fs.unlinkSync.bind(fs);
    let swapped = false;
    jest.spyOn(fs, 'unlinkSync').mockImplementation(((target: fs.PathLike) => {
      realUnlink(target);
      if (!swapped) {
        swapped = true;
        for (const n of fs.readdirSync(logsDir)) realUnlink(path.join(logsDir, n));
        fs.rmdirSync(logsDir);
        fs.renameSync(decoy, logsDir);
      }
    }) as typeof fs.unlinkSync);

    const result = pruneRepairLogs({ dir: logsDir, keep: 1, execute: true });

    expect(swapped).toBe(true);
    expect(fs.readdirSync(logsDir).sort()).toEqual([...decoyNames].sort());
    expect(result.errors.join('\n')).toMatch(/no longer the directory that was listed/);
    expect(result.deleted.map((d) => path.basename(d.path))).toEqual([names[0]]);
  });
});
