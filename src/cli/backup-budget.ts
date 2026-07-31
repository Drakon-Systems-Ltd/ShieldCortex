/**
 * ShieldCortex — budget-aware maintenance backups (#148).
 *
 * A maintenance command must not be the thing that breaks the host.
 *
 * Live on a fleet box, 31 Jul 2026: `doctor` warned about a project-key
 * collision and recommended `--fix-project-keys`. That repair copied the whole
 * 48 MB database as a safety backup with no headroom check, taking the host
 * from 51.7 MB to 98.8 MB against its own 100 MB limit. The next `doctor` then
 * reported a disk FAILURE — caused by the fix it had itself recommended — and
 * blamed "stale migration snapshots" it claimed were auto-pruned. They were not
 * stale, and nothing was pruned. Clearing the file by hand did not help: the
 * next repair recreated it. An unwinnable loop, ending with a host one write
 * away from a failing memory system.
 *
 * The safety backup is worth keeping — it is the rollback point for a
 * destructive rewrite. What it must not do is spend the operator's entire
 * remaining budget without looking, or leave its predecessor lying around.
 */
import { readdirSync, statSync, unlinkSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

/**
 * The accounted disk limit.
 *
 * Duplicated today in `database/init.ts` (MAX_DB_SIZE) and `cli/doctor.ts`
 * (checkDiskUsage's default). Exported here so at least the backup path and
 * the check that reports on it agree; folding the other two onto this constant
 * is worth doing, because three copies of a limit is three chances to drift.
 */
export const DISK_LIMIT_BYTES = 100 * 1024 * 1024;

/** Our own backup shape: `<db>.bak.<ISO-with-dashes>`. Deliberately narrow. */
export const BACKUP_SUFFIX_RE = /\.bak\.\d{4}-\d{2}-\d{2}T[\d-]+Z$/;

/** Total bytes of every regular file in a directory (non-recursive). */
function directoryBytes(dir: string): number {
  let total = 0;
  for (const name of readdirSync(dir)) {
    try {
      const s = statSync(join(dir, name));
      if (s.isFile()) total += s.size;
    } catch {
      // Vanished mid-scan — not our problem, and counting it as 0 is safe
      // because it is no longer occupying space.
    }
  }
  return total;
}

/** Backups of THIS database, newest last. */
function backupsFor(dir: string, dbName: string): string[] {
  return readdirSync(dir)
    .filter(f => f.startsWith(`${dbName}.bak.`) && BACKUP_SUFFIX_RE.test(f))
    .sort();
}

/**
 * Remove all but the newest `keep` backups of `dbName`. Returns what it removed.
 *
 * This is the behaviour doctor's own suggested-fix text has been claiming
 * ("v4.45.1+ also auto-prunes them on start") while nothing implemented it.
 * Never touches the live DB, its WAL/shm siblings, the lock, or anything that
 * does not match our own backup shape.
 */
export function pruneOldBackups(dir: string, dbName: string, keep: number): string[] {
  const all = backupsFor(dir, dbName);
  const doomed = keep <= 0 ? all : all.slice(0, Math.max(0, all.length - keep));
  const removed: string[] = [];
  for (const name of doomed) {
    try {
      unlinkSync(join(dir, name));
      removed.push(name);
    } catch {
      // A backup we cannot remove is not fatal — planBackup will simply find
      // less headroom than it hoped and refuse rather than overfill.
    }
  }
  return removed;
}

export interface BackupPlanInput {
  dbPath: string;
  /** Directory the budget applies to. Defaults to the database's own directory. */
  dir?: string;
  /** The accounted limit — the same 100 MB doctor measures against. */
  limitBytes: number;
}

export type BackupPlan =
  | { action: 'backup'; prune: string[]; reason: string }
  | { action: 'refuse'; prune: string[]; reason: string };

/**
 * Decide whether a full-copy backup fits inside the budget, and what to prune
 * to make it fit.
 *
 * Deliberately conservative: it refuses rather than overfilling, because the
 * caller is about to do something destructive and an operator who is told "I
 * can't take a safety copy" can act, whereas one whose disk silently filled
 * cannot.
 */
export function planBackup(input: BackupPlanInput): BackupPlan {
  const dir = input.dir ?? dirname(input.dbPath);
  const dbName = basename(input.dbPath);
  const dbSize = statSync(input.dbPath).size;

  const used = directoryBytes(dir);
  const headroom = input.limitBytes - used;
  if (headroom >= dbSize) {
    return { action: 'backup', prune: [], reason: 'sufficient headroom for a full backup' };
  }

  // Not enough room as-is. Reclaim from our own previous backups — they are
  // exactly what the new one supersedes.
  const candidates = backupsFor(dir, dbName);
  let reclaimable = 0;
  const prune: string[] = [];
  for (const name of candidates) {
    try {
      reclaimable += statSync(join(dir, name)).size;
      prune.push(name);
      if (headroom + reclaimable >= dbSize) break;
    } catch {
      // ignore
    }
  }

  if (headroom + reclaimable >= dbSize) {
    return {
      action: 'backup',
      prune,
      reason: `pruning ${prune.length} superseded backup(s) to make room for a fresh one`,
    };
  }

  const mb = (n: number) => `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return {
    action: 'refuse',
    prune: [],
    reason:
      `refusing to write a ${mb(dbSize)} safety backup: it would exceed the ${mb(input.limitBytes)} ` +
      `disk budget (${mb(used)} already used, ${mb(Math.max(0, headroom))} free, ` +
      `${mb(reclaimable)} reclaimable from old backups). ` +
      `Free space under the limit, or take your own copy outside it and re-run with --no-backup.`,
  };
}
