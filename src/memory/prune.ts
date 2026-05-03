import { getDatabase } from '../database/init.js';
import { deleteMemory } from './store.js';
import { backupMemoriesDb } from './backup.js';

export interface PruneOptions {
  /** Salience ceiling (inclusive). Memories with salience <= this are candidates. 0..1, default 0.2. */
  salienceLte?: number;
  /** Minimum age in days. Memories older than this are candidates. 1..365, default 30. */
  ageDaysGte?: number;
  /** Optional project scope. Omit for all projects. */
  project?: string;
  /** When true (default) pinned memories are never pruned. */
  excludePinned?: boolean;
  /** When true (default) only count + sample, no deletes. */
  dryRun?: boolean;
}

export interface PruneSampleEntry {
  id: number;
  title: string;
  project: string | null;
  salience: number;
  ageDays: number;
}

export interface PruneResult {
  options: Required<Omit<PruneOptions, 'project'>> & { project: string | null };
  matched: number;
  sample: PruneSampleEntry[];
  deleted?: number;
  backupPath?: string;
}

const DEFAULTS = {
  salienceLte: 0.2,
  ageDaysGte: 30,
  excludePinned: true,
  dryRun: true,
} as const;

const SAMPLE_LIMIT = 10;

interface RowShape {
  id: number;
  title: string;
  project: string | null;
  salience: number;
  age_days: number;
}

function buildWhereClause(options: Required<Omit<PruneOptions, 'project'>> & { project: string | null }): {
  where: string;
  params: unknown[];
} {
  const where: string[] = [
    'salience <= ?',
    "(julianday('now') - julianday(created_at)) >= ?",
    "COALESCE(status, 'active') NOT IN ('archived', 'suppressed')",
  ];
  const params: unknown[] = [options.salienceLte, options.ageDaysGte];

  if (options.project !== null) {
    where.push('project = ?');
    params.push(options.project);
  }
  if (options.excludePinned) {
    where.push('COALESCE(pinned, 0) = 0');
  }

  return { where: where.join(' AND '), params };
}

/**
 * Find + optionally delete memories below a salience threshold older than N
 * days. Always backs up the live DB before any delete; the backup path is
 * returned in the result so the caller can surface it to the user.
 */
export async function pruneMemories(rawOptions: PruneOptions = {}): Promise<PruneResult> {
  const options = {
    salienceLte: rawOptions.salienceLte ?? DEFAULTS.salienceLte,
    ageDaysGte: rawOptions.ageDaysGte ?? DEFAULTS.ageDaysGte,
    project: rawOptions.project ?? null,
    excludePinned: rawOptions.excludePinned ?? DEFAULTS.excludePinned,
    dryRun: rawOptions.dryRun ?? DEFAULTS.dryRun,
  };

  if (options.salienceLte < 0 || options.salienceLte > 1) {
    throw new Error('salienceLte must be between 0 and 1');
  }
  if (options.ageDaysGte < 0) {
    throw new Error('ageDaysGte must be >= 0');
  }

  const { where, params } = buildWhereClause(options);
  const db = getDatabase();

  const countRow = db.prepare(`SELECT COUNT(*) AS n FROM memories WHERE ${where}`).get(...params) as {
    n: number;
  };
  const matched = countRow.n;

  const sampleRows = db
    .prepare(
      `SELECT id, title, project, salience,
              CAST(julianday('now') - julianday(created_at) AS INTEGER) AS age_days
       FROM memories WHERE ${where}
       ORDER BY salience ASC, created_at ASC
       LIMIT ?`,
    )
    .all(...params, SAMPLE_LIMIT) as RowShape[];

  const sample: PruneSampleEntry[] = sampleRows.map((r) => ({
    id: r.id,
    title: r.title,
    project: r.project,
    salience: r.salience,
    ageDays: r.age_days,
  }));

  const result: PruneResult = { options, matched, sample };

  if (options.dryRun || matched === 0) return result;

  result.backupPath = await backupMemoriesDb('pre-prune');

  const idRows = db.prepare(`SELECT id FROM memories WHERE ${where}`).all(...params) as { id: number }[];
  let deleted = 0;
  for (const row of idRows) {
    if (deleteMemory(row.id, { type: 'cli', identifier: 'maintenance:prune' })) deleted++;
  }
  result.deleted = deleted;
  return result;
}
