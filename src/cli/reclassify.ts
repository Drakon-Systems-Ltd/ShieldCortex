/**
 * `shieldcortex memories reclassify [--project X] [--execute]` (#718).
 *
 * The writer-side classifier gained a PERSONAL tier in #718, but it only runs
 * on new writes: every personal note already stored (a "surprise family trip"
 * saved as PUBLIC, say) keeps the label that let it into automated lanes. This
 * re-runs the current classifier over stored rows and RAISES labels that are
 * now too low.
 *
 * It never lowers a label. A stored level can be higher than a fresh
 * classification for good reasons the text alone cannot show — write-time
 * redaction replaced the identifier that justified CONFIDENTIAL, an operator
 * raised it by hand, provenance from the live scan — and lowering any of those
 * would widen who can read the row. Unknown labels (SECRET, foreign clients)
 * are left alone for the same reason.
 *
 * DRY-RUN BY DEFAULT, like prune / dedupe / embed-backfill. The report carries
 * ids and labels only — never titles or content, since the rows it lists are
 * exactly the ones that are private.
 */
import type { Database } from 'better-sqlite3';
import { classifySensitivity } from '../defence/sensitivity/index.js';

/** Ascending. Anything not in this list is left untouched. */
const LADDER = ['PUBLIC', 'INTERNAL', 'PERSONAL', 'CONFIDENTIAL', 'RESTRICTED', 'SECRET'] as const;

function rank(level: string | null | undefined): number {
  // Unlabelled rows are INTERNAL by convention everywhere else.
  const normalised = (level ?? '').trim().toUpperCase() || 'INTERNAL';
  return (LADDER as readonly string[]).indexOf(normalised);
}

export interface ReclassifyOptions {
  execute?: boolean;
  project?: string;
  /** Injected for tests. */
  db?: Database;
  /** Injected for tests; defaults to the shipped classifier. */
  classify?: (content: string, title: string) => { level: string };
}

export interface ReclassifyChange {
  id: number;
  from: string;
  to: string;
}

export interface ReclassifyResult {
  scanned: number;
  changes: ReclassifyChange[];
  /** from→to counts, e.g. { "PUBLIC→PERSONAL": 3 }. */
  transitions: Record<string, number>;
  /** Rows skipped because their stored label is outside the ladder. */
  skippedUnknown: number;
  updated: number;
  dryRun: boolean;
}

export async function reclassifyMemories(options: ReclassifyOptions = {}): Promise<ReclassifyResult> {
  const dryRun = options.execute !== true;
  const classify = options.classify ?? classifySensitivity;

  let db = options.db;
  let openedOwn = false;
  if (!db) {
    const { resolveMemoriesDbPath } = await import('../database/init.js');
    const dbPath = resolveMemoriesDbPath();
    if (dryRun) {
      const BetterSqlite = (await import('better-sqlite3')).default;
      db = new BetterSqlite(dbPath, { readonly: true, fileMustExist: true });
    } else {
      const { initDatabase, getDatabase } = await import('../database/init.js');
      initDatabase();
      db = getDatabase();
    }
    openedOwn = true;
  }

  try {
    const projectClause = options.project ? 'WHERE project = ?' : '';
    const rows = db.prepare(
      `SELECT id, title, content, sensitivity_level FROM memories ${projectClause} ORDER BY id`,
    ).all(...(options.project ? [options.project] : [])) as Array<{
      id: number; title: string | null; content: string | null; sensitivity_level: string | null;
    }>;

    const changes: ReclassifyChange[] = [];
    const transitions: Record<string, number> = {};
    let skippedUnknown = 0;

    for (const row of rows) {
      const currentRank = rank(row.sensitivity_level);
      if (currentRank === -1) {
        skippedUnknown += 1;
        continue;
      }
      const next = classify(row.content ?? '', row.title ?? '').level;
      const nextRank = rank(next);
      if (nextRank <= currentRank) continue;
      const from = LADDER[currentRank];
      const to = LADDER[nextRank];
      changes.push({ id: row.id, from, to });
      const key = `${from}→${to}`;
      transitions[key] = (transitions[key] ?? 0) + 1;
    }

    let updated = 0;
    if (!dryRun && changes.length > 0) {
      const update = db.prepare('UPDATE memories SET sensitivity_level = ? WHERE id = ?');
      const apply = db.transaction((list: ReclassifyChange[]) => {
        for (const c of list) updated += update.run(c.to, c.id).changes;
      });
      apply(changes);
    }

    return { scanned: rows.length, changes, transitions, skippedUnknown, updated, dryRun };
  } finally {
    if (openedOwn && db) {
      if (dryRun) {
        try { db.close(); } catch { /* already closed */ }
      } else {
        try {
          const { closeDatabase } = await import('../database/init.js');
          closeDatabase();
        } catch { /* already closed */ }
      }
    }
  }
}

export async function runReclassify(args: string[]): Promise<void> {
  const projectIdx = args.indexOf('--project');
  let project: string | undefined;
  if (projectIdx !== -1) {
    project = args[projectIdx + 1];
    if (!project || project.startsWith('-')) {
      console.error('reclassify: --project requires a non-empty value that is not another flag');
      process.exitCode = 2;
      return;
    }
  }
  const execute = args.includes('--execute');
  if (execute && args.includes('--dry-run')) {
    console.error('reclassify: --dry-run and --execute cannot be combined');
    process.exitCode = 2;
    return;
  }

  const result = await reclassifyMemories({ execute, project });
  const banner = result.dryRun ? '[DRY RUN] ' : '';
  console.log(`${banner}Reclassify memory sensitivity with the current classifier (#718)`);
  console.log(`  Project: ${project ?? '(all)'}`);
  console.log(`  Scanned: ${result.scanned}`);
  console.log(`  Would raise: ${result.changes.length}${result.skippedUnknown ? ` (skipped ${result.skippedUnknown} with an unknown label)` : ''}`);
  for (const [k, n] of Object.entries(result.transitions)) console.log(`    ${k}: ${n}`);
  if (result.changes.length > 0) {
    const ids = result.changes.slice(0, 50).map((c) => `#${c.id}`).join(' ');
    console.log(`  Ids: ${ids}${result.changes.length > 50 ? ' …' : ''}`);
  }
  if (result.dryRun) {
    if (result.changes.length > 0) console.log('  Re-run with --execute to apply. Labels are only ever raised.');
  } else {
    console.log(`  Updated: ${result.updated}`);
  }
}
