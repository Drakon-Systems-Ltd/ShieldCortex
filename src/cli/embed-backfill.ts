/**
 * `shieldcortex memories embed-backfill` (#458).
 *
 * Until 4.54.16 the hook write path (`scripts/lib/save-memory.mjs`) never
 * populated `memories.embedding`, so on a host where auto-capture is the
 * dominant ingest — which is precisely what the `sc_only` memory plane makes it
 * — the majority of the store ended up vector-less. `src/memory/search.ts`
 * filters on `WHERE embedding IS NOT NULL`, so those rows were silently absent
 * from semantic recall rather than ranked badly.
 *
 * Fixing the writer stops the bleeding; it does not heal the rows already
 * written, and nothing else in the codebase looks for a NULL embedding. This is
 * that repair, and it is the guaranteed-coverage path the write-time embed
 * deliberately falls back to: the hook embeds best-effort under a timeout so it
 * can never stall the turn it is ending, and anything it skipped lands here.
 *
 * DRY-RUN BY DEFAULT, in the house style of `prune` and `dedupe` — a backfill
 * on a large store is a long, worker-bound operation and the operator should see
 * the size of it before starting.
 */
import type { Database } from 'better-sqlite3';

export interface EmbedBackfillOptions {
  /** Perform the writes. Without it the command only reports. */
  execute?: boolean;
  /** Stop after N rows (0 = no limit). */
  limit?: number;
  /** Restrict to one project. */
  project?: string;
  /** Injected for tests; defaults to the real ONNX-backed embedder. */
  embed?: (text: string) => Promise<Float32Array>;
  /** Injected for tests. */
  db?: Database;
  onProgress?: (done: number, total: number) => void;
}

export interface EmbedBackfillResult {
  /** Rows with a NULL embedding matching the filter. */
  missing: number;
  /** Total rows matching the filter, whether embedded or not. */
  total: number;
  embedded: number;
  failed: number;
  dryRun: boolean;
}

interface PendingRow {
  id: number;
  title: string;
  content: string;
}

function readFlag(args: string[], name: string): { present: boolean; raw?: string } {
  const prefix = `${name}=`;
  const eq = args.find((a) => a.startsWith(prefix));
  if (eq) return { present: true, raw: eq.slice(prefix.length) };
  const i = args.indexOf(name);
  if (i === -1) return { present: false };
  return { present: true, raw: args[i + 1] };
}

/** Absent/`--all` → 0 (unbounded). `--limit 0` / `--limit=0` / `--limit=3` must not silently mean all. */
export function parseEmbedBackfillLimit(args: string[]): { ok: true; limit: number } | { ok: false; error: string } {
  const wantAll = args.includes('--all');
  const f = readFlag(args, '--limit');
  if (wantAll && f.present) {
    return { ok: false, error: 'embed-backfill: --all and --limit cannot be combined' };
  }
  if (wantAll) return { ok: true, limit: 0 };
  if (!f.present) return { ok: true, limit: 0 };
  if (f.raw === undefined || !/^[1-9]\d*$/.test(f.raw)) {
    return { ok: false, error: 'embed-backfill: --limit must be a positive integer (omit --limit or pass --all for unbounded)' };
  }
  return { ok: true, limit: Number(f.raw) };
}

export function parseEmbedBackfillProject(args: string[]): { ok: true; project?: string } | { ok: false; error: string } {
  const f = readFlag(args, '--project');
  if (!f.present) return { ok: true };
  if (f.raw === undefined || f.raw === '' || f.raw.startsWith('-')) {
    return { ok: false, error: 'embed-backfill: --project requires a non-empty value that is not another flag' };
  }
  return { ok: true, project: f.raw };
}

export async function backfillEmbeddings(options: EmbedBackfillOptions = {}): Promise<EmbedBackfillResult> {
  const dryRun = options.execute !== true;
  const limit = Number.isFinite(options.limit) && (options.limit as number) >= 0 ? Number(options.limit) : 0;

  let db = options.db;
  let openedOwn = false;
  if (!db) {
    const { resolveMemoriesDbPath } = await import('../database/init.js');
    const dbPath = resolveMemoriesDbPath();
    if (dryRun) {
      const Database = (await import('better-sqlite3')).default;
      db = new Database(dbPath, { readonly: true, fileMustExist: true });
      openedOwn = true;
    } else {
      const { initDatabase, getDatabase } = await import('../database/init.js');
      initDatabase(); // same resolveMemoriesDbPath() as dry-run, without marking the path "explicit"
      db = getDatabase();
      openedOwn = true;
    }
  }
  try {

  const projectClause = options.project ? 'AND project = ?' : '';
  const projectArgs = options.project ? [options.project] : [];

  const total = (db.prepare(
    `SELECT COUNT(*) AS n FROM memories WHERE 1=1 ${projectClause}`,
  ).get(...projectArgs) as { n: number }).n;

  const missing = (db.prepare(
    `SELECT COUNT(*) AS n FROM memories WHERE embedding IS NULL ${projectClause}`,
  ).get(...projectArgs) as { n: number }).n;

  if (dryRun || missing === 0) {
    return { missing, total, embedded: 0, failed: 0, dryRun };
  }

  const rows = db.prepare(
    `SELECT id, title, content FROM memories
      WHERE embedding IS NULL ${projectClause}
      ORDER BY created_at DESC
      ${limit > 0 ? 'LIMIT ?' : ''}`,
  ).all(...projectArgs, ...(limit > 0 ? [limit] : [])) as PendingRow[];

  const embed = options.embed ?? (await import('../embeddings/index.js')).generateEmbedding;
  const update = db.prepare('UPDATE memories SET embedding = ? WHERE id = ?');

  let embedded = 0;
  let failed = 0;

  for (const row of rows) {
    try {
      const vector = await embed(`${row.title} ${row.content}`);
      if (!vector || !vector.buffer) {
        failed += 1;
        continue;
      }
      update.run(Buffer.from(vector.buffer), row.id);
      embedded += 1;
    } catch {
      // One un-embeddable row must not abandon the remaining ones — a single
      // pathological memory would otherwise leave the whole store unrepaired.
      failed += 1;
    }
    options.onProgress?.(embedded + failed, rows.length);
  }

  return { missing, total, embedded, failed, dryRun };
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

export async function runEmbedBackfill(args: string[]): Promise<void> {
  const parsedLimit = parseEmbedBackfillLimit(args);
  const parsedProject = parseEmbedBackfillProject(args);
  try {
    if (!parsedLimit.ok) {
      console.error(parsedLimit.error);
      process.exitCode = 2;
      return;
    }
    if (!parsedProject.ok) {
      console.error(parsedProject.error);
      process.exitCode = 2;
      return;
    }
    const execute = args.includes('--execute');

    const result = await backfillEmbeddings({
      execute,
      limit: parsedLimit.limit,
      project: parsedProject.project,
      onProgress: (done, count) => {
        if (done % 25 === 0 || done === count) {
          process.stdout.write(`  ...${done}/${count}\n`);
        }
      },
    });

    const banner = result.dryRun ? '[DRY RUN] ' : '';
    console.log(`${banner}Backfill embeddings for memories missing a vector (#458)`);
    console.log(`  Project: ${parsedProject.project ?? '(all)'}`);
    console.log(`  Missing: ${result.missing} of ${result.total}`);
    if (result.dryRun) {
      if (result.missing > 0) console.log('  Re-run with --execute to embed them.');
      return;
    }
    console.log(`  Embedded: ${result.embedded}`);
    if (result.failed > 0) console.log(`  Failed:   ${result.failed}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`embed-backfill failed: ${msg}`);
    process.exitCode = process.exitCode || 1;
  } finally {
    try {
      const { disposeModel } = await import('../embeddings/index.js');
      await disposeModel();
    } catch {
      /* worker never started */
    }
    try {
      const { closeDatabase } = await import('../database/init.js');
      closeDatabase();
    } catch {
      /* already closed */
    }
    if (!process.env.JEST_WORKER_ID) {
      process.exit(typeof process.exitCode === 'number' ? process.exitCode : 0);
    }
  }
}
