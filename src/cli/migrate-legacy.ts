import fs from 'fs';
import path from 'path';
import os from 'os';
import { randomUUID } from 'crypto';
import Database from 'better-sqlite3';

interface LegacyMemoryRow {
  id: number;
  type: string;
  category: string;
  title: string;
  content: string;
  project: string | null;
  tags: string | null;
  salience: number | null;
  decayed_score: number | null;
  access_count: number | null;
  last_accessed: string | null;
  created_at: string | null;
  metadata: string | null;
  embedding: Buffer | null;
  scope: string | null;
  transferable: number | null;
}

interface LegacyLinkRow {
  source_id: number;
  target_id: number;
  relationship: string;
  strength: number | null;
  created_at: string | null;
}

interface MigrateOptions {
  /** Source legacy DB paths to import from. Defaults to both ~/.claude-memory/ and ~/.claude-cortex/ */
  sources?: string[];
  /** Target DB path. Default ~/.shieldcortex/memories.db */
  target?: string;
  /** If true, count + report only — no writes. */
  dryRun?: boolean;
}

interface SourceReport {
  path: string;
  exists: boolean;
  memoriesFound: number;
  memoriesImported: number;
  linksFound: number;
  linksImported: number;
  linksSkipped: number;
  error?: string;
}

interface MigrationReport {
  target: string;
  dryRun: boolean;
  sources: SourceReport[];
  totalMemories: number;
  totalLinks: number;
}

const DEFAULT_LEGACY_SOURCES = [
  path.join(os.homedir(), '.claude-cortex', 'memories.db'),
  path.join(os.homedir(), '.claude-memory', 'memories.db'),
];

const DEFAULT_TARGET = path.join(os.homedir(), '.shieldcortex', 'memories.db');

function migrateOne(
  sourcePath: string,
  target: Database.Database,
  dryRun: boolean,
): SourceReport {
  const report: SourceReport = {
    path: sourcePath,
    exists: false,
    memoriesFound: 0,
    memoriesImported: 0,
    linksFound: 0,
    linksImported: 0,
    linksSkipped: 0,
  };

  if (!fs.existsSync(sourcePath)) return report;
  report.exists = true;

  let source: Database.Database | undefined;
  try {
    source = new Database(sourcePath, { readonly: true, fileMustExist: true });
    const memories = source
      .prepare(`
        SELECT id, type, category, title, content, project, tags, salience,
               decayed_score, access_count, last_accessed, created_at,
               metadata, embedding, scope, transferable
        FROM memories
      `)
      .all() as LegacyMemoryRow[];
    const links = source
      .prepare(`
        SELECT source_id, target_id, relationship, strength, created_at
        FROM memory_links
      `)
      .all() as LegacyLinkRow[];

    report.memoriesFound = memories.length;
    report.linksFound = links.length;

    if (dryRun) return report;

    const insertMemory = target.prepare(`
      INSERT INTO memories (
        uuid, type, category, title, content, project, tags, salience,
        decayed_score, access_count, last_accessed, created_at, updated_at,
        metadata, embedding, scope, transferable, source, source_kind, capture_method
      ) VALUES (
        @uuid, @type, @category, @title, @content, @project, @tags, @salience,
        @decayed_score, @access_count, @last_accessed, @created_at, @updated_at,
        @metadata, @embedding, @scope, @transferable, @source, @source_kind, @capture_method
      )
    `);

    const insertLink = target.prepare(`
      INSERT OR IGNORE INTO memory_links (source_id, target_id, relationship, strength, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    const sourceLabel = path.basename(path.dirname(sourcePath));
    const idMap = new Map<number, number>();

    const txn = target.transaction(() => {
      for (const row of memories) {
        const result = insertMemory.run({
          uuid: randomUUID(),
          type: row.type,
          category: row.category,
          title: row.title,
          content: row.content,
          project: row.project,
          tags: row.tags ?? '[]',
          salience: row.salience ?? 0.5,
          decayed_score: row.decayed_score,
          access_count: row.access_count ?? 0,
          last_accessed: row.last_accessed,
          created_at: row.created_at,
          updated_at: row.created_at,
          metadata: row.metadata ?? '{}',
          embedding: row.embedding,
          scope: row.scope ?? 'project',
          transferable: row.transferable ?? 0,
          source: `legacy:${sourceLabel}`,
          source_kind: 'legacy-import',
          capture_method: 'legacy-migrate',
        });
        idMap.set(row.id, Number(result.lastInsertRowid));
        report.memoriesImported++;
      }

      for (const link of links) {
        const newSource = idMap.get(link.source_id);
        const newTarget = idMap.get(link.target_id);
        if (newSource === undefined || newTarget === undefined) {
          report.linksSkipped++;
          continue;
        }
        const linkResult = insertLink.run(
          newSource,
          newTarget,
          link.relationship,
          link.strength ?? 0.5,
          link.created_at,
        );
        if (linkResult.changes > 0) report.linksImported++;
        else report.linksSkipped++;
      }
    });

    txn();
  } catch (err) {
    report.error = err instanceof Error ? err.message : String(err);
  } finally {
    source?.close();
  }

  return report;
}

export function migrateLegacy(options: MigrateOptions = {}): MigrationReport {
  const sources = options.sources ?? DEFAULT_LEGACY_SOURCES;
  const targetPath = options.target ?? DEFAULT_TARGET;
  const dryRun = options.dryRun === true;

  if (!fs.existsSync(targetPath)) {
    throw new Error(`target DB does not exist: ${targetPath} (run \`shieldcortex setup\` first)`);
  }

  const target = new Database(targetPath);
  // Foreign keys on so legacy links to deleted memories fail loudly.
  target.pragma('foreign_keys = ON');
  // The dashboard API server holds an open connection in WAL mode; give the
  // SQLite locking layer plenty of room to coordinate so the migration
  // doesn't bail with SQLITE_BUSY mid-transaction.
  target.pragma('busy_timeout = 10000');

  const report: MigrationReport = {
    target: targetPath,
    dryRun,
    sources: [],
    totalMemories: 0,
    totalLinks: 0,
  };

  try {
    for (const sourcePath of sources) {
      const sourceReport = migrateOne(sourcePath, target, dryRun);
      report.sources.push(sourceReport);
      report.totalMemories += sourceReport.memoriesImported;
      report.totalLinks += sourceReport.linksImported;
    }
  } finally {
    target.close();
  }

  return report;
}

function printReport(report: MigrationReport): void {
  const banner = report.dryRun ? '[DRY RUN] ' : '';
  console.log(`${banner}Legacy memory migration → ${report.target}`);
  console.log('');
  for (const src of report.sources) {
    if (!src.exists) {
      console.log(`  ${src.path}: not found, skipped`);
      continue;
    }
    if (src.error) {
      console.log(`  ${src.path}: ERROR — ${src.error}`);
      continue;
    }
    const verb = report.dryRun ? 'would import' : 'imported';
    console.log(`  ${src.path}:`);
    console.log(`    memories: ${src.memoriesFound} found, ${verb} ${src.memoriesImported}`);
    console.log(`    links:    ${src.linksFound} found, ${verb} ${src.linksImported}, skipped ${src.linksSkipped}`);
  }
  console.log('');
  console.log(report.dryRun
    ? `Total: would import ${report.totalMemories} memories + ${report.totalLinks} links.`
    : `Total: imported ${report.totalMemories} memories + ${report.totalLinks} links.`);
  if (!report.dryRun) {
    console.log('');
    console.log('Tip: back up of the target DB was your responsibility — restore from');
    console.log('     ~/.shieldcortex/memories.db.bak.* if needed.');
  }
}

export async function handleMemoriesCommand(args: string[]): Promise<void> {
  const sub = args[0];
  if (sub === 'migrate-legacy') {
    const dryRun = args.includes('--dry-run');
    const sourceIdx = args.indexOf('--source');
    const sources = sourceIdx !== -1 && args[sourceIdx + 1]
      ? [args[sourceIdx + 1]]
      : undefined;
    const report = migrateLegacy({ sources, dryRun });
    printReport(report);
    return;
  }
  console.log('Usage: shieldcortex memories migrate-legacy [--dry-run] [--source <path>]');
  console.log('');
  console.log('Imports memories from legacy ~/.claude-memory/ and ~/.claude-cortex/');
  console.log('databases into the current ~/.shieldcortex/memories.db.');
  console.log('');
  console.log('  --dry-run        Count rows without writing.');
  console.log('  --source <path>  Override the default legacy source paths (single source).');
  process.exit(1);
}
