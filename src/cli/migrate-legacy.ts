import fs from 'fs';
import path from 'path';
import os from 'os';
import { randomUUID } from 'crypto';
import readline from 'readline';
import Database from 'better-sqlite3';
import { deriveProjectKey } from '../context/derive-project-key.js';

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

function flagValue(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1) return undefined;
  const v = args[idx + 1];
  if (!v || v.startsWith('--')) return undefined;
  return v;
}

async function runPrune(args: string[]): Promise<void> {
  const { initDatabase } = await import('../database/init.js');
  const { pruneMemories } = await import('../memory/prune.js');
  initDatabase();

  const dryRun = !args.includes('--execute');
  const salienceLte = Number(flagValue(args, '--salience-lte') ?? 0.2);
  const ageDaysGte = Number(flagValue(args, '--older-than') ?? 30);
  const project = flagValue(args, '--project');
  const includePinned = args.includes('--include-pinned');

  const result = await pruneMemories({
    salienceLte,
    ageDaysGte,
    project,
    excludePinned: !includePinned,
    dryRun,
  });

  const banner = dryRun ? '[DRY RUN] ' : '';
  console.log(`${banner}Prune memories where salience <= ${salienceLte} AND age >= ${ageDaysGte}d`);
  console.log(`  Project: ${project ?? '(all)'} · ExcludePinned: ${!includePinned}`);
  console.log(`  Matched: ${result.matched}`);
  if (result.sample.length > 0) {
    console.log('  Sample:');
    for (const s of result.sample) {
      console.log(`    #${s.id} [${s.project ?? '-'}] sal ${s.salience.toFixed(2)} · ${s.ageDays}d · ${s.title.slice(0, 60)}`);
    }
  }
  if (!dryRun) {
    console.log(`  Deleted: ${result.deleted ?? 0}`);
    if (result.backupPath) console.log(`  Backup:  ${result.backupPath}`);
  } else if (result.matched > 0) {
    console.log('  Re-run with --execute to delete.');
  }
}

async function runDedupe(args: string[]): Promise<void> {
  const { initDatabase } = await import('../database/init.js');
  const { dedupeMemories } = await import('../memory/dedupe-runner.js');
  initDatabase();

  const dryRun = !args.includes('--execute');
  const project = flagValue(args, '--project');
  const limit = Number(flagValue(args, '--limit') ?? 200);

  const result = await dedupeMemories({ project, dryRun, limit });

  const banner = dryRun ? '[DRY RUN] ' : '';
  console.log(`${banner}Dedupe long-term memories${project ? ` in project ${project}` : ' (all projects)'}`);
  console.log(`  Pairs scanned: ${result.pairsFound}`);
  console.log(`  Clusters: ${result.groups.length}`);
  const totalRemovable = result.groups.reduce((sum, g) => sum + g.removeIds.length, 0);
  console.log(`  Removable: ${totalRemovable}`);
  if (result.groups.length > 0) {
    console.log('  Groups:');
    for (const g of result.groups.slice(0, 10)) {
      console.log(`    keep #${g.keepId} [${g.removeIds.length} dup] ${g.similarity} — "${g.keepTitle.slice(0, 50)}"`);
    }
    if (result.groups.length > 10) console.log(`    … and ${result.groups.length - 10} more`);
  }
  if (!dryRun) {
    console.log(`  Merged: ${result.merged ?? 0}`);
    if (result.backupPath) console.log(`  Backup: ${result.backupPath}`);
  } else if (totalRemovable > 0) {
    console.log('  Re-run with --execute to merge.');
  }
}

function printUsage(): void {
  console.log('Usage: shieldcortex memories <subcommand> [options]');
  console.log('');
  console.log('Subcommands:');
  console.log('  migrate-legacy [--dry-run] [--source <path>]');
  console.log('      Import memories from ~/.claude-memory/ and ~/.claude-cortex/');
  console.log('      into the current ~/.shieldcortex/memories.db.');
  console.log('');
  console.log('  prune [--salience-lte 0.2] [--older-than 30] [--project X]');
  console.log('        [--include-pinned] [--execute]');
  console.log('      Delete memories below salience X older than N days.');
  console.log('      DRY-RUN BY DEFAULT — pass --execute to actually delete.');
  console.log('      Backup auto-saved before any delete.');
  console.log('');
  console.log('  dedupe [--project X] [--limit 200] [--execute]');
  console.log('      Cluster near-duplicate long-term memories and keep the highest-');
  console.log('      salience representative. DRY-RUN BY DEFAULT — pass --execute.');
  console.log('      Backup auto-saved before any merge.');
  console.log('');
  console.log('  repair-project-keys [--scan-paths <dir,dir,...>]');
  console.log('                      [--map basename=canonical]   (repeatable)');
  console.log('                      [--project <key>] [--include-stm] [--execute]');
  console.log('      Relabel memories tagged under a legacy basename project key');
  console.log('      to their canonical owner-repo key (#42). DRY-RUN BY DEFAULT.');
  console.log('      Backup auto-saved before any rewrite; per-rewrite log written');
  console.log('      to ~/.shieldcortex/logs/project-key-repair-<ts>.json.');
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
  if (sub === 'prune') {
    await runPrune(args.slice(1));
    return;
  }
  if (sub === 'dedupe') {
    await runDedupe(args.slice(1));
    return;
  }
  if (sub === 'repair-project-keys') {
    await runRepairProjectKeys(args.slice(1));
    return;
  }
  printUsage();
  process.exit(1);
}

// ============================================================
// repair-project-keys (#42 data recovery)
// ============================================================

interface RepairOptions {
  /** Path to memories.db (defaults to ~/.shieldcortex/memories.db) */
  dbPath?: string;
  /** Walk these dev roots one level deep, propose mappings unambiguously */
  scanPaths?: string[];
  /** Explicit overrides; basename → canonical-key */
  map?: Record<string, string>;
  /** Limit the scan to a single legacy project key */
  onlyProject?: string;
  /** Include short-term rows (default: long-term + episodic only) */
  includeStm?: boolean;
  /** Default false — must be true to actually write */
  execute?: boolean;
  /** When true, never prompt (used by tests). Defaults to interactive. */
  noConfirm?: boolean;
}

interface RepairProposal {
  legacy: string;
  canonical: string;
  count: number;
  source: 'map' | 'scan';
}

interface RepairReport {
  dryRun: boolean;
  proposals: RepairProposal[];
  applied: number;
  logPath?: string;
  backupPath?: string;
}

function parseMapFlags(args: string[]): Record<string, string> {
  const map: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--map' && args[i + 1]) {
      const pair = args[i + 1];
      const eq = pair.indexOf('=');
      if (eq <= 0 || eq === pair.length - 1) {
        throw new Error(`--map expects 'basename=canonical', got '${pair}'`);
      }
      const k = pair.slice(0, eq).trim();
      const v = pair.slice(eq + 1).trim();
      if (!k || !v) throw new Error(`--map basename and canonical must be non-empty: '${pair}'`);
      map[k] = v;
      i++;
    }
  }
  return map;
}

function parseScanPaths(args: string[]): string[] {
  const v = flagValue(args, '--scan-paths');
  if (!v) return [];
  return v
    .split(',')
    .map((s) => s.trim().replace(/^~(?=\/|$)/, os.homedir()))
    .filter(Boolean);
}

async function confirmExecute(prompt: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await new Promise<string>((resolve) => rl.question(prompt, resolve));
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

export async function repairProjectKeys(opts: RepairOptions = {}): Promise<RepairReport> {
  const dbPath = opts.dbPath ?? DEFAULT_TARGET;
  if (!fs.existsSync(dbPath)) {
    throw new Error(`memories DB not found at ${dbPath} — run \`shieldcortex setup\` first`);
  }

  const explicit = opts.map ?? {};
  const scanPaths = opts.scanPaths ?? [];
  const includeStm = opts.includeStm === true;
  const dryRun = opts.execute !== true;

  const db = new Database(dbPath);
  db.pragma('busy_timeout = 10000');

  let report: RepairReport;
  try {
    // 1. Distinct legacy project keys in the DB.
    const typeFilter = includeStm ? '' : "AND type IN ('long_term', 'episodic')";
    const distinct = db
      .prepare(`SELECT DISTINCT project FROM memories WHERE project IS NOT NULL ${typeFilter}`)
      .all() as Array<{ project: string }>;
    const dbProjects = new Set(distinct.map((r) => r.project));

    // 2. Build the proposal set.
    const proposals: RepairProposal[] = [];
    const seen = new Set<string>();

    const addProposal = (legacy: string, canonical: string, source: RepairProposal['source']) => {
      if (legacy === canonical) return;
      if (opts.onlyProject && legacy !== opts.onlyProject) return;
      if (!dbProjects.has(legacy)) return;
      const key = `${legacy} ${canonical}`;
      if (seen.has(key)) return;
      seen.add(key);
      const countQ = db
        .prepare(`SELECT COUNT(*) AS n FROM memories WHERE project = ? ${typeFilter}`)
        .get(legacy) as { n: number };
      proposals.push({ legacy, canonical, count: countQ.n, source });
    };

    // 2a. --map overrides win.
    for (const [legacy, canonical] of Object.entries(explicit)) {
      addProposal(legacy, canonical, 'map');
    }

    // 2b. --scan-paths: walk one level deep, run deriveProjectKey, match by basename.
    for (const root of scanPaths) {
      let entries: string[] = [];
      try {
        entries = fs.readdirSync(root);
      } catch {
        continue;
      }
      for (const name of entries) {
        const child = path.join(root, name);
        let isDir = false;
        try {
          isDir = fs.statSync(child).isDirectory();
        } catch {
          continue;
        }
        if (!isDir) continue;
        const canonical = deriveProjectKey(child);
        if (!canonical || canonical === name) continue;
        addProposal(name, canonical, 'scan');
      }
    }

    report = {
      dryRun,
      proposals,
      applied: 0,
    };

    // 3. Print proposal table.
    const banner = dryRun ? '[DRY RUN] ' : '';
    console.log(`${banner}Project-key repair plan (${dbPath}):`);
    if (proposals.length === 0) {
      console.log('  No proposed rewrites — nothing to do.');
      console.log('');
      console.log('Tip: pass `--scan-paths ~/Development` (or `--map old=new`) so the');
      console.log('     repair tool can match legacy basename keys against canonical');
      console.log('     owner-repo keys derived from the git origin.');
      return report;
    }
    for (const p of proposals) {
      console.log(`  ${p.legacy.padEnd(40)} → ${p.canonical.padEnd(48)} (${p.count} rows, source: ${p.source})`);
    }
    const totalRows = proposals.reduce((s, p) => s + p.count, 0);
    console.log('');
    console.log(`Total: ${totalRows} rows across ${proposals.length} project key(s).`);

    if (dryRun) {
      console.log('');
      console.log('Re-run with --execute to apply. To undo later:');
      console.log('  shieldcortex memories repair-project-keys \\');
      console.log('    ' + proposals.map((p) => `--map ${p.canonical}=${p.legacy}`).join(' \\\n    ') + ' --execute');
      return report;
    }

    // 4. Confirm + backup + write.
    if (!opts.noConfirm) {
      const ok = await confirmExecute(`\nApply ${proposals.length} rewrite(s) to ${totalRows} rows? [y/N] `);
      if (!ok) {
        console.log('Aborted — no changes written.');
        return report;
      }
    }

    const backupPath = `${dbPath}.bak.${new Date().toISOString().replace(/[:.]/g, '-')}`;
    fs.copyFileSync(dbPath, backupPath);
    report.backupPath = backupPath;
    console.log(`Backup: ${backupPath}`);

    const update = db.prepare(
      `UPDATE memories SET project = ? WHERE project = ? ${typeFilter}`
    );
    const txn = db.transaction(() => {
      for (const p of proposals) {
        const r = update.run(p.canonical, p.legacy);
        report.applied += r.changes;
      }
    });
    txn();

    // 5. Per-rewrite JSON log under ~/.shieldcortex/logs/.
    const logsDir = path.join(os.homedir(), '.shieldcortex', 'logs');
    fs.mkdirSync(logsDir, { recursive: true });
    const logPath = path.join(
      logsDir,
      `project-key-repair-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    );
    fs.writeFileSync(
      logPath,
      JSON.stringify(
        {
          dbPath,
          backupPath,
          appliedAt: new Date().toISOString(),
          rewrites: proposals,
          totalRowsAffected: report.applied,
        },
        null,
        2
      ),
      'utf-8'
    );
    report.logPath = logPath;
    console.log(`Applied: ${report.applied} rows`);
    console.log(`Log:     ${logPath}`);
  } finally {
    db.close();
  }

  return report;
}

async function runRepairProjectKeys(args: string[]): Promise<void> {
  const map = parseMapFlags(args);
  const scanPaths = parseScanPaths(args);
  const onlyProject = flagValue(args, '--project');
  const includeStm = args.includes('--include-stm');
  const execute = args.includes('--execute');
  await repairProjectKeys({ map, scanPaths, onlyProject, includeStm, execute });
}
