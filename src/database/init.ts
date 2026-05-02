/**
 * Database initialization and connection management
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync, unlinkSync, renameSync, copyFileSync, readdirSync, openSync, closeSync, realpathSync } from 'fs';
import { basename, dirname, join } from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import { randomUUID } from 'crypto';

const _currentFile = fileURLToPath(import.meta.url);
const _currentDir = dirname(_currentFile);

let db: Database.Database | null = null;
let currentDbPath: string | null = null;
let lockFilePath: string | null = null;
let lockFileFd: number | null = null;
let dbInode: bigint | null = null; // Track file identity for staleness detection

// Anti-bloat: Database size limits
const MAX_DB_SIZE = 100 * 1024 * 1024; // 100MB hard limit
const WARN_DB_SIZE = 50 * 1024 * 1024; // 50MB warning threshold

/**
 * Expand ~ to home directory
 */
function expandPath(path: string): string {
  if (path.startsWith('~')) {
    return join(homedir(), path.slice(1));
  }
  return path;
}

/**
 * Get the database path with legacy fallback
 * - New installs use ~/.shieldcortex/
 * - Existing users with ~/.claude-memory/ continue to work
 */
function getDefaultDbPath(): string {
  const newPath = join(homedir(), '.shieldcortex', 'memories.db');
  const legacyPath = join(homedir(), '.claude-memory', 'memories.db');

  // Prefer new path if it exists, or if neither exists (new install)
  if (existsSync(newPath) || !existsSync(legacyPath)) {
    return newPath;
  }
  // Fall back to legacy path for existing users
  return legacyPath;
}

type RuntimeKind = 'installed' | 'npx-cache' | 'project-checkout' | 'unknown';

interface RuntimeInfo {
  kind: RuntimeKind;
  entryPath: string;
}

interface DatabaseInspection {
  integrity: string;
  count: number | null;
}

interface BackupCandidate {
  path: string;
  count: number;
  mtimeMs: number;
}

function resolveRuntimeInfo(): RuntimeInfo {
  let entryPath = process.argv[1] ?? '';
  try {
    if (entryPath) {
      entryPath = realpathSync(entryPath);
    }
  } catch {
    // Fall back to the raw argv path.
  }

  if (entryPath.includes('/.npm/_npx/')) {
    return { kind: 'npx-cache', entryPath };
  }
  if (entryPath.includes('/node_modules/shieldcortex/')) {
    return { kind: 'installed', entryPath };
  }
  if (entryPath.includes('/ShieldCortex/') || entryPath.includes('\\ShieldCortex\\')) {
    return { kind: 'project-checkout', entryPath };
  }
  return { kind: 'unknown', entryPath };
}

function enforceSafeRuntimePath(expandedPath: string, explicitDbPath: boolean): void {
  if (explicitDbPath || process.env.SHIELDCORTEX_ALLOW_UNSAFE_RUNTIME === '1') {
    return;
  }

  const defaultPath = expandPath(getDefaultDbPath());
  if (expandedPath !== defaultPath) {
    return;
  }

  const runtime = resolveRuntimeInfo();
  if (runtime.kind === 'npx-cache' || runtime.kind === 'project-checkout') {
    throw new Error(
      `[database] Refusing to open ${defaultPath} from ${runtime.kind === 'npx-cache' ? 'an npx cache' : 'a project checkout'}.\n` +
      `Use the installed CLI (\`shieldcortex\`), pass \`--db\` to use a separate database, or set SHIELDCORTEX_ALLOW_UNSAFE_RUNTIME=1 if you really mean to do this.\n` +
      `Runtime path: ${runtime.entryPath}`
    );
  }
}

function inspectDatabaseFile(dbPath: string): DatabaseInspection {
  let inspectionDb: Database.Database | null = null;
  try {
    inspectionDb = new Database(dbPath, {
      readonly: true,
      fileMustExist: true,
    });
    const integrity = runIntegrityCheck(inspectionDb);
    let count: number | null = null;
    try {
      count = (inspectionDb.prepare('SELECT COUNT(*) AS count FROM memories').get() as { count: number }).count;
    } catch {
      count = null;
    }
    return { integrity, count };
  } catch (error) {
    return { integrity: `inspect threw: ${error}`, count: null };
  } finally {
    try {
      inspectionDb?.close();
    } catch {
      // Best-effort close.
    }
  }
}

function listHealthyBackups(dbPath: string): BackupCandidate[] {
  const dir = dirname(dbPath);
  const prefix = `${basename(dbPath)}.corrupt.`;

  return readdirSync(dir)
    .filter((name) => name.startsWith(prefix) && !name.endsWith('-wal') && !name.endsWith('-shm'))
    .map((name) => join(dir, name))
    .map((backupPath) => {
      const inspection = inspectDatabaseFile(backupPath);
      const stats = statSync(backupPath);
      return {
        path: backupPath,
        integrity: inspection.integrity,
        count: inspection.count,
        mtimeMs: stats.mtimeMs,
      };
    })
    .filter((candidate): candidate is BackupCandidate & { integrity: string } => candidate.integrity === 'ok' && typeof candidate.count === 'number' && candidate.count > 0)
    .sort((a, b) => b.mtimeMs - a.mtimeMs)
    .map(({ path, count, mtimeMs }) => ({ path, count, mtimeMs }));
}

function stashLiveDatabase(dbPath: string, suffix: string): void {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const stashPath = `${dbPath}.${suffix}.${timestamp}`;

  if (existsSync(dbPath)) {
    try {
      renameSync(dbPath, stashPath);
    } catch {
      try {
        copyFileSync(dbPath, stashPath);
        unlinkSync(dbPath);
      } catch {
        // Last resort: leave the original in place.
      }
    }
  }

  for (const ext of ['-wal', '-shm']) {
    const liveSidecar = dbPath + ext;
    if (existsSync(liveSidecar)) {
      try {
        renameSync(liveSidecar, stashPath + ext);
      } catch {
        try {
          unlinkSync(liveSidecar);
        } catch {
          // Best-effort cleanup.
        }
      }
    }
  }
}

function restoreBackupAsLive(dbPath: string, backupPath: string, reason: string): void {
  stashLiveDatabase(dbPath, reason);
  copyFileSync(backupPath, dbPath);
}

function acquireStartupLock(dbPath: string): void {
  lockFilePath = `${dbPath}.lock`;
  const runtime = resolveRuntimeInfo();
  const payload = JSON.stringify({
    pid: process.pid,
    startedAt: new Date().toISOString(),
    entryPath: runtime.entryPath,
  }, null, 2);

  const tryOpen = () => {
    lockFileFd = openSync(lockFilePath as string, 'wx');
    writeFileSync(lockFileFd, payload, 'utf-8');
  };

  try {
    tryOpen();
    return;
  } catch {
    let activeProcessError: Error | null = null;
    let existingPid: number | null = null;
    try {
      const existing = JSON.parse(readFileSync(lockFilePath as string, 'utf-8')) as { pid?: number; entryPath?: string };
      if (typeof existing.pid === 'number') {
        existingPid = existing.pid;
        try {
          process.kill(existing.pid, 0);
          activeProcessError = new Error(
            `[database] Refusing startup because ShieldCortex PID ${existing.pid} is already using ${dbPath}` +
            (existing.entryPath ? ` (${existing.entryPath})` : '')
          );
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ESRCH') {
            activeProcessError = error as Error;
          }
        }
      }
    } catch {
      // Stale or unreadable lock file — remove and retry.
    }

    if (activeProcessError) {
      console.error(
        `[database] Another ShieldCortex process (PID ${existingPid ?? 'unknown'}) is using ${dbPath} — ` +
        `continuing anyway (SQLite WAL handles concurrency)`
      );
      lockFilePath = null;
      lockFileFd = null;
      return;
    }

    try {
      unlinkSync(lockFilePath as string);
    } catch {
      // Best-effort stale lock cleanup.
    }

    tryOpen();
  }
}

/**
 * Back up a corrupt database file with a timestamped name.
 * Returns the backup path.
 */
function backupCorruptDatabase(dbPath: string): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupPath = `${dbPath}.corrupt.${timestamp}`;
  try {
    renameSync(dbPath, backupPath);
  } catch {
    // If rename fails (e.g. cross-device), try copy + delete
    try {
      copyFileSync(dbPath, backupPath);
      unlinkSync(dbPath);
    } catch {
      // Last resort — just note the backup path
    }
  }
  // Also back up WAL and SHM files if present
  for (const suffix of ['-wal', '-shm']) {
    const walPath = dbPath + suffix;
    if (existsSync(walPath)) {
      try {
        renameSync(walPath, backupPath + suffix);
      } catch { /* best-effort */ }
    }
  }
  return backupPath;
}

/**
 * Attempt to recover a corrupt database by dumping and reimporting.
 * Returns a new Database instance on success, or null on failure.
 */
function attemptDumpRecovery(dbPath: string): Database.Database | null {
  try {
    // Use sqlite3 CLI to dump — it can often recover partial data
    const dumpOutput = execSync(`sqlite3 "${dbPath}" .dump`, {
      encoding: 'utf-8',
      timeout: 30000,
      maxBuffer: 100 * 1024 * 1024,
    });

    if (!dumpOutput || dumpOutput.trim().length === 0) return null;

    // Back up the corrupt file
    const backupPath = backupCorruptDatabase(dbPath);
    console.error(`[database] Backed up corrupt database to: ${backupPath}`);

    // Create fresh database and import the dump
    const freshDb = new Database(dbPath);
    try {
      freshDb.exec(dumpOutput);
      console.error('[database] Successfully recovered data via dump/reimport.');
      return freshDb;
    } catch {
      // Dump reimport failed — close and let caller handle fresh creation
      freshDb.close();
      if (existsSync(dbPath)) {
        try { unlinkSync(dbPath); } catch { /* best-effort */ }
      }
      return null;
    }
  } catch {
    // sqlite3 CLI not available or dump failed
    return null;
  }
}

/**
 * Remove .corrupt.* and .recovery-failed.* backup files older than 7 days.
 * Runs once at startup after successful init — prevents unbounded accumulation.
 */
function cleanupStaleBackups(dbPath: string): void {
  const dir = dirname(dbPath);
  const base = basename(dbPath);
  const maxAge = 7 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  try {
    for (const name of readdirSync(dir)) {
      if (!name.startsWith(base + '.corrupt.') && !name.startsWith(base + '.recovery-failed.')) continue;
      const filePath = join(dir, name);
      try {
        const age = now - statSync(filePath).mtimeMs;
        if (age > maxAge) {
          unlinkSync(filePath);
        }
      } catch {
        // Best-effort — file may have been removed by another process
      }
    }
  } catch {
    // Non-fatal — dir listing failure shouldn't block startup
  }
}

/**
 * Run integrity check on an open database.
 * Returns 'ok' if healthy, or the error message if corrupt.
 */
function runIntegrityCheck(database: Database.Database): string {
  try {
    // Quick check first (checks first page only)
    const quickResult = database.pragma('integrity_check(1)') as { integrity_check: string }[];
    const quickStatus = quickResult?.[0]?.integrity_check || 'ok';
    if (quickStatus !== 'ok') {
      return quickStatus;
    }

    // Full check
    const fullResult = database.pragma('integrity_check') as { integrity_check: string }[];
    return fullResult?.[0]?.integrity_check || 'ok';
  } catch (e) {
    return `integrity check threw: ${e}`;
  }
}

function isLikelyFtsIntegrityIssue(integrityResult: string): boolean {
  const normalized = integrityResult.toLowerCase();
  return (
    normalized.includes('memories_fts') ||
    normalized.includes('fts5') ||
    normalized.includes('inverted index') ||
    normalized.includes('fts')
  );
}

function attemptFtsRecovery(database: Database.Database): boolean {
  try {
    const ftsTable = database.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='memories_fts'"
    ).get() as { name?: string } | undefined;

    if (!ftsTable?.name) {
      return false;
    }

    // Ensure the primary memories table is still readable before attempting
    // an FTS-only recovery path.
    database.prepare('SELECT id FROM memories LIMIT 1').all();

    database.exec(`INSERT INTO memories_fts(memories_fts) VALUES('rebuild')`);

    const postRepairIntegrity = runIntegrityCheck(database);
    if (postRepairIntegrity === 'ok') {
      console.error('[database] Successfully rebuilt memories_fts after integrity failure.');
      return true;
    }

    console.warn(`[database] FTS rebuild did not fully repair integrity: ${postRepairIntegrity}`);
    return false;
  } catch (error) {
    console.warn(`[database] FTS rebuild failed: ${error}`);
    return false;
  }
}

function verifyOnDiskIntegrity(dbPath: string): string {
  return inspectDatabaseFile(dbPath).integrity;
}

export const __databaseTestUtils = {
  isLikelyFtsIntegrityIssue,
  attemptFtsRecovery,
  verifyOnDiskIntegrity,
  inspectDatabaseFile,
  listHealthyBackups,
  resolveRuntimeInfo,
  enforceSafeRuntimePath,
  acquireStartupLock,
};

/**
 * Initialize the database connection
 */
export function initDatabase(dbPath?: string): Database.Database {
  // Use auto-detected path if not specified
  const resolvedPath = dbPath || getDefaultDbPath();
  const explicitDbPath = Boolean(dbPath);
  if (db) {
    return db;
  }

  const expandedPath = expandPath(resolvedPath);
  enforceSafeRuntimePath(expandedPath, explicitDbPath);
  const dir = dirname(expandedPath);

  // Create directory if it doesn't exist
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  // Store path for size monitoring
  currentDbPath = expandedPath;
  acquireStartupLock(expandedPath);

  console.error(`[database] Startup runtime=${resolveRuntimeInfo().kind} db=${expandedPath} wal=${existsSync(expandedPath + '-wal')} shm=${existsSync(expandedPath + '-shm')}`);

  const healthyBackups = listHealthyBackups(expandedPath);

  // Wrap the initial open in try/catch to handle corrupt files gracefully
  let database: Database.Database;
  try {
    database = new Database(expandedPath);
  } catch (openError) {
    // Database file is corrupt or not a valid SQLite database
    console.error(`❌ Database open failed for ${expandedPath}: ${openError}`);

    const latestHealthyBackup = healthyBackups[0];
    if (latestHealthyBackup) {
      console.error(`[database] Restoring latest healthy backup with ${latestHealthyBackup.count} memories: ${latestHealthyBackup.path}`);
      restoreBackupAsLive(expandedPath, latestHealthyBackup.path, 'failed-open');
      database = new Database(expandedPath);
    } else {
      const backupPath = backupCorruptDatabase(expandedPath);
      console.error(`   Backed up to ${backupPath}`);
      console.error('   Creating fresh database...');
      database = new Database(expandedPath);
    }
  }

  // Integrity check on existing databases (skip for newly created files)
  if (existsSync(expandedPath) && statSync(expandedPath).size > 0) {
    const integrityResult = runIntegrityCheck(database);
    if (integrityResult !== 'ok') {
      console.warn(`[database] WARNING: Database integrity check failed: ${integrityResult}`);

      if (isLikelyFtsIntegrityIssue(integrityResult) && attemptFtsRecovery(database)) {
        console.warn('[database] Preserved memory rows by repairing the FTS index in place.');
      } else {
        const freshIntegrityResult = verifyOnDiskIntegrity(expandedPath);
        if (freshIntegrityResult === 'ok') {
          console.warn('[database] Integrity failure was transient. Reopening the on-disk database without destructive recovery.');
          database.close();
          database = new Database(expandedPath);
        } else {
          console.warn(`[database] Fresh integrity check also failed: ${freshIntegrityResult}`);

          // Close the corrupt connection before attempting recovery
          database.close();

          // Attempt dump/reimport recovery
          const recovered = attemptDumpRecovery(expandedPath);
          if (recovered) {
            database = recovered;
          } else {
            const latestHealthyBackup = healthyBackups[0];
            if (latestHealthyBackup) {
              console.error(`[database] Recovery failed. Restoring latest healthy backup with ${latestHealthyBackup.count} memories: ${latestHealthyBackup.path}`);
              restoreBackupAsLive(expandedPath, latestHealthyBackup.path, 'recovery-failed');
              database = new Database(expandedPath);
            } else {
              // Recovery failed — backup and create fresh
              if (existsSync(expandedPath)) {
                const backupPath = backupCorruptDatabase(expandedPath);
                console.error(`[database] Recovery failed. Backed up corrupt file to: ${backupPath}`);
              }
              console.error('[database] Creating fresh database...');
              database = new Database(expandedPath);
            }
          }
        }
      }
    }
  }

  const currentInspection = inspectDatabaseFile(expandedPath);
  const latestHealthyBackup = healthyBackups[0];
  const liveStats = existsSync(expandedPath) ? statSync(expandedPath) : null;
  if (
    currentInspection.integrity === 'ok'
    && currentInspection.count === 0
    && latestHealthyBackup
    && latestHealthyBackup.count >= 100
    && liveStats
    && (liveStats.mtimeMs - latestHealthyBackup.mtimeMs) < (24 * 60 * 60 * 1000)
  ) {
    console.error(`[database] Empty live database detected alongside a recent healthy backup (${latestHealthyBackup.count} memories). Restoring ${latestHealthyBackup.path}`);
    database.close();
    restoreBackupAsLive(expandedPath, latestHealthyBackup.path, 'empty-live');
    database = new Database(expandedPath);
  }

  db = database;

  // Record file identity so getDatabase() can detect if the file was replaced
  try {
    dbInode = statSync(expandedPath, { bigint: true }).ino;
  } catch {
    dbInode = null;
  }

  // Clean up old corrupt/recovery backups (older than 7 days)
  cleanupStaleBackups(expandedPath);

  // Enable WAL mode for better concurrency
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  // Race condition mitigation: wait up to 10 seconds for locks
  db.pragma('busy_timeout = 10000');
  // Auto-checkpoint every 100 pages (~400KB) to prevent WAL bloat
  db.pragma('wal_autocheckpoint = 100');

  // Register cleanup handlers for graceful shutdown
  registerShutdownHandlers();

  // Run migrations FIRST for existing databases
  // This ensures columns exist before schema tries to create indexes on them
  runMigrations(db);

  // Run schema (uses IF NOT EXISTS, safe for existing tables and indexes)
  const schemaPath = join(_currentDir, 'schema.sql');
  if (existsSync(schemaPath)) {
    const schema = readFileSync(schemaPath, 'utf-8');
    db.exec(schema);
  } else {
    // Inline schema if file not found (for bundled deployment)
    db.exec(getInlineSchema());
  }

  return db;
}

/**
 * Run database migrations for existing databases
 */
function runMigrations(database: Database.Database): void {
  // Check if memories table exists (skip migrations on fresh database)
  const tableExists = database.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='memories'"
  ).get();

  if (!tableExists) {
    // Fresh database - schema will create everything
    return;
  }

  // Check existing columns
  const tableInfo = database.prepare("PRAGMA table_info(memories)").all() as { name: string }[];
  const columnNames = new Set(tableInfo.map(col => col.name));

  // Migration: decayed_score column
  if (!columnNames.has('decayed_score')) {
    database.exec('ALTER TABLE memories ADD COLUMN decayed_score REAL');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_decayed_score ON memories(decayed_score DESC)');
  }

  // Migration: embedding column for semantic search
  if (!columnNames.has('embedding')) {
    database.exec('ALTER TABLE memories ADD COLUMN embedding BLOB');
  }

  // Migration: scope column for cross-project knowledge
  if (!columnNames.has('scope')) {
    database.exec("ALTER TABLE memories ADD COLUMN scope TEXT DEFAULT 'project'");
  }

  // Migration: transferable column for cross-project sharing
  if (!columnNames.has('transferable')) {
    database.exec('ALTER TABLE memories ADD COLUMN transferable INTEGER DEFAULT 0');
  }

  // Migration: Defence columns on memories table
  if (!columnNames.has('trust_score')) {
    database.exec("ALTER TABLE memories ADD COLUMN trust_score REAL DEFAULT 1.0");
  }
  if (!columnNames.has('sensitivity_level')) {
    database.exec("ALTER TABLE memories ADD COLUMN sensitivity_level TEXT DEFAULT 'INTERNAL'");
  }
  if (!columnNames.has('source')) {
    database.exec("ALTER TABLE memories ADD COLUMN source TEXT DEFAULT 'user:direct'");
  }
  if (!columnNames.has('status')) {
    database.exec("ALTER TABLE memories ADD COLUMN status TEXT DEFAULT 'active'");
  }
  if (!columnNames.has('pinned')) {
    database.exec('ALTER TABLE memories ADD COLUMN pinned INTEGER DEFAULT 0');
  }
  if (!columnNames.has('reviewed_at')) {
    database.exec('ALTER TABLE memories ADD COLUMN reviewed_at TIMESTAMP');
  }
  if (!columnNames.has('reviewed_by')) {
    database.exec('ALTER TABLE memories ADD COLUMN reviewed_by TEXT');
  }
  if (!columnNames.has('source_kind')) {
    database.exec("ALTER TABLE memories ADD COLUMN source_kind TEXT DEFAULT 'user'");
  }
  if (!columnNames.has('capture_method')) {
    database.exec("ALTER TABLE memories ADD COLUMN capture_method TEXT DEFAULT 'manual'");
  }
  if (!columnNames.has('cloud_excluded')) {
    database.exec('ALTER TABLE memories ADD COLUMN cloud_excluded INTEGER DEFAULT 0');
  }
  if (!columnNames.has('uuid')) {
    database.exec("ALTER TABLE memories ADD COLUMN uuid TEXT");
  }
  if (!columnNames.has('updated_at')) {
    database.exec('ALTER TABLE memories ADD COLUMN updated_at TIMESTAMP');
  }
  try {
    const rowsWithoutUuid = database.prepare('SELECT id FROM memories WHERE uuid IS NULL OR uuid = ?').all('') as { id: number }[];
    const setUuid = database.prepare('UPDATE memories SET uuid = ? WHERE id = ?');
    for (const row of rowsWithoutUuid) {
      setUuid.run(randomUUID(), row.id);
    }
    database.exec('UPDATE memories SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL');
    database.exec("UPDATE memories SET status = COALESCE(status, 'active') WHERE status IS NULL OR status = ''");
    database.exec('UPDATE memories SET pinned = COALESCE(pinned, 0) WHERE pinned IS NULL');
    database.exec(`
      UPDATE memories
      SET source = CASE
        WHEN source = 'user:direct' AND tags LIKE '%session-end%' THEN 'hook:openclaw-session-end'
        WHEN source = 'user:direct' AND tags LIKE '%session-stop%' THEN 'hook:openclaw-session-stop'
        WHEN source = 'user:direct' AND tags LIKE '%keyword-trigger%' THEN 'hook:openclaw-keyword'
        WHEN source IS NULL AND tags LIKE '%llm-output%' THEN 'agent:openclaw-plugin'
        ELSE source
      END
      WHERE
        (source = 'user:direct' OR source IS NULL)
        AND (
          tags LIKE '%session-end%'
          OR tags LIKE '%session-stop%'
          OR tags LIKE '%keyword-trigger%'
          OR tags LIKE '%llm-output%'
          OR tags LIKE '%realtime-plugin%'
          OR tags LIKE '%openclaw-hook%'
        )
    `);
    database.exec("UPDATE memories SET source_kind = CASE WHEN source LIKE 'hook:%' THEN 'hook' WHEN source LIKE 'api:%' THEN 'api' WHEN source LIKE 'agent:%' THEN 'agent' WHEN source LIKE 'cli:%' THEN 'cli' ELSE COALESCE(source_kind, 'user') END WHERE source_kind IS NULL OR source_kind = ''");
    database.exec("UPDATE memories SET capture_method = CASE WHEN tags LIKE '%auto-extracted%' THEN 'auto' WHEN source_kind = 'hook' THEN 'hook' WHEN source_kind = 'api' THEN 'api' WHEN source_kind = 'agent' THEN 'plugin' WHEN source_kind = 'cli' THEN 'manual' ELSE COALESCE(capture_method, 'manual') END WHERE capture_method IS NULL OR capture_method = ''");
    database.exec(`
      UPDATE memories
      SET source_kind = CASE
        WHEN tags LIKE '%session-end%' OR tags LIKE '%session-stop%' OR tags LIKE '%keyword-trigger%' OR tags LIKE '%openclaw-hook%' THEN 'hook'
        WHEN tags LIKE '%llm-output%' OR tags LIKE '%realtime-plugin%' THEN 'agent'
        ELSE source_kind
      END,
      capture_method = CASE
        WHEN tags LIKE '%session-end%' OR tags LIKE '%session-stop%' OR tags LIKE '%openclaw-hook%' THEN 'auto'
        WHEN tags LIKE '%keyword-trigger%' THEN 'hook'
        WHEN tags LIKE '%llm-output%' OR tags LIKE '%realtime-plugin%' THEN 'auto'
        ELSE capture_method
      END
      WHERE
        tags LIKE '%session-end%'
        OR tags LIKE '%session-stop%'
        OR tags LIKE '%keyword-trigger%'
        OR tags LIKE '%openclaw-hook%'
        OR tags LIKE '%llm-output%'
        OR tags LIKE '%realtime-plugin%'
    `);
    database.exec('UPDATE memories SET cloud_excluded = COALESCE(cloud_excluded, 0) WHERE cloud_excluded IS NULL');
    database.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_uuid ON memories(uuid)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(updated_at DESC)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_status ON memories(status)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_pinned ON memories(pinned DESC)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_source_kind ON memories(source_kind)');
  } catch {
    // Safe to ignore on partially migrated databases
  }

  // Migration: Defence tables (defence_audit, quarantine, fragmentation_entities)
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS defence_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id INTEGER,
        project TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_type TEXT NOT NULL,
        source_identifier TEXT NOT NULL,
        trust_score REAL NOT NULL,
        sensitivity_level TEXT NOT NULL DEFAULT 'INTERNAL',
        firewall_result TEXT NOT NULL CHECK(firewall_result IN ('ALLOW', 'BLOCK', 'QUARANTINE')),
        anomaly_score REAL DEFAULT 0.0,
        threat_indicators TEXT DEFAULT '[]',
        blocked_patterns TEXT DEFAULT '[]',
        reason TEXT,
        fragmentation_score REAL,
        pipeline_duration_ms INTEGER,
        FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_memory ON defence_audit(memory_id);
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON defence_audit(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_result ON defence_audit(firewall_result);
      CREATE INDEX IF NOT EXISTS idx_audit_source ON defence_audit(source_type);
      CREATE INDEX IF NOT EXISTS idx_audit_project ON defence_audit(project);

      CREATE TABLE IF NOT EXISTS quarantine (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_content TEXT NOT NULL,
        original_title TEXT,
        project TEXT,
        source_type TEXT NOT NULL,
        source_identifier TEXT NOT NULL,
        reason TEXT NOT NULL,
        threat_indicators TEXT DEFAULT '[]',
        anomaly_score REAL DEFAULT 0.0,
        firewall_result TEXT NOT NULL CHECK(firewall_result IN ('BLOCK', 'QUARANTINE')),
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'expired')),
        reviewed_at TIMESTAMP,
        reviewed_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        audit_id INTEGER,
        FOREIGN KEY (audit_id) REFERENCES defence_audit(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
      CREATE INDEX IF NOT EXISTS idx_quarantine_created ON quarantine(created_at DESC);

      CREATE TABLE IF NOT EXISTS quarantine_annotations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        suggested_action TEXT NOT NULL,
        confidence REAL NOT NULL,
        similar_group_key TEXT,
        copilot_version TEXT NOT NULL,
        annotation_json TEXT NOT NULL,
        generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (item_id) REFERENCES quarantine(id) ON DELETE CASCADE,
        UNIQUE(item_id, copilot_version)
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_item ON quarantine_annotations(item_id);
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_category ON quarantine_annotations(category);
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_action ON quarantine_annotations(suggested_action);
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_group ON quarantine_annotations(similar_group_key);

      CREATE TABLE IF NOT EXISTS fragmentation_entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id INTEGER NOT NULL,
        entity_value TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        context_snippet TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_frag_entities_memory ON fragmentation_entities(memory_id);
      CREATE INDEX IF NOT EXISTS idx_frag_entities_text ON fragmentation_entities(entity_value);
      CREATE INDEX IF NOT EXISTS idx_frag_entities_type ON fragmentation_entities(entity_type);
    `);
  } catch {
    // Tables may already exist - safe to ignore
  }

  // Migration: project column on defence_audit and quarantine tables
  try {
    const auditCols = database.prepare("PRAGMA table_info(defence_audit)").all() as { name: string }[];
    if (auditCols.length > 0 && !auditCols.some(c => c.name === 'project')) {
      database.exec('ALTER TABLE defence_audit ADD COLUMN project TEXT');
      database.exec('CREATE INDEX IF NOT EXISTS idx_audit_project ON defence_audit(project)');
    }
    const quarantineCols = database.prepare("PRAGMA table_info(quarantine)").all() as { name: string }[];
    if (quarantineCols.length > 0 && !quarantineCols.some(c => c.name === 'project')) {
      database.exec('ALTER TABLE quarantine ADD COLUMN project TEXT');
    }
  } catch {
    // Safe to ignore if tables don't exist yet
  }

  // Backfill: set project on defence_audit/quarantine entries that have NULL project
  try {
    const nullCount = (database.prepare(
      "SELECT COUNT(*) as cnt FROM defence_audit WHERE project IS NULL"
    ).get() as { cnt: number })?.cnt ?? 0;
    if (nullCount > 0) {
      // From linked memories
      database.exec(`UPDATE defence_audit SET project = (
        SELECT m.project FROM memories m WHERE m.id = defence_audit.memory_id
      ) WHERE memory_id IS NOT NULL AND project IS NULL`);
      // Remaining: use most common project
      database.exec(`UPDATE defence_audit SET project = (
        SELECT project FROM memories WHERE project IS NOT NULL GROUP BY project ORDER BY COUNT(*) DESC LIMIT 1
      ) WHERE project IS NULL`);
    }
    const qNullCount = (database.prepare(
      "SELECT COUNT(*) as cnt FROM quarantine WHERE project IS NULL"
    ).get() as { cnt: number })?.cnt ?? 0;
    if (qNullCount > 0) {
      database.exec(`UPDATE quarantine SET project = (
        SELECT project FROM memories WHERE project IS NOT NULL GROUP BY project ORDER BY COUNT(*) DESC LIMIT 1
      ) WHERE project IS NULL`);
    }
  } catch {
    // Safe to ignore
  }

  // Migration: sync_queue table for cloud sync retry
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS sync_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        payload TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        max_attempts INTEGER DEFAULT 3,
        next_retry_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','failed','synced')),
        last_error TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        synced_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_sync_queue_status_retry ON sync_queue(status, next_retry_at);
    `);
  } catch {
    // Table may already exist - safe to ignore
  }

  // Migration: Ontology tables (entities, triples, memory_entities)
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        aliases TEXT DEFAULT '[]',
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        memory_count INTEGER DEFAULT 0,
        UNIQUE(name, type)
      );
      CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);
      CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);

      CREATE TABLE IF NOT EXISTS triples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id INTEGER NOT NULL,
        predicate TEXT NOT NULL,
        object_id INTEGER NOT NULL,
        source_memory_id INTEGER,
        confidence REAL DEFAULT 0.8,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (subject_id) REFERENCES entities(id) ON DELETE CASCADE,
        FOREIGN KEY (object_id) REFERENCES entities(id) ON DELETE CASCADE,
        FOREIGN KEY (source_memory_id) REFERENCES memories(id) ON DELETE SET NULL,
        UNIQUE(subject_id, predicate, object_id)
      );
      CREATE INDEX IF NOT EXISTS idx_triples_subject ON triples(subject_id);
      CREATE INDEX IF NOT EXISTS idx_triples_object ON triples(object_id);
      CREATE INDEX IF NOT EXISTS idx_triples_predicate ON triples(predicate);

      CREATE TABLE IF NOT EXISTS memory_entities (
        memory_id INTEGER NOT NULL,
        entity_id INTEGER NOT NULL,
        role TEXT DEFAULT 'mention',
        FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE,
        FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
        PRIMARY KEY (memory_id, entity_id)
      );
    `);
  } catch {
    // Tables may already exist - safe to ignore
  }

  // Migration: graph_extraction_version column for incremental graph backfill
  if (!columnNames.has('graph_extraction_version')) {
    database.exec('ALTER TABLE memories ADD COLUMN graph_extraction_version INTEGER DEFAULT 0');
  }


  // Migration: v4.0.0 — memory_purpose for type taxonomy
  if (!columnNames.has('memory_purpose')) {
    database.exec("ALTER TABLE memories ADD COLUMN memory_purpose TEXT DEFAULT 'project'");
  }

  // Migration: v4.0.0 — memory_scope for private/team visibility
  if (!columnNames.has('memory_scope')) {
    database.exec("ALTER TABLE memories ADD COLUMN memory_scope TEXT DEFAULT 'private'");
  }

  // Migration: Pro feature tables (custom_patterns, iron_dome_policies, firewall_rules)
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS custom_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'custom',
        severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('critical', 'high', 'medium', 'low')),
        regex TEXT NOT NULL,
        description TEXT DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_custom_patterns_enabled ON custom_patterns(enabled);

      CREATE TABLE IF NOT EXISTS iron_dome_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        config TEXT NOT NULL DEFAULT '{}',
        is_active INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_dome_policies_active ON iron_dome_policies(is_active) WHERE is_active = 1;

      CREATE TABLE IF NOT EXISTS firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 100,
        condition_type TEXT NOT NULL,
        condition_value TEXT NOT NULL,
        action TEXT NOT NULL CHECK(action IN ('block', 'allow', 'quarantine')),
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_firewall_rules_priority ON firewall_rules(priority);
      CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);

      CREATE TABLE IF NOT EXISTS rate_limits (
        source_key TEXT PRIMARY KEY,
        write_count INTEGER NOT NULL DEFAULT 1,
        window_start_ms INTEGER NOT NULL
      );
    `);
  } catch {
    // Tables may already exist - safe to ignore
  }
}

/**
 * Get the current database instance
 */
export function getDatabase(): Database.Database {
  if (!db) {
    throw new Error('Database not initialized. Call initDatabase() first.');
  }

  // Staleness check: if the live file was replaced (recovery renamed it),
  // close the stale handle and re-init against the new file.
  if (currentDbPath && dbInode !== null) {
    try {
      const currentIno = statSync(currentDbPath, { bigint: true }).ino;
      if (currentIno !== dbInode) {
        console.error(`[database] Live database file replaced (inode ${dbInode} → ${currentIno}). Reconnecting.`);
        const pathToReopen = currentDbPath;
        try { db.close(); } catch { /* best-effort */ }
        db = null;
        dbInode = null;
        return initDatabase(pathToReopen);
      }
    } catch {
      // File missing — another process may be mid-recovery. Let the caller hit
      // the error naturally rather than racing the recovery.
    }
  }

  return db!;
}

/**
 * Check whether the database has been initialized.
 * Useful for library consumers (e.g. OpenClaw extensions) that import
 * the defence pipeline without running the full MCP server.
 */
export function isDatabaseInitialized(): boolean {
  return db !== null;
}

/**
 * Close the database connection with proper cleanup
 */
export function closeDatabase(): void {
  if (db) {
    try {
      // Checkpoint WAL before closing to flush all changes
      db.pragma('wal_checkpoint(PASSIVE)');
    } catch {
      // Ignore checkpoint errors on close
    }
    db.close();
    db = null;
    currentDbPath = null;
    dbInode = null;
  }

  if (lockFileFd !== null) {
    try {
      closeSync(lockFileFd);
    } catch {
      // Best-effort close.
    }
    lockFileFd = null;
  }

  if (lockFilePath && existsSync(lockFilePath)) {
    try {
      unlinkSync(lockFilePath);
    } catch {
      // Non-fatal
    }
    lockFilePath = null;
  }
}

/**
 * Repair or verify database health.
 * Intended for `shieldcortex doctor` CLI command.
 */
export function repairDatabase(): { status: 'ok' | 'repaired' | 'recreated'; message: string } {
  const database = getDatabase();

  // Step 1: Integrity check
  const integrityResult = runIntegrityCheck(database);

  if (integrityResult === 'ok') {
    return { status: 'ok', message: 'Database is healthy' };
  }

  console.warn(`[database] Integrity check failed: ${integrityResult}`);
  console.warn('[database] Attempting repair via VACUUM and REINDEX...');

  // Step 2: Try VACUUM + REINDEX
  try {
    database.exec('REINDEX');
    database.exec('VACUUM');

    // Re-check after repair attempt
    const recheckResult = runIntegrityCheck(database);
    if (recheckResult === 'ok') {
      return { status: 'repaired', message: 'Database repaired successfully via VACUUM/REINDEX' };
    }
  } catch (e) {
    console.warn(`[database] VACUUM/REINDEX failed: ${e}`);
  }

  // Step 3: Still corrupt — backup and recreate
  if (!currentDbPath) {
    return { status: 'recreated', message: 'Database path unknown — cannot backup. Please reinitialise.' };
  }

  // Close current connection
  try {
    database.close();
  } catch { /* best-effort */ }
  db = null;

  // Attempt dump recovery first
  const recovered = attemptDumpRecovery(currentDbPath);
  if (recovered) {
    db = recovered;
    // Re-apply pragmas
    db.pragma('journal_mode = WAL');
    db.pragma('synchronous = NORMAL');
    db.pragma('foreign_keys = ON');
    db.pragma('busy_timeout = 10000');
    db.pragma('wal_autocheckpoint = 100');
    return { status: 'repaired', message: 'Database recovered via dump/reimport. Some data may have been lost.' };
  }

  // Full recreation
  const backupPath = backupCorruptDatabase(currentDbPath);
  db = new Database(currentDbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 10000');
  db.pragma('wal_autocheckpoint = 100');

  // Re-apply schema
  const schemaPath = join(_currentDir, 'schema.sql');
  if (existsSync(schemaPath)) {
    const schema = readFileSync(schemaPath, 'utf-8');
    db.exec(schema);
  } else {
    db.exec(getInlineSchema());
  }

  return {
    status: 'recreated',
    message: `Database was unrecoverable. Corrupt file backed up to ${backupPath}. Fresh database created.`,
  };
}

/**
 * Register handlers for graceful shutdown
 */
let shutdownRegistered = false;
function registerShutdownHandlers(): void {
  if (shutdownRegistered) return;
  if (process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID) return;
  shutdownRegistered = true;

  const cleanup = () => {
    closeDatabase();
  };

  // Handle various termination signals
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(0); });
  process.on('SIGTERM', () => { cleanup(); process.exit(0); });
  process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
    cleanup();
    process.exit(1);
  });
}

/**
 * Manually checkpoint the WAL file (call periodically for long-running processes)
 */
export function checkpointWal(): { walPages: number; checkpointed: number } {
  const database = getDatabase();
  const result = database.pragma('wal_checkpoint(PASSIVE)') as { busy: number; log: number; checkpointed: number }[];
  return {
    walPages: result[0]?.log || 0,
    checkpointed: result[0]?.checkpointed || 0,
  };
}

/**
 * Check database file size for bloat prevention
 */
export interface DatabaseSizeInfo {
  size: number;
  sizeFormatted: string;
  warning: boolean;
  blocked: boolean;
  message: string;
}

export function checkDatabaseSize(): DatabaseSizeInfo {
  if (!currentDbPath || !existsSync(currentDbPath)) {
    return {
      size: 0,
      sizeFormatted: '0 KB',
      warning: false,
      blocked: false,
      message: 'Database not initialized',
    };
  }

  const stats = statSync(currentDbPath);
  const size = stats.size;
  const sizeKB = size / 1024;
  const sizeMB = sizeKB / 1024;

  let sizeFormatted: string;
  if (sizeMB >= 1) {
    sizeFormatted = `${sizeMB.toFixed(2)} MB`;
  } else {
    sizeFormatted = `${sizeKB.toFixed(2)} KB`;
  }

  const warning = size > WARN_DB_SIZE;
  const blocked = size > MAX_DB_SIZE;

  let message = `Database size: ${sizeFormatted}`;
  if (blocked) {
    message = `DATABASE BLOCKED: ${sizeFormatted} exceeds 100MB limit. Run consolidation and vacuum.`;
  } else if (warning) {
    message = `WARNING: ${sizeFormatted} approaching 100MB limit. Consider running consolidation.`;
  }

  return { size, sizeFormatted, warning, blocked, message };
}

/**
 * Check if database operations should be blocked due to size
 */
export function isDatabaseBlocked(): boolean {
  return checkDatabaseSize().blocked;
}

/**
 * Inline schema for bundled deployment
 */
function getInlineSchema(): string {
  return `
    CREATE TABLE IF NOT EXISTS memories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL CHECK(type IN ('short_term', 'long_term', 'episodic')),
      category TEXT NOT NULL DEFAULT 'note',
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      project TEXT,
      tags TEXT DEFAULT '[]',
      salience REAL DEFAULT 0.5 CHECK(salience >= 0 AND salience <= 1),
      decayed_score REAL,
      access_count INTEGER DEFAULT 0,
      last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      metadata TEXT DEFAULT '{}',
      embedding BLOB,
      scope TEXT DEFAULT 'project',
      transferable INTEGER DEFAULT 0,
      trust_score REAL DEFAULT 1.0,
      sensitivity_level TEXT DEFAULT 'INTERNAL',
      source TEXT DEFAULT 'user:direct',
      status TEXT DEFAULT 'active' CHECK(status IN ('active', 'archived', 'suppressed', 'canonical')),
      pinned INTEGER DEFAULT 0,
      reviewed_at TIMESTAMP,
      reviewed_by TEXT,
      source_kind TEXT DEFAULT 'user',
      capture_method TEXT DEFAULT 'manual',
      cloud_excluded INTEGER DEFAULT 0,
      graph_extraction_version INTEGER DEFAULT 0,
      memory_purpose TEXT DEFAULT 'project',
      memory_scope TEXT DEFAULT 'private'
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
      title,
      content,
      tags,
      content='memories',
      content_rowid='id',
      tokenize='porter unicode61'
    );

    CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
      INSERT INTO memories_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;

    CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
      INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
      VALUES('delete', old.id, old.title, old.content, old.tags);
    END;

    CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
      INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
      VALUES('delete', old.id, old.title, old.content, old.tags);
      INSERT INTO memories_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;

    CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(type);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_uuid ON memories(uuid);
    CREATE INDEX IF NOT EXISTS idx_memories_project ON memories(project);
    CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category);
    CREATE INDEX IF NOT EXISTS idx_memories_salience ON memories(salience DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_decayed_score ON memories(decayed_score DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_last_accessed ON memories(last_accessed DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(updated_at DESC);

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project TEXT,
      started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ended_at TIMESTAMP,
      summary TEXT,
      memories_created INTEGER DEFAULT 0,
      memories_accessed INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS memory_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_id INTEGER NOT NULL,
      target_id INTEGER NOT NULL,
      relationship TEXT NOT NULL,
      strength REAL DEFAULT 0.5,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (source_id) REFERENCES memories(id) ON DELETE CASCADE,
      FOREIGN KEY (target_id) REFERENCES memories(id) ON DELETE CASCADE,
      UNIQUE(source_id, target_id)
    );

    -- Events table for cross-process IPC (MCP → Dashboard)
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      data TEXT,
      timestamp TEXT NOT NULL,
      processed INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, id);

    CREATE TABLE IF NOT EXISTS entities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      aliases TEXT DEFAULT '[]',
      first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      memory_count INTEGER DEFAULT 0,
      UNIQUE(name, type)
    );

    CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);
    CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);

    CREATE TABLE IF NOT EXISTS triples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_id INTEGER NOT NULL,
      predicate TEXT NOT NULL,
      object_id INTEGER NOT NULL,
      source_memory_id INTEGER,
      confidence REAL DEFAULT 0.8,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (subject_id) REFERENCES entities(id) ON DELETE CASCADE,
      FOREIGN KEY (object_id) REFERENCES entities(id) ON DELETE CASCADE,
      FOREIGN KEY (source_memory_id) REFERENCES memories(id) ON DELETE SET NULL,
      UNIQUE(subject_id, predicate, object_id)
    );

    CREATE INDEX IF NOT EXISTS idx_triples_subject ON triples(subject_id);
    CREATE INDEX IF NOT EXISTS idx_triples_object ON triples(object_id);
    CREATE INDEX IF NOT EXISTS idx_triples_predicate ON triples(predicate);

    CREATE TABLE IF NOT EXISTS memory_entities (
      memory_id INTEGER NOT NULL,
      entity_id INTEGER NOT NULL,
      role TEXT DEFAULT 'mention',
      FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE,
      FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
      PRIMARY KEY (memory_id, entity_id)
    );

    CREATE TABLE IF NOT EXISTS defence_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      memory_id INTEGER,
      project TEXT,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      source_type TEXT NOT NULL,
      source_identifier TEXT NOT NULL,
      trust_score REAL NOT NULL,
      sensitivity_level TEXT NOT NULL DEFAULT 'INTERNAL',
      firewall_result TEXT NOT NULL CHECK(firewall_result IN ('ALLOW', 'BLOCK', 'QUARANTINE')),
      anomaly_score REAL DEFAULT 0.0,
      threat_indicators TEXT DEFAULT '[]',
      blocked_patterns TEXT DEFAULT '[]',
      reason TEXT,
      fragmentation_score REAL,
      pipeline_duration_ms INTEGER,
      FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_memory ON defence_audit(memory_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON defence_audit(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_result ON defence_audit(firewall_result);
    CREATE INDEX IF NOT EXISTS idx_audit_source ON defence_audit(source_type);
    CREATE INDEX IF NOT EXISTS idx_audit_project ON defence_audit(project);

    CREATE TABLE IF NOT EXISTS quarantine (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      original_content TEXT NOT NULL,
      original_title TEXT,
      project TEXT,
      source_type TEXT NOT NULL,
      source_identifier TEXT NOT NULL,
      reason TEXT NOT NULL,
      threat_indicators TEXT DEFAULT '[]',
      anomaly_score REAL DEFAULT 0.0,
      firewall_result TEXT NOT NULL CHECK(firewall_result IN ('BLOCK', 'QUARANTINE')),
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'expired')),
      reviewed_at TIMESTAMP,
      reviewed_by TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP,
      audit_id INTEGER,
      FOREIGN KEY (audit_id) REFERENCES defence_audit(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
    CREATE INDEX IF NOT EXISTS idx_quarantine_created ON quarantine(created_at DESC);

    CREATE TABLE IF NOT EXISTS quarantine_annotations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id INTEGER NOT NULL,
      category TEXT NOT NULL,
      suggested_action TEXT NOT NULL,
      confidence REAL NOT NULL,
      similar_group_key TEXT,
      copilot_version TEXT NOT NULL,
      annotation_json TEXT NOT NULL,
      generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (item_id) REFERENCES quarantine(id) ON DELETE CASCADE,
      UNIQUE(item_id, copilot_version)
    );

    CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_item ON quarantine_annotations(item_id);
    CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_category ON quarantine_annotations(category);
    CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_action ON quarantine_annotations(suggested_action);
    CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_group ON quarantine_annotations(similar_group_key);

    CREATE TABLE IF NOT EXISTS fragmentation_entities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      memory_id INTEGER NOT NULL,
      entity_value TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      context_snippet TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_frag_entities_memory ON fragmentation_entities(memory_id);
    CREATE INDEX IF NOT EXISTS idx_frag_entities_text ON fragmentation_entities(entity_value);
    CREATE INDEX IF NOT EXISTS idx_frag_entities_type ON fragmentation_entities(entity_type);

    CREATE TABLE IF NOT EXISTS sync_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      payload TEXT NOT NULL,
      attempts INTEGER DEFAULT 0,
      max_attempts INTEGER DEFAULT 3,
      next_retry_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','failed','synced')),
      last_error TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      synced_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_sync_queue_status_retry ON sync_queue(status, next_retry_at);

    CREATE TABLE IF NOT EXISTS custom_patterns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'custom',
      severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('critical', 'high', 'medium', 'low')),
      regex TEXT NOT NULL,
      description TEXT DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_custom_patterns_enabled ON custom_patterns(enabled);

    CREATE TABLE IF NOT EXISTS iron_dome_policies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      config TEXT NOT NULL DEFAULT '{}',
      is_active INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_dome_policies_active ON iron_dome_policies(is_active) WHERE is_active = 1;

    CREATE TABLE IF NOT EXISTS firewall_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      priority INTEGER NOT NULL DEFAULT 100,
      condition_type TEXT NOT NULL,
      condition_value TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('block', 'allow', 'quarantine')),
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_firewall_rules_priority ON firewall_rules(priority);
    CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);

    CREATE TABLE IF NOT EXISTS rate_limits (
      source_key TEXT PRIMARY KEY,
      write_count INTEGER NOT NULL DEFAULT 1,
      window_start_ms INTEGER NOT NULL
    );
  `;
}

/**
 * Execute a function within a transaction (auto-commits on success, rollback on error)
 * Use this for batch operations that need atomicity
 */
export function withTransaction<T>(fn: () => T): T {
  const database = getDatabase();
  return database.transaction(fn)();
}

/**
 * Execute a function within an IMMEDIATE transaction (acquires write lock immediately)
 * Use this for critical operations that must not conflict with concurrent writes
 */
export function withImmediateTransaction<T>(fn: () => T): T {
  const database = getDatabase();
  database.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    database.exec('COMMIT');
    return result;
  } catch (e) {
    database.exec('ROLLBACK');
    throw e;
  }
}
