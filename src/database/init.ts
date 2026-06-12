/**
 * Database initialization and connection management
 */

import type Database from 'better-sqlite3';
import BetterSqlite3, { isNativeModuleLoadError } from './better-sqlite3-guard.js';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync, unlinkSync, renameSync, copyFileSync, readdirSync, openSync, closeSync, realpathSync } from 'fs';
import { basename, dirname, join } from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import { runMigrations } from './migrations.js';
import { getInlineSchema } from './inline-schema.js';
import { seedDefaultFirewallRules } from './seed-firewall-rules.js';

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
 *
 * DEPRECATION: the .claude-memory fallback will be removed in v5.0.0 (target
 * Q3 2026). Existing users on the legacy path get a one-time-per-process
 * warning pointing them at `shieldcortex migrate-legacy` so they can move to
 * ~/.shieldcortex/ before the cut. Same applies to .claude-cortex (separate
 * legacy DB read by the CLI migrate command).
 */
let _legacyFallbackWarned = false;
function getDefaultDbPath(): string {
  const newPath = join(homedir(), '.shieldcortex', 'memories.db');
  const legacyPath = join(homedir(), '.claude-memory', 'memories.db');

  // Prefer new path if it exists, or if neither exists (new install)
  if (existsSync(newPath) || !existsSync(legacyPath)) {
    return newPath;
  }
  // Fall back to legacy path for existing users — warn once.
  if (!_legacyFallbackWarned) {
    _legacyFallbackWarned = true;
    console.warn('[shieldcortex] DEPRECATED: reading from ~/.claude-memory/memories.db.');
    console.warn('[shieldcortex] This fallback will be removed in v5.0.0 (target Q3 2026).');
    console.warn('[shieldcortex] To migrate now: shieldcortex migrate-legacy');
  }
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
    inspectionDb = new BetterSqlite3(dbPath, {
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
    const freshDb = new BetterSqlite3(dbPath);
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
 * Remove stale backup files. Runs once at startup after successful init —
 * prevents unbounded accumulation.
 * - .corrupt.* / .recovery-failed.*  — older than 7 days
 * - .pre-backfill-*                  — older than 30 days (longer TTL so the
 *   revert-backfill CLI keeps a usable restore point for a reasonable window)
 */
function cleanupStaleBackups(dbPath: string): void {
  const dir = dirname(dbPath);
  const base = basename(dbPath);
  const maxAge = 7 * 24 * 60 * 60 * 1000;
  const preBackfillMaxAge = 30 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  try {
    for (const name of readdirSync(dir)) {
      const isCorruptOrRecovery =
        name.startsWith(base + '.corrupt.') || name.startsWith(base + '.recovery-failed.');
      const isPreBackfill = name.startsWith(base + '.pre-backfill-');
      if (!isCorruptOrRecovery && !isPreBackfill) continue;
      const filePath = join(dir, name);
      try {
        const age = now - statSync(filePath).mtimeMs;
        const ttl = isPreBackfill ? preBackfillMaxAge : maxAge;
        if (age > ttl) {
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
  cleanupStaleBackups,
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

  // Lazily inspect `.corrupt.*` backups (Phase 17 B4). Each backup inspection
  // opens the file read-only and runs a FULL integrity check, so doing it
  // unconditionally on every startup paid a per-backup scan even when the live
  // DB opened cleanly. Defer it: the only consumers are the corruption /
  // empty-live recovery branches below, so the scan now happens ONLY when
  // recovery is actually invoked. Memoised so a branch that consults it twice
  // still inspects each backup once.
  let _healthyBackups: BackupCandidate[] | null = null;
  const getHealthyBackups = (): BackupCandidate[] => {
    if (_healthyBackups === null) {
      _healthyBackups = listHealthyBackups(expandedPath);
    }
    return _healthyBackups;
  };

  // Wrap the initial open in try/catch to handle corrupt files gracefully
  let database: Database.Database;
  try {
    database = new BetterSqlite3(expandedPath);
  } catch (openError) {
    // A NATIVE-MODULE load failure (missing / ABI-mismatched better-sqlite3
    // binding) throws here too — better-sqlite3 resolves its binding lazily in
    // the constructor, so it surfaces at open time, NOT at require(). That is an
    // INSTALL problem, not file corruption: renaming a healthy DB to .corrupt.*
    // here is data loss (observed 2026-06-09 on an arm64 box after a Node/native
    // mismatch — a live memories.db was moved aside). Never touch the DB file on
    // a binding error; surface an actionable message and let the caller stop.
    if (isNativeModuleLoadError(openError)) {
      const detail = openError instanceof Error ? openError.message : String(openError);
      throw new Error(
        'ShieldCortex could not load its database engine (the better-sqlite3 native module). ' +
        `This is an install / Node-version issue, NOT database corruption — your data at ${expandedPath} is untouched. ` +
        'Rebuild the native module and retry — easiest is `shieldcortex repair`, or manually:\n' +
        '  cd "$(npm root -g)/shieldcortex/node_modules/better-sqlite3" && npm run build-release\n' +
        '(install a C/C++ toolchain first if it fails to compile; a plain `npm rebuild` can silently no-op)\n' +
        `Underlying error: ${detail}`,
      );
    }

    // Database file is corrupt or not a valid SQLite database
    console.error(`❌ Database open failed for ${expandedPath}: ${openError}`);

    const latestHealthyBackup = getHealthyBackups()[0];
    if (latestHealthyBackup) {
      console.error(`[database] Restoring latest healthy backup with ${latestHealthyBackup.count} memories: ${latestHealthyBackup.path}`);
      restoreBackupAsLive(expandedPath, latestHealthyBackup.path, 'failed-open');
      database = new BetterSqlite3(expandedPath);
    } else {
      const backupPath = backupCorruptDatabase(expandedPath);
      console.error(`   Backed up to ${backupPath}`);
      console.error('   Creating fresh database...');
      database = new BetterSqlite3(expandedPath);
    }
  }

  // Integrity check on existing databases (skip for newly created files).
  // This is the SINGLE live-DB integrity scan on the startup path (Phase 17
  // B4). `liveIntegrityOk` records its outcome so the empty-live heuristic
  // below can reuse it instead of re-opening the file and scanning a second
  // time. It stays true for freshly-created files (size 0, check skipped) and
  // for connections rebuilt by a recovery branch — both are known-good.
  let liveIntegrityOk = true;
  if (existsSync(expandedPath) && statSync(expandedPath).size > 0) {
    const integrityResult = runIntegrityCheck(database);
    liveIntegrityOk = integrityResult === 'ok';
    if (integrityResult !== 'ok') {
      console.warn(`[database] WARNING: Database integrity check failed: ${integrityResult}`);

      if (isLikelyFtsIntegrityIssue(integrityResult) && attemptFtsRecovery(database)) {
        console.warn('[database] Preserved memory rows by repairing the FTS index in place.');
        liveIntegrityOk = true; // FTS rebuild re-verified integrity == 'ok'.
      } else {
        const freshIntegrityResult = verifyOnDiskIntegrity(expandedPath);
        if (freshIntegrityResult === 'ok') {
          console.warn('[database] Integrity failure was transient. Reopening the on-disk database without destructive recovery.');
          database.close();
          database = new BetterSqlite3(expandedPath);
          liveIntegrityOk = true; // On-disk re-check was clean.
        } else {
          console.warn(`[database] Fresh integrity check also failed: ${freshIntegrityResult}`);

          // Close the corrupt connection before attempting recovery
          database.close();

          // Attempt dump/reimport recovery
          const recovered = attemptDumpRecovery(expandedPath);
          if (recovered) {
            database = recovered;
          } else {
            const latestHealthyBackup = getHealthyBackups()[0];
            if (latestHealthyBackup) {
              console.error(`[database] Recovery failed. Restoring latest healthy backup with ${latestHealthyBackup.count} memories: ${latestHealthyBackup.path}`);
              restoreBackupAsLive(expandedPath, latestHealthyBackup.path, 'recovery-failed');
              database = new BetterSqlite3(expandedPath);
            } else {
              // Recovery failed — backup and create fresh
              if (existsSync(expandedPath)) {
                const backupPath = backupCorruptDatabase(expandedPath);
                console.error(`[database] Recovery failed. Backed up corrupt file to: ${backupPath}`);
              }
              console.error('[database] Creating fresh database...');
              database = new BetterSqlite3(expandedPath);
            }
          }
          // Dump-recovery, backup-restore and fresh-create all yield a
          // known-good DB — the empty-live heuristic can trust it.
          liveIntegrityOk = true;
        }
      }
    }
  }

  // Empty-live recovery heuristic (Phase 17 B4): this used to call
  // `inspectDatabaseFile(expandedPath)`, which RE-OPENED the live file
  // read-only and ran a SECOND full integrity check purely to obtain the row
  // count — duplicating the scan already performed above. Now the count comes
  // from the open connection and integrity is reused from `liveIntegrityOk`.
  // `getHealthyBackups()` (the eager per-backup scan) is consulted ONLY when
  // the live DB is actually healthy-but-empty, so a normal startup never
  // inspects a backup at all.
  let liveCount: number | null = null;
  try {
    liveCount = (database.prepare('SELECT COUNT(*) AS count FROM memories').get() as { count: number }).count;
  } catch {
    liveCount = null;
  }
  const liveStats = existsSync(expandedPath) ? statSync(expandedPath) : null;
  if (liveIntegrityOk && liveCount === 0) {
    const latestHealthyBackup = getHealthyBackups()[0];
    if (
      latestHealthyBackup
      && latestHealthyBackup.count >= 100
      && liveStats
      && (liveStats.mtimeMs - latestHealthyBackup.mtimeMs) < (24 * 60 * 60 * 1000)
    ) {
      console.error(`[database] Empty live database detected alongside a recent healthy backup (${latestHealthyBackup.count} memories). Restoring ${latestHealthyBackup.path}`);
      database.close();
      restoreBackupAsLive(expandedPath, latestHealthyBackup.path, 'empty-live');
      database = new BetterSqlite3(expandedPath);
    }
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

  // Pre-backfill file snapshot (v4.29.0, B4): before the one-time salience-wall
  // backfill mutates rows, take an offline restore point of the live file. The
  // in-DB `memories_backfill_backup` shares the fate of the live file that
  // empty-live/corrupt recovery could stash, so this on-disk copy is the
  // independent rollback artefact. Checkpoint WAL first so the main file is
  // current before any count-based recovery can fire. Sentinel-gated: only
  // taken once (before the backfill has run), never on :memory: DBs, and never
  // allowed to block startup.
  try {
    const sentinel = db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories_backfill_backup'"
    ).get();
    if (!sentinel && expandedPath !== ':memory:' && existsSync(expandedPath)) {
      db.pragma('wal_checkpoint(TRUNCATE)');
      const snapshotPath = `${expandedPath}.pre-backfill-${Date.now()}`;
      copyFileSync(expandedPath, snapshotPath);
      console.error(`[shieldcortex] pre-backfill snapshot saved: ${snapshotPath}`);
    }
  } catch {
    // Best-effort restore point; never block startup.
  }

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

  // Seed built-in firewall rules. This runs AFTER the schema so the
  // firewall_rules table is guaranteed to exist — `runMigrations()` returns
  // early on a fresh DB (no `memories` table), so seeding cannot live there or
  // it never fires for new installs (the case the README's "seeded on first
  // run" promise covers). Idempotent: the seeder no-ops when built_in rows are
  // already present, so re-running on every startup is safe and cheap.
  try {
    seedDefaultFirewallRules(db);
  } catch {
    // Seeder is best-effort; a failure here must never block startup.
  }

  return db;
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
  db = new BetterSqlite3(currentDbPath);
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
