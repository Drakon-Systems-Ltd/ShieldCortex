/**
 * Database initialization and connection management
 */

import type Database from 'better-sqlite3';
import { getBetterSqlite3 } from './better-sqlite3-guard.js';
import { NativeModuleLoadError, isNativeModuleLoadError, formatNativeLoadError } from './native-load-classify.js';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync, unlinkSync, renameSync, copyFileSync, readdirSync, openSync, closeSync, realpathSync, linkSync, fstatSync } from 'fs';
import { randomUUID } from 'crypto';
import { basename, dirname, join, resolve } from 'path';
import { homedir } from 'os';
import { fileURLToPath } from 'url';
import { execSync } from 'child_process';
import { runMigrations } from './migrations.js';
import { getInlineSchema } from './inline-schema.js';
import { ensureLedger } from '../defence/ledger/chain.js';
import { seedDefaultFirewallRules } from './seed-firewall-rules.js';
import { debugLog } from '../debug-log.js';
import { MAX_DB_FILE_BYTES, WARN_DB_FILE_BYTES } from '../limits.js';
import { mkdirSecure, SECURE_OPEN_MODE } from '../setup/state-permissions.js';

const _currentFile = fileURLToPath(import.meta.url);
const _currentDir = dirname(_currentFile);

let db: Database.Database | null = null;
let currentDbPath: string | null = null;
let lockFilePath: string | null = null;
let lockFileFd: number | null = null;
/** The exact bytes this process published as its lock record; release removes only this. */
let lockOwnedRecord: Buffer | null = null;
/** True only while this process's record is still at the canonical lock path. */
export function holdsStartupLock(): boolean { return verifiedOwnedLock() !== null; }
export class StartupLockHeldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StartupLockHeldError';
  }
}
let dbInode: bigint | null = null; // Track file identity for staleness detection

// Anti-bloat: Database size limits
// Re-exported from the single definition in ../limits.ts (#148 follow-up).
// This bounds the LIVE DB FILE only — not the whole directory. See limits.ts.
const MAX_DB_SIZE = MAX_DB_FILE_BYTES;
const WARN_DB_SIZE = WARN_DB_FILE_BYTES;

/**
 * Expand ~ to home directory
 */
export function expandPath(path: string): string {
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
export function resolveMemoriesDbPath(explicitPath?: string): string {
  const envDbPath = process.env.CLAUDE_MEMORY_DB?.trim();
  return explicitPath || envDbPath || getDefaultDbPath();
}

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

/** Apply the default-database runtime policy before any independent DB open. */
export function assertSafeRuntimeForDbPath(resolvedPath: string): void {
  enforceSafeRuntimePath(expandPath(resolvedPath), false);
}

function inspectDatabaseFile(dbPath: string): DatabaseInspection {
  let inspectionDb: Database.Database | null = null;
  try {
    inspectionDb = new (getBetterSqlite3())(dbPath, {
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

/**
 * A lock record that does not parse (or names no PID) is only treated as stale
 * once its mtime is more than this far in the past: a publisher that creates
 * the file and writes it in two steps (pre-#763 builds, or the no-hard-link
 * fallback below) must not be classed as stale while it is still writing. An
 * mtime in the future counts as fresh, so a clock step cannot age a record.
 *
 * The no-hard-link fallback relies on this grace and is weaker than the
 * atomic temp-then-link publication: a publisher stalled for longer than the
 * grace can have its incomplete record taken over. If another process has
 * taken over its record, it notices that the lock path is no longer its record
 * and does not claim ownership, but it cannot stop the other process from
 * having taken the lock.
 */
const UNREADABLE_LOCK_GRACE_MS = 10_000;
/** Bounded publish / stale-takeover rounds before deferring to the holder. */
const STARTUP_LOCK_ATTEMPTS = 3;

interface LockSnapshot { bytes: Buffer; dev: number; ino: number; mtimeMs: number }
/**
 * A record to match by device, inode and bytes. Identity alone never matches:
 * once the creating descriptor is closed the inode number can be reused by an
 * unrelated record. `partial`: any prefix of `bytes` matches (a write that
 * failed part-way); only used while the creating descriptor is still open.
 */
interface LockIdentity { dev: number; ino: number; bytes: Buffer; partial?: boolean }

/**
 * Lock path → aside name of a record this process moved off the lock path and
 * could not put back. Its owner may be live, so a later acquisition in this
 * process never publishes at that path until the record is back in place,
 * gone, or its owner is known dead (#763).
 */
const displacedLocks = new Map<string, string>();

/**
 * The startup lock path for `dbPath`, spelled one way per database: absolute,
 * normalised, with the parent directory's symlinks resolved when it exists
 * (the lock file itself need not). `displacedLocks` is keyed by this path, so
 * a same-process retry that spells the database differently (`./`, `..`,
 * relative versus absolute, a symlinked parent) still finds a record it left
 * aside instead of publishing into the vacant lock path (#837).
 */
function startupLockPath(dbPath: string): string {
  const absolute = resolve(dbPath);
  let parent = dirname(absolute);
  try {
    parent = realpathSync(parent);
  } catch {
    // Missing or unreadable parent: keep the normalised lexical path.
  }
  return `${join(parent, basename(absolute))}.lock`;
}

/** Read the lock record and its inode through one descriptor; null when absent. */
function readLockSnapshot(path: string): LockSnapshot | null {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
  try {
    const stat = fstatSync(fd);
    return { bytes: readFileSync(fd), dev: stat.dev, ino: stat.ino, mtimeMs: stat.mtimeMs };
  } finally {
    closeSync(fd);
  }
}

const matchesLock = (snapshot: LockSnapshot | null, expected: LockIdentity): boolean =>
  snapshot !== null && snapshot.dev === expected.dev && snapshot.ino === expected.ino &&
  (expected.partial
    ? snapshot.bytes.length <= expected.bytes.length && snapshot.bytes.equals(expected.bytes.subarray(0, snapshot.bytes.length))
    : snapshot.bytes.equals(expected.bytes));

/**
 * This process's lock identity while its own record is at the canonical lock
 * path, else null (#813). A different record at the path revokes the cached
 * ownership for good: another process holds it now. An absent or unreadable
 * path only reports "not owner" without revoking, because another process's
 * stale check may have moved the record aside and be about to link it back
 * (same inode), after which this process owns it again.
 *
 * Without hard links that stale check puts the record back as an exclusive
 * copy of the same bytes, on a new inode (#817). A record whose bytes are
 * exactly `lockOwnedRecord` is still this process's own record: those bytes
 * carry a random nonce this process generated, so no other process publishes
 * them; they only reappear when a stale check copies this record back. Such a
 * record is re-adopted (the retained descriptor moves to the new inode).
 * Any other bytes — a displaced holder now facing another process's record
 * (#813) — still revoke, and a revoked process has no record left to re-adopt.
 *
 * That copy is created exclusively before its bytes are written, so for a
 * moment the path holds an empty file or a strict prefix of
 * `lockOwnedRecord` (#819). Such a record is only possibly mid-publication:
 * it may become this record again, or another publisher's first bytes may
 * happen to match ours so far. It therefore reports "not owner" without
 * revoking, like a vacant path, and never counts as ownership. A later check
 * re-adopts it once it holds exactly `lockOwnedRecord`; once it holds any
 * other complete bytes — including a foreign record that started with the
 * same prefix — it is no longer a prefix and revokes as above.
 */
function verifiedOwnedLock(): LockIdentity | null {
  if (lockFileFd === null || lockFilePath === null || lockOwnedRecord === null) return null;
  let snapshot: LockSnapshot | null;
  try {
    snapshot = readLockSnapshot(lockFilePath);
  } catch {
    return null; // Unreadable: ownership cannot be established right now.
  }
  if (snapshot === null) return null; // Vacant: possibly moved aside mid stale check.
  try {
    const own = fstatSync(lockFileFd);
    const identity = { dev: own.dev, ino: own.ino, bytes: lockOwnedRecord };
    if (matchesLock(snapshot, identity)) return identity;
  } catch {
    return null; // Our descriptor cannot be checked: not provably ours.
  }
  if (snapshot.bytes.equals(lockOwnedRecord)) return readoptOwnLock(lockFilePath, lockOwnedRecord);
  if (snapshot.bytes.length < lockOwnedRecord.length &&
      snapshot.bytes.equals(lockOwnedRecord.subarray(0, snapshot.bytes.length))) {
    return null; // Possibly our record mid copy-restoration: not verified now.
  }
  try { closeSync(lockFileFd); } catch { /* Best-effort close. */ }
  lockFileFd = null;
  lockFilePath = null;
  lockOwnedRecord = null;
  return null;
}

/**
 * Move the retained lock descriptor to the record now at `lockPath` when that
 * opened file holds exactly `bytes` (#817). If the path changed again before
 * it was opened, nothing changes and the next check decides.
 *
 * The descriptor proves which file was opened, not that it is still at
 * `lockPath`: once its bytes are verified, `lockPath` must still name that
 * same device and inode, or the candidate is dropped and nothing changes. This
 * covers a replacement between the open and adoption; it is not an atomic
 * compare-and-swap — a replacement after this check is the same
 * snapshot-to-use window every other ownership check has.
 */
function readoptOwnLock(lockPath: string, bytes: Buffer): LockIdentity | null {
  let fd: number;
  try {
    fd = openSync(lockPath, 'r');
  } catch {
    return null; // Gone or unreadable since the snapshot: not provably ours now.
  }
  let identity: LockIdentity | null = null;
  try {
    const stat = fstatSync(fd);
    if (readFileSync(fd).equals(bytes)) {
      const named = statSync(lockPath);
      if (named.dev === stat.dev && named.ino === stat.ino) identity = { dev: stat.dev, ino: stat.ino, bytes };
    }
  } catch {
    identity = null;
  }
  if (!identity) {
    try { closeSync(fd); } catch { /* Best-effort close. */ }
    return null;
  }
  if (lockFileFd !== null) {
    try { closeSync(lockFileFd); } catch { /* Best-effort close. */ }
  }
  lockFileFd = fd;
  return identity;
}

/**
 * Put a record that was moved aside back at `lockPath` without overwriting a
 * lock published in the meantime: hard link first, then (when the bytes are
 * known) an exclusive create of a copy. False when it could not be put back.
 */
function restoreLock(aside: string, lockPath: string, bytes: Buffer | undefined): boolean {
  try {
    linkSync(aside, lockPath);
    return true;
  } catch (error) {
    // EEXIST: another process published while the record was aside.
    if ((error as NodeJS.ErrnoException).code === 'EEXIST' || !bytes) return false;
  }
  try {
    const fd = createLockExclusive(lockPath, bytes, false);
    if (typeof fd !== 'number') return false;
    closeSync(fd);
    return true;
  } catch {
    return false;
  }
}

/**
 * Remove the lock at `lockPath` only if it is still `expected`: same device
 * and inode, and the same bytes (or, for `partial`, a prefix of them — safe
 * only because the caller still holds the descriptor that created that inode,
 * so no other record can be at it). The record is first
 * renamed aside atomically, so a lock another process published after
 * `expected` was read is never unlinked by name. A record that does not match,
 * or cannot be read, is put back; if that fails it is left at the aside name,
 * never deleted, and recorded in `displacedLocks` (#763).
 *
 * 'restored': a different record was there and is back in place.
 * 'displaced': a different record could not be put back and is left aside.
 * 'failed': the lock could not be moved or read (left aside if not put back).
 */
function removeLockIfUnchanged(
  lockPath: string,
  expected: LockIdentity,
  restoreByCopy = true,
): 'removed' | 'absent' | 'restored' | 'displaced' | 'failed' {
  const aside = `${lockPath}.${randomUUID()}.aside`;
  try {
    renameSync(lockPath, aside);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'absent' : 'failed';
  }
  let moved: LockSnapshot | null = null;
  try {
    moved = readLockSnapshot(aside);
  } catch {
    moved = null;
  }
  if (matchesLock(moved, expected)) {
    try {
      unlinkSync(aside);
    } catch {
      // Best-effort cleanup: the expected record is already off the lock path.
    }
    return 'removed';
  }
  if (restoreLock(aside, lockPath, restoreByCopy ? moved?.bytes : undefined)) {
    try {
      unlinkSync(aside);
    } catch {
      // Best-effort: the record is back at the lock path; only a spare name remains.
    }
    return moved ? 'restored' : 'failed';
  }
  console.error(
    `[database] Left the startup lock record found at ${lockPath} at ${aside}: ` +
    `it was not the record expected and could not be put back`
  );
  displacedLocks.set(lockPath, aside);
  return moved ? 'displaced' : 'failed';
}

/**
 * Create `lockPath` exclusively and write `bytes` into it (no hard links
 * needed). Returns the descriptor only once the completed record is verified
 * to still be the lock path; 'lost' when the path was replaced first (the
 * descriptor is closed, nothing is unlinked); 'exists' when the path is taken.
 * On a write error the path is removed only while it is still the inode this
 * call created, holding bytes this call wrote; the descriptor stays open until
 * that decision is made, so the inode cannot be reused meanwhile.
 */
function createLockExclusive(lockPath: string, bytes: Buffer, restoreByCopy = true): number | 'exists' | 'lost' {
  let fd: number;
  try {
    fd = openSync(lockPath, 'wx', SECURE_OPEN_MODE);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return 'exists';
    throw error;
  }
  let created: { dev: number; ino: number } | null = null;
  try {
    const stat = fstatSync(fd);
    created = { dev: stat.dev, ino: stat.ino };
    writeFileSync(fd, bytes);
  } catch (writeError) {
    if (created) {
      try {
        const current = statSync(lockPath);
        if (current.dev === created.dev && current.ino === created.ino) {
          removeLockIfUnchanged(lockPath, { ...created, bytes, partial: true }, restoreByCopy);
        }
      } catch {
        // Gone or unreadable: nothing of ours to remove.
      }
    }
    try {
      closeSync(fd);
    } catch {
      // Best-effort close.
    }
    throw writeError;
  }
  let current: LockSnapshot | null = null;
  try {
    current = readLockSnapshot(lockPath);
  } catch {
    current = null;
  }
  if (matchesLock(current, { ...created, bytes })) return fd;
  try {
    closeSync(fd);
  } catch {
    // Best-effort close.
  }
  return 'lost';
}

/**
 * Publish `payload` as the lock record with its complete contents in one step:
 * write a private temp file, then hard-link it to the lock path (EEXIST if a
 * lock exists). Returns the descriptor of the published record, 'exists', or
 * 'lost' (no-hard-link fallback only: the path was replaced before the record
 * was complete). The temp name is removed on every path.
 */
function publishLock(lockPath: string, payload: string): number | 'exists' | 'lost' {
  const temp = `${lockPath}.${randomUUID()}.tmp`;
  const fd = openSync(temp, 'wx', SECURE_OPEN_MODE);
  let published = false;
  try {
    writeFileSync(fd, payload, 'utf-8');
    try {
      linkSync(temp, lockPath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EEXIST') return 'exists';
      // link(2) reports EPERM when the filesystem cannot create hard links
      // (e.g. FAT); the temp file is our own, so protected_hardlinks cannot be why.
      if (code !== 'ENOTSUP' && code !== 'ENOSYS' && code !== 'EPERM' && code !== 'EOPNOTSUPP') throw error;
      // No hard links on this filesystem: exclusive create + write, which is
      // weaker (see UNREADABLE_LOCK_GRACE_MS).
      return createLockExclusive(lockPath, Buffer.from(payload, 'utf-8'));
    }
    published = true;
    return fd;
  } finally {
    if (!published) {
      try {
        closeSync(fd);
      } catch {
        // Best-effort close.
      }
    }
    try {
      unlinkSync(temp);
    } catch {
      // Best-effort temp cleanup.
    }
  }
}

/**
 * A record this process displaced from `lockPath` (see `displacedLocks`) is
 * put back first; while it can be neither put back nor shown to belong to a
 * dead (ESRCH) owner, it is the holder and this process must not publish.
 */
function displacedHolder(lockPath: string): { pid: number | null; error: Error } | null {
  const aside = displacedLocks.get(lockPath);
  if (!aside) return null;
  let snapshot: LockSnapshot | null | undefined;
  try {
    snapshot = readLockSnapshot(aside);
  } catch {
    snapshot = undefined; // Unreadable: its owner is unknown.
  }
  if (snapshot === null) {
    displacedLocks.delete(lockPath);
    return null;
  }
  if (restoreLock(aside, lockPath, snapshot?.bytes)) {
    try {
      unlinkSync(aside);
    } catch {
      // Best-effort: the record is back at the lock path; only a spare name remains.
    }
    displacedLocks.delete(lockPath);
    return null; // Back in place: judged like any other record.
  }
  let pid: number | null = null;
  try {
    const parsed = snapshot ? JSON.parse(snapshot.bytes.toString('utf-8')) as { pid?: unknown } : null;
    if (parsed && typeof parsed.pid === 'number') pid = parsed.pid;
  } catch {
    pid = null;
  }
  if (pid !== null) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ESRCH') {
        // Owner gone: the aside is only a stray record now.
        displacedLocks.delete(lockPath);
        return null;
      }
    }
  }
  return {
    pid,
    error: new Error(`[database] Refusing startup because the lock record left at ${aside} could not be put back at ${lockPath}`),
  };
}

/** Live holder (with the error to report) or stale. */
function judgeLock(snapshot: LockSnapshot, dbPath: string, lockPath: string): { live: false } | { live: true; pid: number | null; error: Error } {
  let existing: { pid?: unknown; entryPath?: string } | null = null;
  try {
    existing = JSON.parse(snapshot.bytes.toString('utf-8')) as { pid?: unknown; entryPath?: string };
  } catch {
    existing = null;
  }
  if (!existing || typeof existing.pid !== 'number') {
    // A future mtime (negative age) is fresh: it may be a publication in progress.
    if (Date.now() - snapshot.mtimeMs < UNREADABLE_LOCK_GRACE_MS) {
      return {
        live: true,
        pid: null,
        error: new Error(`[database] Refusing startup because another ShieldCortex process is still writing ${lockPath}`),
      };
    }
    return { live: false };
  }
  try {
    process.kill(existing.pid, 0);
    return {
      live: true,
      pid: existing.pid,
      error: new Error(
        `[database] Refusing startup because ShieldCortex PID ${existing.pid} is already using ${dbPath}` +
        (existing.entryPath ? ` (${existing.entryPath})` : '')
      ),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ESRCH') {
      return { live: true, pid: existing.pid, error: error as Error };
    }
    return { live: false };
  }
}

/**
 * Take the startup lock. Module lock state (`lockFilePath`, `lockFileFd`,
 * `lockOwnedRecord`) is set only once this process's own record is on disk;
 * every other outcome — continue-anyway, refusal, or a thrown error — leaves
 * it untouched (#763).
 */
function acquireStartupLock(dbPath: string, refuseIfLocked = false): void {
  const lockPath = startupLockPath(dbPath);
  const runtime = resolveRuntimeInfo();
  const payload = JSON.stringify({
    pid: process.pid,
    startedAt: new Date().toISOString(),
    entryPath: runtime.entryPath,
    nonce: randomUUID(),
  }, null, 2);

  let holder: { pid: number | null; error: Error } | null = displacedHolder(lockPath);
  for (let attempt = 0; attempt < STARTUP_LOCK_ATTEMPTS && !holder; attempt++) {
    const published = publishLock(lockPath, payload);
    if (typeof published === 'number') {
      lockFileFd = published;
      lockFilePath = lockPath;
      lockOwnedRecord = Buffer.from(payload, 'utf-8');
      return;
    }
    if (published === 'lost') {
      // Our incomplete fallback record was taken over; the replacement stands.
      holder = { pid: null, error: new Error(`[database] Refusing startup because ${lockPath} was replaced before this process finished writing it`) };
      break;
    }

    let snapshot: LockSnapshot | null;
    try {
      snapshot = readLockSnapshot(lockPath);
    } catch (error) {
      // A lock we cannot read is never ours to remove.
      holder = { pid: null, error: error as Error };
      break;
    }
    if (!snapshot) continue; // Released between our publish and read — retry.

    const verdict = judgeLock(snapshot, dbPath, lockPath);
    if (verdict.live) {
      holder = { pid: verdict.pid, error: verdict.error };
      break;
    }
    // Stale: remove exactly the record judged stale, then retry publishing.
    // 'restored' means another process published in between; the next round
    // reads and judges that record instead. 'displaced' means that record
    // could not be put back, so its owner may be live: never publish over it.
    const removal = removeLockIfUnchanged(lockPath, snapshot);
    if (removal === 'failed') {
      holder = { pid: null, error: new Error(`[database] Refusing startup because the stale lock ${lockPath} could not be removed`) };
    } else if (removal === 'displaced') {
      holder = { pid: null, error: new Error(`[database] Refusing startup because the lock record that replaced the stale ${lockPath} could not be put back`) };
    }
  }
  holder ??= { pid: null, error: new Error(`[database] Refusing startup because ${lockPath} kept changing while ShieldCortex was starting`) };

  if (refuseIfLocked) {
    throw new StartupLockHeldError(holder.error.message);
  }
  console.error(
    `[database] Another ShieldCortex process (PID ${holder.pid ?? 'unknown'}) is using ${dbPath} — ` +
    `continuing anyway (SQLite WAL handles concurrency)`
  );
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
    const freshDb = new (getBetterSqlite3())(dbPath);
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
 * - .corrupt.* / .recovery-failed.* / .empty-live.* / .stub* / .bak*  — older than 7 days
 * - .pre-backfill-*  — keep only the most recent restore point; older full-DB
 *   snapshots are pure bloat once a newer one exists (and trip the disk limit)
 */
function cleanupStaleBackups(dbPath: string): void {
  const dir = dirname(dbPath);
  const base = basename(dbPath);
  const maxAge = 7 * 24 * 60 * 60 * 1000;
  const now = Date.now();

  try {
    const entries = readdirSync(dir);

    // Short-lived recovery/migration snapshots: delete after 7 days. Note this now
    // also covers .empty-live.* and .stub* copies, which were previously never
    // cleaned and accumulated next to the live DB after every migration.
    for (const name of entries) {
      const isShortTtl =
        name.startsWith(base + '.corrupt.') ||
        name.startsWith(base + '.recovery-failed.') ||
        name.startsWith(base + '.empty-live.') ||
        name.startsWith(base + '.stub') ||
        name.startsWith(base + '.bak');
      if (!isShortTtl) continue;
      const filePath = join(dir, name);
      try {
        if (now - statSync(filePath).mtimeMs > maxAge) {
          unlinkSync(filePath);
        }
      } catch {
        // Best-effort — file may have been removed by another process
      }
    }

    // .pre-backfill-* are full-DB copies. Keep only the newest as a restore point;
    // a stack of them after back-to-back releases is full DB-sized bloat and is
    // exactly what trips the 100 MB disk limit after a rapid release sequence.
    const preBackfill: Array<{ name: string; mtime: number }> = [];
    for (const name of entries) {
      if (!name.startsWith(base + '.pre-backfill-')) continue;
      try {
        preBackfill.push({ name, mtime: statSync(join(dir, name)).mtimeMs });
      } catch {
        // Skip — file may have vanished
      }
    }
    preBackfill.sort((a, b) => b.mtime - a.mtime);
    for (const { name } of preBackfill.slice(1)) {
      try {
        unlinkSync(join(dir, name));
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
 * The canonical DDL every code path must agree on: prefer the schema.sql
 * shipped alongside this module, fall back to the inline copy for bundled
 * deployments where loose files don't survive. Exported so consumers that
 * need a reference schema (e.g. the doctor's drift check) compare against
 * exactly what initDatabase() applies — never a separately maintained list.
 */
export function getCanonicalSchema(): string {
  const schemaPath = join(_currentDir, 'schema.sql');
  if (existsSync(schemaPath)) {
    return readFileSync(schemaPath, 'utf-8');
  }
  return getInlineSchema();
}

/**
 * Initialize the database connection
 */
export function initDatabase(dbPath?: string, options?: { refuseIfLocked?: boolean }): Database.Database {
  // CLAUDE_MEMORY_DB is the supported sandbox/CLI override used throughout the
  // command surface. Keep an explicit argument highest priority and preserve
  // the existing live default when neither override is present.
  const resolvedPath = resolveMemoriesDbPath(dbPath);
  // Only a REAL caller argument counts as "the operator explicitly chose this
  // database" for the safe-runtime guard. An environment variable is ambient:
  // a redundant CLAUDE_MEMORY_DB pointing at the live default must NOT let an
  // npx cache / project checkout open (and migrate) the production DB.
  const explicitDbPath = Boolean(dbPath);
  if (db) {
    return db;
  }

  const expandedPath = expandPath(resolvedPath);
  enforceSafeRuntimePath(expandedPath, explicitDbPath);
  const dir = dirname(expandedPath);

  // Create directory if it doesn't exist — owner-only from the first mkdir (#218).
  if (!existsSync(dir)) {
    mkdirSecure(dir);
  }

  acquireStartupLock(expandedPath, options?.refuseIfLocked);
  // Store path for size monitoring only after startup lock acquisition.
  currentDbPath = expandedPath;

  // Internal startup state — support-thread material, not user output. Silent
  // unless SHIELDCORTEX_DEBUG / --verbose asks for it (#129).
  debugLog(`[database] Startup runtime=${resolveRuntimeInfo().kind} db=${expandedPath} wal=${existsSync(expandedPath + '-wal')} shm=${existsSync(expandedPath + '-shm')}`);

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
    database = new (getBetterSqlite3())(expandedPath);
  } catch (openError) {
    // A NATIVE-MODULE load failure (missing / ABI-mismatched better-sqlite3
    // binding) throws here too — better-sqlite3 resolves its binding lazily in
    // the constructor, so it surfaces at open time, NOT at require(). That is an
    // INSTALL problem, not file corruption: renaming a healthy DB to .corrupt.*
    // here is data loss (observed 2026-06-09 on an arm64 box after a Node/native
    // mismatch — a live memories.db was moved aside). Never touch the DB file on
    // a binding error; surface an actionable message and let the caller stop.
    //
    // TWO shapes arrive here and only one of them is raw evidence. A packaged
    // prebuild that cannot be dlopen'd throws a RAW error from the constructor;
    // a package that cannot be required at all reaches us as the guard's
    // already-formatted `NativeModuleLoadError`. Re-formatting the second shape
    // is a class flip, not a no-op: formatNativeLoadError's generic diagnosis
    // itself says "this Node build predates the Node-API version it requires",
    // which isPackagedPrebuildLoadError matches, so a second pass relabels a
    // repairable missing/source-only failure as an unfixable packaged-prebuild
    // one. Keep the class, message and cause intact and let the rendered text
    // stay evidence of nothing.
    if (openError instanceof NativeModuleLoadError || isNativeModuleLoadError(openError)) {
      const message = openError instanceof NativeModuleLoadError
        ? openError.message
        : formatNativeLoadError(openError, process.version, String(process.versions.modules));
      throw new NativeModuleLoadError(
        `${message}\n\n` +
        `This is an install / Node-version issue, NOT database corruption — your data at ${expandedPath} is untouched.`,
        openError instanceof NativeModuleLoadError ? openError.cause : openError,
      );
    }

    // Database file is corrupt or not a valid SQLite database
    console.error(`❌ Database open failed for ${expandedPath}: ${openError}`);

    const latestHealthyBackup = getHealthyBackups()[0];
    if (latestHealthyBackup) {
      console.error(`[database] Restoring latest healthy backup with ${latestHealthyBackup.count} memories: ${latestHealthyBackup.path}`);
      restoreBackupAsLive(expandedPath, latestHealthyBackup.path, 'failed-open');
      database = new (getBetterSqlite3())(expandedPath);
    } else {
      const backupPath = backupCorruptDatabase(expandedPath);
      console.error(`   Backed up to ${backupPath}`);
      console.error('   Creating fresh database...');
      database = new (getBetterSqlite3())(expandedPath);
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
          database = new (getBetterSqlite3())(expandedPath);
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
              database = new (getBetterSqlite3())(expandedPath);
            } else {
              // Recovery failed — backup and create fresh
              if (existsSync(expandedPath)) {
                const backupPath = backupCorruptDatabase(expandedPath);
                console.error(`[database] Recovery failed. Backed up corrupt file to: ${backupPath}`);
              }
              console.error('[database] Creating fresh database...');
              database = new (getBetterSqlite3())(expandedPath);
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
      database = new (getBetterSqlite3())(expandedPath);
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
      // Debug-gated: the snapshot is an internal restore point and the line
      // leaks its on-disk path into user output otherwise (#129).
      debugLog(`[shieldcortex] pre-backfill snapshot saved: ${snapshotPath}`);
    }
  } catch {
    // Best-effort restore point; never block startup.
  }

  // Run migrations FIRST for existing databases
  // This ensures columns exist before schema tries to create indexes on them
  runMigrations(db);

  // Run schema (uses IF NOT EXISTS, safe for existing tables and indexes)
  db.exec(getCanonicalSchema());

  // #617: create the chained ledger (identity, epoch 0, epoch-start row) the
  // first time this database is opened by a build that has it. Rows already
  // in defence_audit stay unchained history. Runs after the schema so fresh
  // and migrated databases take the same path. Never blocks startup: a
  // database that cannot create its ledger keeps working unchained and
  // `shieldcortex ledger verify` / doctor report it.
  try {
    ensureLedger(db);
  } catch (err) {
    console.error(`[database] chained ledger could not be initialised: ${err instanceof Error ? err.message : String(err)}`);
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

/** Return the existing handle only while it still names the live database file. */
export function peekDatabase(): Database.Database | null {
  if (!db || !db.open || !currentDbPath || dbInode === null) return null;
  try {
    return statSync(currentDbPath, { bigint: true }).ino === dbInode ? db : null;
  } catch {
    return null;
  }
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

  // Release only a lock this process owns, and only while the on-disk record
  // is still the one it published (same inode, same bytes) — never another
  // process's lock (#763).
  const ownLock = verifiedOwnedLock();
  if (ownLock && lockFilePath) {
    try {
      removeLockIfUnchanged(lockFilePath, ownLock);
    } catch {
      // Non-fatal: release must not fail if the lock changes or cannot be moved.
    }
  }
  if (lockFileFd !== null) {
    try {
      closeSync(lockFileFd);
    } catch {
      // Best-effort close.
    }
  }
  lockFileFd = null;
  lockFilePath = null;
  lockOwnedRecord = null;
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
  db = new (getBetterSqlite3())(currentDbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 10000');
  db.pragma('wal_autocheckpoint = 100');

  // Re-apply schema
  db.exec(getCanonicalSchema());

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
