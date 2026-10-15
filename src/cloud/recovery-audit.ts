/**
 * The audit sink for `shieldcortex config --resign` (#647).
 *
 * Every other protected-root row is best-effort (`emitProtectedAudit`): an
 * audit row is evidence, never a gate, and a Guard decision must not depend on
 * the database. A deliberate re-sign is different — the command exists so that
 * recovering from a tamper alarm is a RECORDED act, so it must not say
 * "recorded" unless the row was actually written. That needs three things the
 * best-effort path does not give:
 *
 *   1. an initialised database. The `config` command never opens one, and
 *      `logAudit` silently returns -1 without it;
 *   2. the insert's status, which `logIronDomeAudit` discards;
 *   3. a database that outlives the process. `CLAUDE_MEMORY_DB=:memory:` is a
 *      supported override, and an insert there returns a real row id that is
 *      gone the moment the database closes. A row id is not a receipt unless
 *      SQLite says the database is on disk.
 *
 * Opened only on the confirmed mutation path, before anything is written, so an
 * unavailable audit log refuses the re-sign instead of being discovered after
 * it. Both imports are dynamic, as in `emitProtectedAudit`: config.ts is loaded
 * by the hook and plugin paths, which must not pull in SQLite.
 */
import { describeProtectedAudit, type ProtectedAuditEvent } from '../defence/iron-dome/protected-root.js';

export interface RecoveryAuditSink {
  /** The audit database file the row goes to. */
  location: string;
  /** Write one row and return its id. Throws when the row was not written — never a silent -1. */
  record(event: ProtectedAuditEvent): number;
  /** Close the database if this sink opened it. Never throws. */
  close(): void;
}

/**
 * Open the defence audit log for one recovery record. Throws when it cannot be
 * opened; the caller must then write nothing.
 *
 * Uses the process's database if one is already initialised, otherwise opens
 * the same one every other CLI command does (`initDatabase()` — the default
 * path or `CLAUDE_MEMORY_DB`, under the same safe-runtime rules) and closes it
 * again afterwards. Refuses a database that is not stored on disk, whichever
 * way it was opened.
 */
export async function openRecoveryAuditSink(): Promise<RecoveryAuditSink> {
  const database = await import('../database/init.js');
  const { recordIronDomeAudit } = await import('../defence/iron-dome/audit.js');
  const openedHere = !database.isDatabaseInitialized();
  if (openedHere) database.initDatabase();
  const db = database.getDatabase();
  const location = db.name;
  // Asked of the connection, not of the path text: better-sqlite3's `memory`
  // flag (`:memory:` and the anonymous `''` temporary database), and SQLite's
  // own `database_list`, whose `file` is empty for any main database that is
  // not a file on disk.
  let onDisk = false;
  try {
    const main = (db.pragma('database_list') as Array<{ name: string; file: string }>)
      .find((entry) => entry.name === 'main');
    onDisk = !db.memory && Boolean(main?.file);
  } catch { /* unknown is not on disk */ }
  if (!onDisk) {
    // Refused before anything is written. Only a database this sink opened is
    // closed; a caller's stays open and usable.
    if (openedHere) {
      try { database.closeDatabase(); } catch { /* nothing was written to it */ }
    }
    throw new Error(
      `the audit database ${location ? `"${location}" ` : ''}is in-memory or temporary, so a row written there ` +
      'would not outlast this command',
    );
  }
  return {
    location,
    record(event) {
      const id = recordIronDomeAudit(describeProtectedAudit(event));
      if (!(id > 0)) throw new Error(`the audit row could not be written to ${location}`);
      return id;
    },
    close() {
      if (!openedHere) return;
      try { database.closeDatabase(); } catch { /* the row, if written, is already committed */ }
    },
  };
}
