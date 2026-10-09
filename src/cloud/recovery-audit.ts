/**
 * The audit sink for `shieldcortex config --resign` (#647).
 *
 * Every other protected-root row is best-effort (`emitProtectedAudit`): an
 * audit row is evidence, never a gate, and a Guard decision must not depend on
 * the database. A deliberate re-sign is different — the command exists so that
 * recovering from a tamper alarm is a RECORDED act, so it must not say
 * "recorded" unless the row was actually written. That needs two things the
 * best-effort path does not give:
 *
 *   1. an initialised database. The `config` command never opens one, and
 *      `logAudit` silently returns -1 without it;
 *   2. the insert's status, which `logIronDomeAudit` discards.
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
 * again afterwards.
 */
export async function openRecoveryAuditSink(): Promise<RecoveryAuditSink> {
  const database = await import('../database/init.js');
  const { recordIronDomeAudit } = await import('../defence/iron-dome/audit.js');
  const openedHere = !database.isDatabaseInitialized();
  if (openedHere) database.initDatabase();
  const location = database.getDatabase().name;
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
