/**
 * ShieldCortex — the RUNNING gateway process, as a fact (#150, #142).
 *
 * Three defects in one week were the same mistake wearing different clothes:
 * a convenient artifact trusted as a proxy for process state. #142 read a
 * boot-time roster snapshot as a live roster; #150 read a months-stale log as
 * the running version (a Mac reported v4.14.10 "running" off a line written in
 * May); #145 echoed a pre-remediation snapshot as the post-remediation state.
 *
 * The rule this module exists to enforce: **no log line may be treated as
 * evidence about the running gateway unless it postdates that gateway's
 * process start.** OpenClaw records every boot in its own SQLite
 * (`gateway_boot_lifecycle`: boot_id, pid, started_at_ms), which gives us the
 * process-start instant without platform-specific service-manager queries.
 * We corroborate the row by checking its pid is actually alive — a recorded
 * boot whose process has exited proves nothing about "now".
 *
 * Best-effort and read-only: any failure returns null, and callers must treat
 * null as "cannot bound the evidence" — degrade to UNKNOWN/unproven, never to
 * a confident claim in either direction.
 */
import fs from 'fs';
import path from 'path';
import { createRequire } from 'module';

export interface RunningGatewayProcess {
  pid: number;
  startedAtMs: number;
}

export interface ReadGatewayProcessOptions {
  /** Injectable liveness probe (defaults to signal-0). */
  isPidAlive?: (pid: number) => boolean;
  /** Injectable row reader, for tests without a SQLite fixture. */
  readLatestBootRow?: (home: string) => { pid: number; started_at_ms: number } | null;
}

function defaultIsPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but is not ours to signal — still alive.
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

function defaultReadLatestBootRow(home: string): { pid: number; started_at_ms: number } | null {
  const dbPath = path.join(home, '.openclaw', 'state', 'openclaw.sqlite');
  if (!fs.existsSync(dbPath)) return null;
  let db: import('better-sqlite3').Database | null = null;
  try {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3') as typeof import('better-sqlite3');
    db = new Database(dbPath, { readonly: true, fileMustExist: true });
    const row = db
      .prepare('SELECT pid, started_at_ms FROM gateway_boot_lifecycle ORDER BY started_at_ms DESC LIMIT 1')
      .get() as { pid: number; started_at_ms: number } | undefined;
    return row ?? null;
  } catch {
    return null;
  } finally {
    try {
      db?.close();
    } catch {
      // ignore
    }
  }
}

/**
 * The currently-running gateway process, or null when it cannot be PROVEN.
 *
 * Null covers: no SQLite, no lifecycle table, no rows, or a newest row whose
 * pid is no longer alive (gateway stopped, or the row belongs to a previous
 * boot on a host where the table lagged). Callers must read null as "unknown",
 * never as "not running" and never as licence to trust unbounded logs.
 */
export function readRunningGatewayProcess(
  home: string,
  options: ReadGatewayProcessOptions = {},
): RunningGatewayProcess | null {
  const readRow = options.readLatestBootRow ?? defaultReadLatestBootRow;
  const isPidAlive = options.isPidAlive ?? defaultIsPidAlive;

  const row = readRow(home);
  if (!row) return null;
  if (typeof row.pid !== 'number' || typeof row.started_at_ms !== 'number') return null;
  if (!Number.isFinite(row.started_at_ms) || row.started_at_ms <= 0) return null;
  if (!isPidAlive(row.pid)) return null;
  return { pid: row.pid, startedAtMs: row.started_at_ms };
}
