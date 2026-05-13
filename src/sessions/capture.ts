/**
 * Session capture — write side.
 *
 * Hooks (`scripts/prompt-recall-hook.mjs`, `scripts/stop-hook.mjs`,
 * `scripts/session-end-hook.mjs`, etc.) call `recordEvent()` or the
 * batched `recordEvents()` to persist turn-by-turn events into the
 * `session_events` table. The timeline reader in `./timeline.ts`
 * then reassembles them into the replay stream.
 *
 * Distinct from the summary `sessions` table (one row per session)
 * and from `defence_audit` (one row per scan). Captures every event
 * with enough fidelity to scrub/replay.
 */

import { getDatabase } from '../database/init.js';

/**
 * Six kinds the schema CHECK constraint enforces. Keeping these in
 * sync with `schema.sql` is load-bearing — adding a new kind requires
 * both a schema migration and a code update here.
 */
export type SessionEventKind =
  | 'prompt'
  | 'response'
  | 'tool_call'
  | 'tool_result'
  | 'tool_error'
  | 'hook_fire';

export interface SessionEventInput {
  session_id: string;
  /** ISO-8601 timestamp string. Caller-supplied so import order is preserved. */
  ts: string;
  kind: SessionEventKind;
  /**
   * Payload — object (auto-serialised to JSON) or string (stored as-is).
   * Strings are kept verbatim so JSONL importers can pass through raw
   * content without double-encoding.
   */
  payload: unknown;
  project?: string | null;
  actor?: string | null;
  duration_ms?: number | null;
  audit_id?: number | null;
}

/**
 * Serialise payload to text. Objects/arrays go through JSON.stringify;
 * strings pass through. This keeps the column NOT NULL constraint
 * satisfied even for empty-object payloads and matches the timeline
 * reader's `JSON.parse` with raw-string fallback.
 */
function serialisePayload(payload: unknown): string {
  if (typeof payload === 'string') return payload;
  return JSON.stringify(payload ?? null);
}

const INSERT_SQL = `
  INSERT INTO session_events
    (session_id, project, ts, kind, actor, payload, duration_ms, audit_id)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`;

/** Insert one event row. Returns the new row id. */
export function recordEvent(input: SessionEventInput): number {
  const db = getDatabase();
  const stmt = db.prepare(INSERT_SQL);
  const result = stmt.run(
    input.session_id,
    input.project ?? null,
    input.ts,
    input.kind,
    input.actor ?? null,
    serialisePayload(input.payload),
    input.duration_ms ?? null,
    input.audit_id ?? null,
  );
  return Number(result.lastInsertRowid);
}

/**
 * Batched insert wrapped in a single transaction. Used when a hook
 * fires and produces several events at once (e.g. stop-hook emitting
 * a `response` plus N tool_call/tool_result pairs from the just-
 * finished turn). All-or-nothing: a CHECK violation rolls back the
 * lot, so the table never holds half a turn.
 */
export function recordEvents(inputs: readonly SessionEventInput[]): number[] {
  if (inputs.length === 0) return [];
  const db = getDatabase();
  const stmt = db.prepare(INSERT_SQL);
  const ids: number[] = [];
  const tx = db.transaction((rows: readonly SessionEventInput[]) => {
    for (const row of rows) {
      const result = stmt.run(
        row.session_id,
        row.project ?? null,
        row.ts,
        row.kind,
        row.actor ?? null,
        serialisePayload(row.payload),
        row.duration_ms ?? null,
        row.audit_id ?? null,
      );
      ids.push(Number(result.lastInsertRowid));
    }
  });
  tx(inputs);
  return ids;
}
