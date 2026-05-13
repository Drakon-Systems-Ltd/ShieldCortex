/**
 * Session capture — read side.
 *
 * `getTimeline(sessionId)` returns every event for a session, sorted
 * by `ts` ascending, with payload JSON.parse'd back into a JS value
 * (or surfaced as a raw string when the payload was deliberately
 * stored as plain text). Powers the dashboard replay scrubber.
 *
 * Kept deliberately minimal — pagination, filtering by kind, and
 * cross-session timelines belong on the API route (`./api/routes/
 * sessions.ts`) above, not in this reader.
 */

import { getDatabase } from '../database/init.js';
import type { SessionEventKind } from './capture.js';

export interface SessionEventRow {
  id: number;
  session_id: string;
  project: string | null;
  ts: string;
  kind: SessionEventKind;
  actor: string | null;
  /** Parsed JSON (object/array/primitive) or raw string fall-through. */
  payload: unknown;
  duration_ms: number | null;
  audit_id: number | null;
  created_at: string;
}

interface RawRow {
  id: number;
  session_id: string;
  project: string | null;
  ts: string;
  kind: SessionEventKind;
  actor: string | null;
  payload: string;
  duration_ms: number | null;
  audit_id: number | null;
  created_at: string;
}

/**
 * Reverse of `capture.serialisePayload`: try JSON.parse, fall back to
 * the raw string if the payload was stored as plain text. We don't
 * throw on un-parseable — the importer may legitimately ingest non-JSON
 * tool output, and a replay viewer that crashes on bad data is useless.
 */
function deserialisePayload(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function hydrate(row: RawRow): SessionEventRow {
  return {
    id: row.id,
    session_id: row.session_id,
    project: row.project,
    ts: row.ts,
    kind: row.kind,
    actor: row.actor,
    payload: deserialisePayload(row.payload),
    duration_ms: row.duration_ms,
    audit_id: row.audit_id,
    created_at: row.created_at,
  };
}

/** All events for a session, in `ts` ascending order. */
export function getTimeline(sessionId: string): SessionEventRow[] {
  const db = getDatabase();
  const rows = db
    .prepare(
      `SELECT id, session_id, project, ts, kind, actor, payload, duration_ms, audit_id, created_at
       FROM session_events
       WHERE session_id = ?
       ORDER BY ts ASC, id ASC`,
    )
    .all(sessionId) as RawRow[];
  return rows.map(hydrate);
}
