/**
 * Hook-side session_events writer.
 *
 * Mirrors the API of `src/sessions/capture.ts` but for `.mjs` hook
 * scripts that import `better-sqlite3` directly and can't reach into
 * the TS module without a build step. The two implementations write
 * the same rows and share the same dedupe constraints.
 *
 * Hooks (prompt-recall, stop, session-end, pre-compact) call
 * `recordSessionEvent(db, event)` with an already-open writable DB
 * connection. Failures are caught + logged at the call site so a
 * defective event capture never blocks the hook's primary job.
 */

const VALID_KINDS = new Set([
  'prompt',
  'response',
  'tool_call',
  'tool_result',
  'tool_error',
  'hook_fire',
]);

const INSERT_SQL = `
  INSERT INTO session_events
    (session_id, project, ts, kind, actor, payload, duration_ms, audit_id)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`;

/** Stringify payload — objects → JSON, strings pass through verbatim. */
function serialisePayload(payload) {
  if (typeof payload === 'string') return payload;
  return JSON.stringify(payload ?? null);
}

/**
 * Insert one event row. Returns the new row id, or `null` on validation
 * failure (the caller decides whether that's an error or expected —
 * e.g. session_id missing from hook data is "expected, skip" not "throw").
 *
 * Does NOT throw on SQL errors — the caller's hook flow must keep going.
 * Captures the error message and returns null so the hook can log it.
 */
export function recordSessionEvent(db, event) {
  if (!db || typeof db.prepare !== 'function') return null;
  if (!event || typeof event !== 'object') return null;
  if (typeof event.session_id !== 'string' || event.session_id.length === 0) return null;
  if (typeof event.ts !== 'string' || event.ts.length === 0) return null;
  if (!VALID_KINDS.has(event.kind)) return null;
  if (event.payload === undefined) return null;

  try {
    const stmt = db.prepare(INSERT_SQL);
    const result = stmt.run(
      event.session_id,
      event.project ?? null,
      event.ts,
      event.kind,
      event.actor ?? null,
      serialisePayload(event.payload),
      event.duration_ms ?? null,
      event.audit_id ?? null,
    );
    return Number(result.lastInsertRowid);
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Batched insert under a single transaction. Returns an array of
 * inserted row ids; rolls back the lot if any row violates a
 * constraint. Empty input returns [] without opening a transaction.
 */
export function recordSessionEvents(db, events) {
  if (!Array.isArray(events) || events.length === 0) return [];
  const stmt = db.prepare(INSERT_SQL);
  const ids = [];
  const tx = db.transaction((rows) => {
    for (const event of rows) {
      if (typeof event?.session_id !== 'string') {
        throw new Error('session_id required');
      }
      if (!VALID_KINDS.has(event.kind)) {
        throw new Error(`invalid kind: ${event.kind}`);
      }
      const result = stmt.run(
        event.session_id,
        event.project ?? null,
        event.ts,
        event.kind,
        event.actor ?? null,
        serialisePayload(event.payload),
        event.duration_ms ?? null,
        event.audit_id ?? null,
      );
      ids.push(Number(result.lastInsertRowid));
    }
  });
  tx(events);
  return ids;
}
