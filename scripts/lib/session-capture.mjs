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

import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

/**
 * #510: the ONE shared write-time PII redactor, from dist. Resolved once when
 * this module loads so both writers stay synchronous for their hook callers.
 * `null` when dist is missing or predates the redactor — see serialisePayload
 * for the fail-safe.
 */
const redactJsonForPersistence = await (async () => {
  try {
    const distRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist');
    const mod = await import(pathToFileURL(resolve(distRoot, 'defence', 'sensitivity', 'pii.js')).href);
    return typeof mod.redactJsonForPersistence === 'function' ? mod.redactJsonForPersistence : null;
  } catch {
    return null;
  }
})();

const VALID_KINDS = new Set([
  'prompt',
  'response',
  'tool_call',
  'tool_result',
  'tool_error',
  'hook_fire',
]);

// v4.28 (Fix #10): `sensitivity_level` carries the defence classifier verdict
// (PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED) so the dashboard replay UI
// can mask/strip rows that contain credentials or otherwise-sensitive prompts.
// Defaults to 'INTERNAL' for events written by callers that don't set it.
const INSERT_SQL = `
  INSERT INTO session_events
    (session_id, project, ts, kind, actor, payload, duration_ms, audit_id, sensitivity_level)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

const RAISED_LEVELS = new Set(['CONFIDENTIAL', 'RESTRICTED', 'SECRET']);
let warnedRedactorUnavailable = false;

/**
 * Redact, then stringify — objects → JSON, strings pass through. This is the
 * persistence boundary for every hook-written session event (single and batch),
 * the twin of `serialisePayload` in src/sessions/capture.ts.
 *
 * FAIL SAFE: with no redactor (or one that throws) the event is still recorded
 * — capture must not stop a hook — but never as ordinary INTERNAL text: the row
 * is stored at CONFIDENTIAL or above and the gap is reported on stderr.
 */
function persistable(event) {
  const level = event.sensitivity_level ?? 'INTERNAL';
  let payload = event.payload;
  let sensitivity = level;
  try {
    if (!redactJsonForPersistence) throw new Error('unavailable');
    payload = redactJsonForPersistence(payload);
  } catch {
    sensitivity = RAISED_LEVELS.has(level) ? level : 'CONFIDENTIAL';
    if (!warnedRedactorUnavailable) {
      warnedRedactorUnavailable = true;
      process.stderr.write('[shieldcortex session-capture] PII redactor unavailable — storing unredacted at raised sensitivity\n');
    }
  }
  return {
    payload: typeof payload === 'string' ? payload : JSON.stringify(payload ?? null),
    sensitivity,
  };
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
    const safe = persistable(event);
    const result = stmt.run(
      event.session_id,
      event.project ?? null,
      event.ts,
      event.kind,
      event.actor ?? null,
      safe.payload,
      event.duration_ms ?? null,
      event.audit_id ?? null,
      safe.sensitivity,
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
      const safe = persistable(event);
      const result = stmt.run(
        event.session_id,
        event.project ?? null,
        event.ts,
        event.kind,
        event.actor ?? null,
        safe.payload,
        event.duration_ms ?? null,
        event.audit_id ?? null,
        safe.sensitivity,
      );
      ids.push(Number(result.lastInsertRowid));
    }
  });
  tx(events);
  return ids;
}
