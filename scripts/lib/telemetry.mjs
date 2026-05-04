/**
 * Hook-invocation telemetry.
 *
 * Records every hook firing so `shieldcortex status` can show "fires but
 * extracts nothing" failure modes (previously indistinguishable from
 * "never fires"). Schema mirrors the migration in src/database/init.ts.
 */

let schemaEnsured = false;

function ensureSchema(db) {
  if (schemaEnsured) return;
  db.exec(`
    CREATE TABLE IF NOT EXISTS hook_invocations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hook_name TEXT NOT NULL,
      invoked_at TEXT NOT NULL DEFAULT (datetime('now')),
      exit_code INTEGER,
      duration_ms INTEGER,
      memories_extracted INTEGER DEFAULT 0,
      transcript_bytes INTEGER,
      notes TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_hook_invocations_name_time ON hook_invocations(hook_name, invoked_at DESC);
  `);
  schemaEnsured = true;
}

/**
 * Insert a single hook-invocation row. All fields except hook_name are
 * optional. Wrapped in try/catch — telemetry must never block a hook.
 *
 * `invoked_at` is supplied as an explicit ISO-8601 UTC string (with `Z`)
 * rather than relying on the SCHEMA's `datetime('now')` default — that
 * default returns a naive `YYYY-MM-DD HH:MM:SS` string with no timezone,
 * which JS Date() then interprets as local time and renders status
 * timestamps off by the local UTC offset.
 */
export function recordHookInvocation(db, info) {
  try {
    ensureSchema(db);
    db.prepare(`
      INSERT INTO hook_invocations
        (hook_name, invoked_at, exit_code, duration_ms, memories_extracted, transcript_bytes, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      info.hookName,
      new Date().toISOString(),
      info.exitCode ?? null,
      info.durationMs ?? null,
      info.memoriesExtracted ?? 0,
      info.transcriptBytes ?? null,
      info.notes ?? null,
    );
  } catch (err) {
    console.error(`[telemetry] Failed to record ${info?.hookName} invocation: ${err?.message}`);
  }
}
