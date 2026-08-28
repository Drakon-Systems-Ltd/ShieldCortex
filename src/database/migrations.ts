/**
 * Schema migrations for existing ShieldCortex databases (extracted from
 * src/database/init.ts in v4.26.0 to keep init.ts focused on connection
 * lifecycle).
 *
 * `runMigrations()` is called during `initDatabase()` AFTER the connection is
 * open but BEFORE the inline/file schema (`CREATE TABLE IF NOT EXISTS`)
 * is applied. The split lets us:
 *   - ALTER TABLE pre-existing rows for new columns the schema introduces
 *   - Backfill data into those columns
 *   - Create extra tables (Pro-feature surface, knowledge graph, sync queue)
 *     that the canonical schema file may not yet declare on older installs
 *
 * Most migrations here are idempotent — guarded by either `IF NOT EXISTS`
 * (CREATE TABLE / CREATE INDEX) or a `PRAGMA table_info(...)` check before
 * `ALTER TABLE ADD COLUMN`. The broad try/catch blocks around the larger
 * DDL clusters use `logIfUnexpectedDdlError` to keep idempotent re-runs
 * silent while still surfacing genuinely-unexpected failures (disk full,
 * permission denied, schema corruption, FK conflict).
 *
 * Adding a new migration: add a guarded block at the end of this function.
 * NEVER reorder existing migrations — that breaks upgrade paths on older
 * databases that have only partially run them.
 */

import type Database from 'better-sqlite3';
import { randomUUID } from 'crypto';

/**
 * Log unexpected errors from idempotent DDL operations (v4.26.0).
 *
 * Most schema migrations are guarded by either:
 *   - `IF NOT EXISTS` (CREATE TABLE / CREATE INDEX), or
 *   - A PRAGMA check (ALTER TABLE ADD COLUMN, only fires when column missing)
 *
 * Those guards mean the typical re-run case is silent and safe. But the broad
 * `catch {}` blocks that wrap them also swallow genuinely-unexpected failures
 * (disk full, permission denied, schema corruption, FK conflict). This helper
 * filters known-idempotent SQLite errors but surfaces anything else on stderr
 * so the doctor / operator can spot real problems.
 */
export function logIfUnexpectedDdlError(err: unknown, op: string): void {
  const msg = err instanceof Error ? err.message : String(err);
  // SQLite errors that are EXPECTED on partial-migration re-runs.
  const expected = [
    /already exists/i,
    /duplicate column/i,
    /no such table/i, // PRAGMA on a missing table when guarding ALTERs
    /no such column/i,
    /no such index/i,
  ];
  if (expected.some((p) => p.test(msg))) return;
  console.error(`[database] unexpected migration error in ${op}: ${msg}`);
}

/**
 * Run database migrations for existing databases.
 *
 * Skips entirely on fresh databases (the schema file creates everything in
 * its post-migration form). For existing databases, it walks every
 * column-add / table-create / backfill that has shipped across ShieldCortex
 * v1.x → v4.x.
 */
export function runMigrations(database: Database.Database): void {
  // Check if memories table exists (skip migrations on fresh database)
  const tableExists = database.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name='memories'"
  ).get();

  if (!tableExists) {
    // Fresh database - schema will create everything
    return;
  }

  // Check existing columns
  const tableInfo = database.prepare("PRAGMA table_info(memories)").all() as { name: string }[];
  const columnNames = new Set(tableInfo.map(col => col.name));

  // Migration: decayed_score column
  if (!columnNames.has('decayed_score')) {
    database.exec('ALTER TABLE memories ADD COLUMN decayed_score REAL');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_decayed_score ON memories(decayed_score DESC)');
  }

  // Migration: embedding column for semantic search
  if (!columnNames.has('embedding')) {
    database.exec('ALTER TABLE memories ADD COLUMN embedding BLOB');
  }

  // Migration: scope column for cross-project knowledge
  if (!columnNames.has('scope')) {
    database.exec("ALTER TABLE memories ADD COLUMN scope TEXT DEFAULT 'project'");
  }

  // Migration: transferable column for cross-project sharing
  if (!columnNames.has('transferable')) {
    database.exec('ALTER TABLE memories ADD COLUMN transferable INTEGER DEFAULT 0');
  }

  // Migration: Defence columns on memories table
  if (!columnNames.has('trust_score')) {
    database.exec("ALTER TABLE memories ADD COLUMN trust_score REAL DEFAULT 1.0");
  }
  if (!columnNames.has('sensitivity_level')) {
    database.exec("ALTER TABLE memories ADD COLUMN sensitivity_level TEXT DEFAULT 'INTERNAL'");
  }
  if (!columnNames.has('source')) {
    database.exec("ALTER TABLE memories ADD COLUMN source TEXT DEFAULT 'user:direct'");
  }
  if (!columnNames.has('status')) {
    database.exec("ALTER TABLE memories ADD COLUMN status TEXT DEFAULT 'active'");
  }
  if (!columnNames.has('pinned')) {
    database.exec('ALTER TABLE memories ADD COLUMN pinned INTEGER DEFAULT 0');
  }
  if (!columnNames.has('reviewed_at')) {
    database.exec('ALTER TABLE memories ADD COLUMN reviewed_at TIMESTAMP');
  }
  if (!columnNames.has('reviewed_by')) {
    database.exec('ALTER TABLE memories ADD COLUMN reviewed_by TEXT');
  }
  if (!columnNames.has('source_kind')) {
    database.exec("ALTER TABLE memories ADD COLUMN source_kind TEXT DEFAULT 'user'");
  }
  if (!columnNames.has('capture_method')) {
    database.exec("ALTER TABLE memories ADD COLUMN capture_method TEXT DEFAULT 'manual'");
  }
  if (!columnNames.has('cloud_excluded')) {
    database.exec('ALTER TABLE memories ADD COLUMN cloud_excluded INTEGER DEFAULT 0');
  }
  if (!columnNames.has('uuid')) {
    database.exec("ALTER TABLE memories ADD COLUMN uuid TEXT");
  }
  if (!columnNames.has('updated_at')) {
    database.exec('ALTER TABLE memories ADD COLUMN updated_at TIMESTAMP');
  }
  try {
    const rowsWithoutUuid = database.prepare('SELECT id FROM memories WHERE uuid IS NULL OR uuid = ?').all('') as { id: number }[];
    const setUuid = database.prepare('UPDATE memories SET uuid = ? WHERE id = ?');
    for (const row of rowsWithoutUuid) {
      setUuid.run(randomUUID(), row.id);
    }
    database.exec('UPDATE memories SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP) WHERE updated_at IS NULL');
    database.exec("UPDATE memories SET status = COALESCE(status, 'active') WHERE status IS NULL OR status = ''");
    database.exec('UPDATE memories SET pinned = COALESCE(pinned, 0) WHERE pinned IS NULL');
    database.exec(`
      UPDATE memories
      SET source = CASE
        WHEN source = 'user:direct' AND tags LIKE '%session-end%' THEN 'hook:openclaw-session-end'
        WHEN source = 'user:direct' AND tags LIKE '%session-stop%' THEN 'hook:openclaw-session-stop'
        WHEN source = 'user:direct' AND tags LIKE '%keyword-trigger%' THEN 'hook:openclaw-keyword'
        WHEN source IS NULL AND tags LIKE '%llm-output%' THEN 'agent:openclaw-plugin'
        ELSE source
      END
      WHERE
        (source = 'user:direct' OR source IS NULL)
        AND (
          tags LIKE '%session-end%'
          OR tags LIKE '%session-stop%'
          OR tags LIKE '%keyword-trigger%'
          OR tags LIKE '%llm-output%'
          OR tags LIKE '%realtime-plugin%'
          OR tags LIKE '%openclaw-hook%'
        )
    `);
    database.exec("UPDATE memories SET source_kind = CASE WHEN source LIKE 'hook:%' THEN 'hook' WHEN source LIKE 'api:%' THEN 'api' WHEN source LIKE 'agent:%' THEN 'agent' WHEN source LIKE 'cli:%' THEN 'cli' ELSE COALESCE(source_kind, 'user') END WHERE source_kind IS NULL OR source_kind = ''");
    database.exec("UPDATE memories SET capture_method = CASE WHEN tags LIKE '%auto-extracted%' THEN 'auto' WHEN source_kind = 'hook' THEN 'hook' WHEN source_kind = 'api' THEN 'api' WHEN source_kind = 'agent' THEN 'plugin' WHEN source_kind = 'cli' THEN 'manual' ELSE COALESCE(capture_method, 'manual') END WHERE capture_method IS NULL OR capture_method = ''");
    database.exec(`
      UPDATE memories
      SET source_kind = CASE
        WHEN tags LIKE '%session-end%' OR tags LIKE '%session-stop%' OR tags LIKE '%keyword-trigger%' OR tags LIKE '%openclaw-hook%' THEN 'hook'
        WHEN tags LIKE '%llm-output%' OR tags LIKE '%realtime-plugin%' THEN 'agent'
        ELSE source_kind
      END,
      capture_method = CASE
        WHEN tags LIKE '%session-end%' OR tags LIKE '%session-stop%' OR tags LIKE '%openclaw-hook%' THEN 'auto'
        WHEN tags LIKE '%keyword-trigger%' THEN 'hook'
        WHEN tags LIKE '%llm-output%' OR tags LIKE '%realtime-plugin%' THEN 'auto'
        ELSE capture_method
      END
      WHERE
        tags LIKE '%session-end%'
        OR tags LIKE '%session-stop%'
        OR tags LIKE '%keyword-trigger%'
        OR tags LIKE '%openclaw-hook%'
        OR tags LIKE '%llm-output%'
        OR tags LIKE '%realtime-plugin%'
    `);
    database.exec('UPDATE memories SET cloud_excluded = COALESCE(cloud_excluded, 0) WHERE cloud_excluded IS NULL');
    database.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_uuid ON memories(uuid)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(updated_at DESC)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_status ON memories(status)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_pinned ON memories(pinned DESC)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_source_kind ON memories(source_kind)');
  } catch (err) {
    logIfUnexpectedDdlError(err, 'memories indexes + uuid backfill');
    // Note: idempotent failures (re-run, columns already present) stay silent.
  }

  // Migration: Defence tables (defence_audit, quarantine, fragmentation_entities)
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS defence_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id INTEGER,
        project TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_type TEXT NOT NULL,
        source_identifier TEXT NOT NULL,
        trust_score REAL NOT NULL,
        sensitivity_level TEXT NOT NULL DEFAULT 'INTERNAL',
        firewall_result TEXT NOT NULL CHECK(firewall_result IN ('ALLOW', 'BLOCK', 'QUARANTINE')),
        anomaly_score REAL DEFAULT 0.0,
        threat_indicators TEXT DEFAULT '[]',
        blocked_patterns TEXT DEFAULT '[]',
        reason TEXT,
        fragmentation_score REAL,
        pipeline_duration_ms INTEGER,
        FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_memory ON defence_audit(memory_id);
      CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON defence_audit(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_result ON defence_audit(firewall_result);
      CREATE INDEX IF NOT EXISTS idx_audit_source ON defence_audit(source_type);
      CREATE INDEX IF NOT EXISTS idx_audit_project ON defence_audit(project);

      CREATE TABLE IF NOT EXISTS quarantine (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_content TEXT NOT NULL,
        original_title TEXT,
        project TEXT,
        source_type TEXT NOT NULL,
        source_identifier TEXT NOT NULL,
        reason TEXT NOT NULL,
        threat_indicators TEXT DEFAULT '[]',
        anomaly_score REAL DEFAULT 0.0,
        firewall_result TEXT NOT NULL CHECK(firewall_result IN ('BLOCK', 'QUARANTINE')),
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected', 'expired')),
        reviewed_at TIMESTAMP,
        reviewed_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        audit_id INTEGER,
        FOREIGN KEY (audit_id) REFERENCES defence_audit(id) ON DELETE SET NULL
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_status ON quarantine(status);
      CREATE INDEX IF NOT EXISTS idx_quarantine_created ON quarantine(created_at DESC);

      CREATE TABLE IF NOT EXISTS quarantine_annotations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        suggested_action TEXT NOT NULL,
        confidence REAL NOT NULL,
        similar_group_key TEXT,
        copilot_version TEXT NOT NULL,
        annotation_json TEXT NOT NULL,
        generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (item_id) REFERENCES quarantine(id) ON DELETE CASCADE,
        UNIQUE(item_id, copilot_version)
      );
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_item ON quarantine_annotations(item_id);
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_category ON quarantine_annotations(category);
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_action ON quarantine_annotations(suggested_action);
      CREATE INDEX IF NOT EXISTS idx_quarantine_annotations_group ON quarantine_annotations(similar_group_key);

      CREATE TABLE IF NOT EXISTS fragmentation_entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        memory_id INTEGER NOT NULL,
        entity_value TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        context_snippet TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_frag_entities_memory ON fragmentation_entities(memory_id);
      CREATE INDEX IF NOT EXISTS idx_frag_entities_text ON fragmentation_entities(entity_value);
      CREATE INDEX IF NOT EXISTS idx_frag_entities_type ON fragmentation_entities(entity_type);

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
  } catch (err) {
    logIfUnexpectedDdlError(err, 'fragmentation_entities + hook_invocations tables');
  }

  // Migration: project column on defence_audit and quarantine tables
  try {
    const auditCols = database.prepare("PRAGMA table_info(defence_audit)").all() as { name: string }[];
    if (auditCols.length > 0 && !auditCols.some(c => c.name === 'project')) {
      database.exec('ALTER TABLE defence_audit ADD COLUMN project TEXT');
      database.exec('CREATE INDEX IF NOT EXISTS idx_audit_project ON defence_audit(project)');
    }
    const quarantineCols = database.prepare("PRAGMA table_info(quarantine)").all() as { name: string }[];
    if (quarantineCols.length > 0 && !quarantineCols.some(c => c.name === 'project')) {
      database.exec('ALTER TABLE quarantine ADD COLUMN project TEXT');
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'defence_audit/quarantine project column add');
  }

  // Backfill: set project on defence_audit/quarantine entries that have NULL project
  try {
    const nullCount = (database.prepare(
      "SELECT COUNT(*) as cnt FROM defence_audit WHERE project IS NULL"
    ).get() as { cnt: number })?.cnt ?? 0;
    if (nullCount > 0) {
      // From linked memories
      database.exec(`UPDATE defence_audit SET project = (
        SELECT m.project FROM memories m WHERE m.id = defence_audit.memory_id
      ) WHERE memory_id IS NOT NULL AND project IS NULL`);
      // Remaining: use most common project
      database.exec(`UPDATE defence_audit SET project = (
        SELECT project FROM memories WHERE project IS NOT NULL GROUP BY project ORDER BY COUNT(*) DESC LIMIT 1
      ) WHERE project IS NULL`);
    }
    const qNullCount = (database.prepare(
      "SELECT COUNT(*) as cnt FROM quarantine WHERE project IS NULL"
    ).get() as { cnt: number })?.cnt ?? 0;
    if (qNullCount > 0) {
      database.exec(`UPDATE quarantine SET project = (
        SELECT project FROM memories WHERE project IS NOT NULL GROUP BY project ORDER BY COUNT(*) DESC LIMIT 1
      ) WHERE project IS NULL`);
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'defence_audit/quarantine project backfill (data migration)');
  }

  // Migration: sync_queue table for cloud sync retry
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS sync_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        payload TEXT NOT NULL,
        attempts INTEGER DEFAULT 0,
        max_attempts INTEGER DEFAULT 3,
        next_retry_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','failed','synced')),
        last_error TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        synced_at TEXT,
        lease_owner TEXT,
        lease_token TEXT,
        lease_expires_at TEXT,
        delivery_key TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_sync_queue_status_retry ON sync_queue(status, next_retry_at);
      CREATE INDEX IF NOT EXISTS idx_sync_queue_lease_exp ON sync_queue(lease_expires_at);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_queue_delivery_key
        ON sync_queue(delivery_key) WHERE delivery_key IS NOT NULL;
    `);
  } catch (err) {
    logIfUnexpectedDdlError(err, 'sync_queue table + index');
  }

  // Migration: Ontology tables (entities, triples, memory_entities)
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        aliases TEXT DEFAULT '[]',
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        memory_count INTEGER DEFAULT 0,
        UNIQUE(name, type)
      );
      CREATE INDEX IF NOT EXISTS idx_entities_name ON entities(name);
      CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);

      CREATE TABLE IF NOT EXISTS triples (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id INTEGER NOT NULL,
        predicate TEXT NOT NULL,
        object_id INTEGER NOT NULL,
        source_memory_id INTEGER,
        confidence REAL DEFAULT 0.8,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (subject_id) REFERENCES entities(id) ON DELETE CASCADE,
        FOREIGN KEY (object_id) REFERENCES entities(id) ON DELETE CASCADE,
        FOREIGN KEY (source_memory_id) REFERENCES memories(id) ON DELETE SET NULL,
        UNIQUE(subject_id, predicate, object_id)
      );
      CREATE INDEX IF NOT EXISTS idx_triples_subject ON triples(subject_id);
      CREATE INDEX IF NOT EXISTS idx_triples_object ON triples(object_id);
      CREATE INDEX IF NOT EXISTS idx_triples_predicate ON triples(predicate);

      CREATE TABLE IF NOT EXISTS memory_entities (
        memory_id INTEGER NOT NULL,
        entity_id INTEGER NOT NULL,
        role TEXT DEFAULT 'mention',
        FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE,
        FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
        PRIMARY KEY (memory_id, entity_id)
      );
    `);
  } catch (err) {
    logIfUnexpectedDdlError(err, 'knowledge-graph tables (entities/triples/memory_entities)');
  }

  // Migration: graph_extraction_version column for incremental graph backfill
  if (!columnNames.has('graph_extraction_version')) {
    database.exec('ALTER TABLE memories ADD COLUMN graph_extraction_version INTEGER DEFAULT 0');
  }


  // Migration: v4.0.0 — memory_purpose for type taxonomy
  if (!columnNames.has('memory_purpose')) {
    database.exec("ALTER TABLE memories ADD COLUMN memory_purpose TEXT DEFAULT 'project'");
  }

  // Migration: v4.0.0 — memory_scope for private/team visibility
  if (!columnNames.has('memory_scope')) {
    database.exec("ALTER TABLE memories ADD COLUMN memory_scope TEXT DEFAULT 'private'");
  }

  // Migration: v4.25.0 — downvote_count for negative-feedback salience.
  // When a user marks a memory unhelpful via `shieldcortex memory downvote
  // <id>`, the count grows and the recall hook's effective-salience
  // calculation multiplies in a (1 - 0.3 × n) penalty (floored at 0.1).
  if (!columnNames.has('downvote_count')) {
    database.exec('ALTER TABLE memories ADD COLUMN downvote_count INTEGER DEFAULT 0');
  }
  if (!columnNames.has('last_downvoted_at')) {
    database.exec('ALTER TABLE memories ADD COLUMN last_downvoted_at TIMESTAMP');
  }

  // Migration: P1/WS3 (issue #60) — defence_verdict provenance column.
  // ADD COLUMN with the 'unverified' default; then a one-time backfill labels
  // every PRE-invariant row 'legacy' (they predate provenance enforcement), so
  // 'unverified' is reserved for post-migration writes that bypassed the funnel.
  // Non-destructive (a brand-new column), so it needs no file snapshot; guarded
  // run-once by a sentinel table (the .dump-survivable guard the salience
  // backfill uses, not user_version). The BEFORE INSERT provenance trigger and
  // the fresh-schema column both come from schema.sql (CREATE ... IF NOT EXISTS),
  // which runs after this on both fresh and existing DBs.
  if (!columnNames.has('defence_verdict')) {
    database.exec("ALTER TABLE memories ADD COLUMN defence_verdict TEXT DEFAULT 'unverified'");
    const backfilled = database.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='memories_provenance_backfilled'",
    ).get();
    if (!backfilled) {
      const tx = database.transaction(() => {
        database.exec("UPDATE memories SET defence_verdict = 'legacy' WHERE defence_verdict IS NULL OR defence_verdict = 'unverified'");
        database.exec('CREATE TABLE IF NOT EXISTS memories_provenance_backfilled (done INTEGER)');
      });
      tx.immediate();
    }
  }
  // Sparse partial index — only indexes rows that have been downvoted.
  // Cheap to maintain (most rows never downvoted) and lets the CLI list
  // downvoted memories without a full scan.
  database.exec(
    'CREATE INDEX IF NOT EXISTS idx_memories_downvote_count ON memories(downvote_count) WHERE downvote_count > 0',
  );

  // Migration: Pro feature tables (custom_patterns, iron_dome_policies, firewall_rules)
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS custom_patterns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'custom',
        severity TEXT NOT NULL DEFAULT 'medium' CHECK(severity IN ('critical', 'high', 'medium', 'low')),
        regex TEXT NOT NULL,
        description TEXT DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_custom_patterns_enabled ON custom_patterns(enabled);

      CREATE TABLE IF NOT EXISTS iron_dome_policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT DEFAULT '',
        config TEXT NOT NULL DEFAULT '{}',
        is_active INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_dome_policies_active ON iron_dome_policies(is_active) WHERE is_active = 1;

      CREATE TABLE IF NOT EXISTS firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 100,
        condition_type TEXT NOT NULL,
        condition_value TEXT NOT NULL,
        action TEXT NOT NULL CHECK(action IN ('block', 'allow', 'quarantine')),
        enabled INTEGER NOT NULL DEFAULT 1,
        built_in INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_firewall_rules_priority ON firewall_rules(priority);
      CREATE INDEX IF NOT EXISTS idx_firewall_rules_enabled ON firewall_rules(enabled);
      CREATE INDEX IF NOT EXISTS idx_firewall_rules_built_in ON firewall_rules(built_in);

      CREATE TABLE IF NOT EXISTS rate_limits (
        source_key TEXT PRIMARY KEY,
        write_count INTEGER NOT NULL DEFAULT 1,
        window_start_ms INTEGER NOT NULL
      );
    `);
  } catch (err) {
    logIfUnexpectedDdlError(err, 'firewall_rules + rate_limits tables');
  }

  // Migration: built_in column on pre-existing firewall_rules (added in v4.15)
  try {
    const cols = database.prepare("PRAGMA table_info(firewall_rules)").all() as { name: string }[];
    if (!cols.some(c => c.name === 'built_in')) {
      database.exec('ALTER TABLE firewall_rules ADD COLUMN built_in INTEGER NOT NULL DEFAULT 0');
      database.exec('CREATE INDEX IF NOT EXISTS idx_firewall_rules_built_in ON firewall_rules(built_in)');
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'firewall_rules.built_in column add');
    // (pipeline handles missing column gracefully; this is informational)
  }

  // Built-in firewall rule seeding now lives in `initDatabase()` AFTER the
  // schema is applied — `runMigrations()` returns early on fresh databases
  // (no `memories` table), so a seed call here never fired for new installs.
  // The init-level call is idempotent and covers both fresh and existing DBs.

  // Migration: session_events.content_hash + dedupe UNIQUE index (v4.17).
  // DBs created between the foundation commit and the importer commit have
  // session_events but no content_hash column. ALTER + idempotent index
  // upgrades them without touching fresh installs (schema.sql handles those).
  try {
    const sessionEventsTable = database
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='session_events'")
      .get();
    if (sessionEventsTable) {
      const sessionCols = database
        .prepare("PRAGMA table_info(session_events)")
        .all() as { name: string }[];
      const sessionColNames = new Set(sessionCols.map((c) => c.name));
      if (!sessionColNames.has('content_hash')) {
        database.exec('ALTER TABLE session_events ADD COLUMN content_hash TEXT');
      }
      database.exec(
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_session_events_dedupe ON session_events(session_id, ts, kind, content_hash)',
      );
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'session_events.content_hash column + dedupe index');
    // (importer-side INSERT OR IGNORE handles missing index gracefully)
  }

  // Migration: session_events.sensitivity_level (v4.28 — Fix #10).
  //
  // Without this, the UserPromptSubmit hook captured the raw prompt verbatim
  // (no pipeline, no credential scan, no sensitivity tag). The column lets
  // the hook record the defence classifier's verdict alongside the redacted
  // text so the dashboard's replay UI can mask/strip RESTRICTED rows.
  // Defaults to 'INTERNAL' for backfilled rows + future callers that omit it.
  try {
    const sessionEventsTable = database
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='session_events'")
      .get();
    if (sessionEventsTable) {
      const sessionCols = database
        .prepare("PRAGMA table_info(session_events)")
        .all() as { name: string }[];
      const sessionColNames = new Set(sessionCols.map((c) => c.name));
      if (!sessionColNames.has('sensitivity_level')) {
        database.exec(
          "ALTER TABLE session_events ADD COLUMN sensitivity_level TEXT DEFAULT 'INTERNAL'",
        );
      }
      database.exec(
        'CREATE INDEX IF NOT EXISTS idx_session_events_sensitivity ON session_events(sensitivity_level)',
      );
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'session_events.sensitivity_level column + index');
  }

  // ---------------------------------------------------------------------------
  // Migration: v4.29.0 — one-time salience-wall backfill (clamp-only).
  //
  // Historically ~80% of stored memories landed at salience=1.0 (the "wall"),
  // collapsing salience as a ranking signal. That stale 1.0 data is all
  // machine-generated (auto / legacy-migrate / plugin captures). Forward-only
  // fixes never cleaned it, so this self-healing auto-migration clamps those
  // rows down to a flat 0.6 on the next process startup after updating.
  //
  // SCOPE IS CLAMP-ONLY. We deliberately do NOT re-derive category or
  // memory_purpose — live data proved the title-prefix heuristic is not
  // authoritative and re-deriving corrupts already-correct labels. The ONLY
  // mutation is lowering salience.
  //
  // Untouched: manual/user rows (explicit user input), pinned rows, and
  // canonical rows. updated_at is intentionally NOT re-stamped — these rows
  // were not user-edited, and re-stamping would trigger a fleet-wide cloud
  // re-sync burst.
  //
  // Run-once guard = existence of `memories_backfill_backup` (NOT user_version,
  // which `.dump`-based disaster recovery does not preserve; the table does).
  // The backup table also powers the revert path (Task 5).
  //
  // This block owns a LOUD catch (NOT logIfUnexpectedDdlError) — a data
  // backfill failure must be visible and retried, not swallowed as idempotent.
  try {
    // Clamp predicate — flat 0.6 for machine rows; manual/user/pinned/canonical
    // untouched. COALESCE guards old fleet DBs with NULL pinned/status.
    const CLAMP_WHERE = `
        salience > 0.6
        AND COALESCE(pinned, 0) = 0
        AND COALESCE(status, 'active') != 'canonical'
        AND capture_method IN ('auto', 'legacy-migrate', 'plugin')`;

    // Run-once guard (outside the txn): if the box already self-healed, bail
    // before doing any FTS or write work.
    const alreadyDone = database.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories_backfill_backup'"
    ).get();

    if (!alreadyDone) {
      // FTS rebuild FIRST, in its own try/catch (B3). On a drifted-FTS DB the
      // per-row memories_au trigger throws "database disk image is malformed"
      // mid-UPDATE and aborts everything. Repairing the index up front means
      // the trigger firings during the clamp won't throw. A rebuild failure
      // here must NOT abort the backfill, so it is isolated.
      try {
        database.exec("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')");
      } catch (ftsErr) {
        const msg = ftsErr instanceof Error ? ftsErr.message : String(ftsErr);
        console.error(`[backfill v4.29.0] FTS rebuild skipped (continuing): ${msg}`);
      }

      // Backup-table creation + the clamp UPDATE in a SINGLE IMMEDIATE
      // transaction (B4). IMMEDIATE grabs the write lock at BEGIN, closing the
      // read-gate -> write race so five concurrent runMigrations processes
      // serialise cleanly. The guard is RE-READ inside the txn: a concurrent
      // winner may have created the table between our outer check and the lock.
      let clamped = 0;
      const run = database.transaction(() => {
        const winnerCreatedTable = database.prepare(
          "SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories_backfill_backup'"
        ).get();
        if (winnerCreatedTable) {
          return; // a concurrent winner already created the table; no-op
        }

        // Back up just the mutated column (clamp-only). Doubles as the run-once
        // guard: even a zero-row match creates the (empty) table so the box
        // never re-scans on subsequent startups.
        database.exec(`
          CREATE TABLE IF NOT EXISTS memories_backfill_backup AS
          SELECT id, salience, datetime('now') AS backed_up_at
          FROM memories
          WHERE ${CLAMP_WHERE}
        `);

        const res = database.prepare(
          `UPDATE memories SET salience = 0.6 WHERE ${CLAMP_WHERE}`
        ).run();
        clamped = res.changes;
      });
      run.immediate();

      // SUCCESS marker (after commit) so the fleet rollout is observable via the
      // existing cloud audit ingest. firewall_result is constrained to
      // ALLOW/BLOCK/QUARANTINE — this is an informational ALLOW marker.
      // ORDERING DEPENDENCY: both markers INSERT into `defence_audit`, which is
      // created earlier in this same function — keep the table migration ahead
      // of this backfill block or the markers will silently no-op (caught below).
      //
      // GATED on clamped > 0: a run that healed nothing (fresh DB, or a box with
      // no stale machine rows) still creates the run-once guard table, but must
      // NOT emit a "healed" telemetry row. An unconditional marker was genuine
      // noise AND tripped the defence-pipeline-bypass invariant (every
      // saveAutoExtractedMemory must produce exactly one defence_audit row —
      // a spurious migration marker made it two).
      if (clamped > 0) {
        try {
          database.prepare(`
            INSERT INTO defence_audit (
              memory_id, project, timestamp,
              source_type, source_identifier,
              trust_score, sensitivity_level, firewall_result,
              anomaly_score, threat_indicators, blocked_patterns,
              reason, fragmentation_score, pipeline_duration_ms
            ) VALUES (NULL, NULL, ?, 'migration', 'backfill-v4.29.0', 1.0, 'INTERNAL', 'ALLOW', 0, '[]', '[]', ?, NULL, 0)
          `).run(
            new Date().toISOString(),
            JSON.stringify({ status: 'success', clamped, version: 'v4.29.0' }),
          );
        } catch {
          // Older schemas may predate the audit columns. The success path itself
          // already committed; the marker is best-effort observability only.
        }
      }
    }
  } catch (err) {
    // LOUD catch — do NOT route through logIfUnexpectedDdlError. Because the
    // guard table is created INSIDE the rolled-back transaction, a failure here
    // leaves NO guard, so the box cleanly retries on next startup.
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[backfill v4.29.0] FAILED, will retry next startup: ${msg}`);
    try {
      database.prepare(`
        INSERT INTO defence_audit (
          memory_id, project, timestamp,
          source_type, source_identifier,
          trust_score, sensitivity_level, firewall_result,
          anomaly_score, threat_indicators, blocked_patterns,
          reason, fragmentation_score, pipeline_duration_ms
        ) VALUES (NULL, NULL, ?, 'migration', 'backfill-v4.29.0', 0, 'INTERNAL', 'BLOCK', 0, '[]', '[]', ?, NULL, 0)
      `).run(
        new Date().toISOString(),
        JSON.stringify({ status: 'failed', error: msg, version: 'v4.29.0' }),
      );
    } catch {
      // Best-effort marker; the stderr line above carries the signal.
    }
  }

  // Migration: control_state table (cross-process kill-switch / pause).
  //
  // Phase 2 hardening: the kill switch / pause mode used to live only in
  // module-level memory, so a dashboard (API process) activation never reached
  // the separate MCP server process. control_state is the single-row source of
  // truth both processes read/write; api/control.ts persists to and refreshes
  // from it. Existing DBs that predate the table get it here (schema.sql /
  // inline-schema.ts cover fresh installs).
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS control_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        mode TEXT NOT NULL DEFAULT 'active' CHECK (mode IN ('active','paused','kill_switch')),
        meta_json TEXT,
        updated_at TEXT NOT NULL
      );
    `);
  } catch (err) {
    logIfUnexpectedDdlError(err, 'control_state');
  }

  // Migration: audit_aggregates table (Phase 8a — bound defence_audit growth).
  //
  // defence_audit grows on every pipeline run with no DELETE anywhere, so a busy
  // agent eventually trips the 100MB hard block (init.ts MAX_DB_SIZE) and bricks
  // its own memory store. Retention purges (src/defence/audit/retention.ts) now
  // delete old rows — but getLifetimeStats() scans the whole table, so a naive
  // purge would make lifetime totals silently undercount. This single-row
  // cumulative aggregate is the rollup target: purges add the to-be-deleted
  // rows' contributions here BEFORE deleting, and getLifetimeStats() returns
  // aggregate + live so the numbers never go backwards.
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS audit_aggregates (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        total_scans INTEGER NOT NULL DEFAULT 0,
        threats_blocked INTEGER NOT NULL DEFAULT 0,
        quarantined INTEGER NOT NULL DEFAULT 0,
        memories_protected INTEGER NOT NULL DEFAULT 0,
        credential_leaks INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT
      );
    `);
  } catch (err) {
    logIfUnexpectedDdlError(err, 'audit_aggregates');
  }

  // Migration: Phase 10 — scope the memories_au FTS trigger to UPDATE OF the
  // indexed columns only (title, content, tags).
  //
  // The trigger originally shipped as `AFTER UPDATE ON memories` with no `OF`
  // column list, so it fired a full FTS5 external-content delete+reinsert on
  // ANY column update. The hottest write path — accessMemory() bumping
  // access_count / last_accessed / salience on every recalled memory, plus the
  // 5-minute decay-score persistence — never touches indexed text, so each read
  // was re-tokenising and rewriting the FTS index for nothing (write
  // amplification + WAL churn + more surface for FTS drift).
  //
  // A `CREATE TRIGGER IF NOT EXISTS` alone CANNOT replace the existing unscoped
  // trigger on an upgraded DB, so we DROP it first, then recreate with the
  // scoped form. Fresh installs already get the scoped trigger from
  // schema.sql / inline-schema.ts; this block only matters for existing DBs.
  try {
    database.exec('DROP TRIGGER IF EXISTS memories_au');
    database.exec(`
      CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE OF title, content, tags ON memories BEGIN
        INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
        VALUES('delete', old.id, old.title, old.content, old.tags);
        INSERT INTO memories_fts(rowid, title, content, tags)
        VALUES (new.id, new.title, new.content, new.tags);
      END;
    `);
  } catch (err) {
    logIfUnexpectedDdlError(err, 'memories_au');
  }

  // Migration: Phase 14 — mcp_tool_hashes table (MCP tool-description drift /
  // rug-pull detection). `shieldcortex mcp scan` stores a sha256 of each MCP
  // server's advertised tool definition (name + description + inputSchema) and
  // compares it on the next scan: a CHANGED hash for an already-seen tool is
  // the classic rug-pull signal (a server silently altering an approved tool
  // description). Mirrors the content-hash idempotency pattern used elsewhere
  // (session_events.content_hash). Fresh installs get this from schema.sql /
  // inline-schema.ts; this block only matters for existing DBs.
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS mcp_tool_hashes (
        server_name TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        last_changed TEXT,
        PRIMARY KEY (server_name, tool_name)
      );
    `);
  } catch (err) {
    logIfUnexpectedDdlError(err, 'mcp_tool_hashes');
  }

  // Migration: provenance ledger (v4.39.0) — add an `operation` discriminator
  // (read/write/delete) and a `content_hash` (write-time tamper-evidence) to
  // defence_audit, a `content_hash` to memories, and an index on memories.source
  // for revoke-by-source. Existing rows keep operation/content_hash NULL (legacy,
  // unclassifiable). Fresh installs get these from schema.sql / inline-schema.ts.
  try {
    const auditCols = database.prepare("PRAGMA table_info(defence_audit)").all() as { name: string }[];
    if (auditCols.length > 0) {
      const auditColNames = new Set(auditCols.map((c) => c.name));
      if (!auditColNames.has('operation')) {
        database.exec('ALTER TABLE defence_audit ADD COLUMN operation TEXT');
      }
      if (!auditColNames.has('content_hash')) {
        database.exec('ALTER TABLE defence_audit ADD COLUMN content_hash TEXT');
      }
      // Threat-graph Phase B (docs/design/2026-08-11-threat-graph.md):
      // source_attested = the resolution was system-derived or strict-mode
      // (NULL on legacy rows and unplumbed paths); risk_modifier = the
      // advisory trust modifier computed for this scan (NULL until the
      // modifier ships/fires). Local-only until declared as egress.
      //
      // NEVER BACKFILL source_attested on historic rows (decision recorded
      // 2026-08-16, attestation Phase 5, pinned by test): NULL→1 is a
      // trust-elevation hole (attesting identities nothing derived), and
      // NULL→0 is a behavioural no-op that only adds mute-lever surface via
      // risk.ts's latest-non-null resolution. The consumption side reads NULL
      // conservatively; history stays NULL, forever.
      if (!auditColNames.has('source_attested')) {
        database.exec('ALTER TABLE defence_audit ADD COLUMN source_attested INTEGER');
      }
      if (!auditColNames.has('risk_modifier')) {
        database.exec('ALTER TABLE defence_audit ADD COLUMN risk_modifier REAL');
      }
      // Serves the threat-graph risk sweep's 28-day windowed counters
      // (per-source range scan); without it the sweep degrades to repeated
      // partial scans across up to 5,000 sources.
      database.exec(
        'CREATE INDEX IF NOT EXISTS idx_audit_source_ident_ts ON defence_audit(source_type, source_identifier, timestamp)'
      );
    }
    // Threat-graph Phase C (Loop 3): allowance bookkeeping on the `allows`
    // edge (approvals, exemplar hashes, strikes). Guarded — the threat_edges
    // table may not exist yet on an install that hasn't opened the graph.
    const edgeCols = database.prepare("PRAGMA table_info(threat_edges)").all() as { name: string }[];
    if (edgeCols.length > 0 && !edgeCols.some((c) => c.name === 'attrs')) {
      database.exec("ALTER TABLE threat_edges ADD COLUMN attrs TEXT NOT NULL DEFAULT '{}'");
    }
    // threat_graph_state: reconcile EVERY nullable column the shipped schema
    // declares, not a hand-picked few. `lease_token` was added to the CREATE
    // TABLE (Phase A, single-writer lease) with no ALTER migration, so every
    // UPGRADED install kept the old table and `runProjectorWithLease` threw
    // `no such column: lease_token` on each worker tick — a silently dead
    // projector behind a green doctor (it judges health by cursor lag, and a
    // cursor that never advances has no lag). Phase D/E columns had one-off
    // ALTERs here; this replaces that per-column pattern with the full list so
    // the next column added to the schema cannot repeat the class. All TEXT +
    // NULL-default, so ADD COLUMN is safe on any prior shape.
    const stateCols = database.prepare("PRAGMA table_info(threat_graph_state)").all() as { name: string }[];
    if (stateCols.length > 0) {
      const have = new Set(stateCols.map((c) => c.name));
      for (const col of [
        'lease_expires_at', 'lease_token', 'last_run_at',
        'last_campaign_at', 'last_conflict_at', 'last_error',
        'rebuild_pending', 'risk_snapshot',
      ]) {
        if (!have.has(col)) {
          database.exec(`ALTER TABLE threat_graph_state ADD COLUMN ${col} TEXT`);
        }
      }
    }
    // Threat-graph Phase E: triple write-time provenance + dispute flag. The
    // `triples` table exists from the ontology migration above, so these are
    // unconditional adds (guarded by column presence). writer_source/writer_trust
    // stay NULL on rows written before this migration (and on backfilled rows).
    const tripleCols = database.prepare("PRAGMA table_info(triples)").all() as { name: string }[];
    if (tripleCols.length > 0) {
      if (!tripleCols.some((c) => c.name === 'valid_from')) {
        database.exec('ALTER TABLE triples ADD COLUMN valid_from TEXT');
      }
      if (!tripleCols.some((c) => c.name === 'valid_to')) {
        database.exec('ALTER TABLE triples ADD COLUMN valid_to TEXT');
      }
      if (!tripleCols.some((c) => c.name === 'writer_source')) {
        database.exec('ALTER TABLE triples ADD COLUMN writer_source TEXT');
      }
      if (!tripleCols.some((c) => c.name === 'writer_trust')) {
        database.exec('ALTER TABLE triples ADD COLUMN writer_trust REAL');
      }
      if (!tripleCols.some((c) => c.name === 'disputed')) {
        database.exec('ALTER TABLE triples ADD COLUMN disputed INTEGER NOT NULL DEFAULT 0');
      }
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'defence_audit provenance columns + threat_edges.attrs + triples provenance');
  }

  if (!columnNames.has('content_hash')) {
    database.exec('ALTER TABLE memories ADD COLUMN content_hash TEXT');
  }
  // Indexes in an unconditional, self-healing block: CREATE INDEX IF NOT EXISTS
  // no-ops if the column already had its index, and back-fills it if the column
  // exists without it (e.g. a column added by a prior partial run).
  try {
    database.exec('CREATE INDEX IF NOT EXISTS idx_audit_operation ON defence_audit(operation)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_content_hash ON memories(content_hash)');
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_source ON memories(source)');
  } catch (err) {
    logIfUnexpectedDdlError(err, 'provenance ledger indexes (audit operation, memories content_hash/source)');
  }

  // Migration: issue #110 — bare-ts index on session_events for the retention
  // purge (src/sessions/retention.ts, DELETE ... WHERE ts < ?). The existing
  // composite (session_id, ts) / (project, ts) indexes can't serve a bare ts
  // range predicate, so without this the daily age purge would full-scan a
  // table that live incidents have shown reaching ~30k rows / ~63 MB. Fresh
  // installs get the index from schema.sql / inline-schema.ts; this block
  // upgrades existing DBs. Guarded on table existence like the other
  // session_events migrations above.
  try {
    const sessionEventsTable = database
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='session_events'")
      .get();
    if (sessionEventsTable) {
      database.exec('CREATE INDEX IF NOT EXISTS idx_session_events_ts ON session_events(ts)');
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'session_events bare-ts retention index');
  }

  // Memory SOTA A-min/B: host/agent scope + capture layer for inject eligibility.
  try {
    if (!columnNames.has('host_id')) {
      database.exec('ALTER TABLE memories ADD COLUMN host_id TEXT');
    }
    if (!columnNames.has('agent_id')) {
      database.exec('ALTER TABLE memories ADD COLUMN agent_id TEXT');
    }
    if (!columnNames.has('capture_layer')) {
      database.exec('ALTER TABLE memories ADD COLUMN capture_layer TEXT');
    }
    // Do not backfill: historic rows did not carry a verifiable attestation
    // decision. Native import writes an explicit 0 through addMemory.
    if (!columnNames.has('source_attested')) {
      database.exec('ALTER TABLE memories ADD COLUMN source_attested INTEGER');
    }
    database.exec('CREATE INDEX IF NOT EXISTS idx_memories_host_agent ON memories(host_id, agent_id)');
  } catch (err) {
    logIfUnexpectedDdlError(err, 'memories host_id/agent_id/capture_layer');
  }

  // Migration: #408 — sync_queue atomic claim / lease columns.
  // Existing installs created sync_queue without lease_*; CREATE IF NOT EXISTS
  // does not add them. Guarded ADD COLUMN so upgrades pick up the claim path.
  try {
    const sq = database
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sync_queue'")
      .get();
    if (sq) {
      const cols = database.prepare('PRAGMA table_info(sync_queue)').all() as { name: string }[];
      const have = new Set(cols.map((c) => c.name));
      for (const col of ['lease_owner', 'lease_token', 'lease_expires_at', 'delivery_key'] as const) {
        if (!have.has(col)) {
          database.exec(`ALTER TABLE sync_queue ADD COLUMN ${col} TEXT`);
        }
      }
      database.exec('CREATE INDEX IF NOT EXISTS idx_sync_queue_lease_exp ON sync_queue(lease_expires_at)');
      database.exec(
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_sync_queue_delivery_key ON sync_queue(delivery_key) WHERE delivery_key IS NOT NULL',
      );
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'sync_queue lease/outbox columns (#408/#409)');
  }

  // Migration: #402 — content_form stamp for the two-key inject gate
  // ('fact'|'directive'|'mixed'|'unknown'). DELIBERATELY no backfill: legacy
  // rows stay NULL, which the read-time form key treats as NOT injectable
  // unless pinned (fail-closed, Opus B1). No index: the queries that filter on
  // content_form (cluster quarantine) are already served by idx_memories_source.
  try {
    if (!columnNames.has('content_form')) {
      database.exec('ALTER TABLE memories ADD COLUMN content_form TEXT');
    }
  } catch (err) {
    logIfUnexpectedDdlError(err, 'memories content_form (#402)');
  }
}
