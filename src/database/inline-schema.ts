/**
 * Inline schema fallback for bundled deployment (extracted from
 * src/database/init.ts in v4.26.0).
 *
 * When `dist/database/schema.sql` is present alongside the compiled
 * `init.js`, `initDatabase()` reads + execs it. Otherwise (some bundled
 * deployments — Vercel, certain bundlers, edge-runtime targets) it falls
 * back to the inline string returned by `getInlineSchema()`.
 *
 * The two should stay in sync. When you edit `schema.sql`, mirror the
 * change here. The CREATE TABLE / CREATE INDEX / CREATE TRIGGER set is
 * intentionally idempotent (`IF NOT EXISTS`) so either source can be
 * applied to either fresh or existing databases without error.
 */
export function getInlineSchema(): string {
  return `
    CREATE TABLE IF NOT EXISTS memories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uuid TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL CHECK(type IN ('short_term', 'long_term', 'episodic')),
      category TEXT NOT NULL DEFAULT 'note',
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      project TEXT,
      tags TEXT DEFAULT '[]',
      salience REAL DEFAULT 0.5 CHECK(salience >= 0 AND salience <= 1),
      decayed_score REAL,
      access_count INTEGER DEFAULT 0,
      last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      metadata TEXT DEFAULT '{}',
      embedding BLOB,
      scope TEXT DEFAULT 'project',
      transferable INTEGER DEFAULT 0,
      trust_score REAL DEFAULT 1.0,
      sensitivity_level TEXT DEFAULT 'INTERNAL',
      source TEXT DEFAULT 'user:direct',
      content_hash TEXT,
      status TEXT DEFAULT 'active' CHECK(status IN ('active', 'archived', 'suppressed', 'canonical')),
      pinned INTEGER DEFAULT 0,
      reviewed_at TIMESTAMP,
      reviewed_by TEXT,
      source_kind TEXT DEFAULT 'user',
      capture_method TEXT DEFAULT 'manual',
      defence_verdict TEXT DEFAULT 'unverified',
      cloud_excluded INTEGER DEFAULT 0,
      graph_extraction_version INTEGER DEFAULT 0,
      memory_purpose TEXT DEFAULT 'project',
      memory_scope TEXT DEFAULT 'private',
      downvote_count INTEGER DEFAULT 0,
      last_downvoted_at TIMESTAMP,
      host_id TEXT,
      agent_id TEXT,
      capture_layer TEXT
    );

    CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
      title,
      content,
      tags,
      content='memories',
      content_rowid='id',
      tokenize='porter unicode61'
    );

    CREATE TRIGGER IF NOT EXISTS trg_memories_provenance BEFORE INSERT ON memories
    WHEN NEW.source IS NULL OR NEW.trust_score IS NULL OR NEW.defence_verdict IS NULL
    BEGIN
      SELECT RAISE(ABORT, 'provenance invariant: a memory write must carry source, trust, and a defence verdict');
    END;

    CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
      INSERT INTO memories_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;

    CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
      INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
      VALUES('delete', old.id, old.title, old.content, old.tags);
    END;

    CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE OF title, content, tags ON memories BEGIN
      INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
      VALUES('delete', old.id, old.title, old.content, old.tags);
      INSERT INTO memories_fts(rowid, title, content, tags)
      VALUES (new.id, new.title, new.content, new.tags);
    END;

    CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(type);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_uuid ON memories(uuid);
    CREATE INDEX IF NOT EXISTS idx_memories_project ON memories(project);
    CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category);
    CREATE INDEX IF NOT EXISTS idx_memories_salience ON memories(salience DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_decayed_score ON memories(decayed_score DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_last_accessed ON memories(last_accessed DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(updated_at DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_source ON memories(source);
    CREATE INDEX IF NOT EXISTS idx_memories_content_hash ON memories(content_hash);
    CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_status ON memories(status);
    CREATE INDEX IF NOT EXISTS idx_memories_pinned ON memories(pinned DESC);
    CREATE INDEX IF NOT EXISTS idx_memories_source_kind ON memories(source_kind);
    CREATE INDEX IF NOT EXISTS idx_memories_host_agent ON memories(host_id, agent_id);

    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project TEXT,
      started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ended_at TIMESTAMP,
      summary TEXT,
      memories_created INTEGER DEFAULT 0,
      memories_accessed INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS memory_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_id INTEGER NOT NULL,
      target_id INTEGER NOT NULL,
      relationship TEXT NOT NULL,
      strength REAL DEFAULT 0.5,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (source_id) REFERENCES memories(id) ON DELETE CASCADE,
      FOREIGN KEY (target_id) REFERENCES memories(id) ON DELETE CASCADE,
      UNIQUE(source_id, target_id)
    );

    CREATE INDEX IF NOT EXISTS idx_links_source ON memory_links(source_id);
    CREATE INDEX IF NOT EXISTS idx_links_target ON memory_links(target_id);

    -- Events table for cross-process IPC (MCP → Dashboard)
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      data TEXT,
      timestamp TEXT NOT NULL,
      processed INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, id);

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
    CREATE INDEX IF NOT EXISTS idx_entities_name_nocase ON entities(name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(type);

    CREATE TABLE IF NOT EXISTS triples (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject_id INTEGER NOT NULL,
      predicate TEXT NOT NULL,
      object_id INTEGER NOT NULL,
      source_memory_id INTEGER,
      confidence REAL DEFAULT 0.8,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      valid_from TEXT,
      valid_to TEXT,
      writer_source TEXT,
      writer_trust REAL,
      disputed INTEGER NOT NULL DEFAULT 0,
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

    CREATE TABLE IF NOT EXISTS threat_nodes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      kind TEXT NOT NULL CHECK(kind IN
        ('source','session','pattern','indicator','event','campaign','operator','entity_ref')),
      key TEXT NOT NULL,
      label TEXT,
      attrs TEXT NOT NULL DEFAULT '{}',
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      UNIQUE(kind, key)
    );

    CREATE INDEX IF NOT EXISTS idx_threat_nodes_kind ON threat_nodes(kind);
    CREATE INDEX IF NOT EXISTS idx_threat_nodes_last_seen ON threat_nodes(last_seen);

    CREATE TABLE IF NOT EXISTS threat_edges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      src INTEGER NOT NULL REFERENCES threat_nodes(id) ON DELETE CASCADE,
      predicate TEXT NOT NULL CHECK(predicate IN
        ('triggered','observed_in','from_source','in_session','matched',
         'mentions','decided','allows','part_of','conflicts_with')),
      dst INTEGER NOT NULL REFERENCES threat_nodes(id) ON DELETE CASCADE,
      count INTEGER NOT NULL DEFAULT 1,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      valid_to TEXT,
      writer TEXT NOT NULL CHECK(writer IN ('projector','operator','backfill')),
      confidence REAL NOT NULL DEFAULT 1.0,
      evidence TEXT NOT NULL DEFAULT '[]',
      attrs TEXT NOT NULL DEFAULT '{}',
      UNIQUE(src, predicate, dst)
    );

    CREATE INDEX IF NOT EXISTS idx_threat_edges_src ON threat_edges(src);
    CREATE INDEX IF NOT EXISTS idx_threat_edges_dst ON threat_edges(dst);
    CREATE INDEX IF NOT EXISTS idx_threat_edges_pred ON threat_edges(predicate);

    CREATE TABLE IF NOT EXISTS threat_graph_state (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      last_audit_id INTEGER NOT NULL DEFAULT 0,
      last_rt_cursor TEXT NOT NULL DEFAULT '',
      projector_version INTEGER NOT NULL DEFAULT 1,
      lease_expires_at TEXT,
      lease_token TEXT,
      last_run_at TEXT,
      last_campaign_at TEXT,
      last_conflict_at TEXT,
      last_error TEXT,
      rebuild_pending TEXT,
      risk_snapshot TEXT
    );

    CREATE TABLE IF NOT EXISTS source_risk (
      source_key TEXT PRIMARY KEY,
      risk REAL NOT NULL DEFAULT 0.0,
      attested INTEGER NOT NULL DEFAULT 0,
      block_count_28d INTEGER NOT NULL DEFAULT 0,
      quarantine_count_28d INTEGER NOT NULL DEFAULT 0,
      scan_count_28d INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );

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
      operation TEXT,
      content_hash TEXT,
      anomaly_score REAL DEFAULT 0.0,
      threat_indicators TEXT DEFAULT '[]',
      blocked_patterns TEXT DEFAULT '[]',
      reason TEXT,
      fragmentation_score REAL,
      pipeline_duration_ms INTEGER,
      source_attested INTEGER,
      risk_modifier REAL,
      FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_memory ON defence_audit(memory_id);
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON defence_audit(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_result ON defence_audit(firewall_result);
    CREATE INDEX IF NOT EXISTS idx_audit_source ON defence_audit(source_type);
    CREATE INDEX IF NOT EXISTS idx_audit_project ON defence_audit(project);
    CREATE INDEX IF NOT EXISTS idx_audit_operation ON defence_audit(operation);
    CREATE INDEX IF NOT EXISTS idx_audit_source_ident_ts ON defence_audit(source_type, source_identifier, timestamp);

    -- Cumulative audit aggregate (single row, id=1) — retention rollup target.
    -- See schema.sql for the rationale.
    CREATE TABLE IF NOT EXISTS audit_aggregates (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      total_scans INTEGER NOT NULL DEFAULT 0,
      threats_blocked INTEGER NOT NULL DEFAULT 0,
      quarantined INTEGER NOT NULL DEFAULT 0,
      memories_protected INTEGER NOT NULL DEFAULT 0,
      credential_leaks INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT
    );

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

    CREATE TABLE IF NOT EXISTS sync_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      payload TEXT NOT NULL,
      attempts INTEGER DEFAULT 0,
      max_attempts INTEGER DEFAULT 3,
      next_retry_at TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','failed','synced')),
      last_error TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      synced_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_sync_queue_status_retry ON sync_queue(status, next_retry_at);

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

    -- Control state (single row, cross-process kill-switch / pause)
    CREATE TABLE IF NOT EXISTS control_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      mode TEXT NOT NULL DEFAULT 'active' CHECK (mode IN ('active','paused','kill_switch')),
      meta_json TEXT,
      updated_at TEXT NOT NULL
    );

    -- v4.17 Session capture (mirrors schema.sql; bundled fallback only).
    -- v4.28 (Fix #10): + sensitivity_level for prompt-redaction tagging.
    CREATE TABLE IF NOT EXISTS session_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      project TEXT,
      ts TIMESTAMP NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN (
        'prompt', 'response', 'tool_call', 'tool_result', 'tool_error', 'hook_fire'
      )),
      actor TEXT,
      payload TEXT NOT NULL,
      duration_ms INTEGER,
      audit_id INTEGER,
      content_hash TEXT,
      sensitivity_level TEXT DEFAULT 'INTERNAL',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (audit_id) REFERENCES defence_audit(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_session_events_session ON session_events(session_id, ts);
    CREATE INDEX IF NOT EXISTS idx_session_events_project ON session_events(project, ts DESC);
    CREATE INDEX IF NOT EXISTS idx_session_events_sensitivity ON session_events(sensitivity_level);
    -- #110: bare-ts index for the retention purge (DELETE ... WHERE ts < ?).
    -- The composite (session_id, ts)/(project, ts) indexes can't serve a bare
    -- ts range predicate, so without this the age purge would full-scan.
    CREATE INDEX IF NOT EXISTS idx_session_events_ts ON session_events(ts);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_session_events_dedupe
      ON session_events(session_id, ts, kind, content_hash);

    -- Phase 14: MCP tool-description hashes (drift / rug-pull detection).
    -- Mirrors schema.sql.
    CREATE TABLE IF NOT EXISTS mcp_tool_hashes (
      server_name TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      first_seen TEXT,
      last_seen TEXT,
      last_changed TEXT,
      PRIMARY KEY (server_name, tool_name)
    );
  `;
}
