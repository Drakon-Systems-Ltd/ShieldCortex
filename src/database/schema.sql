-- Claude Memory Database Schema
-- Brain-like memory storage with full-text search

-- Main memories table
CREATE TABLE IF NOT EXISTS memories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL CHECK(type IN ('short_term', 'long_term', 'episodic')),
  category TEXT NOT NULL DEFAULT 'note',
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  project TEXT,
  tags TEXT DEFAULT '[]',  -- JSON array
  salience REAL DEFAULT 0.5 CHECK(salience >= 0 AND salience <= 1),
  decayed_score REAL,  -- Cached decay calculation for efficient sorting
  access_count INTEGER DEFAULT 0,
  last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  metadata TEXT DEFAULT '{}',  -- JSON object
  embedding BLOB,  -- Vector embedding for semantic search
  scope TEXT DEFAULT 'project',  -- Scope: project or global
  transferable INTEGER DEFAULT 0,  -- Cross-project sharing flag
  trust_score REAL DEFAULT 1.0,
  sensitivity_level TEXT DEFAULT 'INTERNAL',
  source TEXT DEFAULT 'user:direct',
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'archived', 'suppressed', 'canonical')),
  pinned INTEGER DEFAULT 0,
  reviewed_at TIMESTAMP,
  reviewed_by TEXT,
  source_kind TEXT DEFAULT 'user',
  capture_method TEXT DEFAULT 'manual',
  cloud_excluded INTEGER DEFAULT 0,
  graph_extraction_version INTEGER DEFAULT 0,
  memory_purpose TEXT DEFAULT 'project',
  memory_scope TEXT DEFAULT 'private',

  -- Index for common queries
  CONSTRAINT valid_category CHECK(category IN (
    'architecture', 'pattern', 'preference', 'error',
    'context', 'learning', 'todo', 'note', 'relationship', 'custom'
  ))
);

-- Full-text search virtual table
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
  title,
  content,
  tags,
  content='memories',
  content_rowid='id',
  tokenize='porter unicode61'
);

-- Triggers to keep FTS index in sync
CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts(rowid, title, content, tags)
  VALUES (new.id, new.title, new.content, new.tags);
END;

CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
  VALUES('delete', old.id, old.title, old.content, old.tags);
END;

CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
  VALUES('delete', old.id, old.title, old.content, old.tags);
  INSERT INTO memories_fts(rowid, title, content, tags)
  VALUES (new.id, new.title, new.content, new.tags);
END;

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_memories_type ON memories(type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_memories_uuid ON memories(uuid);
CREATE INDEX IF NOT EXISTS idx_memories_project ON memories(project);
CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category);
CREATE INDEX IF NOT EXISTS idx_memories_salience ON memories(salience DESC);
CREATE INDEX IF NOT EXISTS idx_memories_decayed_score ON memories(decayed_score DESC);
CREATE INDEX IF NOT EXISTS idx_memories_last_accessed ON memories(last_accessed DESC);
CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memories_updated ON memories(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_memories_status ON memories(status);
CREATE INDEX IF NOT EXISTS idx_memories_pinned ON memories(pinned DESC);
CREATE INDEX IF NOT EXISTS idx_memories_source_kind ON memories(source_kind);

-- Session tracking for consolidation
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project TEXT,
  started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ended_at TIMESTAMP,
  summary TEXT,
  memories_created INTEGER DEFAULT 0,
  memories_accessed INTEGER DEFAULT 0
);

-- Memory relationships (for linked memories)
CREATE TABLE IF NOT EXISTS memory_links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER NOT NULL,
  target_id INTEGER NOT NULL,
  relationship TEXT NOT NULL, -- 'related', 'supersedes', 'conflicts', 'supports'
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
  data TEXT,  -- JSON stringified event payload
  timestamp TEXT NOT NULL,
  processed INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed, id);

-- Ontology: Unique entities (people, tools, concepts, files, projects)
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

-- Ontology: Subject-predicate-object triples
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

-- Ontology: Link memories to entities they mention
CREATE TABLE IF NOT EXISTS memory_entities (
  memory_id INTEGER NOT NULL,
  entity_id INTEGER NOT NULL,
  role TEXT DEFAULT 'mention',
  FOREIGN KEY (memory_id) REFERENCES memories(id) ON DELETE CASCADE,
  FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE CASCADE,
  PRIMARY KEY (memory_id, entity_id)
);

-- Defence: Full audit trail for all memory operations
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
  threat_indicators TEXT DEFAULT '[]',  -- JSON array of ThreatIndicator strings
  blocked_patterns TEXT DEFAULT '[]',   -- JSON array of matched patterns
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

-- Defence: Quarantine for blocked/suspicious memories pending review
CREATE TABLE IF NOT EXISTS quarantine (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  original_content TEXT NOT NULL,
  original_title TEXT,
  project TEXT,
  source_type TEXT NOT NULL,
  source_identifier TEXT NOT NULL,
  reason TEXT NOT NULL,
  threat_indicators TEXT DEFAULT '[]',  -- JSON array
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

-- Defence: Local Review Copilot annotations for quarantine review
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

-- Defence: Extracted entities for cross-reference fragmentation analysis
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

-- Cloud sync retry queue
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

-- Pro feature: Custom injection patterns
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

-- Pro feature: Custom Iron Dome policies
CREATE TABLE IF NOT EXISTS iron_dome_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  config TEXT NOT NULL DEFAULT '{}',
  is_active INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- At most one active policy at any time
CREATE UNIQUE INDEX IF NOT EXISTS idx_dome_policies_active ON iron_dome_policies(is_active) WHERE is_active = 1;

-- Pro feature: Custom firewall rules
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

-- Rate limits (cross-process, persisted)
CREATE TABLE IF NOT EXISTS rate_limits (
  source_key TEXT PRIMARY KEY,
  write_count INTEGER NOT NULL DEFAULT 1,
  window_start_ms INTEGER NOT NULL
);
