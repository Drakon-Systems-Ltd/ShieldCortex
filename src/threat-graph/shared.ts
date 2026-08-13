/**
 * Threat-graph internals shared by the audit projector and the realtime
 * ledger (kept separate to avoid an import cycle: projector → realtime-ledger).
 */

import os from 'os';
import path from 'path';
import type { Statement } from 'better-sqlite3';
import { getDatabase } from '../database/init.js';

/**
 * Typed attrs shapes. Runtime stays JSON; these keep B's additions honest.
 * DETERMINISM CONTRACT: attrs may contain only values derivable from ledger
 * rows (ledger timestamps included) — canonicalDump() covers attrs, so
 * anything decayed or wall-clock-relative lives in source_risk, which sits
 * outside the determinism contract.
 */
export interface SourceAttrs {
  scan_count?: number;
  allow_count?: number;
  block_count?: number;
  quarantine_count?: number;
  /** Phase B: raw exponent sum + its ledger-time reference. */
  risk_sum?: number;
  risk_ref_ts?: string;
}

export interface EventAttrs {
  verdict?: string;
  anomaly?: number;
  project?: string;
  pipeline_error?: boolean;
  hook?: string;
  reason?: string;
  model?: string;
  chars?: number;
  contentSha256?: string;
}

/**
 * Per-connection prepared-statement cache. init.ts closes and reopens the
 * handle on recovery paths, so statements are keyed by Database instance —
 * a naive once-cache would throw 'database connection is not open' after any
 * reopen and, behind a fail-soft catch, silently disable a feature forever.
 */
const stmtCache = new WeakMap<object, Map<string, Statement>>();

export function cachedStmt(sql: string): Statement {
  const db = getDatabase();
  let perDb = stmtCache.get(db);
  if (!perDb) {
    perDb = new Map();
    stmtCache.set(db, perDb);
  }
  let stmt = perDb.get(sql);
  if (!stmt) {
    stmt = db.prepare(sql);
    perDb.set(sql, stmt);
  }
  return stmt;
}

/** Default realtime JSONL location — matches the OpenClaw plugin's auditDir(). */
export function defaultRealtimeAuditDir(): string {
  return process.env.SHIELDCORTEX_AUDIT_DIR
    || path.join(os.homedir(), '.shieldcortex', 'audit');
}

/**
 * Normalise a ledger timestamp to ISO-8601. defence_audit's DEFAULT
 * CURRENT_TIMESTAMP produces 'YYYY-MM-DD HH:MM:SS' (space, no zone) while the
 * production writers and the realtime rows emit ISO-with-T — and lexicographic
 * MIN/MAX folding across the two formats misorders (' ' < 'T'). Every
 * timestamp entering the graph passes through here first.
 */
export function toIso(ts: string): string {
  if (!ts || ts.includes('T')) return ts;
  const m = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.(\d+))?$/.exec(ts);
  if (!m) return ts;
  const millis = (m[3] ?? '000').padEnd(3, '0').slice(0, 3);
  return `${m[1]}T${m[2]}.${millis}Z`;
}

/**
 * Refuse to run inside an open transaction: better-sqlite3 silently downgrades
 * a nested .immediate() to a SAVEPOINT, discarding the IMMEDIATE lock
 * semantics the claim-and-advance design depends on. Fail loudly instead.
 */
export function assertNotInTransaction(where: string): void {
  if (getDatabase().inTransaction) {
    throw new Error(`threat-graph ${where} must not run inside an open transaction`);
  }
}

/**
 * Upsert a node, folding first_seen/last_seen from the ledger row's
 * timestamp. Returns the node id. The single write primitive for BOTH ledger
 * projectors (and Phase B's sweep) — do not fork per-writer copies.
 */
export function upsertNode(kind: string, key: string, ts: string): number {
  cachedStmt(`
    INSERT INTO threat_nodes (kind, key, attrs, first_seen, last_seen)
    VALUES (?, ?, '{}', ?, ?)
    ON CONFLICT(kind, key) DO UPDATE SET
      first_seen = MIN(first_seen, excluded.first_seen),
      last_seen = MAX(last_seen, excluded.last_seen)
  `).run(kind, key, ts, ts);
  return (cachedStmt('SELECT id FROM threat_nodes WHERE kind = ? AND key = ?')
    .get(kind, key) as { id: number }).id;
}

/**
 * Read-modify-write a node's attrs. THROWS on corrupt attrs JSON — the
 * row-level catch in the batch loop records it and moves the cursor on, so
 * corruption becomes a doctor-visible error instead of a silent counter
 * reset (which, once Phase B stores risk sums here, would be silent risk
 * amnesty).
 */
export function updateAttrs(nodeId: number, mutate: (attrs: Record<string, unknown>) => void): void {
  const row = cachedStmt('SELECT attrs FROM threat_nodes WHERE id = ?').get(nodeId) as { attrs: string };
  let attrs: Record<string, unknown>;
  try {
    attrs = JSON.parse(row.attrs) as Record<string, unknown>;
  } catch {
    throw new Error(`corrupt attrs JSON on threat_node ${nodeId} — rebuild the threat graph`);
  }
  mutate(attrs);
  cachedStmt('UPDATE threat_nodes SET attrs = ? WHERE id = ?').run(JSON.stringify(attrs), nodeId);
}

/**
 * Upsert an edge: count++, MIN/MAX timestamp fold, optionally FIFO-capped
 * evidence. The single edge primitive for all writers.
 */
export function upsertEdge(
  src: number,
  predicate: string,
  dst: number,
  ts: string,
  evidence?: { ref: number; cap: number },
): void {
  const existing = cachedStmt(
    'SELECT id, evidence FROM threat_edges WHERE src = ? AND predicate = ? AND dst = ?'
  ).get(src, predicate, dst) as { id: number; evidence: string } | undefined;

  if (!existing) {
    cachedStmt(`
      INSERT INTO threat_edges (src, predicate, dst, count, first_seen, last_seen, writer, evidence)
      VALUES (?, ?, ?, 1, ?, ?, 'projector', ?)
    `).run(src, predicate, dst, ts, ts, JSON.stringify(evidence ? [evidence.ref] : []));
    return;
  }

  let refs: number[] = [];
  if (evidence) {
    try {
      refs = JSON.parse(existing.evidence) as number[];
    } catch {
      refs = [];
    }
    refs.push(evidence.ref);
    if (refs.length > evidence.cap) refs = refs.slice(-evidence.cap);
  }
  cachedStmt(`
    UPDATE threat_edges SET
      count = count + 1,
      first_seen = MIN(first_seen, ?),
      last_seen = MAX(last_seen, ?),
      evidence = CASE WHEN ? THEN ? ELSE evidence END
    WHERE id = ?
  `).run(ts, ts, evidence ? 1 : 0, JSON.stringify(refs), existing.id);
}

/**
 * Evict oldest event nodes beyond the cap. FK cascade (foreign_keys = ON in
 * init.ts) removes their edges with them; counts already live in the
 * aggregate edges, so eviction loses forensic detail, never totals.
 * Returns a human-readable note when it fired, else null.
 */
export function evictEventOverflow(maxEventNodes: number): string | null {
  const db = getDatabase();
  // Phase E conflict review nodes reuse kind='event' but are a throttled derived
  // layer excluded from canonicalDump — so they must ALSO be excluded from the
  // cap, or evicting real event nodes to make room for them makes the dump
  // diverge between an incremental tick and a rebuild. They are inherently
  // bounded (one per conflicted channel) and re-minted each detection pass.
  const count = (db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'event' AND key NOT LIKE 'conflict:%'").get() as { c: number }).c;
  if (count <= maxEventNodes) return null;
  const excess = count - maxEventNodes;
  db.prepare(`
    DELETE FROM threat_nodes WHERE id IN (
      SELECT id FROM threat_nodes WHERE kind = 'event' AND key NOT LIKE 'conflict:%'
      ORDER BY last_seen ASC, key ASC LIMIT ?
    )
  `).run(excess);
  return `event cap reached: evicted ${excess} oldest event nodes`;
}

/**
 * Edge-count backstop (invariant 6's 200k cap). Event edges dominate edge
 * volume, so shedding oldest event nodes (cascading their edges) is the
 * correct pressure valve; aggregate edges are never evicted.
 */
export function evictEdgeOverflow(maxEdges: number): string | null {
  const db = getDatabase();
  const count = (db.prepare('SELECT COUNT(*) as c FROM threat_edges').get() as { c: number }).c;
  if (count <= maxEdges) return null;
  let evicted = 0;
  // Shed oldest events in chunks until under the cap (or none remain). Conflict
  // review nodes are excluded — they carry no aggregate edges, so evicting them
  // sheds zero edges (and would perturb the determinism dump for nothing).
  for (let guard = 0; guard < 100; guard++) {
    const remaining = (db.prepare('SELECT COUNT(*) as c FROM threat_edges').get() as { c: number }).c;
    if (remaining <= maxEdges) break;
    const removed = db.prepare(`
      DELETE FROM threat_nodes WHERE id IN (
        SELECT id FROM threat_nodes WHERE kind = 'event' AND key NOT LIKE 'conflict:%'
        ORDER BY last_seen ASC, key ASC LIMIT 500
      )
    `).run().changes;
    evicted += Number(removed);
    if (Number(removed) === 0) break;
  }
  return evicted > 0 ? `edge cap reached: evicted ${evicted} oldest event nodes` : null;
}
