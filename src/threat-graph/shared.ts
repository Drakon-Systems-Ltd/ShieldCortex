/**
 * Threat-graph internals shared by the audit projector and the realtime
 * ledger (kept separate to avoid an import cycle: projector → realtime-ledger).
 */

import os from 'os';
import path from 'path';
import { getDatabase } from '../database/init.js';

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
 * Evict oldest event nodes beyond the cap. FK cascade (foreign_keys = ON in
 * init.ts) removes their edges with them; counts already live in the
 * aggregate edges, so eviction loses forensic detail, never totals.
 * Returns a human-readable note when it fired, else null.
 */
export function evictEventOverflow(maxEventNodes: number): string | null {
  const db = getDatabase();
  const count = (db.prepare("SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'event'").get() as { c: number }).c;
  if (count <= maxEventNodes) return null;
  const excess = count - maxEventNodes;
  db.prepare(`
    DELETE FROM threat_nodes WHERE id IN (
      SELECT id FROM threat_nodes WHERE kind = 'event'
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
  // Shed oldest events in chunks until under the cap (or none remain).
  for (let guard = 0; guard < 100; guard++) {
    const remaining = (db.prepare('SELECT COUNT(*) as c FROM threat_edges').get() as { c: number }).c;
    if (remaining <= maxEdges) break;
    const removed = db.prepare(`
      DELETE FROM threat_nodes WHERE id IN (
        SELECT id FROM threat_nodes WHERE kind = 'event'
        ORDER BY last_seen ASC, key ASC LIMIT 500
      )
    `).run().changes;
    evicted += Number(removed);
    if (Number(removed) === 0) break;
  }
  return evicted > 0 ? `edge cap reached: evicted ${evicted} oldest event nodes` : null;
}
