/**
 * Threat Graph projector (docs/design/2026-08-11-threat-graph.md, Phase A).
 *
 * A deterministic projection of the defence_audit ledger into
 * threat_nodes / threat_edges. The ledger is truth; the graph is a derived
 * view — droppable and rebuildable at any time within the retention window.
 *
 * Invariants this module enforces:
 *  - Claim-and-advance batches: the cursor is re-read INSIDE a BEGIN IMMEDIATE
 *    transaction and the batch range derived from that read, so concurrent
 *    projector instances process disjoint ranges or no-op, and a crash
 *    mid-batch discards cursor and partial work together.
 *  - Two-tier volume control: ALLOW rows update source counters + aggregate
 *    `triggered` edges only; event nodes exist solely for notable rows
 *    (BLOCK / QUARANTINE / high-anomaly ALLOW).
 *  - All graph timestamps derive from ledger-row timestamps (normalised to
 *    ISO via toIso), never wall clock.
 *  - Bounded everything: distinct sources are hard-capped (overflow routes to
 *    a bucket node, recorded in the run's errors), evidence arrays are
 *    FIFO-capped, and event nodes/edges are evicted oldest-first beyond
 *    their caps (their contribution already lives in the aggregate edges).
 *  - Node identity is never raw content: source keys are the caller-attested
 *    source tuple, pattern keys are detector names written by the firewall —
 *    attacker-authored text reaches `attrs` at most, never `key`.
 *
 * PROJECTOR_VERSION: bump when projection rules change. The lease runner
 * compares it with threat_graph_state.projector_version and forces a
 * from-zero rebuild on mismatch — projection-logic upgrades roll out without
 * migration scripts.
 */

import { getDatabase } from '../database/init.js';
import { projectRealtimeLedger, type RealtimeResult } from './realtime-ledger.js';
import {
  assertNotInTransaction,
  evictEdgeOverflow,
  evictEventOverflow,
  toIso,
} from './shared.js';

/** Bump when projection rules change to force a rebuild on the next run. */
export const PROJECTOR_VERSION = 1;

export interface ProjectorOptions {
  /** Rows per claim-and-advance batch. */
  batchSize?: number;
  /** Distinct source nodes before new sources route to the overflow bucket. */
  maxSources?: number;
  /** Event nodes retained; oldest are evicted beyond this. */
  maxEventNodes?: number;
  /** Total edges retained; oldest event nodes are shed beyond this. */
  maxEdges?: number;
  /** Ledger refs kept per edge, FIFO (newest kept). */
  evidenceCap?: number;
  /** ALLOW rows at or above this anomaly score are notable. */
  anomalyEventThreshold?: number;
  /** Max length of a source identifier contributing to node identity. */
  sourceKeyMaxLength?: number;
}

export interface ProjectResult {
  processed: number;
  cursor: number;
  eventNodes: number;
  errors: string[];
}

const DEFAULTS: Required<ProjectorOptions> = {
  batchSize: 500,
  maxSources: 5000,
  maxEventNodes: 50_000,
  maxEdges: 200_000,
  evidenceCap: 20,
  anomalyEventThreshold: 0.7,
  sourceKeyMaxLength: 200,
};

interface AuditRow {
  id: number;
  project: string | null;
  timestamp: string;
  source_type: string;
  source_identifier: string;
  firewall_result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  anomaly_score: number | null;
  threat_indicators: string | null;
  blocked_patterns: string | null;
}

function parseJsonArray(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function ensureStateRow(): void {
  getDatabase().prepare('INSERT OR IGNORE INTO threat_graph_state (id) VALUES (1)').run();
}

/**
 * Upsert a node, folding first_seen/last_seen from the ledger row's timestamp.
 * Returns the node id. `attrs` mutation is left to callers via updateAttrs.
 */
function upsertNode(kind: string, key: string, ts: string): number {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO threat_nodes (kind, key, attrs, first_seen, last_seen)
    VALUES (?, ?, '{}', ?, ?)
    ON CONFLICT(kind, key) DO UPDATE SET
      first_seen = MIN(first_seen, excluded.first_seen),
      last_seen = MAX(last_seen, excluded.last_seen)
  `).run(kind, key, ts, ts);
  const row = db.prepare('SELECT id FROM threat_nodes WHERE kind = ? AND key = ?').get(kind, key) as { id: number };
  return row.id;
}

function updateAttrs(nodeId: number, mutate: (attrs: Record<string, unknown>) => void): void {
  const db = getDatabase();
  const row = db.prepare('SELECT attrs FROM threat_nodes WHERE id = ?').get(nodeId) as { attrs: string };
  let attrs: Record<string, unknown>;
  try {
    attrs = JSON.parse(row.attrs) as Record<string, unknown>;
  } catch {
    attrs = {};
  }
  mutate(attrs);
  db.prepare('UPDATE threat_nodes SET attrs = ? WHERE id = ?').run(JSON.stringify(attrs), nodeId);
}

function bump(attrs: Record<string, unknown>, field: string, by = 1): void {
  attrs[field] = (typeof attrs[field] === 'number' ? (attrs[field] as number) : 0) + by;
}

/**
 * Upsert an aggregate edge: count++, timestamp fold, FIFO-capped evidence.
 */
function upsertEdge(
  src: number,
  predicate: string,
  dst: number,
  ts: string,
  evidenceRef: number | null,
  evidenceCap: number,
): void {
  const db = getDatabase();
  const existing = db.prepare(
    'SELECT id, count, evidence FROM threat_edges WHERE src = ? AND predicate = ? AND dst = ?'
  ).get(src, predicate, dst) as { id: number; count: number; evidence: string } | undefined;

  if (!existing) {
    const evidence = evidenceRef === null ? [] : [evidenceRef];
    db.prepare(`
      INSERT INTO threat_edges (src, predicate, dst, count, first_seen, last_seen, writer, evidence)
      VALUES (?, ?, ?, 1, ?, ?, 'projector', ?)
    `).run(src, predicate, dst, ts, ts, JSON.stringify(evidence));
    return;
  }

  let evidence: number[];
  try {
    evidence = JSON.parse(existing.evidence) as number[];
  } catch {
    evidence = [];
  }
  if (evidenceRef !== null) {
    evidence.push(evidenceRef);
    if (evidence.length > evidenceCap) evidence = evidence.slice(-evidenceCap);
  }
  db.prepare(`
    UPDATE threat_edges SET
      count = count + 1,
      first_seen = MIN(first_seen, ?),
      last_seen = MAX(last_seen, ?),
      evidence = ?
    WHERE id = ?
  `).run(ts, ts, JSON.stringify(evidence), existing.id);
}

/**
 * Resolve the source node for a row, honouring the distinct-source cap: once
 * the cap is reached, rows from NEW sources fold into the 'overflow' bucket
 * (identity rotation then shows up as bucket growth, not silent node
 * minting). Overflow use is reported so it lands in last_error via the run.
 */
function resolveSourceNode(
  row: AuditRow,
  ts: string,
  opts: Required<ProjectorOptions>,
  errors: string[],
): number {
  const db = getDatabase();
  const identifier = row.source_identifier.slice(0, opts.sourceKeyMaxLength);
  const key = `${row.source_type}:${identifier}`;

  const existing = db.prepare("SELECT id FROM threat_nodes WHERE kind = 'source' AND key = ?").get(key) as { id: number } | undefined;
  if (existing) {
    upsertNode('source', key, ts); // fold timestamps
    return existing.id;
  }

  const distinct = (db.prepare(
    "SELECT COUNT(*) as c FROM threat_nodes WHERE kind = 'source' AND key != 'overflow'"
  ).get() as { c: number }).c;

  if (distinct >= opts.maxSources) {
    if (!errors.some(e => e.startsWith('source cap'))) {
      errors.push(`source cap (${opts.maxSources}) reached: new sources folding into overflow bucket`);
    }
    return upsertNode('source', 'overflow', ts);
  }
  return upsertNode('source', key, ts);
}

function projectRow(row: AuditRow, opts: Required<ProjectorOptions>, errors: string[]): { eventMinted: boolean } {
  const ts = toIso(row.timestamp);
  const sourceId = resolveSourceNode(row, ts, opts, errors);
  const patterns = parseJsonArray(row.blocked_patterns);
  const indicators = parseJsonArray(row.threat_indicators);
  const anomaly = row.anomaly_score ?? 0;

  // Tier 1: source counters + aggregate triggered edges — every row.
  updateAttrs(sourceId, (attrs) => {
    bump(attrs, 'scan_count');
    if (row.firewall_result === 'ALLOW') bump(attrs, 'allow_count');
    if (row.firewall_result === 'BLOCK') bump(attrs, 'block_count');
    if (row.firewall_result === 'QUARANTINE') bump(attrs, 'quarantine_count');
  });

  const patternIds = new Map<string, number>();
  for (const name of patterns) {
    const patternId = upsertNode('pattern', name, ts);
    patternIds.set(name, patternId);
    upsertEdge(sourceId, 'triggered', patternId, ts, row.id, opts.evidenceCap);
  }

  // Tier 2: event nodes for notable rows only.
  const notable =
    row.firewall_result === 'BLOCK' ||
    row.firewall_result === 'QUARANTINE' ||
    anomaly >= opts.anomalyEventThreshold;
  if (!notable) return { eventMinted: false };

  const eventId = upsertNode('event', `audit:${row.id}`, ts);
  updateAttrs(eventId, (attrs) => {
    attrs.verdict = row.firewall_result;
    attrs.anomaly = anomaly;
    if (row.project) attrs.project = row.project;
    // The fail-closed handler's own BLOCK rows: flagged so Phase B's risk
    // model zero-weights them — a wedged install must not inflate anyone's
    // risk with self-inflicted blocks.
    if (indicators.includes('pipeline_error')) attrs.pipeline_error = true;
  });
  upsertEdge(eventId, 'from_source', sourceId, ts, row.id, opts.evidenceCap);
  for (const [, patternId] of patternIds) {
    upsertEdge(eventId, 'matched', patternId, ts, row.id, opts.evidenceCap);
  }
  return { eventMinted: true };
}

/**
 * Project one batch of defence_audit rows. Atomic claim-and-advance: the
 * cursor is read and advanced inside a single IMMEDIATE transaction.
 * Errors are RETURNED, not persisted — last_error is owned by the callers
 * that own a whole run (runProjectorWithLease / rebuildThreatGraph), so a
 * stale batch error can never linger across healthy runs.
 */
export function projectAuditLedger(options?: ProjectorOptions): ProjectResult {
  assertNotInTransaction('audit projector');
  const opts = { ...DEFAULTS, ...options };
  const db = getDatabase();
  ensureStateRow();

  const result: ProjectResult = { processed: 0, cursor: 0, eventNodes: 0, errors: [] };

  const batch = db.transaction(() => {
    const state = db.prepare('SELECT last_audit_id FROM threat_graph_state WHERE id = 1').get() as { last_audit_id: number };
    const rows = db.prepare(`
      SELECT id, project, timestamp, source_type, source_identifier,
             firewall_result, anomaly_score, threat_indicators, blocked_patterns
      FROM defence_audit WHERE id > ? ORDER BY id ASC LIMIT ?
    `).all(state.last_audit_id, opts.batchSize) as AuditRow[];

    result.cursor = state.last_audit_id;
    for (const row of rows) {
      try {
        const { eventMinted } = projectRow(row, opts, result.errors);
        if (eventMinted) result.eventNodes++;
      } catch (e) {
        // A malformed row must not wedge the cursor forever: record and move on.
        result.errors.push(`audit:${row.id}: ${e instanceof Error ? e.message : String(e)}`);
      }
      result.cursor = row.id;
      result.processed++;
    }

    if (rows.length > 0) {
      for (const note of [evictEventOverflow(opts.maxEventNodes), evictEdgeOverflow(opts.maxEdges)]) {
        if (note) result.errors.push(note);
      }
      db.prepare('UPDATE threat_graph_state SET last_audit_id = ? WHERE id = 1').run(result.cursor);
    }
  });
  batch.immediate();

  return result;
}

/** Loop batches until the ledger is dry. Used by rebuild and the CLI. */
export function projectToCompletion(options?: ProjectorOptions): ProjectResult {
  const total: ProjectResult = { processed: 0, cursor: 0, eventNodes: 0, errors: [] };
  for (;;) {
    const r = projectAuditLedger(options);
    total.processed += r.processed;
    total.eventNodes += r.eventNodes;
    total.errors.push(...r.errors);
    total.cursor = r.cursor;
    if (r.processed === 0) break;
  }
  return total;
}

/** Clear the derived view and reset both cursors. Stamps PROJECTOR_VERSION. */
function clearGraph(): void {
  const db = getDatabase();
  db.transaction(() => {
    db.prepare('DELETE FROM threat_edges').run();
    db.prepare('DELETE FROM threat_nodes').run();
    db.prepare(`
      UPDATE threat_graph_state
      SET last_audit_id = 0, last_rt_cursor = '', last_error = NULL, projector_version = ?
      WHERE id = 1
    `).run(PROJECTOR_VERSION);
  }).immediate();
}

/**
 * Drop the derived view and replay BOTH ledgers from zero. Also the backfill:
 * on first run the graph populates from every retained audit row.
 */
export function rebuildThreatGraph(
  options?: ProjectorOptions & { realtimeDir?: string },
): ProjectResult {
  assertNotInTransaction('rebuild');
  const db = getDatabase();
  ensureStateRow();
  clearGraph();

  const result = projectToCompletion(options);
  if (options?.realtimeDir) {
    for (;;) {
      const rt = projectRealtimeLedger({ dir: options.realtimeDir });
      result.errors.push(...rt.errors);
      if (rt.processed === 0) break;
    }
  }
  db.prepare('UPDATE threat_graph_state SET last_error = ? WHERE id = 1')
    .run(result.errors.length > 0 ? result.errors.join('; ').slice(0, 1000) : null);
  return result;
}

export interface LeaseRunOptions extends ProjectorOptions {
  /** Wall clock (ms). Injectable for tests; graph data never uses it. */
  now?: number;
  /** Lease duration — how long a crashed holder blocks others. */
  leaseMs?: number;
  /** Realtime JSONL directory; omit to skip the second ledger. */
  realtimeDir?: string;
  /** Max claim-and-advance batches per run (bounds a single tick's work). */
  maxBatches?: number;
}

export interface LeaseRunResult {
  ran: boolean;
  audit: ProjectResult | null;
  realtime: RealtimeResult | null;
}

const DEFAULT_LEASE_MS = 120_000;
const DEFAULT_MAX_BATCHES = 20;

/**
 * Run the projector under the single-writer lease. Nothing enforces a worker
 * singleton (MCP servers, the dashboard, `shieldcortex worker` each construct
 * one), so exactly-once projection across N processes comes from an atomic
 * compare-and-set on threat_graph_state: a held, unexpired lease no-ops;
 * completion releases; a crashed holder's lease expires on its own. The
 * lease carries an ownership token so a run that outlives its lease cannot
 * clobber a successor's (release is `WHERE lease_token = mine`).
 *
 * Failure honesty: last_run_at means "a projection COMPLETED" — a failed run
 * best-effort records last_error and does NOT stamp the heartbeat, so the
 * doctor's freshness signal cannot be fooled by a projector that fails every
 * tick. The lease release is exception-isolated: a busy DB during release
 * must never mask the original error (expiry heals an unreleased lease).
 */
export function runProjectorWithLease(options?: LeaseRunOptions): LeaseRunResult {
  assertNotInTransaction('lease runner');
  const db = getDatabase();
  ensureStateRow();
  const now = options?.now ?? Date.now();
  const leaseMs = options?.leaseMs ?? DEFAULT_LEASE_MS;
  const maxBatches = options?.maxBatches ?? DEFAULT_MAX_BATCHES;
  const token = `${now.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

  let acquired = false;
  db.transaction(() => {
    const state = db.prepare('SELECT lease_expires_at FROM threat_graph_state WHERE id = 1')
      .get() as { lease_expires_at: string | null };
    if (state.lease_expires_at && Date.parse(state.lease_expires_at) > now) return;
    db.prepare('UPDATE threat_graph_state SET lease_expires_at = ?, lease_token = ? WHERE id = 1')
      .run(new Date(now + leaseMs).toISOString(), token);
    acquired = true;
  }).immediate();

  if (!acquired) return { ran: false, audit: null, realtime: null };

  let succeeded = false;
  const runErrors: string[] = [];
  try {
    // Projection-rule upgrades: a stored version behind the code forces a
    // from-zero rebuild (the doc's rebuild-on-bump mechanism).
    const stored = (db.prepare('SELECT projector_version FROM threat_graph_state WHERE id = 1')
      .get() as { projector_version: number }).projector_version;
    if (stored !== PROJECTOR_VERSION) {
      clearGraph();
    }

    const audit: ProjectResult = { processed: 0, cursor: 0, eventNodes: 0, errors: [] };
    for (let i = 0; i < maxBatches; i++) {
      const r = projectAuditLedger(options);
      audit.processed += r.processed;
      audit.eventNodes += r.eventNodes;
      audit.errors.push(...r.errors);
      audit.cursor = r.cursor;
      if (r.processed === 0) break;
    }
    runErrors.push(...audit.errors);

    const realtime = options?.realtimeDir
      ? projectRealtimeLedger({ dir: options.realtimeDir })
      : null;
    if (realtime) runErrors.push(...realtime.errors);

    succeeded = true;
    return { ran: true, audit, realtime };
  } catch (e) {
    try {
      db.prepare('UPDATE threat_graph_state SET last_error = ? WHERE id = 1 AND lease_token = ?')
        .run(`run failed: ${e instanceof Error ? e.message : String(e)}`.slice(0, 1000), token);
    } catch { /* best-effort — the thrown error below is the primary signal */ }
    throw e;
  } finally {
    try {
      if (succeeded) {
        db.prepare(`
          UPDATE threat_graph_state
          SET lease_expires_at = NULL, lease_token = NULL, last_run_at = ?, last_error = ?
          WHERE id = 1 AND lease_token = ?
        `).run(
          new Date(now).toISOString(),
          runErrors.length > 0 ? runErrors.join('; ').slice(0, 1000) : null,
          token,
        );
      } else {
        db.prepare('UPDATE threat_graph_state SET lease_expires_at = NULL, lease_token = NULL WHERE id = 1 AND lease_token = ?')
          .run(token);
      }
    } catch { /* a busy release must not mask the run's outcome; expiry heals */ }
  }
}

/**
 * Canonical dump for determinism checks: nodes ordered by (kind, key), edges
 * by (src_key, predicate, dst_key), surrogate ids excluded. Two projections
 * of the same ledger rows must produce byte-identical dumps.
 */
export function canonicalDump(): string {
  const db = getDatabase();
  const nodes = db.prepare(`
    SELECT kind, key, label, attrs, first_seen, last_seen
    FROM threat_nodes ORDER BY kind, key
  `).all() as Array<Record<string, unknown>>;
  const edges = db.prepare(`
    SELECT s.kind AS src_kind, s.key AS src_key, e.predicate,
           d.kind AS dst_kind, d.key AS dst_key,
           e.count, e.first_seen, e.last_seen, e.valid_to, e.writer, e.confidence, e.evidence
    FROM threat_edges e
    JOIN threat_nodes s ON s.id = e.src
    JOIN threat_nodes d ON d.id = e.dst
    ORDER BY s.kind, s.key, e.predicate, d.kind, d.key
  `).all() as Array<Record<string, unknown>>;
  return JSON.stringify({ nodes, edges });
}
