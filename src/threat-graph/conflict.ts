/**
 * Phase E — relation-channel conflict detection (the ShadowMerge defence).
 *
 * ShadowMerge (arXiv:2605.09033) poisons graph-based agent memory by injecting
 * an edge that contradicts an established relation, betting the store will
 * silently merge both. This pass refuses to merge silently: when a
 * SINGLE-VALUED channel (a subject + one of `uses`/`depends_on`/`configures`/
 * `replaces`) holds ≥2 distinct open objects whose writers differ in trust by
 * ≥ the margin, the channel is a conflict.
 *
 * Resolution is SYMMETRIC (see design doc — the red team's first-mover finding):
 *   - BOTH contending triples are flagged `disputed`; NEITHER is auto-suspended.
 *   - One `conflict` event node is minted as the operator review item.
 *   - The operator resolves (keep one / keep both / reject both) via
 *     resolveConflict() below.
 *
 * The pass is STATELESS and IDEMPOTENT: it recomputes `disputed` from scratch
 * each run and re-derives the open-conflict nodes, so incremental ticks and a
 * full rebuild converge. Standing `keep_both` resolutions (read from the
 * operation='review' ledger) suppress re-flagging until a *new* contender
 * appears outside the covered set.
 */

import type { Database } from 'better-sqlite3';
import { getDatabase } from '../database/init.js';
import { logAudit } from '../defence/audit/logger.js';

/**
 * Single-valued predicates: a subject should have exactly one of these. A
 * second value on the same channel is a contradiction, not a second fact.
 * `related_to` (co-occurrence) and every other multi-valued predicate
 * (`fixes`, `extends`, `preferred_over`) assert nothing single-valued and are
 * never conflict channels.
 */
export const SINGLE_VALUED_PREDICATES = ['uses', 'depends_on', 'configures', 'replaces'] as const;

/** Minimum writer-trust spread across contenders for a channel to be flagged. */
export const CONFLICT_TRUST_MARGIN = 0.3;

/**
 * Float tolerance for the (inclusive) margin gate. IEEE-754 subtraction lands
 * some exactly-0.3-apart pairs just below 0.3 (`0.7 - 0.4 === 0.2999999999…`),
 * and 0.7 is the single most common stored writer_trust (the unattested cap),
 * so without this the most common boundary conflict is silently missed.
 */
const MARGIN_EPSILON = 1e-9;

/**
 * Effective trust for a triple with no recorded provenance (backfilled/legacy).
 * Neutral 0.5 — unknown provenance is neither trusted nor distrusted, so legacy
 * triples never manufacture an artificial spread against one another, while a
 * genuinely asymmetric conflict still surfaces.
 */
export const NEUTRAL_WRITER_TRUST = 0.5;

/**
 * Quarantine-approved provenance. Approval admits content; it never crowns a
 * fact — a `user:approved` contender is disqualified from being the
 * authoritative side of a conflict.
 */
export const USER_APPROVED_SOURCE = 'user:approved';

export interface ConflictContender {
  triple_id: number;
  object_id: number;
  object: string;
  writer_source: string | null;
  writer_trust: number | null;
  eff_trust: number;
  valid_from: string | null;
  source_memory_id: number | null;
}

export interface ConflictDetectionResult {
  /** Number of open conflicted channels. */
  conflicts: number;
  /** Number of triples flagged disputed this pass. */
  disputedTriples: number;
  /** Channel keys (`<subject_id>:<predicate>`) currently in conflict. */
  channels: string[];
}

interface OpenTripleRow {
  triple_id: number;
  subject_id: number;
  predicate: string;
  object_id: number;
  writer_source: string | null;
  writer_trust: number | null;
  valid_from: string | null;
  source_memory_id: number | null;
  subject_name: string;
  object_name: string;
}

export function effTrust(writerTrust: number | null): number {
  return typeof writerTrust === 'number' ? writerTrust : NEUTRAL_WRITER_TRUST;
}

/**
 * Cap + strip content-derived display strings before they land in a threat node
 * label/attrs — the same hygiene invariant 5 prescribes for content-derived
 * labels across the threat graph. Entity names are already regex-bounded, so
 * this is defence-in-depth + consistency, not a load-bearing control.
 */
function safeLabel(s: string): string {
  // eslint-disable-next-line no-control-regex
  return (s || '').replace(/[\u0000-\u001F\u007F]/g, ' ').slice(0, 256);
}

/**
 * A resolution recorded in the operation='review' ledger. `keep_both` is the
 * only one the detector must remember — `keep_one`/`reject_both` suspend their
 * losers via valid_to, so those channels resolve themselves in the open query.
 */
export interface ConflictResolution {
  kind: 'conflict_resolution';
  subject_id: number;
  predicate: string;
  resolution: 'keep_one' | 'keep_both' | 'reject_both';
  kept_object_id?: number;
  covered_object_ids: number[];
}

export function parseConflictResolution(reason: string | null | undefined): ConflictResolution | null {
  if (!reason) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(reason);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object') return null;
  const p = parsed as Record<string, unknown>;
  if (p.kind !== 'conflict_resolution') return null;
  if (typeof p.subject_id !== 'number' || typeof p.predicate !== 'string') return null;
  const resolution = p.resolution;
  if (resolution !== 'keep_one' && resolution !== 'keep_both' && resolution !== 'reject_both') return null;
  const covered = Array.isArray(p.covered_object_ids)
    ? p.covered_object_ids.filter((x): x is number => typeof x === 'number')
    : [];
  return {
    kind: 'conflict_resolution',
    subject_id: p.subject_id,
    predicate: p.predicate,
    resolution,
    kept_object_id: typeof p.kept_object_id === 'number' ? p.kept_object_id : undefined,
    covered_object_ids: covered,
  };
}

interface ChannelResolution {
  subjectId: number;
  predicate: string;
  resolution: 'keep_one' | 'keep_both' | 'reject_both';
  covered: Set<number>;
  keptObjectId?: number;
  /** Ledger timestamp — used as valid_to when replaying a suspension. */
  ts: string;
}

/**
 * Latest standing resolution per channel, replayed from the operation='review'
 * ledger (the truth). Last-writer-wins by row id, so an operator changing their
 * mind is honoured. The `reason LIKE` prefilter keeps this off the other
 * review-row writers (risk_reset / auto_release / quarantine_decision), which
 * otherwise grow unbounded with audit history.
 */
function loadResolutions(db: Database): Map<string, ChannelResolution> {
  const rows = db
    .prepare(
      "SELECT reason, timestamp FROM defence_audit WHERE operation = 'review' AND reason LIKE '%conflict_resolution%' ORDER BY id ASC",
    )
    .all() as Array<{ reason: string | null; timestamp: string }>;
  const map = new Map<string, ChannelResolution>();
  for (const r of rows) {
    const res = parseConflictResolution(r.reason);
    if (!res) continue;
    map.set(`${res.subject_id}:${res.predicate}`, {
      subjectId: res.subject_id,
      predicate: res.predicate,
      resolution: res.resolution,
      covered: new Set(res.covered_object_ids),
      keptObjectId: res.kept_object_id,
      ts: r.timestamp,
    });
  }
  return map;
}

/**
 * Re-apply operator suspensions (keep_one/reject_both) to any covered loser that
 * has become open again — e.g. the source memory was edited/merged and its
 * triples were re-extracted with valid_to = NULL. This makes ALL resolutions
 * ledger-durable (uniform with keep_both's coverage replay), closing the gap
 * where an operator-rejected edge would silently go live after an unrelated
 * edit. It only ever SUSPENDS a covered loser per an explicit operator decision
 * — never loosens, never touches an object outside the covered set (a genuinely
 * new contender re-opens the channel instead).
 */
function replayOperatorSuspensions(db: Database, resolutions: Map<string, ChannelResolution>): void {
  const suspend = db.prepare(
    `UPDATE triples SET valid_to = ?, disputed = 0
     WHERE subject_id = ? AND predicate = ? AND object_id = ? AND valid_to IS NULL`,
  );
  for (const res of resolutions.values()) {
    if (res.resolution === 'keep_both') continue;
    for (const objectId of res.covered) {
      if (res.resolution === 'keep_one' && objectId === res.keptObjectId) continue;
      suspend.run(res.ts, res.subjectId, res.predicate, objectId);
    }
  }
}

function upsertConflictNode(
  db: Database,
  channelKey: string,
  group: OpenTripleRow[],
  nowIso: string,
): void {
  const subjectId = group[0].subject_id;
  const predicate = group[0].predicate;
  const key = `conflict:${channelKey}`;

  const contenders: ConflictContender[] = group.map((g) => ({
    triple_id: g.triple_id,
    object_id: g.object_id,
    object: safeLabel(g.object_name),
    writer_source: g.writer_source,
    writer_trust: g.writer_trust,
    eff_trust: effTrust(g.writer_trust),
    valid_from: g.valid_from,
    source_memory_id: g.source_memory_id,
  }));

  // Authoritative side = the single highest-trust contender, EXCLUDING
  // user:approved. A tie (or all-disqualified) yields no clear winner.
  const eligible = contenders.filter((c) => c.writer_source !== USER_APPROVED_SOURCE);
  let authoritativeObjectId: number | null = null;
  if (eligible.length > 0) {
    const maxT = Math.max(...eligible.map((c) => c.eff_trust));
    const top = eligible.filter((c) => c.eff_trust === maxT);
    authoritativeObjectId = top.length === 1 ? top[0].object_id : null;
  }

  const effs = contenders.map((c) => c.eff_trust);
  const subjectName = safeLabel(group[0].subject_name);
  const attrs = {
    type: 'conflict',
    subject_id: subjectId,
    subject: subjectName,
    predicate,
    status: 'open',
    detected_margin: Number((Math.max(...effs) - Math.min(...effs)).toFixed(4)),
    authoritative_object_id: authoritativeObjectId,
    contenders,
  };

  const label = `conflict: ${subjectName} ${predicate} (${contenders.length} contenders)`;
  // Upsert preserving first_seen (when the conflict was first detected).
  db.prepare(
    `INSERT INTO threat_nodes (kind, key, label, attrs, first_seen, last_seen)
     VALUES ('event', ?, ?, ?, ?, ?)
     ON CONFLICT(kind, key) DO UPDATE SET
       label = excluded.label,
       attrs = excluded.attrs,
       last_seen = MAX(threat_nodes.last_seen, excluded.last_seen)`,
  ).run(key, label, JSON.stringify(attrs), nowIso, nowIso);
}

function removeStaleConflictNodes(db: Database, openChannels: string[]): void {
  const keep = new Set(openChannels.map((c) => `conflict:${c}`));
  const existing = db
    .prepare("SELECT id, key FROM threat_nodes WHERE kind = 'event' AND key LIKE 'conflict:%'")
    .all() as Array<{ id: number; key: string }>;
  const stale = existing.filter((n) => !keep.has(n.key)).map((n) => n.id);
  if (stale.length === 0) return;
  const ph = stale.map(() => '?').join(',');
  db.prepare(`DELETE FROM threat_nodes WHERE id IN (${ph})`).run(...stale);
}

/**
 * Run one idempotent conflict-detection pass. Recomputes `disputed` on all
 * single-valued triples and re-derives the open-conflict review nodes.
 */
export function detectRelationConflicts(options?: { nowMs?: number }): ConflictDetectionResult {
  const db = getDatabase();
  const nowIso = new Date(options?.nowMs ?? Date.now()).toISOString();
  const preds = SINGLE_VALUED_PREDICATES;
  const ph = preds.map(() => '?').join(',');

  return db.transaction(() => {
    // 1. Full recompute: clear disputed on every currently-disputed single-valued
    //    triple, then re-set only the ones still in conflict below.
    db.prepare(`UPDATE triples SET disputed = 0 WHERE disputed = 1 AND predicate IN (${ph})`).run(...preds);

    // 1b. Replay operator suspensions from the ledger BEFORE reading the open set,
    //     so a keep_one/reject_both loser resurrected by a memory edit/merge is
    //     re-suspended and excluded below (uniform with keep_both's coverage).
    const resolutions = loadResolutions(db);
    replayOperatorSuspensions(db, resolutions);

    // 2. Open single-valued triples with entity names.
    const rows = db
      .prepare(
        `SELECT t.id AS triple_id, t.subject_id, t.predicate, t.object_id,
                t.writer_source, t.writer_trust, t.valid_from, t.source_memory_id,
                s.name AS subject_name, o.name AS object_name
         FROM triples t
         JOIN entities s ON s.id = t.subject_id
         JOIN entities o ON o.id = t.object_id
         WHERE t.predicate IN (${ph}) AND t.valid_to IS NULL
         ORDER BY t.subject_id, t.predicate, t.id`,
      )
      .all(...preds) as OpenTripleRow[];

    // 3. Group by channel.
    const groups = new Map<string, OpenTripleRow[]>();
    for (const r of rows) {
      const channelKey = `${r.subject_id}:${r.predicate}`;
      const g = groups.get(channelKey);
      if (g) g.push(r);
      else groups.set(channelKey, [r]);
    }

    // keep_both coverage suppresses re-flagging while the open set stays within it.
    const keepBoth = new Map<string, Set<number>>();
    for (const [channelKey, res] of resolutions) {
      if (res.resolution === 'keep_both') keepBoth.set(channelKey, res.covered);
    }
    const setDisputed = db.prepare('UPDATE triples SET disputed = 1 WHERE id = ?');
    const openChannels: string[] = [];
    let disputedCount = 0;

    for (const [channelKey, group] of groups) {
      const objectIds = new Set(group.map((g) => g.object_id));
      if (objectIds.size < 2) continue; // single-valued slot satisfied

      const effs = group.map((g) => effTrust(g.writer_trust));
      const spread = Math.max(...effs) - Math.min(...effs);
      // Inclusive >= margin; the epsilon absorbs IEEE-754 boundary artefacts
      // (e.g. 0.7 - 0.4) so an exactly-0.3-apart pair is not silently dropped.
      if (spread < CONFLICT_TRUST_MARGIN - MARGIN_EPSILON) continue; // benign multi-value coexistence

      // Respect a standing keep_both resolution covering the current open set.
      const covered = keepBoth.get(channelKey);
      if (covered && [...objectIds].every((o) => covered.has(o))) continue;

      openChannels.push(channelKey);
      for (const g of group) {
        setDisputed.run(g.triple_id);
        disputedCount++;
      }
      upsertConflictNode(db, channelKey, group, nowIso);
    }

    // 4. Drop conflict nodes for channels no longer in open conflict.
    removeStaleConflictNodes(db, openChannels);

    return { conflicts: openChannels.length, disputedTriples: disputedCount, channels: openChannels };
  })();
}

export interface ConflictResolutionInput {
  subjectId: number;
  predicate: string;
  resolution: 'keep_one' | 'keep_both' | 'reject_both';
  /** Required for keep_one: the object to keep (must be an open contender). */
  keptObjectId?: number;
}

export interface ConflictResolutionResult {
  channelKey: string;
  resolution: 'keep_one' | 'keep_both' | 'reject_both';
  /** Triples given a valid_to (suspended). */
  suspended: number;
  /** Distinct object ids that were open at resolution time. */
  covered: number[];
}

/**
 * Apply an operator resolution to a relation-channel conflict. Writes the
 * authoritative operation='review' ledger row AND applies the effect
 * immediately (operator UX). A rebuild reproduces the outcome: valid_to is an
 * operator fact that survives, and the keep_both coverage is read back from the
 * ledger by detectRelationConflicts(). The projector never suspends an edge —
 * only this operator path does.
 */
export function resolveConflict(
  input: ConflictResolutionInput,
  operator: string,
  options?: { nowMs?: number },
): ConflictResolutionResult {
  const db = getDatabase();
  const nowIso = new Date(options?.nowMs ?? Date.now()).toISOString();
  const channelKey = `${input.subjectId}:${input.predicate}`;

  // Defence-in-depth: only single-valued channels can be in conflict, so a
  // suspension must never land on a multi-valued (e.g. related_to) edge. The
  // shipped CLI can't reach here with another predicate (it resolves an existing
  // conflict node, only minted for single-valued channels), but a future caller
  // of this exported function could.
  if (!(SINGLE_VALUED_PREDICATES as readonly string[]).includes(input.predicate)) {
    throw new Error(`resolveConflict: '${input.predicate}' is not a single-valued conflict predicate`);
  }

  return db.transaction(() => {
    const open = db
      .prepare(
        `SELECT id, object_id FROM triples
         WHERE subject_id = ? AND predicate = ? AND valid_to IS NULL`,
      )
      .all(input.subjectId, input.predicate) as Array<{ id: number; object_id: number }>;

    if (open.length === 0) {
      throw new Error(`no open triples on channel ${channelKey} to resolve`);
    }
    const covered = [...new Set(open.map((o) => o.object_id))].sort((a, b) => a - b);

    let suspended = 0;
    const suspend = db.prepare('UPDATE triples SET valid_to = ?, disputed = 0 WHERE id = ?');
    const clearDisputed = db.prepare('UPDATE triples SET disputed = 0 WHERE id = ?');

    if (input.resolution === 'keep_one') {
      if (input.keptObjectId === undefined || !covered.includes(input.keptObjectId)) {
        throw new Error(`keep_one requires keptObjectId to be an open contender on ${channelKey}`);
      }
      for (const o of open) {
        if (o.object_id === input.keptObjectId) clearDisputed.run(o.id);
        else {
          suspend.run(nowIso, o.id);
          suspended++;
        }
      }
    } else if (input.resolution === 'reject_both') {
      for (const o of open) {
        suspend.run(nowIso, o.id);
        suspended++;
      }
    } else {
      // keep_both — nothing suspended; both coexist, disputes cleared. The
      // covered set (below) suppresses re-flagging until a new contender.
      for (const o of open) clearDisputed.run(o.id);
    }

    // The authoritative record — a rebuild replays this.
    const payload: ConflictResolution = {
      kind: 'conflict_resolution',
      subject_id: input.subjectId,
      predicate: input.predicate,
      resolution: input.resolution,
      kept_object_id: input.resolution === 'keep_one' ? input.keptObjectId : undefined,
      covered_object_ids: covered,
    };
    try {
      logAudit({
        memory_id: null,
        project: null,
        timestamp: nowIso,
        source_type: 'user',
        source_identifier: operator,
        trust_score: 0.9,
        sensitivity_level: 'INTERNAL',
        firewall_result: 'ALLOW',
        operation: 'review',
        anomaly_score: 0,
        threat_indicators: '[]',
        blocked_patterns: '[]',
        reason: JSON.stringify(payload),
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    } catch {
      // Recording the decision must never break the resolution action itself.
    }

    // Immediate feedback: drop the review node. The next detection pass confirms
    // (fewer open objects, or keep_both coverage) that it stays gone.
    db.prepare("DELETE FROM threat_nodes WHERE kind = 'event' AND key = ?").run(`conflict:${channelKey}`);

    return { channelKey, resolution: input.resolution, suspended, covered };
  })();
}
