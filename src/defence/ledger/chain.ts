/**
 * Chained ledger writer (#617, design §5.7).
 *
 * One ledger per database. `ledger_meta` holds its identity (`ledger_id`, a
 * random 128-bit id created with the chain), the current epoch and the head
 * `(head_seq, head_hash)`. Every chained append reads the head, writes the row
 * at `head_seq + 1` linked to `head_hash`, and moves the head — all inside ONE
 * DB transaction (BEGIN IMMEDIATE, or a savepoint when the caller already
 * holds a transaction). So:
 *   - a crash between the INSERT and the chain finalise rolls the whole row
 *     back: there is never a half-chained row, and the head never moves
 *     without its row;
 *   - concurrent writers (threads or processes) serialise on the SQLite
 *     write lock, so seq is strictly increasing with no duplicates.
 *
 * Chained rows live in two tables that share one seq space: `defence_audit`
 * (security events) and `ledger_marker` (epoch-start, heartbeat,
 * lost-coverage, checkpoint). Markers are kept out of defence_audit so the
 * stats, threat-graph, digest and retention readers never count them.
 *
 * Rows written before the chain existed stay UNCHAINED (NULL chain columns);
 * nothing here ever hashes them into the chain (no retrofit).
 */

import type Database from 'better-sqlite3';
import { randomBytes } from 'crypto';
import {
  GENESIS_PREV_HASH,
  auditRowContent,
  canonicalJson,
  contentDigest,
  markerRowContent,
  rowHash,
  type LedgerMarkerKind,
} from './canonical.js';

export interface LedgerMeta {
  ledger_id: string;
  epoch: number;
  head_seq: number;
  head_hash: string;
  head_timestamp: string;
  chain_started_at: string;
  unchained_max_id: number;
  unchained_count: number;
}

// ── Test seam ───────────────────────────────────────────────────────────────
// Runs between the row INSERT and the chain finalise, inside the transaction.
// Tests use it to throw (in-process crash) or SIGKILL (real crash).
let faultAfterInsert: (() => void) | null = null;

export function __setLedgerFaultForTests(fn: (() => void) | null): void {
  faultAfterInsert = fn;
}

// ── Lost coverage (audit-write failure) ─────────────────────────────────────
interface PendingLoss {
  from: string;
  reason: string;
  count: number;
}

let pendingLoss: PendingLoss | null = null;

export function __resetLedgerStateForTests(): void {
  pendingLoss = null;
  faultAfterInsert = null;
}

/**
 * Record that an audit row could not be persisted. The verdict it described
 * has already been decided (and is returned to the caller unchanged); only
 * the evidence is lost. The next successful chained write appends one
 * `lost-coverage` marker covering the whole failed interval. Lost events are
 * counted, never reconstructed. Process-local: if the process dies before
 * recovery, the loss is visible only as a missing interval.
 */
export function noteAuditWriteFailure(err: unknown, now: Date = new Date()): void {
  const msg = err instanceof Error ? err.message : String(err);
  if (!pendingLoss) {
    pendingLoss = { from: now.toISOString(), reason: msg.slice(0, 300), count: 1 };
  } else {
    pendingLoss.count++;
  }
}

// ── Meta ────────────────────────────────────────────────────────────────────

export function hasLedgerTables(db: Database.Database): boolean {
  const row = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ledger_meta'").get();
  return row !== undefined;
}

export function readLedgerMeta(db: Database.Database): LedgerMeta | null {
  if (!hasLedgerTables(db)) return null;
  const row = db.prepare('SELECT * FROM ledger_meta WHERE id = 1').get() as LedgerMeta | undefined;
  return row ?? null;
}

/**
 * Run `fn` in a write transaction: BEGIN IMMEDIATE at top level (take the
 * write lock before reading the head), a savepoint when nested.
 */
function inWriteTx<T>(db: Database.Database, fn: () => T): T {
  return db.transaction(fn).immediate();
}

interface SurvivingHead {
  ledger_id: string;
  epoch: number;
  seq: number;
  row_hash: string;
}

function survivingHead(db: Database.Database): SurvivingHead | null {
  const row = db.prepare(`
    SELECT ledger_id, epoch, seq, row_hash FROM (
      SELECT ledger_id, epoch, seq, row_hash FROM defence_audit WHERE seq IS NOT NULL AND row_hash IS NOT NULL
      UNION ALL
      SELECT ledger_id, epoch, seq, row_hash FROM ledger_marker
    ) ORDER BY epoch DESC, seq DESC LIMIT 1
  `).get() as SurvivingHead | undefined;
  return row ?? null;
}

function appendMarkerWithMeta(
  db: Database.Database,
  meta: LedgerMeta,
  kind: LedgerMarkerKind,
  payload: unknown,
  timestamp: string,
): { seq: number; rowHash: string } {
  const seq = meta.head_seq + 1;
  const prev = meta.head_hash;
  const payloadText = canonicalJson(payload);
  const digest = contentDigest(markerRowContent({
    ledger_id: meta.ledger_id, epoch: meta.epoch, kind, timestamp, payload: JSON.parse(payloadText),
  }));
  const hash = rowHash(prev, seq, digest);
  db.prepare(`
    INSERT INTO ledger_marker (ledger_id, epoch, seq, kind, timestamp, payload, prev_hash, content_digest, row_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(meta.ledger_id, meta.epoch, seq, kind, timestamp, payloadText, prev, digest, hash);
  moveHead(db, meta, seq, hash, timestamp);
  return { seq, rowHash: hash };
}

function moveHead(db: Database.Database, meta: LedgerMeta, seq: number, hash: string, timestamp: string): void {
  db.prepare('UPDATE ledger_meta SET head_seq = ?, head_hash = ?, head_timestamp = ? WHERE id = 1')
    .run(seq, hash, timestamp);
  meta.head_seq = seq;
  meta.head_hash = hash;
  meta.head_timestamp = timestamp;
}

function startEpoch(
  db: Database.Database,
  fields: Omit<LedgerMeta, 'head_seq' | 'head_hash' | 'head_timestamp'>,
  payload: Record<string, unknown>,
  now: string,
): LedgerMeta {
  const meta: LedgerMeta = { ...fields, head_seq: -1, head_hash: GENESIS_PREV_HASH, head_timestamp: now };
  db.prepare(`
    INSERT OR REPLACE INTO ledger_meta
      (id, ledger_id, epoch, head_seq, head_hash, head_timestamp, chain_started_at, unchained_max_id, unchained_count)
    VALUES (1, @ledger_id, @epoch, @head_seq, @head_hash, @head_timestamp, @chain_started_at, @unchained_max_id, @unchained_count)
  `).run(meta);
  appendMarkerWithMeta(db, meta, 'epoch-start', payload, now);
  return meta;
}

/**
 * Create the ledger if this database does not have one yet, and return its
 * meta. Idempotent. Returns null when the ledger tables do not exist (a
 * database this build has not migrated).
 *
 * - No meta and no chained rows: a new ledger at epoch 0. Existing
 *   defence_audit rows become the UNCHAINED history; the epoch-start row
 *   records their count and id range, and coverage starts now.
 * - No meta but chained rows survive (meta wiped, a reinstall over an
 *   existing database): the same `ledger_id` continues in a new epoch whose
 *   epoch-start names the surviving head. It is always shown by the verifier.
 */
export function ensureLedger(db: Database.Database, opts: { now?: Date } = {}): LedgerMeta | null {
  if (!hasLedgerTables(db)) return null;
  const existing = readLedgerMeta(db);
  if (existing) return existing;
  return inWriteTx(db, () => {
    const again = readLedgerMeta(db);
    if (again) return again;
    const now = (opts.now ?? new Date()).toISOString();
    const head = survivingHead(db);
    if (head) {
      const first = db.prepare(
        "SELECT timestamp, payload FROM ledger_marker WHERE kind = 'epoch-start' ORDER BY epoch ASC, seq ASC LIMIT 1",
      ).get() as { timestamp: string; payload: string } | undefined;
      const hist = first ? (JSON.parse(first.payload).unchained_history ?? null) : null;
      return startEpoch(db, {
        ledger_id: head.ledger_id,
        epoch: head.epoch + 1,
        chain_started_at: first?.timestamp ?? now,
        unchained_max_id: hist?.max_id ?? 0,
        unchained_count: hist?.count ?? 0,
      }, {
        reason: 'ledger-meta-missing',
        previous_head: { epoch: head.epoch, seq: head.seq, row_hash: head.row_hash },
        previous_head_source: 'surviving-rows',
      }, now);
    }
    const u = db.prepare(
      'SELECT COUNT(*) AS c, MAX(id) AS m, MIN(timestamp) AS f, MAX(timestamp) AS l FROM defence_audit WHERE seq IS NULL',
    ).get() as { c: number; m: number | null; f: string | null; l: string | null };
    return startEpoch(db, {
      ledger_id: randomBytes(16).toString('hex'),
      epoch: 0,
      chain_started_at: now,
      unchained_max_id: u.m ?? 0,
      unchained_count: u.c,
    }, {
      reason: u.c > 0 ? 'migration' : 'new-ledger',
      previous_head: null,
      unchained_history: { count: u.c, max_id: u.m ?? 0, first_timestamp: u.f, last_timestamp: u.l },
    }, now);
  });
}

/** Append a chained marker row (epoch-start is written by the ledger itself). */
export function appendLedgerMarker(
  db: Database.Database,
  kind: Exclude<LedgerMarkerKind, 'epoch-start'>,
  payload: Record<string, unknown>,
  opts: { now?: Date } = {},
): { seq: number; rowHash: string } | null {
  return inWriteTx(db, () => {
    const meta = ensureLedger(db);
    if (!meta) return null;
    return appendMarkerWithMeta(db, meta, kind, payload, (opts.now ?? new Date()).toISOString());
  });
}

function flushLostCoverage(db: Database.Database, meta: LedgerMeta): PendingLoss | null {
  const loss = pendingLoss;
  if (!loss) return null;
  const to = new Date().toISOString();
  appendMarkerWithMeta(db, meta, 'lost-coverage', {
    from: loss.from,
    to,
    reason: loss.reason,
    events_lost: loss.count,
  }, to);
  return loss;
}

/**
 * Insert one defence_audit row, chained. `values` maps column → value; the
 * keys are code-controlled column names, never caller data. The digest is
 * computed from the row read back inside the transaction (see canonical.ts).
 *
 * A pending lost-coverage interval is written first, in the same transaction,
 * and cleared only after commit. Throws on failure; callers that must never
 * throw (logAudit) catch and call noteAuditWriteFailure().
 */
export function insertChainedAuditRow(db: Database.Database, values: Record<string, unknown>): number {
  let flushed: PendingLoss | null = null;
  const id = inWriteTx(db, () => {
    const meta = ensureLedger(db);
    const cols = Object.keys(values);
    if (!meta) {
      const res = db.prepare(
        `INSERT INTO defence_audit (${cols.join(', ')}) VALUES (${cols.map((c) => `@${c}`).join(', ')})`,
      ).run(values);
      return Number(res.lastInsertRowid);
    }
    flushed = flushLostCoverage(db, meta);
    const seq = meta.head_seq + 1;
    const prev = meta.head_hash;
    const all = { ...values, ledger_id: meta.ledger_id, epoch: meta.epoch, seq, prev_hash: prev };
    const allCols = Object.keys(all);
    const res = db.prepare(
      `INSERT INTO defence_audit (${allCols.join(', ')}) VALUES (${allCols.map((c) => `@${c}`).join(', ')})`,
    ).run(all);
    const rowId = Number(res.lastInsertRowid);
    if (faultAfterInsert) faultAfterInsert();
    const stored = db.prepare('SELECT * FROM defence_audit WHERE id = ?').get(rowId) as Record<string, unknown>;
    const digest = contentDigest(auditRowContent(stored, meta.ledger_id, meta.epoch));
    const hash = rowHash(prev, seq, digest);
    db.prepare('UPDATE defence_audit SET content_digest = ?, row_hash = ? WHERE id = ?').run(digest, hash, rowId);
    moveHead(db, meta, seq, hash, new Date().toISOString());
    return rowId;
  });
  if (flushed && pendingLoss === flushed) pendingLoss = null;
  return id;
}

/**
 * Write a heartbeat row when nothing has been chained for `intervalMs`, so a
 * quiet period is distinguishable from a missing one. Returns true when a
 * heartbeat was written.
 */
export function writeHeartbeatIfDue(
  db: Database.Database,
  opts: { intervalMs: number; now?: number },
): boolean {
  const now = opts.now ?? Date.now();
  return inWriteTx(db, () => {
    const meta = ensureLedger(db);
    if (!meta) return false;
    const last = Date.parse(meta.head_timestamp);
    if (Number.isFinite(last) && now - last < opts.intervalMs) return false;
    appendMarkerWithMeta(db, meta, 'heartbeat', { interval_ms: opts.intervalMs }, new Date(now).toISOString());
    return true;
  });
}

/**
 * Start a new epoch (reinstall or deliberate reset): epoch+1 at seq 0, whose
 * epoch-start names the previous head. The verifier always shows it.
 */
export function resetLedgerEpoch(db: Database.Database, reason: string, opts: { now?: Date } = {}): LedgerMeta {
  return inWriteTx(db, () => {
    const meta = ensureLedger(db);
    if (!meta) throw new Error('ledger tables are missing; open the database with this build first');
    const now = (opts.now ?? new Date()).toISOString();
    return startEpoch(db, {
      ledger_id: meta.ledger_id,
      epoch: meta.epoch + 1,
      chain_started_at: meta.chain_started_at,
      unchained_max_id: meta.unchained_max_id,
      unchained_count: meta.unchained_count,
    }, {
      reason,
      previous_head: { epoch: meta.epoch, seq: meta.head_seq, row_hash: meta.head_hash },
      previous_head_source: 'ledger_meta',
    }, now);
  });
}

export interface PrunedRun {
  epoch: number;
  from: number;
  to: number;
  count: number;
  start_hash: string;
  boundary_hash: string;
}

/**
 * Retention hook: call INSIDE the retention transaction, BEFORE deleting the
 * defence_audit rows selected by `where`. Keeps the skeleton `(seq,
 * content_digest)` of every chained row being pruned (unless disabled) and
 * appends a chained checkpoint row:
 *   { range, count, start_hash = prev_hash(first), boundary_hash = row_hash(last),
 *     skeleton_kept, runs, unchained_pruned, receipt_serials: [] }
 * `runs` splits the pruned rows into contiguous seq ranges (size-pressure
 * pruning is not contiguous). Unchained rows are counted, never witnessed.
 */
export function recordPrunedAuditRows(
  db: Database.Database,
  where: string,
  params: unknown[],
  opts: { keepSkeleton: boolean; now?: Date },
): void {
  const meta = ensureLedger(db);
  if (!meta) return;
  const rows = db.prepare(`
    SELECT id, ledger_id, epoch, seq, prev_hash, content_digest, row_hash
    FROM defence_audit WHERE (${where})
  `).all(...params) as Array<{
    id: number; ledger_id: string | null; epoch: number | null; seq: number | null;
    prev_hash: string | null; content_digest: string | null; row_hash: string | null;
  }>;
  if (rows.length === 0) return;
  const chained = rows
    .filter((r) => r.seq !== null && r.row_hash !== null)
    .sort((a, b) => (Number(a.epoch) - Number(b.epoch)) || (Number(a.seq) - Number(b.seq)));
  const unchainedPruned = rows.length - chained.length;

  const runs: PrunedRun[] = [];
  for (const r of chained) {
    const last = runs[runs.length - 1];
    if (last && last.epoch === r.epoch && last.to + 1 === r.seq) {
      last.to = Number(r.seq);
      last.count++;
      last.boundary_hash = String(r.row_hash);
    } else {
      runs.push({
        epoch: Number(r.epoch),
        from: Number(r.seq),
        to: Number(r.seq),
        count: 1,
        start_hash: String(r.prev_hash),
        boundary_hash: String(r.row_hash),
      });
    }
  }

  if (opts.keepSkeleton) {
    const ins = db.prepare(
      'INSERT OR REPLACE INTO ledger_skeleton (ledger_id, epoch, seq, content_digest) VALUES (?, ?, ?, ?)',
    );
    for (const r of chained) ins.run(r.ledger_id, r.epoch, r.seq, r.content_digest);
  }

  const first = runs[0];
  const last = runs[runs.length - 1];
  appendMarkerWithMeta(db, meta, 'checkpoint', {
    range: first ? { from: { epoch: first.epoch, seq: first.from }, to: { epoch: last.epoch, seq: last.to } } : null,
    count: chained.length,
    start_hash: first ? first.start_hash : null,
    boundary_hash: last ? last.boundary_hash : null,
    skeleton_kept: opts.keepSkeleton,
    runs,
    unchained_pruned: unchainedPruned,
    receipt_serials: [],
  }, (opts.now ?? new Date()).toISOString());
}
