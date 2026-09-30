/**
 * `ledger verify` (#617, design §5.7). Read-only: walks the chain of one
 * database and reports what it can and cannot check. Used by the CLI and by
 * the doctor row, so both say the same thing.
 */

import type Database from 'better-sqlite3';
import {
  GENESIS_PREV_HASH,
  auditRowContent,
  contentDigest,
  markerRowContent,
  rowHash,
} from './canonical.js';
import type { LedgerMeta, PrunedRun } from './chain.js';

/**
 * What a locally consistent chain does NOT show (§5.7 "What the free chain
 * detects alone"). Printed in every report, text and JSON.
 */
export const LEDGER_LIMITS_STATEMENT =
  'A locally consistent chain detects inconsistent edits: a row changed or deleted in the middle breaks the hashes from there. ' +
  'It does NOT show completeness (events that were never recorded, or were lost, leave no row), and it does not show that the chain ' +
  'was not rewritten as a whole or that its tail was not deleted: nothing outside this database says what the head should be. ' +
  'Those are detectable only against an independently retained head (one kept outside this database, or an external anchor receipt). ' +
  'There are no anchors yet, so every checkpoint here is local, not independently committed.';

export const CHECKPOINT_COMMITMENT = 'local, not independently committed' as const;

export type LedgerStatus = 'consistent' | 'inconsistent' | 'unchained';

export type LedgerProblemKind =
  | 'prev-hash-mismatch'
  | 'digest-mismatch'
  | 'row-hash-mismatch'
  | 'gap'
  | 'duplicate-seq'
  | 'epoch-start-missing'
  | 'epoch-link-mismatch'
  | 'checkpoint-mismatch'
  | 'skeleton-mismatch'
  | 'head-mismatch'
  | 'foreign-ledger'
  | 'ledger-meta-missing'
  | 'unchained-row-after-start';

export interface LedgerProblem {
  epoch: number | null;
  seq: number | null;
  kind: LedgerProblemKind;
  detail: string;
}

export interface LedgerEpochInfo {
  epoch: number;
  startedAt: string | null;
  reason: string | null;
  firstSeq: number | null;
  lastSeq: number | null;
  rows: number;
  previousHead: { epoch: number; seq: number; row_hash: string } | null;
  previousHeadCheck: 'none' | 'matches' | 'differs' | 'not-present' | 'unknown';
}

export interface LedgerCheckpointInfo {
  epoch: number;
  seq: number;
  timestamp: string;
  count: number;
  unchainedPruned: number;
  skeletonKept: boolean;
  runs: PrunedRun[];
  recheck: 'recomputed' | 'not-re-checkable' | 'failed';
  commitment: typeof CHECKPOINT_COMMITMENT;
}

export interface LedgerReport {
  status: LedgerStatus;
  ledgerId: string | null;
  currentEpoch: number | null;
  head: { epoch: number; seq: number; rowHash: string } | null;
  chainedRows: number;
  firstBad: LedgerProblem | null;
  problems: LedgerProblem[];
  unchainedHistory: {
    count: number;
    maxId: number;
    firstTimestamp: string | null;
    lastTimestamp: string | null;
    coverageStartsAt: string | null;
  } | null;
  epochs: LedgerEpochInfo[];
  gaps: Array<{ epoch: number; fromSeq: number; toSeq: number }>;
  missingIntervals: Array<{ from: string; to: string | null; open: boolean; afterSeq: number; epoch: number }>;
  lostCoverage: Array<{ epoch: number; seq: number; from: string; to: string; reason: string; eventsLost: number | 'unknown' }>;
  checkpoints: LedgerCheckpointInfo[];
  heartbeatIntervalMs: number;
  verifiedAt: string;
  limits: string;
}

const DEFAULT_HEARTBEAT_MS = 60 * 60 * 1000;

interface ChainedRow {
  table: 'defence_audit' | 'ledger_marker';
  raw: Record<string, unknown>;
  ledger_id: string;
  epoch: number;
  seq: number;
  prev_hash: string;
  content_digest: string;
  row_hash: string;
  timestamp: string;
  kind: string | null;
  payload: Record<string, unknown> | null;
}

function tableExists(db: Database.Database, name: string): boolean {
  return db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(name) !== undefined;
}

/** ISO and SQLite `YYYY-MM-DD HH:MM:SS` (UTC) timestamps → epoch ms. */
function parseTs(ts: unknown): number {
  if (typeof ts !== 'string') return NaN;
  const iso = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(ts) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(ts)
    ? `${ts.replace(' ', 'T')}Z`
    : ts;
  return Date.parse(iso);
}

function parsePayload(text: unknown): Record<string, unknown> | null {
  try {
    const v = JSON.parse(String(text));
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function unchainedStats(db: Database.Database, maxId: number | null): LedgerReport['unchainedHistory'] {
  if (!tableExists(db, 'defence_audit')) return null;
  const hasSeq = (db.prepare('PRAGMA table_info(defence_audit)').all() as { name: string }[]).some((c) => c.name === 'seq');
  const conds: string[] = [];
  const params: unknown[] = [];
  if (hasSeq) conds.push('seq IS NULL');
  if (maxId !== null) { conds.push('id <= ?'); params.push(maxId); }
  const where = conds.length ? `WHERE ${conds.join(' AND ')}` : '';
  const u = db.prepare(
    `SELECT COUNT(*) AS c, MAX(id) AS m, MIN(timestamp) AS f, MAX(timestamp) AS l FROM defence_audit ${where}`,
  ).get(...params) as { c: number; m: number | null; f: string | null; l: string | null };
  return { count: u.c, maxId: maxId ?? u.m ?? 0, firstTimestamp: u.f, lastTimestamp: u.l, coverageStartsAt: null };
}

function emptyReport(heartbeatIntervalMs: number, now: number): LedgerReport {
  return {
    status: 'unchained',
    ledgerId: null,
    currentEpoch: null,
    head: null,
    chainedRows: 0,
    firstBad: null,
    problems: [],
    unchainedHistory: null,
    epochs: [],
    gaps: [],
    missingIntervals: [],
    lostCoverage: [],
    checkpoints: [],
    heartbeatIntervalMs,
    verifiedAt: new Date(now).toISOString(),
    limits: LEDGER_LIMITS_STATEMENT,
  };
}

/**
 * Walk the chain. Never writes. `now` and `heartbeatIntervalMs` feed the
 * missing-interval check: a stretch longer than twice the heartbeat interval
 * with no chained row at all (not even a heartbeat) is reported.
 */
export function verifyLedger(
  db: Database.Database,
  opts: { now?: number; heartbeatIntervalMs?: number } = {},
): LedgerReport {
  const now = opts.now ?? Date.now();
  const heartbeatIntervalMs = opts.heartbeatIntervalMs ?? DEFAULT_HEARTBEAT_MS;
  const report = emptyReport(heartbeatIntervalMs, now);
  const problems = report.problems;
  const problem = (epoch: number | null, seq: number | null, kind: LedgerProblemKind, detail: string): void => {
    problems.push({ epoch, seq, kind, detail });
  };

  if (!tableExists(db, 'ledger_meta') || !tableExists(db, 'ledger_marker')) {
    report.unchainedHistory = unchainedStats(db, null);
    return report;
  }

  const meta = (db.prepare('SELECT * FROM ledger_meta WHERE id = 1').get() as LedgerMeta | undefined) ?? null;

  // ── Load every chained row from both tables ──────────────────────────────
  const rows: ChainedRow[] = [];
  for (const r of db.prepare('SELECT * FROM defence_audit WHERE seq IS NOT NULL').all() as Record<string, unknown>[]) {
    rows.push({
      table: 'defence_audit', raw: r,
      ledger_id: String(r.ledger_id), epoch: Number(r.epoch), seq: Number(r.seq),
      prev_hash: String(r.prev_hash), content_digest: String(r.content_digest), row_hash: String(r.row_hash),
      timestamp: String(r.timestamp), kind: null, payload: null,
    });
  }
  for (const r of db.prepare('SELECT * FROM ledger_marker').all() as Record<string, unknown>[]) {
    rows.push({
      table: 'ledger_marker', raw: r,
      ledger_id: String(r.ledger_id), epoch: Number(r.epoch), seq: Number(r.seq),
      prev_hash: String(r.prev_hash), content_digest: String(r.content_digest), row_hash: String(r.row_hash),
      timestamp: String(r.timestamp), kind: String(r.kind), payload: parsePayload(r.payload),
    });
  }
  report.chainedRows = rows.length;

  if (!meta) {
    report.unchainedHistory = unchainedStats(db, null);
    if (rows.length === 0) return report;
    problem(null, null, 'ledger-meta-missing',
      `${rows.length} chained rows exist but ledger_meta is missing — the ledger identity and head were removed`);
  }

  // Which ledger this database is. With meta gone, the earliest epoch-start names it.
  const firstStart = rows
    .filter((r) => r.kind === 'epoch-start')
    .sort((a, b) => (a.epoch - b.epoch) || (a.seq - b.seq))[0];
  const ledgerId = meta?.ledger_id ?? firstStart?.ledger_id ?? rows[0]?.ledger_id ?? null;
  report.ledgerId = ledgerId;
  report.currentEpoch = meta?.epoch ?? null;

  if (meta) {
    const u = unchainedStats(db, meta.unchained_max_id);
    report.unchainedHistory = u ? { ...u, coverageStartsAt: meta.chain_started_at } : null;
    const after = db.prepare('SELECT COUNT(*) AS c, MIN(id) AS m FROM defence_audit WHERE seq IS NULL AND id > ?')
      .get(meta.unchained_max_id) as { c: number; m: number | null };
    if (after.c > 0) {
      problem(null, null, 'unchained-row-after-start',
        `${after.c} defence_audit row(s) without chain columns were written after the chain started (first id ${after.m})`);
    }
  }

  // ── Checkpoint runs, keyed by where they start ───────────────────────────
  const runsByStart = new Map<string, PrunedRun>();
  for (const r of rows) {
    if (r.kind !== 'checkpoint' || !r.payload) continue;
    const runs = Array.isArray(r.payload.runs) ? r.payload.runs as PrunedRun[] : [];
    for (const run of runs) runsByStart.set(`${run.epoch}:${run.from}`, run);
  }
  const skeleton = new Map<string, string>();
  if (tableExists(db, 'ledger_skeleton')) {
    for (const s of db.prepare('SELECT ledger_id, epoch, seq, content_digest FROM ledger_skeleton').all() as Array<{ ledger_id: string; epoch: number; seq: number; content_digest: string }>) {
      skeleton.set(`${s.ledger_id}:${s.epoch}:${s.seq}`, s.content_digest);
    }
  }
  const runOutcome = new Map<PrunedRun, 'recomputed' | 'not-re-checkable' | 'failed'>();

  // ── Walk each epoch in seq order ─────────────────────────────────────────
  const byEpoch = new Map<number, Map<number, ChainedRow[]>>();
  for (const r of rows) {
    if (!byEpoch.has(r.epoch)) byEpoch.set(r.epoch, new Map());
    const m = byEpoch.get(r.epoch)!;
    if (!m.has(r.seq)) m.set(r.seq, []);
    m.get(r.seq)!.push(r);
  }
  for (const run of runsByStart.values()) {
    if (!byEpoch.has(run.epoch)) byEpoch.set(run.epoch, new Map());
  }
  const epochTails = new Map<number, { seq: number; hash: string }>();
  const timeline: Array<{ epoch: number; seq: number; ts: number; tsText: string } | 'break'> = [];

  for (const epoch of [...byEpoch.keys()].sort((a, b) => a - b)) {
    const bySeq = byEpoch.get(epoch)!;
    let maxSeq = -1;
    for (const s of bySeq.keys()) maxSeq = Math.max(maxSeq, s);
    for (const run of runsByStart.values()) if (run.epoch === epoch) maxSeq = Math.max(maxSeq, run.to);

    const info: LedgerEpochInfo = {
      epoch, startedAt: null, reason: null, firstSeq: null, lastSeq: null, rows: 0,
      previousHead: null, previousHeadCheck: epoch === 0 ? 'none' : 'unknown',
    };

    let running = GENESIS_PREV_HASH;
    let lastSeq = -1;
    for (let s = 0; s <= maxSeq; s++) {
      const present = bySeq.get(s);
      if (!present || present.length === 0) {
        const run = runsByStart.get(`${epoch}:${s}`);
        if (run) {
          if (run.start_hash !== running) {
            problem(epoch, s, 'checkpoint-mismatch', `pruned range ${s}–${run.to} starts from ${run.start_hash.slice(0, 12)}…, chain has ${running.slice(0, 12)}…`);
          }
          const firstSkel = skeleton.get(`${ledgerId}:${epoch}:${run.from}`);
          if (firstSkel === undefined && !skeletonClaimed(rows, run)) {
            runOutcome.set(run, 'not-re-checkable');
          } else {
            let h = run.start_hash;
            let ok = true;
            for (let q = run.from; q <= run.to; q++) {
              const d = skeleton.get(`${ledgerId}:${epoch}:${q}`);
              if (d === undefined) {
                problem(epoch, q, 'skeleton-mismatch', `skeleton witness for pruned seq ${q} is missing`);
                ok = false;
                break;
              }
              h = rowHash(h, q, d);
            }
            if (ok && h !== run.boundary_hash) {
              problem(epoch, run.from, 'skeleton-mismatch', `pruned range ${run.from}–${run.to} recomputes to ${h.slice(0, 12)}…, checkpoint says ${run.boundary_hash.slice(0, 12)}…`);
              ok = false;
            }
            runOutcome.set(run, ok ? 'recomputed' : 'failed');
          }
          running = run.boundary_hash;
          lastSeq = run.to;
          s = run.to;
          timeline.push('break');
          continue;
        }
        // A hole with no checkpoint: rows deleted.
        let end = s;
        while (end + 1 <= maxSeq && !bySeq.has(end + 1) && !runsByStart.has(`${epoch}:${end + 1}`)) end++;
        report.gaps.push({ epoch, fromSeq: s, toSeq: end });
        problem(epoch, s, 'gap', end === s ? `seq ${s} is missing and no checkpoint covers it` : `seq ${s}–${end} are missing and no checkpoint covers them`);
        const next = bySeq.get(end + 1)?.[0];
        if (next) running = next.prev_hash;
        s = end;
        timeline.push('break');
        continue;
      }
      if (present.length > 1) {
        problem(epoch, s, 'duplicate-seq', `${present.length} rows claim seq ${s}`);
      }
      const r = present[0];
      info.rows += present.length;
      if (info.firstSeq === null) info.firstSeq = s;
      if (ledgerId !== null && r.ledger_id !== ledgerId) {
        problem(epoch, s, 'foreign-ledger', `row belongs to ledger ${r.ledger_id}, this database is ${ledgerId}`);
      }
      if (s === 0) {
        if (r.kind !== 'epoch-start') {
          problem(epoch, 0, 'epoch-start-missing', 'seq 0 is not an epoch-start row');
        } else if (r.payload) {
          info.startedAt = r.timestamp;
          info.reason = typeof r.payload.reason === 'string' ? r.payload.reason : null;
          const ph = r.payload.previous_head as LedgerEpochInfo['previousHead'] | undefined;
          info.previousHead = ph ?? null;
        }
      }
      if (r.prev_hash !== running) {
        problem(epoch, s, 'prev-hash-mismatch', `prev_hash does not link to the row before (expected ${running.slice(0, 12)}…)`);
      }
      let digest: string | null = null;
      try {
        digest = r.table === 'defence_audit'
          ? contentDigest(auditRowContent(r.raw, r.ledger_id, r.epoch))
          : r.payload
            ? contentDigest(markerRowContent({ ledger_id: r.ledger_id, epoch: r.epoch, kind: String(r.kind), timestamp: r.timestamp, payload: r.payload }))
            : null;
      } catch {
        digest = null;
      }
      if (digest !== r.content_digest) {
        problem(epoch, s, 'digest-mismatch', `row content no longer matches its content_digest (${r.table})`);
      } else if (rowHash(r.prev_hash, s, r.content_digest) !== r.row_hash) {
        problem(epoch, s, 'row-hash-mismatch', 'row_hash does not match prev_hash, seq and content_digest');
      }
      running = r.row_hash;
      lastSeq = s;

      const ts = parseTs(r.timestamp);
      if (Number.isFinite(ts)) timeline.push({ epoch, seq: s, ts, tsText: r.timestamp });

      if (r.kind === 'lost-coverage' && r.payload) {
        const p = r.payload;
        report.lostCoverage.push({
          epoch, seq: s,
          from: String(p.from), to: String(p.to), reason: String(p.reason ?? ''),
          eventsLost: typeof p.events_lost === 'number' ? p.events_lost : 'unknown',
        });
      }
      if (r.kind === 'checkpoint' && r.payload) {
        const p = r.payload;
        report.checkpoints.push({
          epoch, seq: s, timestamp: r.timestamp,
          count: Number(p.count ?? 0),
          unchainedPruned: Number(p.unchained_pruned ?? 0),
          skeletonKept: p.skeleton_kept === true,
          runs: Array.isArray(p.runs) ? p.runs as PrunedRun[] : [],
          recheck: 'not-re-checkable',
          commitment: CHECKPOINT_COMMITMENT,
        });
      }
    }
    info.lastSeq = lastSeq >= 0 ? lastSeq : null;
    if (lastSeq >= 0) epochTails.set(epoch, { seq: lastSeq, hash: running });
    report.epochs.push(info);
  }

  // Checkpoint re-check outcome: recomputed only if every run recomputed.
  for (const cp of report.checkpoints) {
    const outcomes = cp.runs.map((run) => {
      for (const [k, v] of runOutcome) if (k.epoch === run.epoch && k.from === run.from) return v;
      return 'not-re-checkable' as const;
    });
    cp.recheck = outcomes.includes('failed')
      ? 'failed'
      : outcomes.length > 0 && outcomes.every((o) => o === 'recomputed') ? 'recomputed' : 'not-re-checkable';
  }

  // ── Epoch boundaries ─────────────────────────────────────────────────────
  for (const info of report.epochs) {
    if (info.epoch === 0) continue;
    if (!info.previousHead) { info.previousHeadCheck = 'unknown'; continue; }
    const tail = epochTails.get(info.previousHead.epoch);
    if (!tail) { info.previousHeadCheck = 'not-present'; continue; }
    if (tail.seq === info.previousHead.seq && tail.hash === info.previousHead.row_hash) {
      info.previousHeadCheck = 'matches';
    } else {
      info.previousHeadCheck = 'differs';
      problem(info.epoch, 0, 'epoch-link-mismatch',
        `epoch ${info.epoch} names previous head seq ${info.previousHead.seq}, epoch ${info.previousHead.epoch} ends at seq ${tail.seq} with a different hash`);
    }
  }

  // ── Recorded head vs chain tail ──────────────────────────────────────────
  if (meta) {
    const tail = epochTails.get(meta.epoch);
    report.head = { epoch: meta.epoch, seq: meta.head_seq, rowHash: meta.head_hash };
    const maxEpoch = Math.max(-1, ...report.epochs.map((e) => e.epoch));
    if (maxEpoch > meta.epoch) {
      problem(maxEpoch, null, 'head-mismatch', `rows exist in epoch ${maxEpoch} but the recorded epoch is ${meta.epoch}`);
    } else if (!tail || tail.seq !== meta.head_seq || tail.hash !== meta.head_hash) {
      problem(meta.epoch, tail?.seq ?? null, 'head-mismatch',
        `recorded head is seq ${meta.head_seq}, the chain ends at ${tail ? `seq ${tail.seq}` : 'no row'}${tail && tail.seq === meta.head_seq ? ' with a different hash' : ''}`);
    }
  } else {
    const last = report.epochs[report.epochs.length - 1];
    const tail = last ? epochTails.get(last.epoch) : undefined;
    if (last && tail) report.head = { epoch: last.epoch, seq: tail.seq, rowHash: tail.hash };
  }

  // ── Missing intervals ────────────────────────────────────────────────────
  const threshold = 2 * heartbeatIntervalMs;
  let prev: { epoch: number; seq: number; ts: number; tsText: string } | null = null;
  for (const t of timeline) {
    if (t === 'break') { prev = null; continue; }
    if (prev && t.ts - prev.ts > threshold) {
      report.missingIntervals.push({ from: prev.tsText, to: t.tsText, open: false, afterSeq: prev.seq, epoch: prev.epoch });
    }
    if (!prev || t.ts >= prev.ts) prev = t;
  }
  if (prev && now - prev.ts > threshold) {
    report.missingIntervals.push({ from: prev.tsText, to: null, open: true, afterSeq: prev.seq, epoch: prev.epoch });
  }

  report.firstBad = problems[0] ?? null;
  report.status = problems.length > 0 ? 'inconsistent' : (rows.length === 0 && !meta ? 'unchained' : 'consistent');
  return report;
}

/** A run whose checkpoint said skeleton_kept is re-checked even if witnesses are gone (then it fails). */
function skeletonClaimed(rows: ChainedRow[], run: PrunedRun): boolean {
  for (const r of rows) {
    if (r.kind !== 'checkpoint' || !r.payload || r.payload.skeleton_kept !== true) continue;
    const runs = Array.isArray(r.payload.runs) ? r.payload.runs as PrunedRun[] : [];
    if (runs.some((x) => x.epoch === run.epoch && x.from === run.from)) return true;
  }
  return false;
}

function where(p: LedgerProblem): string {
  if (p.seq !== null) return `epoch ${p.epoch} seq ${p.seq}`;
  if (p.epoch !== null) return `epoch ${p.epoch}`;
  return 'ledger';
}

/** One-line summary used by the doctor row. */
export function summariseLedgerReport(r: LedgerReport): string {
  if (r.status === 'unchained') {
    const n = r.unchainedHistory?.count ?? 0;
    return `unchained — no chain in this database yet (${n} audit row(s) of unchained history); the chain starts the next time ShieldCortex opens it`;
  }
  if (r.status === 'inconsistent') {
    const f = r.firstBad!;
    return `inconsistent — first bad: ${where(f)} (${f.kind}: ${f.detail}); ${r.problems.length} problem(s)`;
  }
  const head = r.head ? `head epoch ${r.head.epoch} seq ${r.head.seq}` : 'no head';
  const extras: string[] = [];
  if (r.unchainedHistory && r.unchainedHistory.count > 0) extras.push(`${r.unchainedHistory.count} unchained history row(s)`);
  if (r.missingIntervals.length) extras.push(`${r.missingIntervals.length} missing interval(s)`);
  if (r.lostCoverage.length) extras.push(`${r.lostCoverage.length} lost-coverage marker(s)`);
  if (r.epochs.length > 1) extras.push(`${r.epochs.length} epochs`);
  return `consistent — ${r.chainedRows} chained row(s), ${head}${extras.length ? `; ${extras.join(', ')}` : ''}; local only, not independently committed`;
}

/** Human-readable report (the CLI's default output). */
export function formatLedgerReport(r: LedgerReport): string {
  const out: string[] = [];
  const headline = r.status === 'inconsistent' && r.firstBad
    ? `Chained ledger: INCONSISTENT — first bad: ${where(r.firstBad)} (${r.firstBad.kind})`
    : `Chained ledger: ${r.status.toUpperCase()}`;
  out.push(headline);
  if (r.ledgerId) {
    out.push(`  ledger ${r.ledgerId} · current epoch ${r.currentEpoch ?? 'unknown'} · ${r.chainedRows} chained row(s)` +
      (r.head ? ` · head seq ${r.head.seq} (${r.head.rowHash.slice(0, 16)}…)` : ''));
  }
  if (r.problems.length) {
    out.push('  Problems:');
    for (const p of r.problems) out.push(`    - ${where(p)}: ${p.kind} — ${p.detail}`);
  }
  const u = r.unchainedHistory;
  if (u && (u.count > 0 || u.coverageStartsAt)) {
    if (u.coverageStartsAt && u.count === 0) {
      out.push(`  coverage starts ${u.coverageStartsAt}; no unchained history before it.`);
    } else if (u.coverageStartsAt) {
      out.push(`  unchained history — coverage starts ${u.coverageStartsAt}: ${u.count} audit row(s) (ids ≤ ${u.maxId}) were written before the chain existed. They are not chained and were never hashed into it.`);
    } else {
      out.push(`  unchained history: ${u.count} audit row(s); this database has no chain yet.`);
    }
  }
  if (r.epochs.length) {
    out.push('  Epochs:');
    for (const e of r.epochs) {
      const link = e.epoch === 0 ? '' : ` — previous head ${e.previousHead ? `epoch ${e.previousHead.epoch} seq ${e.previousHead.seq}` : 'not named'}: ${e.previousHeadCheck}`;
      out.push(`    - epoch ${e.epoch}: started ${e.startedAt ?? 'unknown'} (${e.reason ?? 'no epoch-start'}), seq ${e.firstSeq ?? '-'}–${e.lastSeq ?? '-'}, ${e.rows} row(s)${link}`);
    }
  }
  if (r.gaps.length) {
    out.push('  Gaps in seq (rows missing, no checkpoint):');
    for (const g of r.gaps) out.push(`    - epoch ${g.epoch} seq ${g.fromSeq}${g.toSeq !== g.fromSeq ? `–${g.toSeq}` : ''}`);
  }
  const hours = r.heartbeatIntervalMs / 3_600_000;
  if (r.missingIntervals.length) {
    out.push(`  Missing intervals (no rows and no heartbeat for more than ${2 * hours}h):`);
    for (const m of r.missingIntervals) out.push(`    - missing interval ${m.from} → ${m.open ? 'now (still open)' : m.to}`);
  } else {
    out.push(`  Missing intervals: none longer than ${2 * hours}h (heartbeat every ${hours}h)`);
  }
  if (r.lostCoverage.length) {
    out.push('  Lost coverage (audit writes failed; the events were not recorded and are not reconstructed):');
    for (const l of r.lostCoverage) out.push(`    - ${l.from} → ${l.to}: ${l.eventsLost} event(s) lost — ${l.reason}`);
  }
  if (r.checkpoints.length) {
    out.push('  Retention checkpoints:');
    for (const c of r.checkpoints) {
      const ranges = c.runs.map((x) => `${x.epoch}:${x.from}${x.to !== x.from ? `–${x.to}` : ''}`).join(', ') || 'none';
      const check = c.recheck === 'recomputed'
        ? 'pruned range recomputed from the skeleton'
        : c.recheck === 'failed' ? 'pruned range does NOT recompute' : 'contents and witnesses pruned — not re-checkable';
      out.push(`    - seq ${c.seq} (${c.timestamp}): ${c.count} chained row(s) pruned [${ranges}]` +
        `${c.unchainedPruned ? ` + ${c.unchainedPruned} unchained` : ''}; skeleton ${c.skeletonKept ? 'kept' : 'not kept'}; ${check}; ${c.commitment}`);
    }
  }
  out.push('');
  out.push(r.limits);
  return out.join('\n') + '\n';
}
