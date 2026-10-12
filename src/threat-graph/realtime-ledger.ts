/**
 * Realtime JSONL — the threat graph's second ledger (Phase A.2).
 *
 * Conversation scans in the OpenClaw gateway are deliberately DB-free: their
 * detections land only in ~/.shieldcortex/audit/realtime-YYYY-MM-DD.jsonl
 * (plugins/openclaw/index.ts auditLog). This module tails those files with a
 * '<file>:<line>' cursor in threat_graph_state.last_rt_cursor and projects
 * `type:"threat"` rows into the graph.
 *
 * Invariant 5: `reason` is scanner-generated free text summarising hostile
 * content — stored capped in event attrs, NEVER as node identity. The `hook`
 * field is caller-influenceable, so it is normalised against a closed
 * allowlist before becoming source-node identity; anything else collapses to
 * 'unknown', bounding conversation source nodes structurally.
 *
 * Invariant 6: files larger than maxFileBytes are skipped (error recorded,
 * cursor advanced past) rather than read into memory — a corrupt or hostile
 * multi-GB file must not OOM the worker.
 *
 * Tail race: the gateway appends concurrently, so the final line of a file
 * may be mid-write. An unterminated final line is NEVER consumed — the next
 * tick re-reads it complete. Without this, a partially-appended threat row
 * parses as "malformed" and the cursor skips a real detection forever.
 *
 * Claim-and-advance: file reading happens outside the transaction; the apply
 * + cursor advance re-checks the cursor inside BEGIN IMMEDIATE and no-ops if
 * another instance advanced it first.
 *
 * #579 Slice 1A: a malformed stored cursor reports and halts before the
 * directory is listed (graph and cursor unchanged; recovery is an operator
 * action). A listed pending file whose stat or read fails holds projection
 * at that file — nothing of it or of any later file commits this run.
 */

import { getDatabase } from '../database/init.js';
import {
  assertNotInTransaction,
  evictEventOverflow,
  toIso,
  upsertEdge,
  upsertNode,
} from './shared.js';
import {
  FILE_CONSUMED_LINE,
  nodeRealtimePlaneFs,
  parseRealtimeCursor,
  readPlainRealtimeFile,
  REALTIME_PLAIN_RE,
  type RealtimeCursor,
  type RealtimePlaneFs,
} from './realtime-plane.js';

export interface RealtimeLedgerOptions {
  /** Directory holding realtime-YYYY-MM-DD.jsonl files. */
  dir: string;
  /** Max JSONL lines (of any type) consumed per call. */
  batchSize?: number;
  /** Max chars of `reason` retained in event attrs. */
  reasonCap?: number;
  /** Max length of a session key contributing to node identity. */
  sessionKeyMaxLength?: number;
  /** Files larger than this are skipped, not read (OOM guard). */
  maxFileBytes?: number;
  /** Event nodes retained; oldest are evicted beyond this. */
  maxEventNodes?: number;
}

export interface RealtimeResult {
  processed: number;
  cursor: string;
  eventNodes: number;
  errors: string[];
}

const DEFAULT_BATCH = 2000;
const DEFAULT_REASON_CAP = 256;
const DEFAULT_SESSION_KEY_MAX = 128;
const DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_EVENT_NODES = 50_000;

/** Fixed text: never echoes the stored cursor into last_error. */
export const MALFORMED_CURSOR_ERROR =
  'realtime cursor malformed; realtime projection halted, graph and cursor unchanged';
export const BARRIER_VIOLATION_ERROR = 'internal: realtime barrier violated; no commit';

/**
 * Hook names are caller-influenceable JSONL content; only this closed set may
 * become source-node identity (invariant 5).
 */
const KNOWN_HOOKS = new Set(['llm_input', 'llm_output', 'before_agent_run', 'tool_response']);

interface PendingLine {
  file: string;
  line: number; // 1-based within the file
  raw: string;
}

interface CollectResult {
  pending: PendingLine[];
  errors: string[];
  /** Cursor floor from skipped (oversized) files, '' when none. */
  cursorFloor: string;
  /** Listed pending file whose stat/read failed; nothing at or after it is collected. */
  heldAt?: string;
}

/**
 * Test-owned seams. Production callers use projectRealtimeLedger(), which
 * passes none; there is no environment or global switch.
 */
export interface RealtimeLedgerSeams {
  fs?: RealtimePlaneFs;
  /** Runs after collection, immediately before the apply transaction. */
  beforeApply?: () => void;
}

/** Collect unconsumed lines after the cursor, oldest file first. */
function collectPending(
  dir: string,
  cursor: Extract<RealtimeCursor, { kind: 'empty' | 'valid' }>,
  batchSize: number,
  maxFileBytes: number,
  fsOps: RealtimePlaneFs,
): CollectResult {
  const out: CollectResult = { pending: [], errors: [], cursorFloor: '' };

  let names: string[];
  try {
    names = fsOps.readdir(dir).filter(n => REALTIME_PLAIN_RE.test(n)).sort();
  } catch {
    return out; // missing dir = nothing to project, not an error
  }

  const parsed = cursor.kind === 'valid' ? cursor : null;

  for (const name of names) {
    if (parsed && name < parsed.file) continue;
    const skip = parsed && name === parsed.file ? parsed.line : 0;
    if (skip >= FILE_CONSUMED_LINE) continue; // previously skipped as oversized

    const read = readPlainRealtimeFile(dir, name, maxFileBytes, fsOps);
    if (read.kind === 'oversize') {
      out.errors.push(`${name}: ${read.size} bytes exceeds the ${maxFileBytes}-byte file cap — skipped`);
      out.cursorFloor = `${name}:${FILE_CONSUMED_LINE}`;
      continue;
    }
    if (read.kind === 'unavailable') {
      // Unknown consumption is preserved: never skip past a listed pending
      // file we could not read. Later files are not even stat'd this run.
      out.errors.push(`${name}: unavailable (${read.stage} ${read.code}); realtime projection held at this file`);
      out.heldAt = name;
      return out;
    }

    // The final split element is either '' (terminated file) or a line still
    // being appended by the gateway (tail race) — excluded in both cases.
    const lines = read.content.split('\n');
    const consumable = lines.length - 1;
    for (let i = skip; i < consumable; i++) {
      out.pending.push({ file: name, line: i + 1, raw: lines[i] });
      if (out.pending.length >= batchSize) return out;
    }
  }
  return out;
}

/** File part of a canonical '<file>:<line>' string. */
function cursorFile(cursor: string): string {
  return cursor.slice(0, cursor.lastIndexOf(':'));
}

/**
 * Defensive check: with a hold at D, nothing of D or later may commit. The
 * collector already guarantees this; a violation is reported, never thrown.
 * Only NEW progress is checked — the unchanged start cursor may sit in D.
 */
function barrierHolds(collected: CollectResult): boolean {
  const heldAt = collected.heldAt;
  if (!heldAt) return true;
  if (collected.pending.some(p => !(p.file < heldAt))) return false;
  if (collected.cursorFloor && !(cursorFile(collected.cursorFloor) < heldAt)) return false;
  return true;
}

export function projectRealtimeLedger(options: RealtimeLedgerOptions): RealtimeResult {
  return projectRealtimeLedgerWithSeams(options, {});
}

/** @internal Test entry point; see RealtimeLedgerSeams. */
export function projectRealtimeLedgerWithSeams(
  options: RealtimeLedgerOptions,
  seams: RealtimeLedgerSeams,
): RealtimeResult {
  assertNotInTransaction('realtime ledger');
  const db = getDatabase();
  const batchSize = options.batchSize ?? DEFAULT_BATCH;
  const reasonCap = options.reasonCap ?? DEFAULT_REASON_CAP;
  const sessionKeyMax = options.sessionKeyMaxLength ?? DEFAULT_SESSION_KEY_MAX;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const maxEventNodes = options.maxEventNodes ?? DEFAULT_MAX_EVENT_NODES;

  db.prepare('INSERT OR IGNORE INTO threat_graph_state (id) VALUES (1)').run();
  const startCursor = (db.prepare('SELECT last_rt_cursor FROM threat_graph_state WHERE id = 1')
    .get() as { last_rt_cursor: string }).last_rt_cursor;

  // Strict classification BEFORE listing the directory, so the outcome for a
  // malformed cursor never depends on directory state. Report and halt: no
  // replay, no healing write. startCursor (raw) stays the CAS token below.
  const parsedStart = parseRealtimeCursor(startCursor);
  if (parsedStart.kind === 'malformed') {
    return { processed: 0, cursor: startCursor, eventNodes: 0, errors: [MALFORMED_CURSOR_ERROR] };
  }

  const collected = collectPending(
    options.dir, parsedStart, batchSize, maxFileBytes, seams.fs ?? nodeRealtimePlaneFs,
  );
  const result: RealtimeResult = {
    processed: 0,
    cursor: startCursor,
    eventNodes: 0,
    errors: [...collected.errors],
  };
  if (collected.pending.length === 0 && !collected.cursorFloor) return result;
  if (!barrierHolds(collected)) {
    result.errors.push(BARRIER_VIOLATION_ERROR);
    return result;
  }
  seams.beforeApply?.();

  const apply = db.transaction(() => {
    // Claim-and-advance: if another instance moved the cursor since we read
    // the files, our pending set is stale — no-op rather than double-project.
    const current = (db.prepare('SELECT last_rt_cursor FROM threat_graph_state WHERE id = 1')
      .get() as { last_rt_cursor: string }).last_rt_cursor;
    if (current !== startCursor) return;

    for (const item of collected.pending) {
      result.processed++;
      result.cursor = `${item.file}:${item.line}`;

      let row: Record<string, unknown>;
      try {
        const parsed: unknown = JSON.parse(item.raw);
        // JSON.parse('null') / '42' / '"x"' / '[]' all SUCCEED — a non-object
        // line used to throw on `row.type` OUTSIDE this catch, rolling back
        // the transaction with the cursor unadvanced and permanently wedging
        // the projection on one hostile or accidental line (this file is
        // same-user-writable). Non-objects are malformed rows: record + skip.
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('non-object row');
        }
        row = parsed as Record<string, unknown>;
      } catch {
        result.errors.push(`${item.file}:${item.line}: malformed JSON`);
        continue;
      }
      if (row.type !== 'threat') continue;

      const ts = toIso(typeof row.ts === 'string' ? row.ts : '1970-01-01T00:00:00.000Z');
      const rawHook = typeof row.hook === 'string' ? row.hook : 'unknown';
      const hook = KNOWN_HOOKS.has(rawHook) ? rawHook : 'unknown';
      const sessionId = typeof row.sessionId === 'string' ? row.sessionId.slice(0, sessionKeyMax) : null;

      const eventId = upsertNode('event', `rt:${item.file}:${item.line}`, ts);
      const attrs: Record<string, unknown> = { hook };
      if (typeof row.reason === 'string') attrs.reason = row.reason.slice(0, reasonCap);
      if (typeof row.model === 'string') attrs.model = row.model.slice(0, 128);
      if (typeof row.chars === 'number') attrs.chars = row.chars;
      if (typeof row.contentSha256 === 'string') attrs.contentSha256 = row.contentSha256.slice(0, 64);
      // Session taint state at scan time (Phase D): the gateway records whether
      // this detection tainted the session, so attribution can distinguish a
      // taint-raising event. Forward-compatible — absent on older rows.
      if (typeof row.tainted === 'boolean') attrs.tainted = row.tainted;
      // Writer-side attestation claim (attestation Phase 4) — RECORD-ONLY.
      // Strict === true: this file is same-user-writable (hostile-influenceable),
      // so truthiness is not acceptable, and the claim must NEVER feed accrual —
      // attrs.attested is attribution metadata, a DIFFERENT fact from
      // source_risk.attested (sweep-derived from defence_audit). Absent or any
      // non-true value ⇒ unattested. Old rows lack the field (compat: unattested).
      if (row.attested === true) attrs.attested = true;
      db.prepare('UPDATE threat_nodes SET attrs = ? WHERE id = ?').run(JSON.stringify(attrs), eventId);

      const sourceId = upsertNode('source', `conversation:${hook}`, ts);
      upsertEdge(eventId, 'from_source', sourceId, ts);

      if (sessionId) {
        const sessId = upsertNode('session', sessionId, ts);
        upsertEdge(eventId, 'in_session', sessId, ts);
      }
      result.eventNodes++;
    }

    // The realtime path respects the event cap too — a hostile JSONL stream
    // must not grow the graph past invariant 6's bounds.
    const evictNote = evictEventOverflow(maxEventNodes);
    if (evictNote) result.errors.push(evictNote);

    // Oversized-file sentinel outranks a shorter consumed position.
    if (collected.cursorFloor && collected.cursorFloor > result.cursor) {
      result.cursor = collected.cursorFloor;
    }
    db.prepare('UPDATE threat_graph_state SET last_rt_cursor = ? WHERE id = 1').run(result.cursor);
  });
  apply.immediate();

  return result;
}
