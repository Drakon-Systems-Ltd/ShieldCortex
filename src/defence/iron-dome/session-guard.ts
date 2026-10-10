/**
 * Session-guard index + degraded-run summary (#242 / #260).
 *
 * Claude Code already writes `session-guard/<sc-…>.jsonl` from the PreToolUse
 * hook and summarises at stop-hook. The OpenClaw interceptor — where the #242
 * cron incidents happened — wrote nothing. This module is the one formula
 * both planes use so a row keyed on a raw sessionId is never silently dropped
 * by the `/^sc-[a-f0-9]{16}$/` filename check.
 *
 * `actionKey` / binding fields are optional passengers. This module only
 * requires origin, sessionKey and a degraded outcome.
 *
 * #654: a summary is a RECEIPT that lists exactly the guard identities it
 * counted (`guardFingerprints`), and only listed identities are suppressed on
 * a later pass. Identity resolution, the bounded positioned reader and the
 * coverage contract below are kept in step with scripts/stop-hook.mjs, which
 * cannot import this module; the #654 parity vectors pin the two together.
 */
import { createHash, createHmac, randomBytes } from 'node:crypto';
import {
  appendFileSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  readSync, readdirSync, writeFileSync, type Stats,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const GUARD_DEGRADED_OUTCOMES = new Set([
  'auto_denied',
  'denied_no_prompt_surface',
  'failure_denied',
  'failure_allowed',
  'warned',
  'denied',
  // #372: operator card decisions that ended in NO. A held dangerous action
  // the operator refused (or let time out / cancelled) is guard degradation a
  // #260 summary must surface. `approved_once` stays out on the same logic
  // that keeps `approved` out — a granted approval is not degradation.
  'card_denied',
  'card_timeout',
  'card_cancelled',
]);

export const GUARD_INDEX_ORIGINS = new Set(['claude-code-hook', 'openclaw-interceptor']);
export const SUMMARY_ORIGINS = new Set(['claude-code-stop-hook', 'openclaw-session-end']);

export function isGuardIndexOrigin(origin: unknown): boolean {
  return GUARD_INDEX_ORIGINS.has(String(origin ?? ''));
}

export function isSummaryOrigin(origin: unknown): boolean {
  return SUMMARY_ORIGINS.has(String(origin ?? ''));
}

export interface SessionGuardOptions {
  home?: string;
  salt?: string;
  origin?: string;
}

function stateHome(home?: string): string {
  return home ?? homedir();
}

function auditDirFor(home?: string): string {
  // Honour the same test/runtime override the interceptor uses. Only when the
  // caller did not pin a home — a pinned home is the isolation boundary.
  if (home === undefined) {
    const override = process.env.SHIELDCORTEX_AUDIT_DIR;
    if (typeof override === 'string' && override.trim()) return override.trim();
  }
  return join(stateHome(home), '.shieldcortex', 'audit');
}

/** Same formula as scripts/pre-tool-hook.mjs and scripts/stop-hook.mjs. */
export function sessionKeyFor(value: string | undefined, opts: SessionGuardOptions = {}): string | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  const salt = opts.salt ?? sessionKeySalt(opts.home);
  if (!salt) return null;
  return `sc-${createHmac('sha256', salt).update(`action-guard-session:${value}`).digest('hex').slice(0, 16)}`;
}

export function sessionKeySalt(home?: string): string | null {
  const fromEnv = process.env.SHIELDCORTEX_SESSION_SALT;
  if (typeof fromEnv === 'string' && /^[a-f0-9]{64}$/i.test(fromEnv)) return fromEnv.toLowerCase();
  try {
    const dir = join(stateHome(home), '.shieldcortex');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const primary = join(dir, 'action-guard-session-salt');
    if (existsSync(primary)) {
      const existing = readFileSync(primary, 'utf8').trim().toLowerCase();
      if (/^[a-f0-9]{64}$/.test(existing)) return existing;
    }
    const salt = randomBytes(32).toString('hex');
    try {
      writeFileSync(primary, `${salt}\n`, { flag: 'wx', mode: 0o600 });
      return salt;
    } catch {
      if (existsSync(primary)) {
        const raced = readFileSync(primary, 'utf8').trim().toLowerCase();
        if (/^[a-f0-9]{64}$/.test(raced)) return raced;
      }
      return salt;
    }
  } catch {
    return null;
  }
}

export function appendSessionGuardIndex(opts: {
  home?: string;
  entry: Record<string, unknown>;
}): boolean {
  const sessionKey = String(opts.entry.sessionKey ?? '');
  if (!/^sc-[a-f0-9]{16}$/.test(sessionKey)) return false;
  if (!isGuardIndexOrigin(opts.entry.origin)) return false;
  if (!GUARD_DEGRADED_OUTCOMES.has(String(opts.entry.outcome ?? ''))) return false;
  try {
    const dir = join(auditDirFor(opts.home), 'session-guard');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    appendFileSync(join(dir, `${sessionKey}.jsonl`), `${JSON.stringify({ recordKind: 'guard', ...opts.entry })}\n`);
    return true;
  } catch {
    return false;
  }
}

// ==================== #654: guard identity ====================

/** Copied verbatim from scripts/stop-hook.mjs; pinned equal by the parity test. */
export const SAFE_SUMMARY_SIGNALS = new Set([
  'secret-egress', 'approval-required', 'fallback-scan', 'privilege-escalation',
  'filesystem-destructive', 'destructive-filesystem', 'dangerous-shell',
  'command-exec', 'network-egress', 'credential-access', 'data-exfiltration',
  'untrusted-script', 'reviewed-script', 'shell-injection', 'persistence-risk',
]);

export function cleanSignal(value: unknown): string | null {
  const signal = String(value ?? '').trim();
  return SAFE_SUMMARY_SIGNALS.has(signal) ? signal : signal ? 'redacted-signal' : null;
}

function cleanThreats(row: Record<string, unknown>): string[] {
  return Array.isArray(row.threats) ? row.threats.map(cleanSignal).filter((t): t is string => Boolean(t)).sort() : [];
}

function sha16(payload: string): string {
  return createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

/**
 * The stop hook's `guardFingerprint`, byte for byte, evaluated at `physKey`.
 * The ID test COERCES with String() and the inserted ID is String(value) —
 * exactly HEAD's legacy formula, so every receipt it already wrote stays
 * readable. Do not "tidy" the coercion: it is the compatibility contract.
 */
export function v1Fingerprint(row: Record<string, unknown>, physKey: string): string {
  return sha16(JSON.stringify({
    sessionKey: row.sessionKey,
    action: row.action,
    outcome: row.outcome,
    tool: row.tool,
    ts: row.ts,
    auditEventId: /^[a-f0-9]{32}$/.test(String(row.auditEventId ?? '')) ? String(row.auditEventId) : physKey,
    threats: cleanThreats(row),
  }));
}

/** A different key (`bindingNonce`, `n:` prefix) from every v1 preimage, which
 *  always carries `auditEventId`, so the two fingerprint domains are disjoint. */
export function nonceFingerprint(row: Record<string, unknown>): string {
  return sha16(JSON.stringify({
    sessionKey: row.sessionKey,
    action: row.action,
    outcome: row.outcome,
    tool: row.tool,
    ts: row.ts,
    bindingNonce: `n:${String(row.nonce)}`,
    threats: cleanThreats(row),
  }));
}

const BINDING_PLANES = new Set(['action_guard', 'conversation_firewall']);
const BINDING_STRING_FIELDS = ['gatewayInstanceId', 'hookName', 'pluginId', 'nonce', 'actionKey'] as const;

/** Pure structural copy of hasRequiredBinding (enforcement-binding.ts). It
 *  must never call the binder, which has filesystem side effects. */
export function hasValidBindingNonce(row: Record<string, unknown>): boolean {
  if (!BINDING_PLANES.has(String(row.plane ?? ''))) return false;
  if (typeof row.seq !== 'number' || !Number.isInteger(row.seq) || row.seq < 1) return false;
  for (const field of BINDING_STRING_FIELDS) {
    const v = row[field];
    if (typeof v !== 'string' || v.length === 0) return false;
  }
  return /^[0-9a-f]{32}$/.test(String(row.nonce));
}

export type IdentityBasis = 'eventId' | 'bindingNonce' | 'physicalRow';

export interface GuardIdentity {
  /** The fingerprint a receipt lists for this row. */
  primary: string;
  basis: IdentityBasis;
  /** The HEAD v1 fingerprint at this position: a historical receipt may list it. */
  v1: string;
}

/**
 * ID → nonce → physical position. A strictly valid producer-minted
 * `auditEventId` wins; a valid binding nonce is shared by both copies of one
 * bound emission; anything else is identified by where it physically sits,
 * which can over-count a mirrored ID-less row (disclosed, never merged).
 * A non-string value that only COERCES to 32 hex fails the strict test: its
 * basis is not eventId, though its v1 stays HEAD's so old receipts match.
 */
export function guardIdentity(row: Record<string, unknown>, physKey: string): GuardIdentity {
  const v1 = v1Fingerprint(row, physKey);
  if (typeof row.auditEventId === 'string' && /^[a-f0-9]{32}$/.test(row.auditEventId)) {
    return { primary: v1, basis: 'eventId', v1 };
  }
  if (hasValidBindingNonce(row)) return { primary: nonceFingerprint(row), basis: 'bindingNonce', v1 };
  return { primary: v1, basis: 'physicalRow', v1 };
}

// ==================== #654: bounded positioned reader + coverage ====================

export const MAX_RECEIPT_IDENTITIES = 16384;
const MAX_AUDIT_SCAN_FILES = 256;
const MAX_AUDIT_SCAN_BYTES = 64 * 1024 * 1024;
const MAX_JSONL_LINE_BYTES = 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;
const REALTIME_NAME = /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/;

export type ReadPass = 'receipts' | 'guards';
/** `not-sought`: this pass does not read the audit dir (OpenClaw guards are index-only). */
export type AuditDirState = 'absent' | 'listed' | 'not-sought' | 'refused' | 'failed';
export type IndexState = 'absent' | 'read' | 'truncated' | 'refused' | 'failed';

export interface PassGaps {
  auditDir: AuditDirState;
  index: IndexState;
  skippedFiles: number;
  refusedFiles: number;
  failedFiles: number;
  droppedLines: number;
}

export interface CoverageGaps { receipts: PassGaps; guards: PassGaps }
export type Coverage = 'bounded-complete' | 'partial';

type SourceStatus = 'absent' | 'read' | 'truncated' | 'refused' | 'failed';

/** Test seams only: fail a read mid-stream or fail one append, from a test,
 *  without touching a live audit tree. Unset in production. */
export interface SessionGuardTestHooks {
  beforeReadChunk?: (info: { pass: ReadPass; file: string; chunk: number }) => void;
  beforeAppend?: (info: { target: 'primary' | 'mirror'; file: string }) => void;
}
let testHooks: SessionGuardTestHooks = {};
export function __setSessionGuardTestHooks(hooks: SessionGuardTestHooks | null): void {
  testHooks = hooks ?? {};
}

function newPassGaps(): PassGaps {
  // Positive completion: everything starts as a failure and is promoted only
  // on the normal path that proves otherwise.
  return { auditDir: 'failed', index: 'failed', skippedFiles: 0, refusedFiles: 0, failedFiles: 0, droppedLines: 0 };
}

function passComplete(g: PassGaps): boolean {
  return (g.auditDir === 'absent' || g.auditDir === 'listed' || g.auditDir === 'not-sought')
    && (g.index === 'absent' || g.index === 'read')
    && g.skippedFiles === 0 && g.refusedFiles === 0 && g.failedFiles === 0 && g.droppedLines === 0;
}

function errCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | null)?.code;
}

interface ReadSource {
  file: string;
  isIndex: boolean;
  /** Realtime candidates: the size observed at discovery, read to exactly that. */
  size?: number;
  identity?: { dev: number; ino: number };
}

/**
 * The stop hook's `forEachJsonlLine`, ported for physKey parity: O_NOFOLLOW,
 * regular file, nlink 1, dev/ino pinned; 64 KiB chunks decoded PER CHUNK
 * (matching the hook, so a non-ASCII `tool` fingerprints the same in both
 * readers — a decoder fix must land in both at once); oversized lines are
 * skipped but still consume a lineIndex. Unlike HEAD it reports how it ended,
 * and it is `read` only if it reached the size it set out to read: an early
 * EOF is a failure, not completion.
 */
function readJsonlPositioned(
  source: ReadSource,
  pass: ReadPass,
  visitor: (line: string, lineIndex: number) => void,
): { status: SourceStatus; droppedLines: number } {
  let droppedLines = 0;
  let st: Stats;
  try {
    st = lstatSync(source.file);
  } catch (err) {
    return { status: errCode(err) === 'ENOENT' ? 'absent' : 'failed', droppedLines };
  }
  if (!st.isFile() || st.isSymbolicLink()) return { status: 'refused', droppedLines };
  let fd: number;
  try {
    fd = openSync(source.file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (err) {
    return { status: errCode(err) === 'ELOOP' ? 'refused' : 'failed', droppedLines };
  }
  try {
    const opened = fstatSync(fd);
    const expected = source.identity ?? { dev: st.dev, ino: st.ino };
    if (opened.dev !== expected.dev || opened.ino !== expected.ino) return { status: 'refused', droppedLines };
    if (!opened.isFile() || opened.nlink > 1) return { status: 'refused', droppedLines };
    let target: number;
    let truncated = false;
    if (source.isIndex) {
      target = Math.min(opened.size, MAX_AUDIT_SCAN_BYTES);
      truncated = opened.size > MAX_AUDIT_SCAN_BYTES;
    } else {
      target = source.size ?? 0;
      // Shrunk since discovery: what was listed can no longer be read.
      if (opened.size < target) return { status: 'failed', droppedLines };
    }
    const buf = Buffer.alloc(READ_CHUNK_BYTES);
    let carry = '';
    let lineIndex = 0;
    let totalRead = 0;
    let chunk = 0;
    let droppingOversizedLine = false;
    while (totalRead < target) {
      testHooks.beforeReadChunk?.({ pass, file: source.file, chunk });
      chunk += 1;
      const bytesRead = readSync(fd, buf, 0, Math.min(buf.length, target - totalRead), null);
      if (bytesRead <= 0) break;
      totalRead += bytesRead;
      carry += buf.subarray(0, bytesRead).toString('utf8');
      for (;;) {
        const newline = carry.indexOf('\n');
        if (newline < 0) break;
        const line = carry.slice(0, newline);
        carry = carry.slice(newline + 1);
        if (droppingOversizedLine) {
          droppingOversizedLine = false;
          lineIndex += 1;
          continue;
        }
        if (Buffer.byteLength(line, 'utf8') > MAX_JSONL_LINE_BYTES) {
          droppedLines += 1;
          lineIndex += 1;
          continue;
        }
        visitor(line, lineIndex++);
      }
      if (Buffer.byteLength(carry, 'utf8') > MAX_JSONL_LINE_BYTES) {
        carry = '';
        droppingOversizedLine = true;
        droppedLines += 1;
      }
    }
    if (totalRead !== target) return { status: 'failed', droppedLines };
    if (!droppingOversizedLine && carry && Buffer.byteLength(carry, 'utf8') <= MAX_JSONL_LINE_BYTES) visitor(carry, lineIndex);
    return { status: truncated ? 'truncated' : 'read', droppedLines };
  } catch {
    return { status: 'failed', droppedLines };
  } finally {
    try { closeSync(fd); } catch { /* ignore */ }
  }
}

interface RealtimeListing {
  state: AuditDirState;
  files: ReadSource[];
  skipped: number;
  refused: number;
  failed: number;
}

/** The stop hook's discovery (newest name first, 256 files, 64 MiB, an
 *  over-budget file skipped not truncated), reporting what it could not see.
 *  Only ENOENT on the audit dir itself is "absent"; existsSync is not used
 *  because it maps every error to false. */
function listRealtimeFiles(auditDir: string): RealtimeListing {
  const out: RealtimeListing = { state: 'failed', files: [], skipped: 0, refused: 0, failed: 0 };
  try {
    let dirStat: Stats;
    try {
      dirStat = lstatSync(auditDir);
    } catch (err) {
      if (errCode(err) === 'ENOENT') out.state = 'absent';
      return out;
    }
    if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
      out.state = 'refused';
      return out;
    }
    const candidates: Array<{ file: string; size: number; dev: number; ino: number }> = [];
    for (const name of readdirSync(auditDir).filter((f) => REALTIME_NAME.test(f))) {
      const file = join(auditDir, name);
      let st: Stats;
      try {
        st = lstatSync(file);
      } catch {
        out.failed += 1;
        continue;
      }
      if (!st.isFile() || st.isSymbolicLink()) {
        out.refused += 1;
        continue;
      }
      candidates.push({ file, size: st.size, dev: st.dev, ino: st.ino });
    }
    candidates.sort((a, b) => b.file.localeCompare(a.file));
    let bytes = 0;
    for (const [i, item] of candidates.entries()) {
      if (out.files.length >= MAX_AUDIT_SCAN_FILES) { out.skipped += candidates.length - i; break; }
      if (item.size > MAX_AUDIT_SCAN_BYTES) { out.skipped += 1; continue; }
      const remaining = MAX_AUDIT_SCAN_BYTES - bytes;
      if (remaining <= 0) { out.skipped += candidates.length - i; break; }
      if (item.size > remaining) { out.skipped += 1; continue; }
      out.files.push({ file: item.file, isIndex: false, size: item.size, identity: { dev: item.dev, ino: item.ino } });
      bytes += item.size;
    }
    out.state = 'listed';
    return out;
  } catch {
    return { state: 'failed', files: [], skipped: 0, refused: 0, failed: 0 };
  }
}

/**
 * Read `sources` for one pass. Rows from a source that was refused or failed
 * (including mid-stream) are neither counted nor allowed to suppress: the
 * visitor writes into a per-source buffer that is committed only when the
 * source was read to its target (or, for the index, its 64 MiB prefix).
 */
function runPass<T>(
  pass: ReadPass,
  sources: ReadSource[],
  gaps: PassGaps,
  visit: (line: string, lineIndex: number, file: string, out: T[]) => void,
): T[] {
  const committed: T[] = [];
  let processed = 0;
  try {
    for (const source of sources) {
      const local: T[] = [];
      const res = readJsonlPositioned(source, pass, (line, lineIndex) => visit(line, lineIndex, source.file, local));
      gaps.droppedLines += res.droppedLines;
      if (source.isIndex) gaps.index = res.status;
      else if (res.status === 'refused') gaps.refusedFiles += 1;
      // A listed candidate that is now absent vanished after listing: a failure.
      else if (res.status !== 'read') gaps.failedFiles += 1;
      if (res.status === 'read' || res.status === 'truncated') committed.push(...local);
      processed += 1;
    }
  } catch {
    for (const source of sources.slice(processed)) {
      if (source.isIndex) gaps.index = 'failed';
      else gaps.failedFiles += 1;
    }
  }
  return committed;
}

function parseLine(line: string): Record<string, unknown> | null {
  if (!line.trim()) return null;
  try {
    const row = JSON.parse(line) as unknown;
    return row && typeof row === 'object' && !Array.isArray(row) ? row as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

interface ReceiptObservation {
  fingerprints: string[] | null;
  legacy: boolean;
}

interface GuardCandidate {
  row: Record<string, unknown>;
  id: GuardIdentity;
}

export type OverlapReason = 'fingerprintless-summary' | 'position-dependent-receipt' | 'receipt-coverage-partial';

function describeGaps(gaps: CoverageGaps): string {
  const parts: string[] = [];
  for (const pass of ['receipts', 'guards'] as const) {
    const g = gaps[pass];
    const kinds: string[] = [];
    if (g.auditDir !== 'absent' && g.auditDir !== 'listed' && g.auditDir !== 'not-sought') kinds.push(`auditDir=${g.auditDir}`);
    if (g.index !== 'absent' && g.index !== 'read') kinds.push(`index=${g.index}`);
    for (const k of ['skippedFiles', 'refusedFiles', 'failedFiles', 'droppedLines'] as const) {
      if (g[k] > 0) kinds.push(`${k}=${g[k]}`);
    }
    if (kinds.length) parts.push(`${pass}:${kinds.join(',')}`);
  }
  return parts.join(' ');
}

export interface ActionGuardDegradedResult {
  recorded: boolean;
  count: number;
  sessionKey?: string;
  existing?: boolean;
  coverage?: Coverage;
  coverageGaps?: CoverageGaps;
  /** Final write outcomes: return value and stderr only, never persisted. */
  receipt?: 'primary+index' | 'primary-only' | 'none';
  indexMirror?: 'ok' | 'failed' | 'not-attempted';
  pendingRemaining?: number;
}

export function recordActionGuardDegraded(
  rawSessionId: string | undefined,
  opts: SessionGuardOptions = {},
): ActionGuardDegradedResult {
  const sessionKey = sessionKeyFor(rawSessionId, opts);
  if (!sessionKey) return { recorded: false, count: 0 };
  const auditDir = auditDirFor(opts.home);
  const indexFile = join(auditDir, 'session-guard', `${sessionKey}.jsonl`);
  const coverageGaps: CoverageGaps = { receipts: newPassGaps(), guards: newPassGaps() };

  // Receipts come from the index AND the bounded primary audit, so a receipt
  // whose index mirror failed still counts. Guards stay index-only (G6).
  const listing = listRealtimeFiles(auditDir);
  coverageGaps.receipts.auditDir = listing.state;
  coverageGaps.receipts.skippedFiles = listing.skipped;
  coverageGaps.receipts.refusedFiles = listing.refused;
  coverageGaps.receipts.failedFiles = listing.failed;
  coverageGaps.guards.auditDir = 'not-sought';
  const indexSource: ReadSource = { file: indexFile, isIndex: true };

  const receipts = runPass<ReceiptObservation>('receipts', [indexSource, ...listing.files], coverageGaps.receipts, (line, _i, _f, out) => {
    const row = parseLine(line);
    if (!row || !isDegradedSummary(row, sessionKey)) return;
    if (Array.isArray(row.guardFingerprints)) {
      out.push({
        fingerprints: row.guardFingerprints.map(String).filter((fp) => /^[a-f0-9]{16}$/.test(fp)),
        legacy: row.fingerprintScheme !== 2,
      });
    } else {
      out.push({ fingerprints: null, legacy: false });
    }
  });
  const guards = runPass<GuardCandidate>('guards', [indexSource], coverageGaps.guards, (line, lineIndex, file, out) => {
    const row = parseLine(line);
    if (!row || !isDegradedGuard(row, sessionKey)) return;
    out.push({ row, id: guardIdentity(row, `${file}:${lineIndex}`) });
  });

  const covered = new Set<string>();
  let fingerprinted = 0;
  let legacy = 0;
  let unknownMembershipSummaryRows = 0;
  for (const r of receipts) {
    if (r.fingerprints === null) { unknownMembershipSummaryRows += 1; continue; }
    fingerprinted += 1;
    if (r.legacy) legacy += 1;
    for (const fp of r.fingerprints) covered.add(fp);
  }
  const receiptFingerprints = covered.size;
  // Step A: an observable historical v1 alias covers its row's primary, so a
  // receipt that listed one copy of a bound row by position covers its mirror.
  for (const g of guards) {
    if (covered.has(g.id.primary) || covered.has(g.id.v1)) covered.add(g.id.primary);
  }
  // Step B: pending = what no receipt lists, one entry per identity.
  const pending: GuardCandidate[] = [];
  const pendingSeen = new Set<string>();
  for (const g of guards) {
    if (covered.has(g.id.primary) || pendingSeen.has(g.id.primary)) continue;
    pendingSeen.add(g.id.primary);
    pending.push(g);
  }

  const coverage: Coverage = passComplete(coverageGaps.receipts) && passComplete(coverageGaps.guards)
    ? 'bounded-complete' : 'partial';
  const status = { coverage, coverageGaps };
  if (coverage === 'partial') {
    console.error(`[shieldcortex] action_guard_degraded coverage=partial sessionKey=${sessionKey} ${describeGaps(coverageGaps)}`);
  }
  if (pending.length === 0) {
    // `existing` means "nothing pending in what this reader inspected" — read
    // it together with `coverage`.
    return receiptFingerprints > 0
      ? { recorded: true, count: 0, existing: true, sessionKey, ...status }
      : { recorded: false, count: 0, sessionKey, ...status };
  }

  const batch = pending.slice(0, MAX_RECEIPT_IDENTITIES);
  const pendingRemaining = pending.length - batch.length;
  const rows = batch.map((g) => g.row);
  const identityBasis = { eventId: 0, bindingNonce: 0, physicalRow: 0 };
  for (const g of batch) identityBasis[g.id.basis] += 1;
  const overlapReasons: OverlapReason[] = [];
  if (unknownMembershipSummaryRows > 0) overlapReasons.push('fingerprintless-summary');
  // Coarse on purpose: position-based prior coverage cannot be ruled out, so
  // say so. Never inferred from a missing file, a timestamp or content.
  if ((legacy > 0 && identityBasis.bindingNonce > 0) || (fingerprinted > 0 && identityBasis.physicalRow > 0)) {
    overlapReasons.push('position-dependent-receipt');
  }
  if (!passComplete(coverageGaps.receipts)) overlapReasons.push('receipt-coverage-partial');

  const threats = [...new Set(rows.flatMap((r) =>
    Array.isArray(r.threats) ? r.threats.map((t) => String(t).slice(0, 120)) : [],
  ))].slice(0, 25);
  const times = rows.map((r) => String(r.ts ?? '')).filter(Boolean).sort();
  const counts = rows.reduce<Record<string, number>>((acc, r) => {
    const outcome = String(r.outcome ?? 'unknown');
    acc[outcome] = (acc[outcome] ?? 0) + 1;
    return acc;
  }, {});
  const entry = {
    type: 'session_summary',
    recordKind: 'summary',
    origin: opts.origin ?? 'openclaw-session-end',
    sessionKey,
    action: 'session_health',
    outcome: 'action_guard_degraded',
    guardOutcomeCount: batch.length,
    guardFingerprints: batch.map((g) => g.id.primary),
    fingerprintScheme: 2,
    identityBasis,
    // Cardinality of THIS batch only — not novelty, not coverage.
    eventCountExact: identityBasis.physicalRow === 0,
    ...(overlapReasons.length ? { historicalOverlap: 'possible', overlapReasons } : {}),
    ...(unknownMembershipSummaryRows > 0 ? { unknownMembershipSummaryRows } : {}),
    coverage,
    coverageGaps,
    ...(pendingRemaining > 0 ? { pendingRemaining } : {}),
    outcomes: counts,
    threats,
    firstGuardTs: times[0],
    lastGuardTs: times[times.length - 1],
    ts: new Date().toISOString(),
  };
  const line = `${JSON.stringify(entry)}\n`;
  const extra = pendingRemaining > 0 ? { pendingRemaining } : {};
  // Primary first; the mirror only after the primary landed. A mirror failure
  // no longer reports the whole receipt as unrecorded (#654 W1): the primary
  // is recovered from bounded realtime by the next pass.
  try {
    mkdirSync(auditDir, { recursive: true, mode: 0o700 });
    const primary = join(auditDir, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`);
    testHooks.beforeAppend?.({ target: 'primary', file: primary });
    appendFileSync(primary, line);
  } catch {
    return { recorded: false, count: batch.length, sessionKey, receipt: 'none', indexMirror: 'not-attempted', ...status, ...extra };
  }
  let mirrored = false;
  try {
    mkdirSync(join(auditDir, 'session-guard'), { recursive: true, mode: 0o700 });
    testHooks.beforeAppend?.({ target: 'mirror', file: indexFile });
    appendFileSync(indexFile, line);
    mirrored = true;
  } catch {
    console.error(`[shieldcortex] action_guard_degraded index mirror FAILED sessionKey=${sessionKey}; the primary receipt stands`);
  }
  console.error(`[shieldcortex] action_guard_degraded sessionKey=${sessionKey} guardOutcomes=${batch.length} origin=${entry.origin}`);
  return {
    recorded: true,
    count: batch.length,
    sessionKey,
    receipt: mirrored ? 'primary+index' : 'primary-only',
    indexMirror: mirrored ? 'ok' : 'failed',
    ...status,
    ...extra,
  };
}

function isDegradedSummary(row: Record<string, unknown>, sessionKey: string): boolean {
  return (row.recordKind === 'summary' || row.type === 'session_summary')
    && isSummaryOrigin(row.origin)
    && row.sessionKey === sessionKey
    && row.outcome === 'action_guard_degraded';
}

/** Aligned with the stop hook's per-row checks (#654); keeps OpenClaw's own
 *  outcome set (G7). */
function isDegradedGuard(row: Record<string, unknown>, sessionKey: string): boolean {
  return (row.recordKind === 'guard' || row.type === 'intercept')
    && isGuardIndexOrigin(row.origin)
    && row.action !== 'notify'
    && row.sessionKey === sessionKey
    && GUARD_DEGRADED_OUTCOMES.has(String(row.outcome ?? ''));
}
