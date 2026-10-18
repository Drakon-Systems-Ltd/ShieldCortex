import { getDatabase, withTransaction } from '../../database/init.js';
import { addMemory, MemoryBlockedError } from '../../memory/store.js';
import type { Memory, MemorySourceKind } from '../../memory/types.js';
import { recordQuarantineDecision } from '../../threat-graph/decision.js';

type QuarantineRow = {
  id: number;
  original_title: string | null;
  original_content: string;
  project: string | null;
  source_type: string | null;
  source_identifier: string | null;
  reason: string | null;
  firewall_result: 'BLOCK' | 'QUARANTINE';
  threat_indicators: string | null;
  audit_id: number | null;
};

function parseIndicators(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const p = JSON.parse(raw) as unknown[];
    return p.filter((x): x is string => typeof x === 'string');
  } catch { return []; }
}

/** Ledger the operator's decision so the threat-graph allowance derivation
 * (Loop 3) can consume it. `bulk` flags by-source/batch approvals, which never
 * count toward an allowance. Best-effort; never throws into the review. */
function ledgerDecision(row: QuarantineRow, decision: 'approve' | 'reject', reviewedBy: string, bulk: boolean): void {
  // memory_file (and any non-DefenceSource source_type) never produces a
  // consumable allowance — its key space doesn't match the scan pipeline's —
  // so skip it rather than mint annotation-only noise.
  if (row.source_type === 'memory_file') return;
  recordQuarantineDecision({
    quarantineId: row.id,
    decision,
    sourceType: row.source_type,
    sourceIdentifier: row.source_identifier,
    title: row.original_title,
    content: row.original_content,
    reason: row.reason,
    auditId: row.audit_id,
    threatIndicators: parseIndicators(row.threat_indicators),
    reviewedBy,
    bulk,
    project: row.project,
  });
}

export interface QuarantineReviewResult {
  id: number;
  status: 'approved' | 'rejected';
  memoryId?: number;
  /** Why an approval request ended `rejected` (absent on a plain reject). */
  reason?: string;
}

export interface QuarantineBulkReviewResult {
  success: boolean;
  updated: number;
  total: number;
  promoted: number;
  /** Items an approval request could not admit (now `rejected`). */
  rejected: number;
  items: QuarantineReviewResult[];
}

function getPendingQuarantineRow(id: number): QuarantineRow | null {
  const db = getDatabase();
  const row = db.prepare(
    `SELECT id, original_title, original_content, project, source_type, source_identifier,
            reason, firewall_result, threat_indicators, audit_id
       FROM quarantine
      WHERE id = ? AND status = 'pending'`
  ).get(id) as QuarantineRow | undefined;

  return row ?? null;
}

function normalizeSourceKind(sourceType: string | null): MemorySourceKind {
  switch (sourceType) {
    case 'cli':
    case 'hook':
    case 'plugin':
    case 'agent':
    case 'import':
    case 'cloud':
    case 'api':
      return sourceType;
    default:
      return 'system';
  }
}

const APPROVAL_SOURCE = { type: 'user', identifier: 'approved' } as const;

function maxQuarantineId(): number {
  const row = getDatabase().prepare('SELECT COALESCE(MAX(id), 0) AS m FROM quarantine').get() as { m: number };
  return row.m;
}

/**
 * #824: a refused re-admission must not leave its own new `pending` hold
 * behind. The re-scan inside addMemory records the refused content as a fresh
 * quarantine row under the approval source; the original row (already holding
 * the same content as evidence) is about to be marked rejected, so that new
 * row is a duplicate that would re-queue the item for another approval.
 * Removes only rows this attempt created: ids above the pre-attempt maximum,
 * still pending, under the approval source. The re-scan's audit row is kept.
 */
function discardReadmissionHolds(maxIdBefore: number): void {
  getDatabase().prepare(
    `DELETE FROM quarantine
      WHERE id > ? AND status = 'pending' AND source_type = ? AND source_identifier = ?`,
  ).run(maxIdBefore, APPROVAL_SOURCE.type, APPROVAL_SOURCE.identifier);
}

function promoteApprovedQuarantineRow(row: QuarantineRow, reviewedBy: string): Memory {
  return addMemory(
    {
      title: row.original_title?.trim() || `Recovered quarantined memory ${row.id}`,
      content: row.original_content,
      project: row.project ?? undefined,
      tags: ['quarantine-approved'],
      metadata: {
        approvedFromQuarantine: true,
        quarantineId: row.id,
        quarantineReason: row.reason ?? null,
        // Original provenance is preserved here (the trust now reflects the
        // human approval, not the original source).
        originalSourceType: row.source_type ?? null,
        originalSourceIdentifier: row.source_identifier ?? null,
      },
      captureMethod: 'review',
      reviewedBy,
      sourceKind: normalizeSourceKind(row.source_type),
    },
    undefined,
    // A human approving the item IS the parent-approval the quarantine was
    // waiting for, so admit at user:approved (0.9 — out of the 0.5–0.7 auto-
    // quarantine band). Trust alone does not stop a re-hold: trust-independent
    // detectors (e.g. the skill-level threat detector) still hold on the
    // RE-SCAN, and genuinely-malicious content fails closed. The caller turns
    // that into a single rejected review and discards the re-scan's own hold
    // row, so approval never re-queues the item (#824).
    APPROVAL_SOURCE,
    // Code-constant identity (the MCP surface rejects a declared user: type) →
    // attested by construction. An approved-then-still-malicious re-scan BLOCK
    // accrues to user:approved.
    { sourceAttested: true },
  );
}

function markPendingRowReviewed(id: number, status: 'approved' | 'rejected', reviewedBy: string): void {
  const db = getDatabase();
  const reviewedAt = new Date().toISOString();
  const result = db.prepare(
    'UPDATE quarantine SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = ?'
  ).run(status, reviewedAt, reviewedBy, id, 'pending');

  if (result.changes === 0) {
    throw new Error('Quarantine entry not found or already reviewed');
  }
}

function approveExistingPendingRow(row: QuarantineRow, reviewedBy: string, bulk = false): QuarantineReviewResult {
  if (row.source_type === 'memory_file') {
    markPendingRowReviewed(row.id, 'approved', reviewedBy);
    ledgerDecision(row, 'approve', reviewedBy, bulk);
    return {
      id: row.id,
      status: 'approved',
    };
  }

  // Never re-admit content the pipeline HARD-BLOCKED. Approving a BLOCK item
  // rejects it instead of laundering hard-rejected poison back into memory.
  if (row.firewall_result === 'BLOCK') {
    markPendingRowReviewed(row.id, 'rejected', reviewedBy);
    ledgerDecision(row, 'reject', reviewedBy, bulk);
    return { id: row.id, status: 'rejected', reason: 'hard-blocked content is never re-admitted' };
  }

  // QUARANTINE (soft hold): re-admit through the pipeline at operator-approved
  // trust. If the re-scan still refuses it, fail closed — reject, don't admit —
  // and leave no new pending hold for the same content behind (#824).
  let memory: Memory;
  const maxIdBefore = maxQuarantineId();
  try {
    memory = promoteApprovedQuarantineRow(row, reviewedBy);
  } catch (e) {
    if (e instanceof MemoryBlockedError) {
      discardReadmissionHolds(maxIdBefore);
      markPendingRowReviewed(row.id, 'rejected', reviewedBy);
      ledgerDecision(row, 'reject', reviewedBy, bulk);
      return { id: row.id, status: 'rejected', reason: `still held on re-scan: ${e.reason}` };
    }
    throw e;
  }
  markPendingRowReviewed(row.id, 'approved', reviewedBy);
  ledgerDecision(row, 'approve', reviewedBy, bulk);

  return {
    id: row.id,
    status: 'approved',
    memoryId: memory.id,
  };
}

function rejectPendingQuarantineRow(id: number, reviewedBy: string, bulk = false): QuarantineReviewResult | null {
  const row = getPendingQuarantineRow(id);
  if (!row) {
    return null;
  }

  markPendingRowReviewed(row.id, 'rejected', reviewedBy);
  ledgerDecision(row, 'reject', reviewedBy, bulk);
  return { id, status: 'rejected' };
}

export function approveQuarantineItem(id: number, reviewedBy: string = 'dashboard'): QuarantineReviewResult | null {
  return withTransaction(() => {
    const row = getPendingQuarantineRow(id);
    if (!row) return null;
    return approveExistingPendingRow(row, reviewedBy);
  });
}

export function rejectQuarantineItem(id: number, reviewedBy: string = 'dashboard'): QuarantineReviewResult | null {
  return withTransaction(() => rejectPendingQuarantineRow(id, reviewedBy));
}

export function approveQuarantineItems(ids: number[], reviewedBy: string = 'dashboard'): QuarantineBulkReviewResult {
  return withTransaction(() => {
    const items: QuarantineReviewResult[] = [];

    for (const id of ids) {
      const row = getPendingQuarantineRow(id);
      if (!row) continue;
      // Batch approval is triage, not N independent judgements — flag bulk so
      // these never earn an allowance (Loop 3's approve-farm guard).
      items.push(approveExistingPendingRow(row, reviewedBy, true));
    }

    return {
      success: true,
      updated: items.length,
      total: ids.length,
      promoted: items.filter((item) => item.memoryId).length,
      rejected: items.filter((item) => item.status === 'rejected').length,
      items,
    };
  });
}

export function rejectQuarantineItems(ids: number[], reviewedBy: string = 'dashboard'): QuarantineBulkReviewResult {
  return withTransaction(() => {
    const items: QuarantineReviewResult[] = [];

    for (const id of ids) {
      const result = rejectPendingQuarantineRow(id, reviewedBy);
      if (result) items.push(result);
    }

    return {
      success: true,
      updated: items.length,
      total: ids.length,
      promoted: 0,
      rejected: items.length,
      items,
    };
  });
}

export function approveQuarantineItemsBySource(sourceIdentifier: string, reviewedBy: string = 'dashboard'): QuarantineBulkReviewResult {
  const db = getDatabase();
  const ids = db.prepare(
    "SELECT id FROM quarantine WHERE status = 'pending' AND source_identifier = ? ORDER BY created_at ASC"
  ).all(sourceIdentifier) as Array<{ id: number }>;

  return approveQuarantineItems(ids.map((item) => item.id), reviewedBy);
}

/**
 * Reply text for an approval request (MCP `quarantine_review`). Reports the
 * recorded outcome: a refused approval says so (#824).
 */
export function describeApproveResult(id: number, result: QuarantineReviewResult): string {
  if (result.status !== 'approved') {
    return `Quarantine item ${id} was not approved: ${result.reason ?? 'it could not be admitted'}. `
      + 'The item is now rejected and was not added to memory.';
  }
  return `Quarantine item ${id} approved${result.memoryId ? ` and promoted to memory ${result.memoryId}` : ''}.`;
}

/** Reply text for a by-source approval batch: approved and refused counts. */
export function describeBulkApproveResult(sourceIdentifier: string, result: QuarantineBulkReviewResult): string {
  const approved = result.updated - result.rejected;
  const notApproved = result.rejected > 0
    ? `; ${result.rejected} not approved (could not be admitted; now rejected, not added to memory)`
    : '';
  return `Batch reviewed ${result.updated} of ${result.total} items from "${sourceIdentifier}": `
    + `${approved} approved (${result.promoted} promoted to memory)${notApproved}.`;
}
