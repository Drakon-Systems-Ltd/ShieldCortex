import { getDatabase, withTransaction } from '../../database/init.js';
import { addMemory } from '../../memory/store.js';
import type { Memory, MemorySourceKind } from '../../memory/types.js';

type QuarantineRow = {
  id: number;
  original_title: string | null;
  original_content: string;
  project: string | null;
  source_type: string | null;
  source_identifier: string | null;
  reason: string | null;
};

export interface QuarantineReviewResult {
  id: number;
  status: 'approved' | 'rejected';
  memoryId?: number;
}

export interface QuarantineBulkReviewResult {
  success: boolean;
  updated: number;
  total: number;
  promoted: number;
  items: QuarantineReviewResult[];
}

function getPendingQuarantineRow(id: number): QuarantineRow | null {
  const db = getDatabase();
  const row = db.prepare(
    `SELECT id, original_title, original_content, project, source_type, source_identifier, reason
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

function promoteApprovedQuarantineRow(row: QuarantineRow, reviewedBy: string): Memory {
  return addMemory({
    title: row.original_title?.trim() || `Recovered quarantined memory ${row.id}`,
    content: row.original_content,
    project: row.project ?? undefined,
    tags: ['quarantine-approved'],
    metadata: {
      approvedFromQuarantine: true,
      quarantineId: row.id,
      quarantineReason: row.reason ?? null,
      originalSourceType: row.source_type ?? null,
      originalSourceIdentifier: row.source_identifier ?? null,
    },
    captureMethod: 'review',
    reviewedBy,
    sourceKind: normalizeSourceKind(row.source_type),
    source:
      row.source_type && row.source_identifier
        ? `${row.source_type}:${row.source_identifier}`
        : 'quarantine:review',
  });
}

function approveExistingPendingRow(row: QuarantineRow, reviewedBy: string): QuarantineReviewResult {
  const db = getDatabase();
  const memory = promoteApprovedQuarantineRow(row, reviewedBy);
  const reviewedAt = new Date().toISOString();
  const result = db.prepare(
    'UPDATE quarantine SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = ?'
  ).run('approved', reviewedAt, reviewedBy, row.id, 'pending');

  if (result.changes === 0) {
    throw new Error('Quarantine entry not found or already reviewed');
  }

  return {
    id: row.id,
    status: 'approved',
    memoryId: memory.id,
  };
}

function rejectPendingQuarantineRow(id: number, reviewedBy: string): QuarantineReviewResult | null {
  const db = getDatabase();
  const reviewedAt = new Date().toISOString();
  const result = db.prepare(
    'UPDATE quarantine SET status = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = ?'
  ).run('rejected', reviewedAt, reviewedBy, id, 'pending');

  if (result.changes === 0) {
    return null;
  }

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
      items.push(approveExistingPendingRow(row, reviewedBy));
    }

    return {
      success: true,
      updated: items.length,
      total: ids.length,
      promoted: items.filter((item) => item.memoryId).length,
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
