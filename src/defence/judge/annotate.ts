import { getDatabase } from '../../database/init.js';
import { requireFeature } from '../../license/gate.js';
import { reviewQuarantineItem } from './index.js';
import { saveQuarantineAnnotation, getAnnotationForItem } from './annotations-store.js';
import { recordAnnotationCreated } from './telemetry.js';
import type { AnnotationRunResult, ReviewAnnotation, ReviewQuarantineItem } from './types.js';

interface QuarantineRow {
  id: number;
  original_title: string | null;
  original_content: string;
  project: string | null;
  source_type: string | null;
  source_identifier: string | null;
  reason: string | null;
  threat_indicators: string | null;
  anomaly_score: number | null;
  firewall_result: string | null;
  created_at: string | null;
}

function parseThreatIndicators(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === 'string') : [];
  } catch {
    return [];
  }
}

function toReviewItem(row: QuarantineRow): ReviewQuarantineItem {
  return {
    id: row.id,
    content: row.original_content,
    title: row.original_title,
    project: row.project,
    sourceType: row.source_type,
    sourceIdentifier: row.source_identifier,
    reason: row.reason,
    threatIndicators: parseThreatIndicators(row.threat_indicators),
    anomalyScore: row.anomaly_score,
    firewallResult: row.firewall_result,
    createdAt: row.created_at,
  };
}

function shouldPersistAnnotation(annotation: ReviewAnnotation): boolean {
  return annotation.synthetic !== true;
}

function getPendingRow(id: number): QuarantineRow | null {
  const db = getDatabase();
  const row = db.prepare(`
    SELECT id, original_title, original_content, project, source_type, source_identifier,
           reason, threat_indicators, anomaly_score, firewall_result, created_at
    FROM quarantine
    WHERE id = ? AND status = 'pending'
  `).get(id) as QuarantineRow | undefined;
  return row ?? null;
}

export async function annotateQuarantineItem(id: number): Promise<ReviewAnnotation | null> {
  requireFeature('local_ai_explainer');
  const row = getPendingRow(id);
  if (!row) return null;

  const annotation = await reviewQuarantineItem(toReviewItem(row));
  if (!shouldPersistAnnotation(annotation)) return null;

  saveQuarantineAnnotation(annotation);
  recordAnnotationCreated(annotation);
  return annotation;
}

export async function annotatePendingQuarantineItems(
  options: { limit?: number; project?: string } = {},
): Promise<AnnotationRunResult> {
  requireFeature('local_ai_explainer');
  const db = getDatabase();
  const limit = Math.max(1, Math.min(500, Math.floor(options.limit ?? 50)));
  const rows = (options.project
    ? db.prepare(`
        SELECT id, original_title, original_content, project, source_type, source_identifier,
               reason, threat_indicators, anomaly_score, firewall_result, created_at
        FROM quarantine
        WHERE status = 'pending' AND project = ?
          AND NOT EXISTS (
            SELECT 1 FROM quarantine_annotations qa WHERE qa.item_id = quarantine.id
          )
        ORDER BY created_at ASC
        LIMIT ?
      `).all(options.project, limit)
    : db.prepare(`
        SELECT id, original_title, original_content, project, source_type, source_identifier,
               reason, threat_indicators, anomaly_score, firewall_result, created_at
        FROM quarantine
        WHERE status = 'pending'
          AND NOT EXISTS (
            SELECT 1 FROM quarantine_annotations qa WHERE qa.item_id = quarantine.id
          )
        ORDER BY created_at ASC
        LIMIT ?
      `).all(limit)) as QuarantineRow[];

  const result: AnnotationRunResult = {
    attempted: rows.length,
    annotated: 0,
    skipped: 0,
    failed: 0,
  };

  for (const row of rows) {
    try {
      const annotation = await reviewQuarantineItem(toReviewItem(row));
      if (!shouldPersistAnnotation(annotation)) {
        result.skipped++;
        continue;
      }
      saveQuarantineAnnotation(annotation);
      recordAnnotationCreated(annotation);
      result.annotated++;
    } catch {
      result.failed++;
    }
  }

  return result;
}

export { getAnnotationForItem };
