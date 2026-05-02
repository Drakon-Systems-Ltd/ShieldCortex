import { getDatabase } from '../../database/init.js';
import type { ReviewAnnotation } from './types.js';

interface AnnotationRow {
  item_id: number;
  annotation_json: string;
}

function toNumericItemId(itemId: string): number {
  const numericId = Number(itemId);
  if (!Number.isSafeInteger(numericId) || numericId <= 0) {
    throw new Error(`invalid_annotation_item_id:${itemId}`);
  }
  return numericId;
}

export function saveQuarantineAnnotation(annotation: ReviewAnnotation): void {
  const db = getDatabase();
  const itemId = toNumericItemId(annotation.itemId);
  db.prepare(`
    INSERT INTO quarantine_annotations (
      item_id,
      category,
      suggested_action,
      confidence,
      similar_group_key,
      copilot_version,
      annotation_json,
      generated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(item_id, copilot_version) DO UPDATE SET
      category = excluded.category,
      suggested_action = excluded.suggested_action,
      confidence = excluded.confidence,
      similar_group_key = excluded.similar_group_key,
      annotation_json = excluded.annotation_json,
      generated_at = excluded.generated_at
  `).run(
    itemId,
    annotation.category,
    annotation.suggestedAction,
    annotation.confidence,
    annotation.similarGroupKey,
    annotation.copilotVersion,
    JSON.stringify(annotation),
    annotation.generatedAt,
  );
}

export function getAnnotationForItem(id: number): ReviewAnnotation | null {
  const db = getDatabase();
  const row = db.prepare(`
    SELECT item_id, annotation_json
    FROM quarantine_annotations
    WHERE item_id = ?
    ORDER BY generated_at DESC
    LIMIT 1
  `).get(id) as AnnotationRow | undefined;

  if (!row) return null;
  try {
    return JSON.parse(row.annotation_json) as ReviewAnnotation;
  } catch {
    return null;
  }
}

export function listAnnotations(limit: number = 50): ReviewAnnotation[] {
  const db = getDatabase();
  const rows = db.prepare(`
    SELECT item_id, annotation_json
    FROM quarantine_annotations
    ORDER BY generated_at DESC
    LIMIT ?
  `).all(limit) as AnnotationRow[];

  return rows.flatMap((row) => {
    try {
      return [JSON.parse(row.annotation_json) as ReviewAnnotation];
    } catch {
      return [];
    }
  });
}
