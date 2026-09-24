import { getDatabase } from '../../database/init.js';
import { redactAnnotationForPersistence } from './redact.js';
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

/**
 * Persist a Review Copilot annotation and return the form that was stored.
 *
 * #538: this is a persistence boundary. The judge's free text (summary,
 * evidence snippets, reasoning, group key) is redacted here, before the row is
 * written, so an identifier in a quarantine row — a legacy row stored raw
 * before #510, or one the model paraphrased — never lands in a second table.
 * Callers must use the RETURNED annotation (the admin API echoes it) rather
 * than the one they passed in.
 */
export function saveQuarantineAnnotation(input: ReviewAnnotation): ReviewAnnotation {
  const db = getDatabase();
  const itemId = toNumericItemId(input.itemId);
  const annotation = redactAnnotationForPersistence(input);
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
  return annotation;
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
