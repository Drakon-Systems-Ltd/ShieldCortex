import { appendFileSync, chmodSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { getReviewCopilotConfig } from '../../cloud/config.js';
import type { ReviewAnnotation } from './types.js';

export type ReviewCopilotTelemetryEvent =
  | {
      type: 'annotation_created';
      ts: string;
      item_id: number | string;
      category: string;
      suggested_action: string;
      confidence: number;
      similar_group_key: string | null;
      copilot_version: string;
    }
  | { type: 'operator_decision'; ts: string; item_id: number | string; decision: string; reviewed_by: string }
  | { type: 'model_unavailable'; ts: string; reason: string }
  | { type: 'validation_failed'; ts: string; reason: string };

function telemetryPath(): string {
  return getReviewCopilotConfig().telemetryPath;
}

export function appendReviewCopilotTelemetry(event: ReviewCopilotTelemetryEvent): void {
  const path = telemetryPath();
  try {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, JSON.stringify(event) + '\n', { mode: 0o600 });
    try { chmodSync(path, 0o600); } catch { /* best-effort */ }
  } catch {
    // Telemetry must never affect the quarantine review flow.
  }
}

export function recordAnnotationCreated(annotation: ReviewAnnotation): void {
  appendReviewCopilotTelemetry({
    type: 'annotation_created',
    ts: new Date().toISOString(),
    item_id: annotation.itemId,
    category: annotation.category,
    suggested_action: annotation.suggestedAction,
    confidence: annotation.confidence,
    similar_group_key: annotation.similarGroupKey,
    copilot_version: annotation.copilotVersion,
  });
}

export function recordOperatorDecision(itemId: number | string, decision: string, reviewedBy: string): void {
  if (!getReviewCopilotConfig().enabled) return;
  appendReviewCopilotTelemetry({
    type: 'operator_decision',
    ts: new Date().toISOString(),
    item_id: itemId,
    decision,
    reviewed_by: reviewedBy,
  });
}
