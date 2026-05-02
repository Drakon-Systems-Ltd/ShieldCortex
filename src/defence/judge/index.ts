import { getReviewCopilotConfig } from '../../cloud/config.js';
import { fallbackAnnotation } from './fallback.js';
import { decideReviewAnnotation, deterministicAnnotation } from './decision.js';
import { buildReviewPrompt } from './prompt.js';
import { runReviewCopilotPrompt, preloadReviewCopilotModel, disposeReviewCopilotWorker } from './runner.js';
import { parseReviewAnnotation } from './schema.js';
import { appendReviewCopilotTelemetry } from './telemetry.js';
import { groupSimilarItems, withSimilarGroupKey } from './grouping.js';
import type { ReviewAnnotation, ReviewBatch, ReviewQuarantineItem } from './types.js';

export type {
  AnnotationRunResult,
  ReviewAnnotation,
  ReviewBatch,
  ReviewCopilotCategory,
  ReviewCopilotSuggestion,
  ReviewEvidence,
  ReviewQuarantineItem,
} from './types.js';

export { groupSimilarItems, computeSimilarGroupKey } from './grouping.js';
export { parseReviewAnnotation, validateReviewAnnotation } from './schema.js';
export { fallbackAnnotation } from './fallback.js';
export { decideReviewAnnotation } from './decision.js';
export { preloadReviewCopilotModel, disposeReviewCopilotWorker } from './runner.js';

export async function reviewQuarantineItem(item: ReviewQuarantineItem): Promise<ReviewAnnotation> {
  const config = getReviewCopilotConfig();
  if (!config.enabled) {
    return fallbackAnnotation(item, config.modelId, 'Review Copilot disabled.');
  }

  const deterministicDecision = decideReviewAnnotation(item);
  const rawText = await runReviewCopilotPrompt(buildReviewPrompt(item, deterministicDecision));
  const validation = parseReviewAnnotation(rawText, item, config.modelId, deterministicDecision);

  if (!validation.ok) {
    appendReviewCopilotTelemetry({
      type: validation.reason === 'model_unavailable' ? 'model_unavailable' : 'validation_failed',
      ts: new Date().toISOString(),
      reason: validation.reason,
    });
    return withSimilarGroupKey(deterministicAnnotation(
      item,
      validation.annotation.copilotVersion,
      deterministicDecision,
      validation.reason,
    ));
  }

  return withSimilarGroupKey(validation.annotation);
}

export function groupReviewAnnotations(annotations: ReviewAnnotation[]): ReviewBatch[] {
  return groupSimilarItems(annotations);
}
