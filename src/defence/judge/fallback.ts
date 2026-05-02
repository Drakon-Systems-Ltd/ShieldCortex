import type { ReviewAnnotation, ReviewQuarantineItem } from './types.js';

export const REVIEW_COPILOT_PROMPT_VERSION = 'review-copilot-prompt-v1';

export function getCopilotVersion(modelId: string): string {
  return `${modelId}@${REVIEW_COPILOT_PROMPT_VERSION}`;
}

export function fallbackAnnotation(
  item: Pick<ReviewQuarantineItem, 'id'>,
  modelId: string = 'unavailable',
  reason: string = 'No local model annotation was available.',
): ReviewAnnotation {
  return {
    itemId: String(item.id),
    category: 'uncertain',
    summary: 'Review Copilot unavailable.',
    evidence: [],
    suggestedAction: 'keep_quarantined',
    confidence: 0,
    similarGroupKey: null,
    reasoning: reason.slice(0, 400),
    copilotVersion: getCopilotVersion(modelId),
    generatedAt: new Date().toISOString(),
    synthetic: true,
  };
}
