import { createHash } from 'crypto';
import type { ReviewAnnotation, ReviewBatch } from './types.js';

const STOP_WORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from', 'in',
  'is', 'it', 'of', 'on', 'or', 'that', 'the', 'this', 'to', 'with',
]);

function normalizeSummaryTokens(summary: string): string {
  return summary
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((token) => token.length > 2 && !STOP_WORDS.has(token))
    .slice(0, 10)
    .join(' ');
}

export function computeSimilarGroupKey(annotation: Pick<ReviewAnnotation, 'category' | 'suggestedAction' | 'summary'>): string {
  const basis = [
    annotation.category,
    annotation.suggestedAction,
    normalizeSummaryTokens(annotation.summary),
  ].join('|');
  const digest = createHash('sha256').update(basis).digest('hex').slice(0, 12);
  return `sg-${digest}`;
}

export function withSimilarGroupKey(annotation: ReviewAnnotation): ReviewAnnotation {
  return {
    ...annotation,
    similarGroupKey: annotation.similarGroupKey ?? computeSimilarGroupKey(annotation),
  };
}

export function groupSimilarItems(annotations: ReviewAnnotation[]): ReviewBatch[] {
  const grouped = new Map<string, ReviewAnnotation[]>();

  for (const annotation of annotations.map(withSimilarGroupKey)) {
    const key = annotation.similarGroupKey ?? computeSimilarGroupKey(annotation);
    const list = grouped.get(key) ?? [];
    list.push(annotation);
    grouped.set(key, list);
  }

  return [...grouped.entries()]
    .map(([key, items]) => {
      const confidenceTotal = items.reduce((sum, item) => sum + item.confidence, 0);
      return {
        key,
        category: items[0].category,
        suggestedAction: items[0].suggestedAction,
        count: items.length,
        itemIds: items.map((item) => item.itemId),
        confidenceAvg: items.length > 0 ? confidenceTotal / items.length : 0,
        annotations: items,
      } satisfies ReviewBatch;
    })
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
}
