/**
 * Memory Staleness Scoring — v4.0.0
 *
 * Provides staleness awareness to memories based on age.
 * Used by search and recall to surface freshness warnings.
 */

const MS_PER_DAY = 86_400_000;

/**
 * Days since memory was created.
 */
export function memoryAgeDays(createdAt: number): number {
  return Math.max(0, Math.floor((Date.now() - createdAt) / MS_PER_DAY));
}

/**
 * Human-readable age string.
 */
export function memoryAge(createdAt: number): string {
  const days = memoryAgeDays(createdAt);
  if (days === 0) return 'today';
  if (days === 1) return 'yesterday';
  if (days < 7) return `${days} days ago`;
  if (days < 14) return '1 week ago';
  if (days < 30) return `${Math.floor(days / 7)} weeks ago`;
  if (days < 60) return '1 month ago';
  if (days < 365) return `${Math.floor(days / 30)} months ago`;
  return `${Math.floor(days / 365)} year${Math.floor(days / 365) > 1 ? 's' : ''} ago`;
}

/**
 * Freshness score: 1.0 for today, exponentially decaying.
 * Half-life of ~7 days: score ≈ 0.5 after a week.
 */
export function memoryFreshnessScore(createdAt: number): number {
  const days = memoryAgeDays(createdAt);
  if (days === 0) return 1.0;
  // Exponential decay with half-life of 7 days
  return Math.max(0.01, Math.exp(-0.099 * days));
}

/**
 * Warning text for stale memories (>2 days old). Returns null for fresh memories.
 */
export function memoryFreshnessWarning(createdAt: number): string | null {
  const days = memoryAgeDays(createdAt);
  if (days <= 2) return null;
  const age = memoryAge(createdAt);
  const score = memoryFreshnessScore(createdAt);
  if (score < 0.1) {
    return `⚠️ Very stale memory (${age}, freshness ${(score * 100).toFixed(0)}%) — verify before relying on this`;
  }
  return `⚠️ Aging memory (${age}, freshness ${(score * 100).toFixed(0)}%) — may need verification`;
}

/**
 * Append staleness warning to a memory's content for display.
 */
export function appendStalenessWarning(content: string, createdAt: Date): string {
  const warning = memoryFreshnessWarning(createdAt.getTime());
  if (!warning) return content;
  return `${content}\n\n${warning}`;
}
