'use client';

import { useQuarantine } from '@/hooks/useDefence';
import { useReviewQueue } from '@/hooks/useReviewQueue';
import { useXRayFindingsStats } from '@/hooks/useXRayFindings';
import { queryStatus, type QueryStatus } from '@/lib/query-status';
import { summarize, type CountedSource } from '@/lib/needs-you';

/**
 * The three decision queues that already have a read endpoint, composed for
 * the Needs you inbox (Opus design §2, §5 step 4):
 * - held back: pending quarantine (`/api/v1/quarantine?status=pending`), selected project
 * - memories to check: contradiction + duplicate PAIRS (`/api/review/queue`), selected project
 * - scanner findings still marked new (`/api/xray/findings/stats`), whole computer
 * Held actions have no pending-approvals endpoint yet, so they are not here.
 * Counting rules (stale, floors, totals) live in `@/lib/needs-you` (#692).
 */
export interface NeedsYouSource extends CountedSource {
  /** Last known count, or undefined while pending / unavailable. */
  count: number | undefined;
  /** Server error text when the latest fetch failed. */
  error?: string;
  refetch: () => void;
}

type QueryLike = { data: unknown; isError: boolean; error?: unknown; refetch: () => unknown };

function source(q: QueryLike, count: number | undefined, atLeast = false): NeedsYouSource {
  const status: QueryStatus = queryStatus(q);
  return {
    status,
    count: status === 'unavailable' || status === 'pending' ? undefined : count,
    atLeast,
    error: q.isError && q.error instanceof Error ? q.error.message : undefined,
    refetch: () => void q.refetch(),
  };
}

export function useNeedsYou(project?: string | null) {
  const quarantine = useQuarantine('pending', 5, project ?? undefined);
  const review = useReviewQueue(project);
  const findings = useXRayFindingsStats();

  const summary = review.data?.summary;
  const coverage = review.data?.pairCoverage;
  // Pairs are cut off at the server limit, and contradiction discovery samples
  // big stores. A server that does not report coverage is treated as a floor.
  const memoriesAtLeast = !coverage
    || coverage.duplicates.capped
    || coverage.contradictions.capped
    || coverage.contradictions.scanPartial;

  const heldBack = source(quarantine, quarantine.data?.total);
  const memories = source(review, summary ? (summary.contradictions ?? 0) + (summary.duplicates ?? 0) : undefined, memoriesAtLeast);
  const scanner = source(findings, findings.data?.new);

  return {
    heldBack,
    heldBackItems: quarantine.data?.items ?? [],
    memories,
    contradictions: summary?.contradictions ?? 0,
    duplicates: summary?.duplicates ?? 0,
    pairCoverage: coverage,
    scanner,
    /** Scanner findings are machine-wide; the project filter does not apply to them. */
    scannerScope: 'computer' as const,
    ...summarize([heldBack, memories, scanner]),
  };
}
