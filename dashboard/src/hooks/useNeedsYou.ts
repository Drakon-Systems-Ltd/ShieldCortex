'use client';

import { useQuarantine } from '@/hooks/useDefence';
import { useReviewQueue } from '@/hooks/useReviewQueue';
import { useXRayFindingsStats } from '@/hooks/useXRayFindings';
import { queryStatus, type QueryStatus } from '@/lib/query-status';

/**
 * The three decision queues that already have a read endpoint, composed for
 * the Needs you inbox (Opus design §2, §5 step 4):
 * - held back: pending quarantine (`/api/v1/quarantine?status=pending`)
 * - memories to check: contradictions + duplicates (`/api/review/queue`)
 * - scanner findings still marked new (`/api/xray/findings/stats`)
 * Held actions have no pending-approvals endpoint yet, so they are not here.
 */
export interface NeedsYouSource {
  status: QueryStatus;
  /** Confirmed count, or undefined while pending / unavailable. */
  count: number | undefined;
  refetch: () => void;
}

export function useNeedsYou(project?: string | null) {
  const quarantine = useQuarantine('pending', 5, project ?? undefined);
  const review = useReviewQueue(project);
  const findings = useXRayFindingsStats();

  const source = (q: { data: unknown; isError: boolean; refetch: () => unknown }, count: number | undefined): NeedsYouSource => {
    const status = queryStatus(q);
    return { status, count: status === 'unavailable' || status === 'pending' ? undefined : count, refetch: () => void q.refetch() };
  };

  const summary = review.data?.summary;
  const heldBack = source(quarantine, quarantine.data?.total);
  const memories = source(review, summary ? (summary.contradictions ?? 0) + (summary.duplicates ?? 0) : undefined);
  const scanner = source(findings, findings.data?.new);

  const known = [heldBack, memories, scanner].map((s) => s.count).filter((n): n is number => typeof n === 'number');
  return {
    heldBack,
    heldBackItems: quarantine.data?.items ?? [],
    memories,
    contradictions: summary?.contradictions ?? 0,
    duplicates: summary?.duplicates ?? 0,
    scanner,
    /** Sum of the confirmed counts only: never a fake zero for a failed source. */
    total: known.reduce((a, b) => a + b, 0),
    allKnown: known.length === 3,
  };
}
