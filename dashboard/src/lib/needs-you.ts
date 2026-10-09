import type { QueryStatus } from '@/lib/query-status';

/**
 * Honest-count rules for the Needs you inbox and its sidebar badge (#692).
 *
 * Invariant: bounded, stale, unavailable or mixed-scope data is never shown as
 * an exact current count or as an all-clear.
 *   - Only `confirmed` counts are summed. A stale count may have changed since,
 *     so it is shown per section as "last known", never added to the total.
 *   - A count can be a floor (`atLeast`): review pairs are cut off at the
 *     server's limit and contradiction discovery samples large stores.
 *   - Because every excluded or floored source contributes >= 0, the confirmed
 *     sum is a true lower bound, written "N+" whenever anything is missing.
 */
export interface CountedSource {
  status: QueryStatus;
  /** Last known count (confirmed or stale); undefined while pending / unavailable. */
  count: number | undefined;
  /** The count is a floor: the real number may be higher. */
  atLeast: boolean;
}

export interface NeedsYouSummary {
  /** Sum of confirmed counts only. */
  confirmedTotal: number;
  /** Every source confirmed and none of them a floor: `confirmedTotal` is exact. */
  exact: boolean;
  /** Some source is stale or unavailable (failed, not merely still loading). */
  anyFailed: boolean;
  anyPending: boolean;
  /** Safe to say nothing is waiting in the observed queues. */
  allClear: boolean;
}

export function summarize(sources: CountedSource[]): NeedsYouSummary {
  const confirmed = sources.filter((s) => s.status === 'confirmed');
  const confirmedTotal = confirmed.reduce((sum, s) => sum + (s.count ?? 0), 0);
  const exact = confirmed.length === sources.length && confirmed.every((s) => !s.atLeast);
  return {
    confirmedTotal,
    exact,
    anyFailed: sources.some((s) => s.status === 'stale' || s.status === 'unavailable'),
    anyPending: sources.some((s) => s.status === 'pending'),
    allClear: exact && confirmedTotal === 0,
  };
}

export interface Badge {
  text: string;
  label: string;
}

/** Sidebar badge: "N" only when exact, "N+" for a floor, "?" when nothing confirmed but something failed. */
export function needsYouBadge(s: NeedsYouSummary): Badge | undefined {
  if (s.confirmedTotal > 0) {
    return s.exact
      ? { text: String(s.confirmedTotal), label: `${s.confirmedTotal} waiting` }
      : { text: `${s.confirmedTotal}+`, label: `at least ${s.confirmedTotal} waiting` };
  }
  if (s.anyFailed) return { text: '?', label: "some lists couldn't be checked" };
  return undefined;
}

/** Section count text with its unit; a stale number is labelled as last known. */
export function sourceCountText(s: CountedSource, unit: string): string {
  if (s.status === 'unavailable') return "couldn't load";
  if (s.status === 'pending' || s.count === undefined) return '…';
  const n = `${s.count.toLocaleString()}${s.atLeast ? '+' : ''} ${unit}`;
  return s.status === 'stale' ? `${n} · last known` : n;
}
