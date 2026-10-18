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
  /**
   * Set when a project is selected: the number then mixes that project's
   * held-back items and memory pairs with scanner findings from the whole
   * computer, which the project filter does not apply to.
   */
  scope?: string;
}

/**
 * Sidebar badge: "N" only when exact, "N+" for a floor, "?" when nothing
 * confirmed but something failed. With a project selected the number is not a
 * project count, so the badge says which parts are which (#692).
 */
export function needsYouBadge(s: NeedsYouSummary, project?: string | null): Badge | undefined {
  let badge: Badge | undefined;
  if (s.confirmedTotal > 0) {
    badge = s.exact
      ? { text: String(s.confirmedTotal), label: `${s.confirmedTotal} waiting` }
      : { text: `${s.confirmedTotal}+`, label: `at least ${s.confirmedTotal} waiting` };
  } else if (s.anyFailed) {
    badge = { text: '?', label: "some lists couldn't be checked" };
  }
  if (!badge || !project) return badge;
  const scope = `Held back and memories: project ${project}. Scanner findings: this whole computer.`;
  return { ...badge, label: `${badge.label}. ${scope}`, scope };
}

/** Section count text with its unit; a stale number is labelled as last known. */
export function sourceCountText(s: CountedSource, unit: string): string {
  if (s.status === 'unavailable') return "couldn't load";
  if (s.status === 'pending' || s.count === undefined) return '…';
  const n = `${s.count.toLocaleString()}${s.atLeast ? '+' : ''} ${unit}`;
  return s.status === 'stale' ? `${n} · last known` : n;
}
