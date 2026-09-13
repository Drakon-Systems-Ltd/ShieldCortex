import type { StatusPillState } from '@/components/ds/StatusPill';

/**
 * Honest-state derivation for Overview rows (brief §13.4, review item 5).
 *
 * Every row, count and pill on the Overview derives its state from the React
 * Query result through this one helper, so a loading or failed fetch can never
 * render as "clear", "0" or green:
 *
 *   pending      no data yet (first fetch in flight)          → "checking…"
 *   unavailable  no data and the fetch failed                 → "unavailable"
 *   stale        we have data but the latest refetch failed   → last known + caption
 *   confirmed    data present, last fetch succeeded
 */
export type QueryStatus = 'pending' | 'unavailable' | 'stale' | 'confirmed';

/** The subset of a React Query result the derivation needs. */
export interface QueryLike<T = unknown> {
  data: T | undefined;
  isError: boolean;
}

export function queryStatus(q: QueryLike): QueryStatus {
  if (q.data === undefined) return q.isError ? 'unavailable' : 'pending';
  return q.isError ? 'stale' : 'confirmed';
}

/** Worst-of for a row that depends on several queries (unavailable > pending > stale > confirmed). */
export function combineStatus(...statuses: QueryStatus[]): QueryStatus {
  const rank: Record<QueryStatus, number> = { unavailable: 3, pending: 2, stale: 1, confirmed: 0 };
  return statuses.reduce<QueryStatus>((worst, s) => (rank[s] > rank[worst] ? s : worst), 'confirmed');
}

export interface Pill {
  state: StatusPillState;
  text: string;
}

/**
 * Pill for a row: `confirmed` is what the row claims when its data is fresh;
 * the other three states override it. A stale `ok` is downgraded to `warn`
 * (we cannot currently vouch for it); stale `fail`/`warn`/`off` keep their
 * colour — a last-known problem is still a problem.
 */
export function pillFor(status: QueryStatus, confirmed: Pill): Pill {
  switch (status) {
    case 'pending':
      return { state: 'unknown', text: 'checking…' };
    case 'unavailable':
      return { state: 'unavailable', text: 'unavailable' };
    case 'stale':
      return {
        state: confirmed.state === 'ok' ? 'warn' : confirmed.state,
        text: `${confirmed.text} · stale (refetch failed)`,
      };
    default:
      return confirmed;
  }
}

/** Count text: never a fabricated zero — '…' while pending, '—' when unavailable. */
export function countText(n: number | undefined, status: QueryStatus): string {
  if (status === 'unavailable') return '—';
  if (status === 'pending' || n === undefined) return '…';
  return n.toLocaleString();
}

export type FirewallMode = 'strict' | 'balanced' | 'permissive';

/**
 * Write-firewall pill. `tampered` is NEVER green regardless of mode; permissive
 * is labelled as what it is (advisory — writes are recorded, not blocked), not
 * "enforced (permissive)".
 */
export function firewallPill(
  status: QueryStatus,
  data: { mode: FirewallMode; tampered: boolean } | undefined,
): Pill {
  if (!data) return pillFor(status, { state: 'unknown', text: 'checking…' });
  let confirmed: Pill;
  if (data.tampered) confirmed = { state: 'fail', text: `config tampered (${data.mode})` };
  else if (data.mode === 'permissive') confirmed = { state: 'warn', text: 'permissive — advisory only, not blocking' };
  else confirmed = { state: 'ok', text: `enforced (${data.mode})` };
  return pillFor(status, confirmed);
}

/** Action Guard (Iron Dome) pill: on / off, with the honest overrides. */
export function guardPill(status: QueryStatus, enabled: boolean | undefined): Pill {
  return pillFor(status, enabled ? { state: 'ok', text: 'on' } : { state: 'off', text: 'off' });
}

/**
 * Conversation scanning: the Injection Scanner is an Iron Dome module with no
 * independent toggle in `/api/iron-dome/status` (it runs whenever Iron Dome is
 * on), so this row mirrors the module state the Protection → Status tab derives —
 * labelled as such rather than pretending to a switch that does not exist.
 */
export function scanningPill(status: QueryStatus, enabled: boolean | undefined): Pill {
  return pillFor(status, enabled ? { state: 'ok', text: 'on (injection scanner)' } : { state: 'off', text: 'off' });
}

/** Operations (control) pill: emergency stop > paused > mode. */
export function operationsPill(
  status: QueryStatus,
  data: { killSwitchActive?: boolean; paused?: boolean; mode?: string } | undefined,
): Pill {
  const confirmed: Pill = data?.killSwitchActive
    ? { state: 'fail', text: 'emergency stop' }
    : data?.paused
      ? { state: 'warn', text: 'paused' }
      : { state: 'ok', text: data?.mode ?? 'running' };
  return pillFor(status, confirmed);
}
