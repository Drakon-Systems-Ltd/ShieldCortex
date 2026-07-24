import { describe, it, expect } from '@jest/globals';

/**
 * Issue #120 acceptance fixture — "this session's injection set, with expected
 * ranking inverted."
 *
 * On the Jarvis box (24 Jul 2026) the SessionStart preamble surfaced three
 * transactional fragments at 100% salience while the genuinely load-bearing
 * facts from the same period (an OAuth root-cause finding, a fleet-billing
 * doctrine) ranked below the fold.
 *
 * This fixture reconstructs that injection set and asserts that
 * orderByEffectiveSalience (the actual SessionStart ordering helper) now ranks
 * the consequence facts ABOVE the transactional noise — even though the
 * transactional rows carry the higher raw salience and the more recent access,
 * i.e. frequency/recency no longer dominate consequence.
 */

// Every row shares the SAME recent access so ONLY content class differentiates
// them — and the transactional rows are handed the ADVANTAGE (max raw salience,
// more accesses) to prove the class factor overturns frequency/recency.
const NOW = Date.parse('2026-07-24T09:00:00Z');
const FRESH = '2026-07-24T08:00:00Z';

const TRANSACTIONAL = [
  {
    id: 'heartbeat-tally',
    salience: 1.0,
    access_count: 40,
    last_accessed: FRESH,
    pinned: 0,
    downvote_count: 0,
    content:
      '0, reran 0, blocked 2. Blocked: Chroma Gel Shopify→Xero Sync — cron: job interrupted by gateway restart',
  },
  {
    id: 'revert-escalation',
    salience: 1.0,
    access_count: 35,
    last_accessed: FRESH,
    pinned: 0,
    downvote_count: 0,
    content:
      "running the revert out-of-band, which left the cron history's last run as error, so the watcher re-escalated the same stale failure every 6h",
  },
  {
    id: 'briefing-delivery',
    salience: 1.0,
    access_count: 30,
    last_accessed: FRESH,
    pinned: 0,
    downvote_count: 0,
    content: '12 delivered, 0 bounced, 3 queued — briefing emails sent successfully at 07:00',
  },
];

const CONSEQUENCE = [
  {
    id: 'oauth-root-cause',
    salience: 0.8,
    access_count: 1,
    last_accessed: FRESH,
    pinned: 0,
    downvote_count: 0,
    content:
      'Root cause: the Xero OAuth refresh failed because the token was cached past its 3600s TTL; the fix was to refresh eagerly before each sync.',
  },
  {
    id: 'fleet-billing-doctrine',
    salience: 0.8,
    access_count: 1,
    last_accessed: FRESH,
    pinned: 0,
    downvote_count: 0,
    content:
      'Doctrine: fleet billing is metered per active agent, so idle worktrees must be torn down — never left running by design.',
  },
];

describe('Issue #120 acceptance — injection-set ranking inverted', () => {
  it('both consequence facts out-rank all three transactional fragments', async () => {
    const { orderByEffectiveSalience } = await import('../../scripts/lib/session-context.mjs');
    // Interleave so the initial order can't accidentally produce the result.
    const injectionSet = [
      TRANSACTIONAL[0],
      CONSEQUENCE[0],
      TRANSACTIONAL[1],
      CONSEQUENCE[1],
      TRANSACTIONAL[2],
    ];

    const ordered = orderByEffectiveSalience(injectionSet, { now: NOW });
    const rankById = new Map(ordered.map((m, i) => [m.id, i]));

    const worstConsequenceRank = Math.max(
      rankById.get('oauth-root-cause')!,
      rankById.get('fleet-billing-doctrine')!,
    );
    const bestTransactionalRank = Math.min(
      rankById.get('heartbeat-tally')!,
      rankById.get('revert-escalation')!,
      rankById.get('briefing-delivery')!,
    );

    // Every consequence fact ranks strictly above every transactional one.
    expect(worstConsequenceRank).toBeLessThan(bestTransactionalRank);
    // Concretely: the top two slots are the consequence facts.
    expect(ordered.slice(0, 2).map((m) => m.id).sort()).toEqual(
      ['fleet-billing-doctrine', 'oauth-root-cause'],
    );
  });

  it('pre-#120 the transactional rows would have won on raw salience (guards the regression)', () => {
    // Sanity check on the fixture itself: by RAW salience DESC (the old boot
    // ordering), the transactional 1.0 rows sort above the 0.8 consequence rows.
    const injectionSet = [...TRANSACTIONAL, ...CONSEQUENCE];
    const byRaw = [...injectionSet].sort((a, b) => b.salience - a.salience);
    expect(byRaw.slice(0, 3).every((m) => TRANSACTIONAL.includes(m))).toBe(true);
  });
});
