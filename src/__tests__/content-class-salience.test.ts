import { describe, it, expect } from '@jest/globals';

/**
 * Issue #120 — content-class weighting folded into effective salience.
 *
 * effective = base × recency × access × pin × downvote × completeness × CLASS
 *
 * CLASS penalises transactional/status content and boosts consequence content,
 * recomputed from the (stable) content on every rank so the raw-salience
 * ratchet cannot erase it. The acceptance requirement is that consequence
 * out-ranks transactional even when frequency (raw salience) and recency favour
 * the transactional row — "frequency/recency must not dominate consequence".
 */

const NEUTRAL = { last_accessed: '2026-07-24T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 0 };
const NOW = Date.parse('2026-07-24T00:00:00Z');

const TRANSACTIONAL = '0, reran 0, blocked 2. Blocked: Chroma Gel Shopify→Xero Sync — cron: job interrupted by gateway restart';
const CONSEQUENCE = 'Root cause: the OAuth refresh failed because the token was cached past its TTL; the fix was to refresh eagerly.';
const NEUTRAL_FACT = 'The dashboard build copies static assets into the standalone output directory.';

describe('computeEffectiveSalience — content-class factor (#120)', () => {
  it('ranks consequence > neutral > transactional at identical salience/recency/access', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const consequence = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: CONSEQUENCE }, { now: NOW });
    const neutral = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: NEUTRAL_FACT }, { now: NOW });
    const transactional = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: TRANSACTIONAL }, { now: NOW });
    expect(consequence).toBeGreaterThan(neutral);
    expect(neutral).toBeGreaterThan(transactional);
  });

  it('frequency does not dominate consequence: a maxed-out transactional ratchet still loses to a consequence fact', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    // Both maxed on the ratchet; the transactional row is re-extracted every
    // session so it is heavily accessed, the consequence row mattered once.
    // Content class must still invert them.
    const transactional = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, access_count: 50, content: TRANSACTIONAL },
      { now: NOW },
    );
    const consequence = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, access_count: 1, content: CONSEQUENCE },
      { now: NOW },
    );
    expect(consequence).toBeGreaterThan(transactional);
  });

  it('recency does not dominate consequence: a fresh transactional loses to a one-half-life-stale consequence', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const freshTransactional = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, last_accessed: '2026-07-24T00:00:00Z', content: TRANSACTIONAL },
      { now: NOW },
    );
    const staleConsequence = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, last_accessed: '2026-07-10T00:00:00Z', content: CONSEQUENCE }, // 14d = one half-life
      { now: NOW },
    );
    expect(staleConsequence).toBeGreaterThan(freshTransactional);
  });

  it('class weights are opts/env-tunable', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const base = { ...NEUTRAL, salience: 1.0, content: TRANSACTIONAL };
    const soft = computeEffectiveSalience(base, { now: NOW, classPenalty: 0.9 });
    const hard = computeEffectiveSalience(base, { now: NOW, classPenalty: 0.2 });
    expect(hard).toBeLessThan(soft);
  });

  it('back-compat: no content leaves the factor neutral (v4.25 callers unaffected)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const score = computeEffectiveSalience({ ...NEUTRAL, salience: 0.5 }, { now: NOW });
    expect(score).toBeCloseTo(0.5, 3);
  });

  it('never zeroes a transactional memory (re-rank only)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const score = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: TRANSACTIONAL }, { now: NOW });
    expect(score).toBeGreaterThan(0);
  });
});
