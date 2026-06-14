import { describe, it, expect } from '@jest/globals';

/**
 * v4.33.1: completeness factor in effective salience.
 *
 * Field finding (edith, 2026-06-14): raw `salience` is a one-way ratchet —
 * reinforcement-on-access / search-reinforce / consolidation link-bonus all
 * only ever ADD (each Math.min(1.0, …)), while temporal decay is diverted to a
 * separate `decayed_score` column and never folded back. So every long-lived
 * memory saturates at raw salience 1.0. On edith, 43/43 long-term rows sat at
 * exactly 1.0 and 81% of them were mid-sentence FRAGMENTS ("the resources this
 * year.", "so you can actually run the test first?"). They tied real facts at
 * the ceiling and dominated the SessionStart preamble + recall.
 *
 * The extraction-time signal that distinguishes them (the 0.6 auto cap, the
 * -0.15 fragment penalty) is transient — the ratchet erases it. The durable fix
 * is to apply a completeness signal at READ time, recomputed from the (stable)
 * content on every rank, so a fragment can never out-rank a complete fact of
 * equal recency/access regardless of how high the ratchet drove its raw score.
 *
 * effective = base × recency × access × pin × downvote_penalty × COMPLETENESS
 *
 * completeness = 1 for a self-contained capture, fragmentFactor (<1) for a
 * capture sliced mid-clause (leading or trailing on a function word). It only
 * RE-RANKS (factor > 0, never drops) — same philosophy as the downvote floor.
 */

const NEUTRAL = { last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 0 };
const NOW = Date.parse('2026-05-27T00:00:00Z');

describe('v4.33.1 computeEffectiveSalience — completeness factor', () => {
  it('a complete fact out-ranks a mid-sentence fragment of identical salience/recency/access', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const complete = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, content: 'ClassDojo join-request sentinel fires every 30 minutes and pings on pending joins.' },
      { now: NOW },
    );
    const fragment = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, content: 'the resources this year.' },
      { now: NOW },
    );
    expect(fragment).toBeLessThan(complete);
  });

  it('penalises a leading-fragment that starts on a function word (real field examples)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    for (const frag of [
      'so you can actually run the test first?',          // #693, starts "so"
      'in the responder skill, not the monitor.',         // #332, starts "in"
      'and all 40 crons are now healthy.',                // #2648, starts "and"
      'with website-policy URLs added to evidence.',      // #984, starts "with"
      '— the daily check now emails the right place.',    // #2795, em-dash then "the"
    ]) {
      const eff = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: frag }, { now: NOW });
      const base = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: 'Decision: PostgreSQL chosen for JSONB support and partial indexes.' }, { now: NOW });
      expect(eff).toBeLessThan(base);
    }
  });

  it('penalises a trailing-fragment that dangles on a function word with no terminator', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const dangling = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, content: 'The fix was to move the normalisation step after the' },
      { now: NOW },
    );
    const complete = computeEffectiveSalience(
      { ...NEUTRAL, salience: 1.0, content: 'The fix was to move the normalisation step after the API filter.' },
      { now: NOW },
    );
    expect(dangling).toBeLessThan(complete);
  });

  it('does NOT penalise a complete capture that legitimately starts with a lowercase command/identifier', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    // "npm" / "git" / a backticked identifier are content words, not function
    // words — a complete note may open with one. No false-positive penalty.
    const base = { ...NEUTRAL, salience: 1.0 };
    const cmd = computeEffectiveSalience({ ...base, content: 'npm run build-release rebuilds the native binding in the install dir.' }, { now: NOW });
    const code = computeEffectiveSalience({ ...base, content: '`email_reply.send_reply(message_id, body)` is the canonical reply path.' }, { now: NOW });
    const reference = computeEffectiveSalience({ ...base, content: 'PostgreSQL chosen for JSONB support.' }, { now: NOW });
    expect(cmd).toBeCloseTo(reference, 5);
    expect(code).toBeCloseTo(reference, 5);
  });

  it('completeness defaults to neutral (1.0) when no content is provided — back-compat with v4.25 callers', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    // recency=1, access=1, pin=1, dv=1, completeness=1 → base
    const score = computeEffectiveSalience({ ...NEUTRAL, salience: 0.5 }, { now: NOW });
    expect(score).toBeCloseTo(0.5, 3);
  });

  it('fragment penalty only re-ranks, never zeroes (factor > 0)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const frag = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: 'the resources this year.' }, { now: NOW });
    expect(frag).toBeGreaterThan(0);
  });

  it('fragmentFactor is env/opts-tunable like the other constants', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const frag = { ...NEUTRAL, salience: 1.0, content: 'the resources this year.' };
    const half = computeEffectiveSalience(frag, { now: NOW, fragmentFactor: 0.5 });
    const tenth = computeEffectiveSalience(frag, { now: NOW, fragmentFactor: 0.1 });
    expect(tenth).toBeLessThan(half);
    // complete content ignores the knob entirely
    const complete = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: 'PostgreSQL chosen for JSONB.' }, { now: NOW, fragmentFactor: 0.1 });
    const completeDefault = computeEffectiveSalience({ ...NEUTRAL, salience: 1.0, content: 'PostgreSQL chosen for JSONB.' }, { now: NOW });
    expect(complete).toBeCloseTo(completeDefault, 5);
  });
});
