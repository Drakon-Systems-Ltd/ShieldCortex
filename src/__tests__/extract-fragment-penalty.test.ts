import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs hook utility (no type decls)
import { completenessAdjustment, processSegments } from '../../scripts/lib/extract-memorable-segments.mjs';

/**
 * Jarvis P2 (2026-06-08): the 0.6 auto-extract cap bounds salience but adds no
 * QUALITY signal, so a truncated/mid-clause fragment competes on equal footing
 * with a complete, self-contained fact (and out-ranks lower-scored complete
 * facts). His ask: "penalise incomplete/fragmentary captures; reward
 * self-contained, high-signal facts. Keep existing decay/tests intact."
 *
 * completenessAdjustment is the pure, testable signal; processSegments folds it
 * into the score so a complete capture out-scores an otherwise-identical
 * fragment.
 */
describe('fragment-quality salience penalty', () => {
  it('gives a complete sentence no penalty', () => {
    expect(completenessAdjustment('We decided to use Postgres for JSON support.')).toBe(0);
    expect(completenessAdjustment('Why did the build break?')).toBe(0);
    expect(completenessAdjustment('Ship it now!')).toBe(0);
    // Trailing closing quote/paren after the terminator still counts as complete.
    expect(completenessAdjustment('He said "do it now."')).toBe(0);
  });

  it('penalises a mid-clause fragment with no terminator', () => {
    expect(completenessAdjustment('We decided to use Postgres for JSON support and')).toBeLessThan(0);
    expect(completenessAdjustment('arms only if')).toBeLessThan(0);
  });

  it('a complete capture out-scores an otherwise-identical fragment in processSegments', () => {
    const mk = (content: string) => [
      { title: 'Decision: ' + content.slice(0, 40), content, extractorType: 'decision' },
    ];
    // Parallel content, same keywords — the ONLY difference is the terminator.
    const complete = processSegments(
      mk('We decided to adopt structured logging across every service in the platform.'),
      0.1,
      { applyFrequencyBoost: false },
    );
    const fragment = processSegments(
      mk('We decided to adopt structured logging across every service in the platform without'),
      0.1,
      { applyFrequencyBoost: false },
    );
    expect(complete).toHaveLength(1);
    expect(fragment).toHaveLength(1);
    expect(complete[0].salience).toBeGreaterThan(fragment[0].salience);
  });
});
