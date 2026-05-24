import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs hook utility
import { calculateSalience, AUTO_EXTRACT_SALIENCE_CAP } from '../../scripts/lib/extract-memorable-segments.mjs';

/**
 * Regression guard for the v4.22.0 salience-cap fix.
 *
 * Pre-v4.22.0 `calculateSalience()` (the auto-extract one in
 * scripts/lib/extract-memorable-segments.mjs) stacked keyword bonuses to
 * ~1.85 pre-cap and clamped at 1.0. A downstream cap at line 558 of the
 * same file kept the FINAL stored salience at 0.6, but the function itself
 * returned 1.0 — fragile if callers consume the return value directly.
 *
 * v4.22.0 adds an `autoExtractMode` option that caps the return value at
 * `AUTO_EXTRACT_SALIENCE_CAP` (0.6) directly, so the safety-in-depth holds
 * even when the downstream cap is removed or bypassed.
 */
describe('extract-memorable-segments — calculateSalience cap (v4.22.0)', () => {
  const KITCHEN_SINK = [
    'IMPORTANT: this is a critical architecture decision.',
    'We chose to refactor the auth bug fix using a new pattern.',
    'For future reference: always use `src/auth/index.ts` (line 42).',
  ].join(' ');

  it('AUTO_EXTRACT_SALIENCE_CAP is exported and equals 0.6', () => {
    expect(AUTO_EXTRACT_SALIENCE_CAP).toBe(0.6);
  });

  it('default mode (no autoExtractMode flag) caps at 1.0 for backward compatibility', () => {
    const score = calculateSalience(KITCHEN_SINK);
    expect(score).toBeGreaterThan(0.6);
    expect(score).toBeLessThanOrEqual(1.0);
  });

  it('autoExtractMode=true caps at AUTO_EXTRACT_SALIENCE_CAP regardless of keyword stacking', () => {
    const score = calculateSalience(KITCHEN_SINK, { autoExtractMode: true });
    expect(score).toBeLessThanOrEqual(AUTO_EXTRACT_SALIENCE_CAP);
    // And it should still reach the cap when many signals stack — i.e. it
    // doesn't suppress the score, just bounds it
    expect(score).toBe(AUTO_EXTRACT_SALIENCE_CAP);
  });

  it('autoExtractMode=true returns the same low score for low-signal text (cap only bounds upward)', () => {
    const lowSignal = 'unrelated chatter with no specific markers at all';
    const defaultScore = calculateSalience(lowSignal);
    const cappedScore = calculateSalience(lowSignal, { autoExtractMode: true });
    expect(cappedScore).toBe(defaultScore);
  });

  it('autoExtractMode=false (explicit) behaves identically to default mode', () => {
    const score1 = calculateSalience(KITCHEN_SINK);
    const score2 = calculateSalience(KITCHEN_SINK, { autoExtractMode: false });
    expect(score2).toBe(score1);
  });
});
