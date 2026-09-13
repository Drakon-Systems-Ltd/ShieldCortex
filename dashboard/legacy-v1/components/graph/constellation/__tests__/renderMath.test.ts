import { computeNodeRadius, computeLinkAlpha, computeLinkWidth } from '../renderMath.js';

describe('computeNodeRadius', () => {
  it('returns baseRadius when energy is 0', () => {
    expect(computeNodeRadius({ baseRadius: 6, energy: 0, breathAmp: 0.08 })).toBeCloseTo(6, 6);
  });

  it('scales by (1 + energy × breathAmp) — clamped to non-negative', () => {
    expect(computeNodeRadius({ baseRadius: 10, energy: 1, breathAmp: 0.08 })).toBeCloseTo(10.8, 6);
    expect(computeNodeRadius({ baseRadius: 10, energy: -1, breathAmp: 0.08 })).toBeCloseTo(9.2, 6);
    // Sun-strong (energy=1, breathAmp=0.14) → 10 × 1.14 = 11.4
    expect(computeNodeRadius({ baseRadius: 10, energy: 1, breathAmp: 0.14 })).toBeCloseTo(11.4, 6);
  });

  it('never returns negative or zero radius', () => {
    expect(computeNodeRadius({ baseRadius: 6, energy: -100, breathAmp: 0.5 })).toBeGreaterThan(0);
  });
});

describe('computeLinkAlpha', () => {
  it('returns 0.35 floor at zero energies', () => {
    expect(computeLinkAlpha(0, 0)).toBeCloseTo(0.35, 6);
  });

  it('saturates at 0.95 when either endpoint is at energy 1', () => {
    expect(computeLinkAlpha(1, 0)).toBeCloseTo(0.95, 6);
    expect(computeLinkAlpha(0, 1)).toBeCloseTo(0.95, 6);
    expect(computeLinkAlpha(1, 1)).toBeCloseTo(0.95, 6);
  });

  it('uses max of the two endpoint energies', () => {
    expect(computeLinkAlpha(0.2, 0.6)).toBeCloseTo(0.35 + 0.6 * 0.6, 6);
  });

  it('clamps alpha into [0, 1] even with out-of-range input', () => {
    expect(computeLinkAlpha(-1, -1)).toBeGreaterThanOrEqual(0);
    expect(computeLinkAlpha(5, 5)).toBeLessThanOrEqual(1);
  });
});

describe('computeLinkWidth', () => {
  it('returns 1.0 at zero energies and scales linearly to 1.8 at max', () => {
    expect(computeLinkWidth(0, 0)).toBeCloseTo(1.0, 6);
    expect(computeLinkWidth(1, 0)).toBeCloseTo(1.8, 6);
    expect(computeLinkWidth(0, 1)).toBeCloseTo(1.8, 6);
  });
});
