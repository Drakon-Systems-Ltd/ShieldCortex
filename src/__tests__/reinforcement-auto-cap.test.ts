import { describe, it, expect } from '@jest/globals';
import { calculateReinforcementBoost } from '../memory/decay.js';
import { DEFAULT_CONFIG, type Memory } from '../memory/types.js';

/**
 * Phase 1a (roadmap): cap the salience ratchet FORWARD-ONLY for auto-extracted
 * memories. Reinforcement-on-access is what drives auto-extracted captures (max
 * 0.6 at extraction) up to the 1.0 wall over time. Capping reinforcement at the
 * same 0.6 stops the wall growing AND lazily corrects a saturated legacy auto
 * row the next time it's accessed. Deliberate (manual/hook/api) captures stay
 * uncapped — a human saving something is allowed to be maximally salient.
 */
const mem = (over: Partial<Memory>): Memory =>
  ({ salience: 0.55, accessCount: 0, captureMethod: 'manual', ...over } as unknown as Memory);

describe('calculateReinforcementBoost — auto-extracted ratchet cap (0.6)', () => {
  it('an auto-extracted memory never reinforces above 0.6', () => {
    expect(calculateReinforcementBoost(mem({ captureMethod: 'auto', salience: 0.55 }), DEFAULT_CONFIG)).toBeLessThanOrEqual(0.6);
  });

  it('a saturated legacy auto memory (1.0) is corrected down to 0.6 on next access', () => {
    expect(calculateReinforcementBoost(mem({ captureMethod: 'auto', salience: 1.0 }), DEFAULT_CONFIG)).toBeCloseTo(0.6, 5);
  });

  it('a deliberate (manual) memory still reinforces above 0.6 toward 1.0', () => {
    expect(calculateReinforcementBoost(mem({ captureMethod: 'manual', salience: 0.9 }), DEFAULT_CONFIG)).toBeGreaterThan(0.6);
  });

  it('hook/plugin/api captures are not treated as auto (stay uncapped)', () => {
    for (const cm of ['hook', 'plugin', 'api'] as const) {
      expect(calculateReinforcementBoost(mem({ captureMethod: cm, salience: 0.9 }), DEFAULT_CONFIG)).toBeGreaterThan(0.6);
    }
  });

  it('still honours the global 1.0 ceiling for deliberate captures', () => {
    expect(calculateReinforcementBoost(mem({ captureMethod: 'manual', salience: 1.0 }), DEFAULT_CONFIG)).toBeLessThanOrEqual(1.0);
  });
});
