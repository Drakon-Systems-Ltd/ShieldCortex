import { describe, expect, it } from '@jest/globals';
import { shouldShowProUpsell, UPSELL_CONSTANTS, type UpsellInputs } from '../cli/upsell.js';

/**
 * Pro-tier upsell — retired with the Free + Enterprise pricing model.
 *
 * There is no self-serve Pro tier to upsell to, so the decision function is
 * pinned to NEVER show, whatever the inputs. The module and its state file
 * stay (fleet scripts still call `config --upsell-mute/--upsell-unmute`),
 * but no copy is ever rendered.
 */
describe('shouldShowProUpsell (retired — never shows)', () => {
  const NOW = new Date('2026-05-25T12:00:00.000Z').getTime();
  const DAY_MS = 86_400_000;

  function baseInput(overrides: Partial<UpsellInputs> = {}): UpsellInputs {
    return {
      tier: 'free',
      trial: null,
      monthlyScanCount: 0,
      monthlyScanLimit: UPSELL_CONSTANTS.FREE_MONTHLY_SCAN_LIMIT,
      daysActive: 0,
      memoryCount: 0,
      proLastShownAt: null,
      proMuted: false,
      now: NOW,
      ...overrides,
    };
  }

  it.each(['free', 'pro', 'team', 'enterprise'] as const)(
    'never shows on tier=%s',
    (tier) => {
      const r = shouldShowProUpsell(baseInput({ tier, monthlyScanCount: 9999 }));
      expect(r.show).toBe(false);
      expect(r.reason).toBeNull();
      expect(r.copy).toBeNull();
    },
  );

  it('never shows on the old usage trigger (>=80% of the free quota)', () => {
    const r = shouldShowProUpsell(baseInput({ monthlyScanCount: 500 }));
    expect(r.show).toBe(false);
    expect(r.copy).toBeNull();
  });

  it('never shows on the old engagement trigger (14+ days, 100+ memories)', () => {
    const r = shouldShowProUpsell(baseInput({ daysActive: 30, memoryCount: 200 }));
    expect(r.show).toBe(false);
    expect(r.copy).toBeNull();
  });

  it('never shows on the old trial-ended trigger', () => {
    const expiresAt = new Date(NOW - 1 * DAY_MS).toISOString();
    const r = shouldShowProUpsell(baseInput({ trial: { active: false, expiresAt } }));
    expect(r.show).toBe(false);
    expect(r.copy).toBeNull();
  });

  it('never shows even when unmuted and outside any throttle window', () => {
    const r = shouldShowProUpsell(
      baseInput({
        monthlyScanCount: 500,
        proMuted: false,
        proLastShownAt: NOW - 365 * DAY_MS,
      }),
    );
    expect(r.show).toBe(false);
    expect(r.copy).toBeNull();
  });

  it('still returns a well-formed trace for observability', () => {
    const r = shouldShowProUpsell(baseInput({ monthlyScanCount: 400, proMuted: true }));
    expect(r.trace.tier).toBe('free');
    expect(r.trace.muted).toBe(true);
    expect(typeof r.trace.usagePct).toBe('number');
  });
});
