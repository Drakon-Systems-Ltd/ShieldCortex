import { describe, expect, it } from '@jest/globals';
import { shouldShowProUpsell, UPSELL_CONSTANTS, type UpsellInputs } from '../cli/upsell.js';

/**
 * Pro-tier upsell trigger — pure-function unit tests.
 *
 * Three triggers (priority order): trial_ended → usage → engagement. All
 * gated on `tier === 'free'` and not throttled / muted.
 */
describe('shouldShowProUpsell', () => {
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

  // ── Gates (never-show paths) ───────────────────────────────────────

  it.each(['pro', 'team', 'enterprise'] as const)(
    'never shows on tier=%s (paying users)',
    (tier) => {
      const r = shouldShowProUpsell(baseInput({ tier, monthlyScanCount: 9999 }));
      expect(r.show).toBe(false);
      expect(r.reason).toBeNull();
    },
  );

  it('never shows when muted, even with a strong trigger', () => {
    const r = shouldShowProUpsell(baseInput({ proMuted: true, monthlyScanCount: 500 }));
    expect(r.show).toBe(false);
    expect(r.trace.muted).toBe(true);
  });

  it('suppresses when shown within the throttle window (7 days)', () => {
    const r = shouldShowProUpsell(
      baseInput({
        monthlyScanCount: 500,
        proLastShownAt: NOW - 3 * DAY_MS, // 3 days ago — inside window
      }),
    );
    expect(r.show).toBe(false);
    expect(r.trace.throttled).toBe(true);
  });

  it('shows again after the throttle window expires', () => {
    const r = shouldShowProUpsell(
      baseInput({
        monthlyScanCount: 500,
        proLastShownAt: NOW - 8 * DAY_MS, // 8 days ago — outside window
      }),
    );
    expect(r.show).toBe(true);
    expect(r.trace.throttled).toBe(false);
  });

  // ── Trigger: trial_ended ───────────────────────────────────────────

  it('fires trial_ended when trial expired within the last 30 days', () => {
    const expiresAt = new Date(NOW - 1 * DAY_MS).toISOString();
    const r = shouldShowProUpsell(
      baseInput({ trial: { active: false, expiresAt } }),
    );
    expect(r.show).toBe(true);
    expect(r.reason).toBe('trial_ended');
    expect(r.copy).toMatch(/trial ended 1 day ago/);
    expect(r.copy).toContain(expiresAt.slice(0, 10));
  });

  it('does NOT fire trial_ended for a trial that expired >30 days ago', () => {
    const expiresAt = new Date(NOW - 31 * DAY_MS).toISOString();
    const r = shouldShowProUpsell(
      baseInput({ trial: { active: false, expiresAt } }),
    );
    expect(r.show).toBe(false);
  });

  it('does NOT fire trial_ended while trial is still active (gated upstream by tier check too)', () => {
    const expiresAt = new Date(NOW + 5 * DAY_MS).toISOString();
    // An active trial means the user's effective tier is 'pro' upstream; this
    // test pins that even if 'free' is passed (defensive), an active trial
    // shouldn't be reported as "ended".
    const r = shouldShowProUpsell(
      baseInput({ trial: { active: true, expiresAt }, monthlyScanCount: 0 }),
    );
    expect(r.show).toBe(false);
  });

  // ── Trigger: usage ─────────────────────────────────────────────────

  it('fires usage trigger at exactly 80% of the monthly limit', () => {
    const r = shouldShowProUpsell(baseInput({ monthlyScanCount: 400 }));
    expect(r.show).toBe(true);
    expect(r.reason).toBe('usage');
    expect(r.copy).toMatch(/400\/500/);
    expect(r.copy).toMatch(/about 80% of the cap/);
  });

  it('does not fire usage trigger at 79% (just below threshold)', () => {
    const r = shouldShowProUpsell(baseInput({ monthlyScanCount: 395 }));
    expect(r.show).toBe(false);
    expect(r.trace.usagePct).toBe(0.79);
  });

  // ── Trigger: engagement ────────────────────────────────────────────

  it('fires engagement trigger at 14 days + 100 memories', () => {
    const r = shouldShowProUpsell(baseInput({ daysActive: 14, memoryCount: 100 }));
    expect(r.show).toBe(true);
    expect(r.reason).toBe('engagement');
    expect(r.copy).toMatch(/ShieldCortex 14 days with 100 memories/);
  });

  it('does NOT fire engagement at 13 days (just under)', () => {
    const r = shouldShowProUpsell(baseInput({ daysActive: 13, memoryCount: 500 }));
    expect(r.show).toBe(false);
  });

  it('does NOT fire engagement at 99 memories (just under)', () => {
    const r = shouldShowProUpsell(baseInput({ daysActive: 30, memoryCount: 99 }));
    expect(r.show).toBe(false);
  });

  // ── Priority: trial_ended beats usage when both qualify ────────────

  it('prioritises trial_ended over usage when both triggers fire', () => {
    const expiresAt = new Date(NOW - 1 * DAY_MS).toISOString();
    const r = shouldShowProUpsell(
      baseInput({
        trial: { active: false, expiresAt },
        monthlyScanCount: 500,
      }),
    );
    expect(r.show).toBe(true);
    expect(r.reason).toBe('trial_ended');
  });

  // ── Copy invariants ────────────────────────────────────────────────

  it('every shown copy includes the same 3 numbered steps + mute hint', () => {
    const triggers: Partial<UpsellInputs>[] = [
      { monthlyScanCount: 500 },
      { daysActive: 30, memoryCount: 200 },
      { trial: { active: false, expiresAt: new Date(NOW - 5 * DAY_MS).toISOString() } },
    ];
    for (const t of triggers) {
      const r = shouldShowProUpsell(baseInput(t));
      expect(r.show).toBe(true);
      expect(r.copy).toMatch(/1\.\s+npx shieldcortex login/);
      expect(r.copy).toMatch(/2\.\s+Visit shieldcortex\.ai\/pricing/);
      expect(r.copy).toMatch(/3\.\s+Done — your existing API key auto-upgrades/);
      expect(r.copy).toMatch(/Mute: npx shieldcortex config --upsell-mute/);
      expect(r.copy).toMatch(/ShieldCortex Pro — £29\/mo/);
    }
  });
});
