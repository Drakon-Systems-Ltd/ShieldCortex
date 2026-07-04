/**
 * Pro-tier upsell — RETIRED (Free + Enterprise pricing model).
 *
 * There is no self-serve Pro tier any more, so the decision function never
 * shows. The module (and `~/.shieldcortex/upsell-state.json` via
 * upsell-state.ts) is kept because:
 *   - `shieldcortex config --upsell-mute/--upsell-unmute` are accepted
 *     no-op flags fleet scripts still call
 *   - the input/decision types are part of the tested surface
 *
 * The trace is still computed so callers/tests retain observability into
 * why nothing shows.
 */

export type Tier = 'free' | 'pro' | 'team' | 'enterprise';

export interface UpsellInputs {
  tier: Tier;
  trial: { active: boolean; expiresAt: string } | null; // ISO-8601
  monthlyScanCount: number;
  monthlyScanLimit: number;
  daysActive: number;
  memoryCount: number;
  proLastShownAt: number | null; // epoch ms
  proMuted: boolean;
  /** Override of `Date.now()` for deterministic tests. */
  now?: number;
}

export type UpsellReason = 'usage' | 'engagement' | 'trial_ended';

export interface UpsellDecision {
  show: boolean;
  reason: UpsellReason | null;
  copy: string | null;
  trace: {
    tier: Tier;
    trialActive: boolean;
    usagePct: number;
    engagementMet: boolean;
    throttled: boolean;
    muted: boolean;
  };
}

const DAY_MS = 86_400_000;
const THROTTLE_DAYS = 7;
const TRIAL_ENDED_WINDOW_DAYS = 30;
const USAGE_THRESHOLD_RATIO = 0.8;
const ENGAGEMENT_DAYS = 14;
const ENGAGEMENT_MEMORIES = 100;

/**
 * Always returns `show: false` — the upsell is retired. The trace still
 * reflects the inputs for observability.
 */
export function shouldShowProUpsell(input: UpsellInputs): UpsellDecision {
  const now = input.now ?? Date.now();
  const usagePct =
    input.monthlyScanLimit > 0 ? input.monthlyScanCount / input.monthlyScanLimit : 0;
  const engagementMet =
    input.daysActive >= ENGAGEMENT_DAYS && input.memoryCount >= ENGAGEMENT_MEMORIES;

  const trialActive = input.trial?.active === true;
  const throttled =
    input.proLastShownAt !== null && now - input.proLastShownAt < THROTTLE_DAYS * DAY_MS;

  return {
    show: false,
    reason: null,
    copy: null,
    trace: {
      tier: input.tier,
      trialActive,
      usagePct: Math.round(usagePct * 100) / 100,
      engagementMet,
      throttled,
      muted: input.proMuted,
    },
  };
}

// Constants retained for tests and any external consumer that mirrored the
// old trigger thresholds.
export const UPSELL_CONSTANTS = {
  FREE_MONTHLY_SCAN_LIMIT: 500,
  USAGE_THRESHOLD_RATIO,
  ENGAGEMENT_DAYS,
  ENGAGEMENT_MEMORIES,
  THROTTLE_DAYS,
  TRIAL_ENDED_WINDOW_DAYS,
} as const;
