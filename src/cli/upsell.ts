/**
 * Pro-tier upsell — pure trigger logic.
 *
 * No I/O. Inputs are computed by the caller (doctor wires this in
 * src/cli/doctor.ts; the dashboard banner consumes the same constants via
 * dashboard/src/components/shield/ProUpsellCard.tsx).
 *
 * Three triggers, evaluated in priority order after gating on `tier === 'free'`:
 *   1. trial_ended  — `!trial.active && trial.expiresAt within last 30 days`
 *   2. usage        — monthly scan count ≥ 80% of free quota (= 400/500)
 *   3. engagement   — 14+ days active AND 100+ memories
 *
 * Throttle: skipped if shown within last 7 days. Mute: hard-off via
 * `~/.shieldcortex/upsell-state.json#proMuted`.
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

const STEPS = [
  '1.  npx shieldcortex login',
  '2.  Visit shieldcortex.ai/pricing → Upgrade to Pro',
  '3.  Done — your existing API key auto-upgrades.',
].join('\n  ');

const VALUE_LINE =
  'Pro lifts the limit to 10K scans/month, adds team invites, and 90-day\n' +
  '  audit retention.';

const MUTE_LINE = 'Mute: npx shieldcortex config --upsell-mute';

function render(leadLine: string): string {
  return [
    'ShieldCortex Pro — £29/mo',
    '',
    `  ${leadLine}`,
    `  ${VALUE_LINE}`,
    '',
    `  ${STEPS}`,
    '',
    `  ${MUTE_LINE}`,
  ].join('\n');
}

function leadFor(reason: UpsellReason, input: UpsellInputs): string {
  if (reason === 'usage') {
    const pct = Math.round((input.monthlyScanCount / input.monthlyScanLimit) * 100);
    return `You've used ${input.monthlyScanCount}/${input.monthlyScanLimit} free scans this month — about ${pct}% of the cap.`;
  }
  if (reason === 'engagement') {
    return `You've been on ShieldCortex ${input.daysActive} days with ${input.memoryCount} memories. You're past the "trying it out" phase.`;
  }
  // trial_ended
  const expiresAtMs = input.trial ? new Date(input.trial.expiresAt).getTime() : 0;
  const daysAgo = Math.max(0, Math.floor(((input.now ?? Date.now()) - expiresAtMs) / DAY_MS));
  const date = input.trial ? input.trial.expiresAt.slice(0, 10) : '';
  return `Your Pro trial ended ${daysAgo} day${daysAgo === 1 ? '' : 's'} ago (${date}). You're back on the free tier.`;
}

export function shouldShowProUpsell(input: UpsellInputs): UpsellDecision {
  const now = input.now ?? Date.now();
  const usagePct =
    input.monthlyScanLimit > 0 ? input.monthlyScanCount / input.monthlyScanLimit : 0;
  const engagementMet =
    input.daysActive >= ENGAGEMENT_DAYS && input.memoryCount >= ENGAGEMENT_MEMORIES;

  const trialActive = input.trial?.active === true;
  const throttled =
    input.proLastShownAt !== null && now - input.proLastShownAt < THROTTLE_DAYS * DAY_MS;

  const trace = {
    tier: input.tier,
    trialActive,
    usagePct: Math.round(usagePct * 100) / 100,
    engagementMet,
    throttled,
    muted: input.proMuted,
  };

  // Gate 1: tier must be 'free'. Anyone paying — or in active trial — sees nothing.
  if (input.tier !== 'free') {
    return { show: false, reason: null, copy: null, trace };
  }

  // Gate 2: hard mute.
  if (input.proMuted) {
    return { show: false, reason: null, copy: null, trace };
  }

  // Gate 3: throttle.
  if (throttled) {
    return { show: false, reason: null, copy: null, trace };
  }

  // Trial just ended — highest-priority reason. Window: 30 days post-expiry.
  if (input.trial && !input.trial.active && input.trial.expiresAt) {
    const expiresAtMs = new Date(input.trial.expiresAt).getTime();
    if (Number.isFinite(expiresAtMs)) {
      const daysSince = (now - expiresAtMs) / DAY_MS;
      if (daysSince >= 0 && daysSince <= TRIAL_ENDED_WINDOW_DAYS) {
        return {
          show: true,
          reason: 'trial_ended',
          copy: render(leadFor('trial_ended', input)),
          trace,
        };
      }
    }
  }

  // Usage threshold — 80% of the free monthly scan quota.
  if (usagePct >= USAGE_THRESHOLD_RATIO) {
    return {
      show: true,
      reason: 'usage',
      copy: render(leadFor('usage', input)),
      trace,
    };
  }

  // Engagement threshold — settled-in user.
  if (engagementMet) {
    return {
      show: true,
      reason: 'engagement',
      copy: render(leadFor('engagement', input)),
      trace,
    };
  }

  return { show: false, reason: null, copy: null, trace };
}

// Constants are re-exported so the dashboard (mirroring this logic in JSX) can
// stay in lockstep without duplicating magic numbers.
export const UPSELL_CONSTANTS = {
  FREE_MONTHLY_SCAN_LIMIT: 500,
  USAGE_THRESHOLD_RATIO,
  ENGAGEMENT_DAYS,
  ENGAGEMENT_MEMORIES,
  THROTTLE_DAYS,
  TRIAL_ENDED_WINDOW_DAYS,
} as const;
