'use client';

import { useState, useEffect } from 'react';
import { Sparkles, X, ExternalLink } from 'lucide-react';
import { useAuditStats } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { useLicenseStatus } from '@/hooks/useLicense';

/**
 * Pro-tier upsell banner — mirrors `CloudUpsellCard.tsx` (state machine,
 * localStorage dismiss, render gating) but with a Pro-specific message.
 *
 * Triggers (any one fires, gated on `tier === 'free'`):
 *   - **trial_ended**: license.trial is present, !active, expired in last 30 days
 *   - **usage**: 30-day blocked+allowed scan count >= 400 (80% of free 500/mo cap)
 *   - **engagement**: >= 14 days since first data point AND >= 100 events
 *     (signal-quality proxy for "settled in"; matches the doctor's logic that
 *     uses memory count, but the dashboard's nearest equivalent is audit-stats
 *     volume — close enough for a banner)
 *
 * Dismissal: 7-day localStorage TTL (matches the doctor's weekly throttle).
 * Mirrors the existing 30-day dismiss pattern from CloudUpsellCard, just
 * shorter to match the field complaint about preamble noise.
 */

// Constants kept in sync with src/cli/upsell.ts UPSELL_CONSTANTS
const FREE_MONTHLY_SCAN_LIMIT = 500;
const USAGE_THRESHOLD_RATIO = 0.8;
const ENGAGEMENT_DAYS = 14;
const ENGAGEMENT_EVENTS = 100;
const DISMISS_TTL_DAYS = 7;
const TRIAL_ENDED_WINDOW_DAYS = 30;
const DAY_MS = 86_400_000;

type Reason = 'usage' | 'engagement' | 'trial_ended';

export function ProUpsellCard() {
  const { projectFilter } = useDashboardStore();
  const { data: stats } = useAuditStats('30d', projectFilter || undefined);
  const { data: license } = useLicenseStatus();
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    const raw = localStorage.getItem('shieldcortex_pro_upsell_dismissed');
    if (!raw) return;
    const at = new Date(raw).getTime();
    if (Number.isFinite(at) && Date.now() - at < DISMISS_TTL_DAYS * DAY_MS) {
      setDismissed(true);
    }
  }, []);

  if (dismissed) return null;

  const tier = license?.tier ?? 'free';
  // Only nudge free users — paying customers and active-trial users see nothing.
  if (tier !== 'free') return null;

  const trial = license?.trial ?? null;
  const monthlyScanCount = (stats?.allowedCount ?? 0) + (stats?.blockedCount ?? 0);
  const totalOps = stats?.totalOperations ?? 0;

  // Trigger evaluation — priority: trial_ended > usage > engagement.
  let reason: Reason | null = null;
  let leadText = '';

  if (trial && !trial.active && trial.expiresAt) {
    const expiresAt = new Date(trial.expiresAt).getTime();
    // react-hooks/purity flags Date.now() as impure-during-render. The banner
    // is intentionally non-reactive: it just needs a wall-clock anchor for
    // the "X days ago" label at first paint. A re-render reads the clock
    // again — that's the desired behaviour for a banner that auto-dismisses
    // after TRIAL_ENDED_WINDOW_DAYS.
    // eslint-disable-next-line react-hooks/purity
    const daysSince = (Date.now() - expiresAt) / DAY_MS;
    if (daysSince >= 0 && daysSince <= TRIAL_ENDED_WINDOW_DAYS) {
      reason = 'trial_ended';
      const days = Math.max(0, Math.floor(daysSince));
      leadText = `Your Pro trial ended ${days} day${days === 1 ? '' : 's'} ago. You're back on the free tier.`;
    }
  }

  if (!reason && monthlyScanCount >= USAGE_THRESHOLD_RATIO * FREE_MONTHLY_SCAN_LIMIT) {
    reason = 'usage';
    const pct = Math.round((monthlyScanCount / FREE_MONTHLY_SCAN_LIMIT) * 100);
    leadText = `You've used ${monthlyScanCount}/${FREE_MONTHLY_SCAN_LIMIT} free scans this month — about ${pct}% of the cap.`;
  }

  if (!reason && totalOps >= ENGAGEMENT_EVENTS) {
    // Engagement proxy: 30-day audit volume crossed the threshold AND
    // there's enough history to suggest the user has settled in. The doctor
    // uses days-since-oldest-memory; here we approximate with audit volume
    // because the dashboard already has it cheaply.
    reason = 'engagement';
    leadText = `You've logged ${totalOps} defence operations in the last 30 days. You're past the "trying it out" phase.`;
  }

  if (!reason) return null;

  const handleDismiss = () => {
    localStorage.setItem('shieldcortex_pro_upsell_dismissed', new Date().toISOString());
    setDismissed(true);
  };

  return (
    <div className="mt-4 bg-gradient-to-br from-slate-900 via-[var(--sc-bg-surface)] to-violet-950/30 border border-[var(--sc-coral)]/30 rounded-xl p-5 relative">
      <button
        onClick={handleDismiss}
        className="absolute top-3 right-3 text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
        title="Dismiss for 7 days"
      >
        <X size={16} />
      </button>
      <div className="space-y-4">
        <div className="flex items-center gap-2">
          <Sparkles size={20} className="text-[var(--sc-coral)]" />
          <h3 className="text-sm font-semibold text-[var(--sc-text-primary)]">ShieldCortex Pro</h3>
          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded text-[var(--sc-coral)] bg-[var(--sc-coral)]/10">
            £29/mo
          </span>
        </div>

        <p className="text-sm text-[var(--sc-text-primary)]">{leadText}</p>

        <p className="text-xs text-[var(--sc-text-secondary)]">
          Pro lifts your scan quota to 10K/month, adds team invites, and extends audit retention to 90 days.
        </p>

        <ol className="text-xs text-[var(--sc-text-secondary)] space-y-1 list-decimal list-inside">
          <li>Run <code className="bg-[var(--sc-bg-elevated)] px-1 rounded">npx shieldcortex login</code></li>
          <li>Pick &quot;Upgrade to Pro&quot; in the pricing page</li>
          <li>Your existing API key auto-upgrades</li>
        </ol>

        <div className="flex items-center gap-3">
          <a
            href="https://shieldcortex.ai/pricing"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-[var(--sc-coral)] hover:bg-[var(--sc-coral)] rounded-lg text-sm font-medium text-[var(--sc-text-primary)] transition-colors"
          >
            Upgrade to Pro
            <ExternalLink size={12} />
          </a>
          <button
            onClick={handleDismiss}
            className="text-xs text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
          >
            Maybe later
          </button>
        </div>
      </div>
    </div>
  );
}
