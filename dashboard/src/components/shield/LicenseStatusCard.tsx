'use client';

import { useState } from 'react';
import { Shield, Key, CheckCircle2, XCircle, Loader2, Sparkles, Lock, ChevronDown, ChevronUp } from 'lucide-react';
import { useLicenseStatus, useActivateLicense, useDeactivateLicense } from '@/hooks/useLicense';
import { useBillingSetup } from '@/hooks/useBillingSetup';
import { TIER_LABELS, TIER_COLOURS, TIER_BG, PLAN_PRICING } from '@/lib/license';

/** Pro features shown in the free-tier CTA — short, punchy descriptions */
const PRO_HIGHLIGHTS = [
  'Custom injection patterns',
  'Custom Iron Dome policies',
  'Custom firewall rules',
  'Audit export (JSON/CSV)',
  'Skill scanner deep mode',
];

type UpgradeView = 'default' | 'checkout' | 'activate';

export function LicenseStatusCard() {
  const { data: license, isLoading } = useLicenseStatus();
  const activateMutation = useActivateLicense();
  const deactivateMutation = useDeactivateLicense();
  const billing = useBillingSetup();
  const [keyInput, setKeyInput] = useState('');
  const [upgradeView, setUpgradeView] = useState<UpgradeView>('default');
  const [email, setEmail] = useState('');
  const [plan, setPlan] = useState<'pro' | 'team'>('pro');
  const [showFeatures, setShowFeatures] = useState(false);

  if (isLoading || !license) {
    return (
      <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4 mb-4">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-[var(--sc-text-muted)]" />
          <span className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading licence...</span>
        </div>
      </div>
    );
  }

  const tier = license.tier;
  const isPaid = tier !== 'free';

  const handleActivate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyInput.trim()) return;
    activateMutation.mutate(keyInput.trim(), {
      onSuccess: () => {
        setKeyInput('');
        setUpgradeView('default');
      },
    });
  };

  const handleDeactivate = () => {
    if (!confirm(`Remove your ${TIER_LABELS[tier]} licence key? You will lose access to paid features.`)) return;
    deactivateMutation.mutate();
  };

  // ── Free tier: prominent upgrade banner ──
  if (!isPaid) {
    return (
      <div className="relative overflow-hidden rounded-xl mb-4 bg-gradient-to-br from-slate-900 via-[var(--sc-bg-surface)] to-cyan-950/30 border border-[var(--sc-cyan)]/30">
        {/* Subtle glow accent */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-[var(--sc-cyan)]/5 rounded-full blur-2xl -translate-y-1/2 translate-x-1/2" />

        <div className="relative p-5">
          {/* Header row */}
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-[var(--sc-cyan)]/10 border border-[var(--sc-cyan)]/20">
                <Sparkles size={16} className="text-[var(--sc-cyan)]" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-[var(--sc-text-primary)]">Unlock Pro Features</h3>
                <p className="text-[11px] text-[var(--sc-text-secondary)] mt-0.5">
                  Your defence pipeline is fully active. Upgrade for advanced controls.
                </p>
              </div>
            </div>
            <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] border border-[var(--sc-border)]">
              Free
            </span>
          </div>

          {/* Pro feature highlights */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 mb-4">
            {PRO_HIGHLIGHTS.map((feature) => (
              <div key={feature} className="flex items-center gap-1.5 text-xs">
                <Lock size={10} className="text-[var(--sc-cyan)]/60 shrink-0" />
                <span className="text-[var(--sc-text-secondary)]">{feature}</span>
              </div>
            ))}
          </div>

          {/* Actions */}
          {billing.state === 'complete' ? (
            <div className="flex items-center gap-2 p-3 bg-[var(--sc-cyan)]/10 border border-[var(--sc-cyan)]/20 rounded-lg">
              <CheckCircle2 size={16} className="text-[var(--sc-cyan)] shrink-0" />
              <span className="text-xs text-[var(--sc-cyan)]">Pro activated! Your dashboard is refreshing...</span>
            </div>
          ) : billing.state === 'polling' || billing.state === 'activating' ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 p-3 bg-[var(--sc-cyan)]/10 border border-[var(--sc-cyan)]/20 rounded-lg">
                <Loader2 size={14} className="text-[var(--sc-cyan)] animate-spin shrink-0" />
                <span className="text-xs text-[var(--sc-cyan)]">
                  {billing.state === 'activating' ? 'Activating licence...' : 'Complete payment in the Stripe tab...'}
                </span>
              </div>
              <button
                onClick={() => { billing.reset(); setUpgradeView('default'); }}
                className="text-[10px] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
              >
                Cancel
              </button>
            </div>
          ) : upgradeView === 'checkout' ? (
            <div className="space-y-3">
              <div>
                <label className="text-[10px] text-[var(--sc-text-muted)] mb-1 block">Email</label>
                <input
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg px-3 py-2 text-xs text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-cyan)]"
                  autoFocus
                />
              </div>
              <div className="flex gap-2">
                {(['pro', 'team'] as const).map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setPlan(p)}
                    className={`flex-1 px-3 py-2 text-xs font-medium rounded-lg border transition-colors ${
                      plan === p
                        ? 'bg-[var(--sc-cyan)]/20 border-[var(--sc-cyan)]/50 text-[var(--sc-cyan)]'
                        : 'bg-[var(--sc-bg-elevated)] border-[var(--sc-border)] text-[var(--sc-text-secondary)] hover:border-[var(--sc-border)]'
                    }`}
                  >
                    {PLAN_PRICING[p].label} — {PLAN_PRICING[p].price}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => billing.startCheckout(email, plan)}
                  disabled={billing.state === 'submitting' || !email.trim()}
                  className="flex-1 inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan-mid)] disabled:opacity-50 text-[var(--sc-text-primary)] rounded-lg transition-colors"
                >
                  {billing.state === 'submitting' ? (
                    <Loader2 size={12} className="animate-spin" />
                  ) : (
                    'Continue to Checkout'
                  )}
                </button>
                <button
                  onClick={() => { setUpgradeView('default'); billing.reset(); }}
                  className="px-3 py-2 text-xs text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
                >
                  Back
                </button>
              </div>
              {billing.error && (
                <p className="text-xs text-[var(--sc-coral)]">{billing.error}</p>
              )}
            </div>
          ) : upgradeView === 'activate' ? (
            <div className="space-y-2">
              <form onSubmit={handleActivate} className="flex gap-2">
                <input
                  type="text"
                  placeholder="sc_pro_..."
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  className="flex-1 bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg px-3 py-2 text-xs text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-cyan)]"
                  autoFocus
                />
                <button
                  type="submit"
                  disabled={activateMutation.isPending || !keyInput.trim()}
                  className="px-4 py-2 text-xs font-medium bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan-mid)] disabled:opacity-50 text-[var(--sc-text-primary)] rounded-lg transition-colors"
                >
                  {activateMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : 'Activate'}
                </button>
                <button
                  type="button"
                  onClick={() => { setUpgradeView('default'); setKeyInput(''); activateMutation.reset(); }}
                  className="px-3 py-2 text-xs text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
                >
                  Back
                </button>
              </form>
              {activateMutation.isError && (
                <p className="text-xs text-[var(--sc-coral)]">
                  {activateMutation.error instanceof Error ? activateMutation.error.message : 'Activation failed'}
                </p>
              )}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => setUpgradeView('checkout')}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan-mid)] text-[var(--sc-text-primary)] rounded-lg transition-colors"
                >
                  Upgrade to Pro
                </button>
                <button
                  onClick={() => setUpgradeView('activate')}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-[var(--sc-bg-elevated)] hover:bg-[var(--sc-bg-elevated)] text-[var(--sc-text-primary)] rounded-lg transition-colors border border-[var(--sc-border)]"
                >
                  <Key size={12} />
                  I Have a Key
                </button>
              </div>
              {billing.error && (
                <div className="space-y-2">
                  <p className="text-xs text-[var(--sc-coral)]">{billing.error}</p>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => { billing.reset(); setUpgradeView('checkout'); }}
                      className="text-[10px] text-[var(--sc-cyan)] hover:text-[var(--sc-cyan)] transition-colors"
                    >
                      Try Again
                    </button>
                    <span className="text-[10px] text-[var(--sc-text-muted)]">·</span>
                    <button
                      onClick={() => { billing.reset(); setUpgradeView('activate'); }}
                      className="text-[10px] text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)] transition-colors"
                    >
                      I Have a Key
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  }

  // ── Paid tier: compact status card ──
  const enabledCount = license.features.filter(f => f.enabled).length;
  const totalCount = license.features.length;

  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-cyan)]/40 rounded-xl p-4 mb-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Shield size={16} className={TIER_COLOURS[tier]} />
          <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Licence</h3>
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${TIER_COLOURS[tier]} ${TIER_BG[tier]}`}>
            {TIER_LABELS[tier]}
          </span>
        </div>
        <span className="text-[10px] text-[var(--sc-text-muted)]">
          {enabledCount}/{totalCount} features
        </span>
      </div>

      {/* Licence details */}
      <div className="space-y-2 mb-3">
        {license.email && (
          <div className="flex items-center justify-between text-xs">
            <span className="text-[var(--sc-text-muted)]">Email</span>
            <span className="text-[var(--sc-text-primary)]">{license.email}</span>
          </div>
        )}
        {license.daysUntilExpiry !== null && (
          <div className="flex items-center justify-between text-xs">
            <span className="text-[var(--sc-text-muted)]">Expires</span>
            <span className={license.daysUntilExpiry <= 7 ? 'text-[var(--sc-amber)]' : 'text-[var(--sc-text-primary)]'}>
              {license.daysUntilExpiry <= 0
                ? 'Expired (grace period)'
                : `${license.daysUntilExpiry} days`}
            </span>
          </div>
        )}
      </div>

      {/* Feature list toggle */}
      <button
        onClick={() => setShowFeatures(!showFeatures)}
        className="flex items-center gap-1 text-[10px] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors mb-2"
      >
        {showFeatures ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {showFeatures ? 'Hide features' : 'Show features'}
      </button>

      {showFeatures && (
        <div className="space-y-1.5 mb-3">
          {license.features.map((f) => (
            <div key={f.feature} className="flex items-center gap-2 text-xs">
              {f.enabled ? (
                <CheckCircle2 size={12} className="text-[var(--sc-cyan)] shrink-0" />
              ) : (
                <XCircle size={12} className="text-[var(--sc-text-muted)] shrink-0" />
              )}
              <span className={f.enabled ? 'text-[var(--sc-text-primary)]' : 'text-[var(--sc-text-muted)]'}>
                {f.description.split('.')[0]}
              </span>
              {!f.enabled && (
                <span className={`text-[9px] px-1 py-0.5 rounded ${TIER_COLOURS[f.requiredTier]} ${TIER_BG[f.requiredTier]}`}>
                  {TIER_LABELS[f.requiredTier]}
                </span>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Deactivate */}
      <button
        onClick={handleDeactivate}
        disabled={deactivateMutation.isPending}
        className="text-[10px] text-[var(--sc-text-muted)] hover:text-[var(--sc-coral)] transition-colors"
      >
        Deactivate
      </button>
    </div>
  );
}
