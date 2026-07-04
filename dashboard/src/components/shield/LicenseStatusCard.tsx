'use client';

import { useState } from 'react';
import { Shield, Key, CheckCircle2, XCircle, Loader2, ChevronDown, ChevronUp } from 'lucide-react';
import { useLicenseStatus, useActivateLicense, useDeactivateLicense } from '@/hooks/useLicense';
import { TIER_LABELS, TIER_COLOURS, TIER_BG } from '@/lib/license';

export function LicenseStatusCard() {
  const { data: license, isLoading } = useLicenseStatus();
  const activateMutation = useActivateLicense();
  const deactivateMutation = useDeactivateLicense();
  const [keyInput, setKeyInput] = useState('');
  const [showActivate, setShowActivate] = useState(false);
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
        setShowActivate(false);
      },
    });
  };

  const handleDeactivate = () => {
    if (!confirm(`Remove your ${TIER_LABELS[tier]} licence key? You will lose access to licensed features.`)) return;
    deactivateMutation.mutate();
  };

  // ── Free tier: everything local is included; key activation for Enterprise/legacy keys ──
  if (!isPaid) {
    return (
      <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-5 mb-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-[var(--sc-cyan)]" />
            <h3 className="text-sm font-semibold text-[var(--sc-text-primary)]">Licence</h3>
          </div>
          <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] border border-[var(--sc-border)]">
            Free
          </span>
        </div>

        <p className="text-xs text-[var(--sc-text-secondary)] mb-4">
          Every local feature is included on the Free tier — custom patterns, policies, firewall
          rules, audit export, deep scanning, and Cortex. Enterprise adds cloud replication, team
          management, and shared patterns:{' '}
          <a href="mailto:sales@drakonsystems.com" className="text-[var(--sc-cyan)] hover:underline">
            sales@drakonsystems.com
          </a>
        </p>

        {showActivate ? (
          <div className="space-y-2">
            <form onSubmit={handleActivate} className="flex gap-2">
              <input
                type="text"
                placeholder="sc_ent_..."
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
                onClick={() => { setShowActivate(false); setKeyInput(''); activateMutation.reset(); }}
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
          <button
            type="button"
            onClick={() => setShowActivate(true)}
            className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-[var(--sc-bg-elevated)] hover:bg-[var(--sc-bg-elevated)] text-[var(--sc-text-primary)] rounded-lg transition-colors border border-[var(--sc-border)]"
          >
            <Key size={12} />
            I Have a Key
          </button>
        )}
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
