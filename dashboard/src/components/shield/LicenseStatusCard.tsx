'use client';

import { useState } from 'react';
import { Shield, Key, CheckCircle2, XCircle, Loader2, ExternalLink, Sparkles, Lock, ChevronDown, ChevronUp } from 'lucide-react';
import { useLicenseStatus, useActivateLicense, useDeactivateLicense } from '@/hooks/useLicense';
import { TIER_LABELS, TIER_COLOURS, TIER_BG } from '@/lib/license';

/** Pro features shown in the free-tier CTA — short, punchy descriptions */
const PRO_HIGHLIGHTS = [
  'Custom injection patterns',
  'Custom Iron Dome policies',
  'Custom firewall rules',
  'Audit export (JSON/CSV)',
  'Skill scanner deep mode',
];

export function LicenseStatusCard() {
  const { data: license, isLoading } = useLicenseStatus();
  const activateMutation = useActivateLicense();
  const deactivateMutation = useDeactivateLicense();
  const [keyInput, setKeyInput] = useState('');
  const [showActivate, setShowActivate] = useState(false);
  const [showFeatures, setShowFeatures] = useState(false);

  if (isLoading || !license) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-4">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-slate-500" />
          <span className="text-xs text-slate-500 animate-pulse">Loading licence...</span>
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
    if (!confirm(`Remove your ${TIER_LABELS[tier]} licence key? You will lose access to paid features.`)) return;
    deactivateMutation.mutate();
  };

  // ── Free tier: prominent upgrade banner ──
  if (!isPaid) {
    return (
      <div className="relative overflow-hidden rounded-xl mb-4 bg-gradient-to-br from-slate-900 via-slate-900 to-cyan-950/30 border border-cyan-700/30">
        {/* Subtle glow accent */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 rounded-full blur-2xl -translate-y-1/2 translate-x-1/2" />

        <div className="relative p-5">
          {/* Header row */}
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                <Sparkles size={16} className="text-cyan-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">Unlock Pro Features</h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Your defence pipeline is fully active. Upgrade for advanced controls.
                </p>
              </div>
            </div>
            <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
              Free
            </span>
          </div>

          {/* Pro feature highlights */}
          <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 mb-4">
            {PRO_HIGHLIGHTS.map((feature) => (
              <div key={feature} className="flex items-center gap-1.5 text-xs">
                <Lock size={10} className="text-cyan-500/60 shrink-0" />
                <span className="text-slate-400">{feature}</span>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-3">
            {!showActivate ? (
              <>
                <a
                  href="https://shieldcortex.ai/pricing"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
                >
                  View Plans
                  <ExternalLink size={11} />
                </a>
                <button
                  onClick={() => setShowActivate(true)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors border border-slate-700"
                >
                  <Key size={12} />
                  I Have a Key
                </button>
              </>
            ) : (
              <form onSubmit={handleActivate} className="flex-1 flex gap-2">
                <input
                  type="text"
                  placeholder="sc_pro_..."
                  value={keyInput}
                  onChange={(e) => setKeyInput(e.target.value)}
                  className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  autoFocus
                />
                <button
                  type="submit"
                  disabled={activateMutation.isPending || !keyInput.trim()}
                  className="px-4 py-2 text-xs font-medium bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg transition-colors"
                >
                  {activateMutation.isPending ? <Loader2 size={12} className="animate-spin" /> : 'Activate'}
                </button>
                <button
                  type="button"
                  onClick={() => { setShowActivate(false); setKeyInput(''); activateMutation.reset(); }}
                  className="px-3 py-2 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                >
                  Cancel
                </button>
              </form>
            )}
          </div>

          {/* CLI hint */}
          <p className="mt-3 text-[10px] text-slate-600">
            Or via CLI: <code className="text-slate-500 bg-slate-800/50 px-1 py-0.5 rounded">shieldcortex license activate sc_pro_...</code>
          </p>

          {/* Error */}
          {activateMutation.isError && (
            <p className="mt-2 text-xs text-red-400">
              {activateMutation.error instanceof Error ? activateMutation.error.message : 'Activation failed'}
            </p>
          )}
        </div>
      </div>
    );
  }

  // ── Paid tier: compact status card ──
  const enabledCount = license.features.filter(f => f.enabled).length;
  const totalCount = license.features.length;

  return (
    <div className="bg-slate-900 border border-cyan-800/40 rounded-xl p-4 mb-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Shield size={16} className={TIER_COLOURS[tier]} />
          <h3 className="text-sm font-medium text-slate-300">Licence</h3>
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${TIER_COLOURS[tier]} ${TIER_BG[tier]}`}>
            {TIER_LABELS[tier]}
          </span>
        </div>
        <span className="text-[10px] text-slate-500">
          {enabledCount}/{totalCount} features
        </span>
      </div>

      {/* Licence details */}
      <div className="space-y-2 mb-3">
        {license.email && (
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-500">Email</span>
            <span className="text-slate-300">{license.email}</span>
          </div>
        )}
        {license.daysUntilExpiry !== null && (
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-500">Expires</span>
            <span className={license.daysUntilExpiry <= 7 ? 'text-yellow-400' : 'text-slate-300'}>
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
        className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-slate-300 transition-colors mb-2"
      >
        {showFeatures ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        {showFeatures ? 'Hide features' : 'Show features'}
      </button>

      {showFeatures && (
        <div className="space-y-1.5 mb-3">
          {license.features.map((f) => (
            <div key={f.feature} className="flex items-center gap-2 text-xs">
              {f.enabled ? (
                <CheckCircle2 size={12} className="text-emerald-400 shrink-0" />
              ) : (
                <XCircle size={12} className="text-slate-600 shrink-0" />
              )}
              <span className={f.enabled ? 'text-slate-300' : 'text-slate-600'}>
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
        className="text-[10px] text-slate-600 hover:text-red-400 transition-colors"
      >
        Deactivate
      </button>
    </div>
  );
}
