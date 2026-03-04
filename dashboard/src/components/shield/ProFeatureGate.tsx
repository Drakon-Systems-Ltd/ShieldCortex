'use client';

import { Lock, ExternalLink } from 'lucide-react';
import { useLicenseStatus } from '@/hooks/useLicense';
import { TIER_LABELS } from '@/lib/license';
import type { GatedFeature } from '@/lib/license';

interface ProFeatureGateProps {
  /** The feature key to check */
  feature: GatedFeature;
  /** Content to render when the feature is unlocked */
  children: React.ReactNode;
  /** Optional short label for what this feature does */
  label?: string;
}

/**
 * Wraps content that requires a paid licence.
 * If the feature is enabled, renders children normally.
 * If not, shows a lock overlay with upgrade prompt.
 */
export function ProFeatureGate({ feature, children, label }: ProFeatureGateProps) {
  const { data: license } = useLicenseStatus();

  // While loading, render children (avoids flash of lock state)
  if (!license) return <>{children}</>;

  const featureInfo = license.features.find(f => f.feature === feature);
  if (!featureInfo || featureInfo.enabled) return <>{children}</>;

  const requiredTier = featureInfo.requiredTier;

  return (
    <div className="relative">
      {/* Blurred content behind the gate */}
      <div className="pointer-events-none select-none opacity-30 blur-[2px]">
        {children}
      </div>

      {/* Lock overlay */}
      <div className="absolute inset-0 flex flex-col items-center justify-center bg-slate-900/60 rounded-xl backdrop-blur-sm">
        <Lock size={24} className="text-slate-500 mb-2" />
        <p className="text-sm font-medium text-slate-300 mb-1">
          {TIER_LABELS[requiredTier]} Feature
        </p>
        {label && (
          <p className="text-xs text-slate-500 mb-3 text-center max-w-xs">
            {label}
          </p>
        )}
        <a
          href="https://shieldcortex.ai/pricing"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 px-4 py-2 text-xs bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors"
        >
          Upgrade to {TIER_LABELS[requiredTier]}
          <ExternalLink size={10} />
        </a>
      </div>
    </div>
  );
}
