'use client';

import { Lock, ExternalLink } from 'lucide-react';
import { useLicenseStatus } from '@/hooks/useLicense';
import { TIER_LABELS } from '@/lib/license';
import { Button } from '@/components/ds/Button';
import type { GatedFeature } from '@/lib/license';

interface ProFeatureGateProps {
  feature: GatedFeature;
  children: React.ReactNode;
  label?: string;
}

export function ProFeatureGate({ feature, children, label }: ProFeatureGateProps) {
  const { data: license } = useLicenseStatus();

  if (!license) return <>{children}</>;

  const featureInfo = license.features.find(f => f.feature === feature);
  if (!featureInfo || featureInfo.enabled) return <>{children}</>;

  const requiredTier = featureInfo.requiredTier;

  return (
    <div className="relative">
      <div className="pointer-events-none select-none opacity-20 blur-[3px]">
        {children}
      </div>

      <div className="absolute inset-0 flex flex-col items-center justify-center rounded-2xl bg-[var(--sc-card-bg-strong)] backdrop-blur-sm">
        <div className="rounded-xl bg-[var(--sc-coral)]/10 p-3">
          <Lock size={24} className="text-[var(--sc-coral)]" />
        </div>
        <p className="mt-3 text-sm font-semibold text-[var(--sc-text-primary)]">
          {TIER_LABELS[requiredTier]} Feature
        </p>
        {label && (
          <p className="mt-1 max-w-xs text-center text-xs text-[var(--sc-text-muted)]">
            {label}
          </p>
        )}
        <a
          href="https://shieldcortex.ai/pricing"
          target="_blank"
          rel="noopener noreferrer"
          className="mt-4"
        >
          <Button variant="coral" size="sm" glow>
            Upgrade to {TIER_LABELS[requiredTier]}
            <ExternalLink size={12} />
          </Button>
        </a>
      </div>
    </div>
  );
}
