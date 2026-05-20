'use client';

import { useSearchParams } from 'next/navigation';
import { useState, Suspense } from 'react';
import { PageSkeleton } from '@/components/ds/Skeleton';
import { Cloud, CreditCard, Plug, Settings } from 'lucide-react';
import { PageHeader } from '@/components/ds/PageHeader';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { CloudSyncDiagnosticsView } from '@/components/cloud/CloudSyncDiagnosticsView';
import { IntegrationsView } from '@/components/settings/IntegrationsView';
import { MaintenanceCard } from '@/components/settings/MaintenanceCard';
import { PrunePanel } from '@/components/settings/PrunePanel';
import { DedupePanel } from '@/components/settings/DedupePanel';
import { LicenseStatusCard } from '@/components/shield/LicenseStatusCard';
import { useLicenseStatus } from '@/hooks/useLicense';
import { TIER_LABELS } from '@/lib/license';
import { loadIntensity, saveIntensity, type IntensityLevel } from '@/components/graph/constellation/intensity';

type SettingsTab = 'cloud' | 'integrations' | 'licence' | 'admin';

function SettingsContent() {
  const searchParams = useSearchParams();
  const urlTab = searchParams.get('tab') as SettingsTab | null;
  const validUrlTab = urlTab && ['cloud', 'integrations', 'licence', 'admin'].includes(urlTab) ? urlTab : null;
  const [userTab, setTab] = useState<SettingsTab>('cloud');
  const tab = validUrlTab ?? userTab;
  const { data: license } = useLicenseStatus();
  const [intensity, setIntensity] = useState<IntensityLevel>(() => loadIntensity());
  const onIntensityChange = (next: IntensityLevel) => {
    setIntensity(next);
    saveIntensity(next);
  };

  const tabs = [
    { id: 'cloud', label: 'Cloud Sync', icon: <Cloud size={14} /> },
    { id: 'integrations', label: 'Integrations', icon: <Plug size={14} /> },
    { id: 'licence', label: 'Licence', icon: <CreditCard size={14} /> },
    { id: 'admin', label: 'Admin', icon: <Settings size={14} /> },
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <PageHeader
          eyebrow="Configuration"
          title="Settings"
          subtitle="Cloud sync, licence management, and system configuration."
          tabs={tabs}
          activeTab={tab}
          onTabChange={(id) => setTab(id as SettingsTab)}
          actions={
            <Badge variant={license?.tier === 'pro' ? 'cyan' : license?.tier === 'team' ? 'coral' : 'muted'}>
              {TIER_LABELS[license?.tier ?? 'free']}
            </Badge>
          }
        />

        <div>
          {tab === 'cloud' && <CloudSyncDiagnosticsView />}
          {tab === 'integrations' && <IntegrationsView />}
          {tab === 'licence' && (
            <div className="space-y-6">
              <LicenseStatusCard />
              <GlassCard className="p-6">
                <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Upgrade</h3>
                <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">
                  Pro unlocks deep X-Ray scanning, custom firewall rules, custom Iron Dome policies, audit exports, and more.
                  Team adds cloud sync and team management.
                </p>
                <div className="mt-4 flex gap-3">
                  <a href="https://shieldcortex.ai/pricing" target="_blank" rel="noopener noreferrer">
                    <Button variant="coral" glow>View pricing</Button>
                  </a>
                </div>
              </GlassCard>
            </div>
          )}
          {tab === 'admin' && (
            <div className="space-y-6">
              <MaintenanceCard />
              <PrunePanel />
              <DedupePanel />
              <GlassCard className="p-6">
                <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Graph Motion</h3>
                <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">
                  How lively the knowledge graph feels. Per-browser.
                </p>
                <div
                  role="radiogroup"
                  aria-label="Graph motion intensity"
                  className="mt-4 flex gap-2"
                >
                  {(['subtle', 'moderate', 'strong'] as const).map((level) => (
                    <label
                      key={level}
                      className={`flex flex-1 cursor-pointer items-center gap-2 rounded-lg border px-4 py-3 transition-colors ${
                        intensity === level
                          ? 'border-[var(--sc-accent-cyan)] bg-[var(--sc-bg-elevated)]'
                          : 'border-transparent bg-[var(--sc-bg-elevated)] hover:border-[var(--sc-border-subtle)]'
                      }`}
                    >
                      <input
                        type="radio"
                        name="graph-intensity"
                        value={level}
                        checked={intensity === level}
                        onChange={() => onIntensityChange(level)}
                        className="accent-[var(--sc-accent-cyan)]"
                      />
                      <span className="text-sm text-[var(--sc-text-primary)]">
                        {level[0].toUpperCase() + level.slice(1)}
                      </span>
                    </label>
                  ))}
                </div>
              </GlassCard>
              <GlassCard className="p-6">
                <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">System Information</h3>
                <div className="mt-4 space-y-3">
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-secondary)]">Dashboard</span>
                    <span className="font-mono text-sm text-[var(--sc-text-primary)]">localhost:3030</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-secondary)]">API Server</span>
                    <span className="font-mono text-sm text-[var(--sc-text-primary)]">localhost:3001</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-secondary)]">Database</span>
                    <span className="font-mono text-sm text-[var(--sc-text-primary)]">~/.shieldcortex/memories.db</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-bg-elevated)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-secondary)]">Licence Tier</span>
                    <Badge variant={license?.tier === 'pro' ? 'cyan' : license?.tier === 'team' ? 'coral' : 'muted'}>
                      {TIER_LABELS[license?.tier ?? 'free']}
                    </Badge>
                  </div>
                </div>
              </GlassCard>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function SettingsView() {
  return (
    <Suspense fallback={<PageSkeleton />}>
      <SettingsContent />
    </Suspense>
  );
}
