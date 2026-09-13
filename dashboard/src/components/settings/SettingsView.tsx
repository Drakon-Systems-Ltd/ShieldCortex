'use client';

import { useSearchParams } from 'next/navigation';
import { useState, Suspense } from 'react';
import { PageSkeleton } from '@/components/ds/Skeleton';
import { Cloud, CreditCard, Plug, Settings } from 'lucide-react';
import { PageHeader } from '@/components/ds/PageHeader';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import { CloudSyncDiagnosticsView } from '@/components/cloud/CloudSyncDiagnosticsView';
import { IntegrationsView } from '@/components/settings/IntegrationsView';
import { MaintenanceCard } from '@/components/settings/MaintenanceCard';
import { PrunePanel } from '@/components/settings/PrunePanel';
import { DedupePanel } from '@/components/settings/DedupePanel';
import { LicenseStatusCard } from '@/components/shield/LicenseStatusCard';
import { useLicenseStatus } from '@/hooks/useLicense';
import { TIER_LABELS } from '@/lib/license';

type SettingsTab = 'cloud' | 'integrations' | 'licence' | 'admin';

function SettingsContent() {
  const searchParams = useSearchParams();
  const urlTab = searchParams.get('tab') as SettingsTab | null;
  const validUrlTab = urlTab && ['cloud', 'integrations', 'licence', 'admin'].includes(urlTab) ? urlTab : null;
  const [userTab, setTab] = useState<SettingsTab>('cloud');
  const tab = validUrlTab ?? userTab;
  const { data: license } = useLicenseStatus();
  // v2: the CIC "graph motion intensity" control was removed with the
  // constellation renderer — the v2 graph has no ambient motion to tune and
  // honours prefers-reduced-motion directly.

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
                <h3 className="text-lg font-semibold text-[var(--sc-text)]">Enterprise</h3>
                <p className="mt-2 text-sm text-[var(--sc-text-dim)]">
                  Cloud replication, team management, shared patterns, self-hosted deployments, and fleets:{' '}
                  <a href="mailto:sales@drakonsystems.com" className="text-[var(--sc-ok)] hover:underline">
                    sales@drakonsystems.com
                  </a>
                </p>
              </GlassCard>
            </div>
          )}
          {tab === 'admin' && (
            <div className="space-y-6">
              <MaintenanceCard />
              <PrunePanel />
              <DedupePanel />
              <GlassCard className="p-6">
                <h3 className="text-lg font-semibold text-[var(--sc-text)]">System Information</h3>
                <div className="mt-4 space-y-3">
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-dim)]">Dashboard</span>
                    <span className="font-mono text-sm text-[var(--sc-text)]">localhost:3030</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-dim)]">API Server</span>
                    <span className="font-mono text-sm text-[var(--sc-text)]">localhost:3001</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-dim)]">Database</span>
                    <span className="font-mono text-sm text-[var(--sc-text)]">~/.shieldcortex/memories.db</span>
                  </div>
                  <div className="flex items-center justify-between rounded-lg bg-[var(--sc-surface-2)] px-4 py-3">
                    <span className="text-sm text-[var(--sc-text-dim)]">Licence Tier</span>
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
