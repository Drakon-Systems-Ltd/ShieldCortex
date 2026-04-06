'use client';

import { useSearchParams } from 'next/navigation';
import { useState, Suspense } from 'react';
import { PageSkeleton } from '@/components/ds/Skeleton';
import {
  AlertTriangle,
  RadioTower,
  Shield,
  ShieldAlert,
} from 'lucide-react';
import { StatCard } from '@/components/ds/StatCard';
import { PageHeader } from '@/components/ds/PageHeader';
import { useIronDomeStatus } from '@/hooks/useIronDome';
import { useAuditStats, useQuarantine } from '@/hooks/useDefence';
import { useInterceptorEvents } from '@/hooks/useInterceptorEvents';
import { IronDomeView } from '@/components/dome/IronDomeView';
import { QuarantineView } from '@/components/quarantine/QuarantineView';
import { AuditLogView } from '@/components/audit/AuditLogView';
import { InterceptorEventsView } from '@/components/protection/InterceptorEventsView';
import { PolicyManagementView } from '@/components/protection/PolicyManagementView';

type ProtectionTab = 'dome' | 'quarantine' | 'audit' | 'intercepts' | 'policies';

function ProtectionContent() {
  const searchParams = useSearchParams();
  const urlTab = searchParams.get('tab') as ProtectionTab | null;
  const validUrlTab = urlTab && ['dome', 'quarantine', 'audit', 'intercepts', 'policies'].includes(urlTab) ? urlTab : null;
  const [userTab, setTab] = useState<ProtectionTab>('dome');
  const tab = validUrlTab ?? userTab;

  const { data: ironDome } = useIronDomeStatus();
  const { data: auditStats } = useAuditStats('24h');
  const { data: quarantine } = useQuarantine('pending', 10);
  const { data: intercepts } = useInterceptorEvents({ limit: 25 });

  const tabs = [
    { id: 'dome', label: 'Iron Dome', icon: <ShieldAlert size={14} /> },
    { id: 'quarantine', label: 'Quarantine', count: quarantine?.total ?? 0 },
    { id: 'audit', label: 'Audit' },
    { id: 'intercepts', label: 'Intercepts', count: intercepts?.summary?.total ?? 0 },
    { id: 'policies', label: 'Policies', locked: false },
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <PageHeader
          eyebrow="Defence"
          title="Protection"
          subtitle="Active controls, review queues, and operator policy tuning."
          tabs={tabs}
          activeTab={tab}
          onTabChange={(id) => setTab(id as ProtectionTab)}
        />

        {/* Stats row */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Iron Dome"
            value={ironDome?.enabled ? 'Active' : 'Inactive'}
            icon={Shield}
            accent={ironDome?.enabled ? 'cyan' : 'muted'}
          />
          <StatCard
            label="Blocked (24h)"
            value={auditStats?.blockedCount ?? 0}
            icon={ShieldAlert}
            accent={auditStats?.blockedCount ? 'coral' : 'muted'}
          />
          <StatCard
            label="Quarantine"
            value={quarantine?.total ?? 0}
            icon={AlertTriangle}
            accent={quarantine?.total ? 'amber' : 'muted'}
          />
          <StatCard
            label="Intercepts"
            value={intercepts?.summary?.total ?? 0}
            icon={RadioTower}
            accent="cyan"
          />
        </div>

        {/* Tab content */}
        <div>
          {tab === 'dome' && <IronDomeView />}
          {tab === 'quarantine' && <QuarantineView />}
          {tab === 'audit' && <AuditLogView />}
          {tab === 'intercepts' && <InterceptorEventsView />}
          {tab === 'policies' && <PolicyManagementView />}
        </div>
      </div>
    </div>
  );
}

export function ProtectionOverview() {
  return (
    <Suspense fallback={<PageSkeleton />}>
      <ProtectionContent />
    </Suspense>
  );
}
