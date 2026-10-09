'use client';

import { Suspense } from 'react';
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
import { protectionTabs, protectionTabHref } from '@/components/protection/protection-tabs';
import { useUrlTab } from '@/hooks/useUrlTab';
import { useRouter } from 'next/navigation';

type ProtectionTab = 'status' | 'quarantine' | 'audit' | 'intercepts' | 'policies';

const VALID_TABS: ProtectionTab[] = ['status', 'quarantine', 'audit', 'intercepts', 'policies'];

function ProtectionContent() {
  // 'dome' is the pre-restyle tab id (brief §8 renamed Iron Dome -> Status);
  // kept as an alias so old deep links and bookmarks still land.
  const [tab, setTab] = useUrlTab<ProtectionTab>('/protection', VALID_TABS, 'status', { dome: 'status' });
  const router = useRouter();

  const { data: ironDome } = useIronDomeStatus();
  const { data: auditStats } = useAuditStats('24h');
  const { data: quarantine } = useQuarantine('pending', 10);
  const { data: intercepts } = useInterceptorEvents({ limit: 25 });

  const tabs = protectionTabs({
    quarantine: quarantine?.total ?? 0,
    intercepts: intercepts?.summary?.total ?? 0,
  });

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <PageHeader
          title="Protection"
          subtitle="What your agents tried to do, and what ShieldCortex did about it."
          tabs={tabs}
          activeTab={tab}
          onTabChange={(id) => (id === 'scanner' ? router.push(protectionTabHref(id)) : setTab(id as ProtectionTab))}
        />

        {/* Stats row */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Protection level"
            value={ironDome?.enabled ? 'On' : 'Off'}
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
            label="Held back"
            value={quarantine?.total ?? 0}
            icon={AlertTriangle}
            accent={quarantine?.total ? 'amber' : 'muted'}
          />
          <StatCard
            label="Activity"
            value={intercepts?.summary?.total ?? 0}
            icon={RadioTower}
            accent="cyan"
          />
        </div>

        {/* Tab content */}
        <div>
          {tab === 'status' && <IronDomeView />}
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
