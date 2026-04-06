'use client';

import { useSearchParams } from 'next/navigation';
import { useState, Suspense } from 'react';
import { PageSkeleton } from '@/components/ds/Skeleton';
import dynamic from 'next/dynamic';
import {
  Database,
  GitBranch,
  Inbox,
  Search,
  Sparkles,
} from 'lucide-react';
import { PageHeader } from '@/components/ds/PageHeader';
import { StatCard } from '@/components/ds/StatCard';
import { useStats, useContradictions, useQuality } from '@/hooks/useMemories';
import { useReviewQueue } from '@/hooks/useReviewQueue';
import { RecallWorkspace } from '@/components/recall/RecallWorkspace';
import { ReviewQueueView } from '@/components/review/ReviewQueueView';
import CaptureTab from './capture-tab';

const UnifiedGraph = dynamic(
  () => import('@/components/graph/UnifiedGraph'),
  {
    ssr: false,
    loading: () => (
      <div className="flex h-[600px] items-center justify-center text-[var(--sc-text-muted)]">
        Loading graph...
      </div>
    ),
  },
);

type MemoryTab = 'recall' | 'review' | 'capture' | 'graph';

function MemoryContent() {
  const searchParams = useSearchParams();
  const urlTab = searchParams.get('tab') as MemoryTab | null;
  const validUrlTab = urlTab && ['recall', 'review', 'capture', 'graph'].includes(urlTab) ? urlTab : null;
  const [userTab, setTab] = useState<MemoryTab>('recall');
  const tab = validUrlTab ?? userTab;

  const { data: stats } = useStats();
  const { data: contradictions } = useContradictions();
  const { data: quality } = useQuality();
  const { data: reviewQueue } = useReviewQueue();

  const totalMemories = stats?.total ?? 0;
  const healthyCount = stats?.decayDistribution?.healthy ?? 0;
  const contradictionCount = contradictions?.count ?? contradictions?.contradictions?.length ?? 0;
  const duplicateCount = quality?.duplicates?.count ?? 0;

  // Total items needing review across all queue sections
  const reviewTotal = reviewQueue
    ? Object.values(reviewQueue.summary).reduce((sum, n) => sum + n, 0)
    : 0;

  const tabs = [
    { id: 'recall', label: 'Recall', icon: <Search size={14} /> },
    { id: 'review', label: 'Review', count: reviewTotal || undefined },
    { id: 'capture', label: 'Capture', icon: <Sparkles size={14} /> },
    { id: 'graph', label: 'Graph', icon: <GitBranch size={14} /> },
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <PageHeader
          eyebrow="Memory"
          title="Memory Operations"
          subtitle="Search, review, capture, and explore your knowledge base."
          tabs={tabs}
          activeTab={tab}
          onTabChange={(id) => setTab(id as MemoryTab)}
        />

        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Total Memories" value={totalMemories.toLocaleString()} icon={Database} accent="cyan" />
          <StatCard label="Healthy" value={healthyCount.toLocaleString()} icon={Sparkles} accent="cyan" />
          <StatCard label="Contradictions" value={contradictionCount} icon={Inbox} accent={contradictionCount > 0 ? 'coral' : 'muted'} />
          <StatCard label="Duplicates" value={duplicateCount} icon={GitBranch} accent={duplicateCount > 0 ? 'amber' : 'muted'} />
        </div>

        <div>
          {tab === 'recall' && <RecallWorkspace />}
          {tab === 'review' && <ReviewQueueView />}
          {tab === 'capture' && <CaptureTab />}
          {tab === 'graph' && (
            <div className="h-[600px] rounded-2xl border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]">
              <UnifiedGraph />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function MemoryPage() {
  return (
    <Suspense fallback={<PageSkeleton />}>
      <MemoryContent />
    </Suspense>
  );
}
