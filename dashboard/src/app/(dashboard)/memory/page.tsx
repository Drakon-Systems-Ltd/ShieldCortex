'use client';

import { useSearchParams, usePathname, useRouter } from 'next/navigation';
import { useState, Suspense, useCallback } from 'react';
import { PageSkeleton } from '@/components/ds/Skeleton';
import dynamic from 'next/dynamic';
import {
  Database,
  FileText,
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
import { MemoriesView } from '@/components/memories/MemoriesView';
import { MemoryFilesView } from '@/components/memories/MemoryFilesView';

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

type MemoryTab = 'library' | 'files' | 'recall' | 'review' | 'graph';

function normaliseTab(tab: string | null): MemoryTab | null {
  if (tab === 'capture') return 'library';
  return tab && ['library', 'files', 'recall', 'review', 'graph'].includes(tab)
    ? (tab as MemoryTab)
    : null;
}

function MemoryContent() {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const validUrlTab = normaliseTab(searchParams.get('tab'));
  const [userTab, setUserTab] = useState<MemoryTab>('library');
  const tab = validUrlTab ?? userTab;

  // When the user clicks a tab, replace the URL search param so the URL stays
  // canonical and validUrlTab follows the click. Without this, a click only
  // updates `userTab` but `validUrlTab` keeps winning and the active tab
  // appears stuck.
  const setTab = useCallback((next: MemoryTab) => {
    setUserTab(next);
    const params = new URLSearchParams(searchParams.toString());
    if (next === 'library') {
      params.delete('tab');
    } else {
      params.set('tab', next);
    }
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  }, [pathname, router, searchParams]);

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
    { id: 'library', label: 'Library', icon: <Database size={14} />, count: totalMemories || undefined },
    { id: 'files', label: 'Files', icon: <FileText size={14} /> },
    { id: 'recall', label: 'Recall', icon: <Search size={14} /> },
    { id: 'review', label: 'Review', count: reviewTotal || undefined },
    { id: 'graph', label: 'Graph', icon: <GitBranch size={14} /> },
  ];

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <PageHeader
          eyebrow="Memory"
          title="Memory Operations"
          subtitle="Search stored memories, scan agent memory files, and inspect recall quality."
          tabs={tabs}
          activeTab={tab}
          onTabChange={(id) => setTab(id as MemoryTab)}
        />

        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard label="Stored Memories" value={totalMemories.toLocaleString()} icon={Database} accent="cyan" />
          <StatCard label="Healthy" value={healthyCount.toLocaleString()} icon={Sparkles} accent="cyan" />
          <StatCard label="Contradictions" value={contradictionCount} icon={Inbox} accent={contradictionCount > 0 ? 'coral' : 'muted'} />
          <StatCard label="Duplicates" value={duplicateCount} icon={GitBranch} accent={duplicateCount > 0 ? 'amber' : 'muted'} />
        </div>

        <div>
          {tab === 'library' && <MemoriesView />}
          {tab === 'files' && <MemoryFilesView />}
          {tab === 'recall' && <RecallWorkspace />}
          {tab === 'review' && <ReviewQueueView />}
          {tab === 'graph' && (
            <div className="rounded-md border border-[var(--term-border)] bg-[var(--term-surface)] overflow-hidden flex flex-col">
              <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[var(--term-border)] bg-[var(--term-surface-2)] font-mono">
                <span aria-hidden className="w-2.5 h-2.5 rounded-full bg-[var(--term-light-red)]" />
                <span aria-hidden className="w-2.5 h-2.5 rounded-full bg-[var(--term-light-yellow)]" />
                <span aria-hidden className="w-2.5 h-2.5 rounded-full bg-[var(--term-light-green)]" />
                <span className="ml-2 text-xs text-[var(--term-text-muted)] select-none">knowledge-graph</span>
              </div>
              <div className="h-[600px]">
                <UnifiedGraph />
              </div>
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
