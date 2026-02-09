'use client';

/**
 * Brain Control Centre
 *
 * Full control centre wrapper replacing the raw BrainScene on the Brain tab.
 * Assembles: TopStatsBar, CategoryHealthSidebar, BrainScene, MemoryInspector, ActivityFeed.
 */

import { useState, useCallback } from 'react';
import { Memory, MemoryLink, MemoryStats } from '@/types/memory';
import { useDashboardStore } from '@/lib/store';
import {
  useStats,
  useContradictions,
  useMemoryLinks,
  useConsolidate,
  useBoostMemory,
  useDemoteMemory,
  usePromoteMemory,
  useDeleteMemory,
  useQuarantineMemory,
  useEditMemory,
  useWorkerStatus,
} from '@/hooks/useMemories';
import { useQuarantine } from '@/hooks/useDefence';
import { TopStatsBar } from './TopStatsBar';
import { CategoryHealthSidebar } from './CategoryHealthSidebar';
import { MemoryInspector } from './MemoryInspector';
import { ActivityFeed } from './ActivityFeed';
import { BrainScene } from './BrainScene';

interface BrainControlCentreProps {
  memories: Memory[];
  links: MemoryLink[];
  stats: MemoryStats | undefined;
  isLoading: boolean;
}

export function BrainControlCentre({
  memories,
  links,
  stats,
  isLoading,
}: BrainControlCentreProps) {
  const {
    selectedMemory,
    setSelectedMemory,
    recentEvents,
    projectFilter,
  } = useDashboardStore();

  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [feedCollapsed, setFeedCollapsed] = useState(false);

  // Data hooks
  const { data: contradictionsData } = useContradictions(projectFilter || undefined);
  const { data: quarantineData } = useQuarantine('pending', 50, projectFilter || undefined);
  const { data: workerStatus } = useWorkerStatus();

  // Mutation hooks
  const consolidateMutation = useConsolidate();
  const boostMutation = useBoostMemory();
  const demoteMutation = useDemoteMemory();
  const promoteMutation = usePromoteMemory();
  const deleteMutation = useDeleteMemory();
  const quarantineMutation = useQuarantineMemory();
  const editMutation = useEditMemory();

  const contradictionCount = contradictionsData?.count ?? 0;
  const quarantineCount = quarantineData?.total ?? 0;

  // Calculate last consolidation time from worker status
  const lastConsolidation = workerStatus?.lastMediumTick ?? workerStatus?.lastLightTick ?? null;

  // Map worker status to the shape expected by child components
  const mappedWorkerStatus = workerStatus
    ? { running: workerStatus.isRunning, lastRun: workerStatus.lastLightTick ?? workerStatus.lastMediumTick ?? undefined }
    : null;

  // Handlers
  const handleSelectMemory = useCallback(
    (memory: Memory | null) => {
      setSelectedMemory(memory);
    },
    [setSelectedMemory]
  );

  const handleNavigateToMemory = useCallback(
    (id: number) => {
      const memory = memories.find((m) => m.id === id);
      if (memory) {
        setSelectedMemory(memory);
      }
    },
    [memories, setSelectedMemory]
  );

  const handleBoost = useCallback(
    (id: number) => boostMutation.mutate(id),
    [boostMutation]
  );

  const handleDemote = useCallback(
    (id: number) => demoteMutation.mutate(id),
    [demoteMutation]
  );

  const handlePromote = useCallback(
    (id: number) => promoteMutation.mutate(id),
    [promoteMutation]
  );

  const handleDelete = useCallback(
    (id: number) => {
      deleteMutation.mutate(id);
      setSelectedMemory(null);
    },
    [deleteMutation, setSelectedMemory]
  );

  const handleQuarantine = useCallback(
    (id: number) => {
      quarantineMutation.mutate({ id, reason: 'Quarantined from Brain Control Centre' });
      setSelectedMemory(null);
    },
    [quarantineMutation, setSelectedMemory]
  );

  const handleEdit = useCallback(
    (id: number, updates: { title?: string; content?: string; tags?: string[]; category?: string }) => {
      editMutation.mutate({ id, updates });
    },
    [editMutation]
  );

  const handleConsolidate = useCallback(() => {
    consolidateMutation.mutate();
  }, [consolidateMutation]);

  const handleClickContradictions = useCallback(() => {
    const first = contradictionsData?.contradictions?.[0];
    if (!first) return;
    const memory = memories.find((m) => m.id === first.memoryAId);
    if (memory) {
      setSelectedMemory(memory);
    }
  }, [contradictionsData, memories, setSelectedMemory]);

  const handleActivityClick = useCallback(
    (eventData: unknown) => {
      const data = eventData as Record<string, unknown> | null;
      if (data?.memoryId) {
        handleNavigateToMemory(data.memoryId as number);
      } else if (data?.id) {
        handleNavigateToMemory(data.id as number);
      }
    },
    [handleNavigateToMemory]
  );

  // Get links for the selected memory
  const selectedMemoryLinks = selectedMemory
    ? links.filter(
        (l) => l.source_id === selectedMemory.id || l.target_id === selectedMemory.id
      )
    : [];

  if (isLoading) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-slate-950">
        <div className="text-slate-400 animate-pulse">Loading Brain...</div>
      </div>
    );
  }

  return (
    <div className="w-full h-full flex flex-col bg-slate-950 relative">
      {/* Top Stats Bar */}
      <TopStatsBar
        stats={stats ?? { total: 0, shortTerm: 0, longTerm: 0, episodic: 0, byCategory: {}, averageSalience: 0 }}
        contradictionCount={contradictionCount}
        quarantineCount={quarantineCount}
        lastConsolidation={lastConsolidation}
        workerStatus={mappedWorkerStatus}
        onClickContradictions={handleClickContradictions}
      />

      {/* Main content area: sidebar + brain + inspector */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Left: Category Health Sidebar */}
        <CategoryHealthSidebar
          stats={stats ?? { total: 0, shortTerm: 0, longTerm: 0, episodic: 0, byCategory: {}, averageSalience: 0 }}
          memories={memories}
          onCategoryClick={setCategoryFilter}
          activeCategory={categoryFilter}
          onConsolidate={handleConsolidate}
          isConsolidating={consolidateMutation.isPending}
          workerStatus={mappedWorkerStatus}
        />

        {/* Centre: 3D Brain + Activity Feed */}
        <div className="flex-1 flex flex-col relative">
          <div className="flex-1 relative">
            <BrainScene
              memories={memories}
              links={links}
              selectedMemory={selectedMemory}
              onSelectMemory={handleSelectMemory}
              categoryFilter={categoryFilter}
            />
          </div>

          {/* Bottom: Activity Feed */}
          <ActivityFeed
            events={recentEvents}
            onClickEvent={handleActivityClick}
            isCollapsed={feedCollapsed}
            onToggleCollapse={() => setFeedCollapsed(!feedCollapsed)}
          />
        </div>

        {/* Right: Memory Inspector */}
        <MemoryInspector
          memory={selectedMemory}
          links={selectedMemoryLinks}
          onClose={() => setSelectedMemory(null)}
          onBoost={handleBoost}
          onDemote={handleDemote}
          onPromote={handlePromote}
          onDelete={handleDelete}
          onQuarantine={handleQuarantine}
          onEdit={handleEdit}
          onNavigateToMemory={handleNavigateToMemory}
        />
      </div>

    </div>
  );
}
