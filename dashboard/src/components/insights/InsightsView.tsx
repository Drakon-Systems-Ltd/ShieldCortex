'use client';

import { useActivity } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { ActivityHeatmap } from './ActivityHeatmap';
import { KnowledgeMapPanel } from './KnowledgeMapPanel';
import { QualityPanel } from './QualityPanel';
import type { MemoryStats } from '@/types/memory';

interface InsightsViewProps {
  selectedProject?: string;
  stats?: MemoryStats;
}

export function InsightsView({ selectedProject, stats }: InsightsViewProps) {
  const { data: activityData } = useActivity(selectedProject);
  const { setViewMode, setCategoryFilter } = useDashboardStore();

  const handleNavigate = (filter: { category?: string }) => {
    if (filter.category) {
      setCategoryFilter(filter.category);
    }
    setViewMode('memories');
  };

  return (
    <div className="h-full overflow-y-auto p-6 space-y-8">
      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Activity</h2>
        <ActivityHeatmap activity={activityData?.activity ?? []} />
      </section>

      {stats && (
        <section>
          <h2 className="text-lg font-semibold text-white mb-4">Knowledge Coverage</h2>
          <KnowledgeMapPanel stats={stats} onNavigate={handleNavigate} />
        </section>
      )}

      <section>
        <h2 className="text-lg font-semibold text-white mb-4">Memory Quality</h2>
        <QualityPanel project={selectedProject} />
      </section>
    </div>
  );
}
