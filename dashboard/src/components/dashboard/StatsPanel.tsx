'use client';

/**
 * Stats Panel
 * Displays memory statistics and health metrics
 */

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { MemoryStats } from '@/types/memory';
import { CATEGORY_COLORS } from '@/lib/category-colors';

interface StatsPanelProps {
  stats: MemoryStats | undefined;
  isLoading: boolean;
}

export function StatsPanel({ stats, isLoading }: StatsPanelProps) {
  if (isLoading) {
    return (
      <div className="space-y-4 animate-pulse">
        <div className="h-32 bg-slate-800 rounded-lg" />
        <div className="h-48 bg-slate-800 rounded-lg" />
      </div>
    );
  }

  if (!stats) {
    return (
      <Card className="bg-slate-900 border-slate-700">
        <CardContent className="p-4 text-slate-400 text-center">
          No data available
        </CardContent>
      </Card>
    );
  }

  const healthPercentage = stats.decayDistribution
    ? Math.round(
        (stats.decayDistribution.healthy /
          (stats.decayDistribution.healthy +
            stats.decayDistribution.fading +
            stats.decayDistribution.critical)) *
          100
      ) || 0
    : 0;

  return (
    <div className="space-y-4">
      {/* Health Indicator */}
      <Card className="bg-slate-900 border-slate-700">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">
            System Health
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-3">
            <div
              className={`w-3 h-3 rounded-full ${
                healthPercentage > 70
                  ? 'bg-green-500'
                  : healthPercentage > 40
                  ? 'bg-yellow-500'
                  : 'bg-red-500'
              }`}
            />
            <span className="text-white font-medium">{healthPercentage}% Healthy</span>
          </div>
          {stats.decayDistribution && (
            <div className="flex gap-1 h-2 rounded-full overflow-hidden">
              <div
                className="bg-green-500 transition-all"
                style={{
                  width: `${
                    (stats.decayDistribution.healthy / stats.total) * 100
                  }%`,
                }}
              />
              <div
                className="bg-yellow-500 transition-all"
                style={{
                  width: `${
                    (stats.decayDistribution.fading / stats.total) * 100
                  }%`,
                }}
              />
              <div
                className="bg-red-500 transition-all"
                style={{
                  width: `${
                    (stats.decayDistribution.critical / stats.total) * 100
                  }%`,
                }}
              />
            </div>
          )}
          <div className="text-xs text-slate-400">
            Avg Salience: {(stats.averageSalience * 100).toFixed(0)}%
          </div>
        </CardContent>
      </Card>

      {/* Memory Counts */}
      <Card className="bg-slate-900 border-slate-700">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">
            Memory Stats
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-slate-400">Total</span>
            <span className="text-white font-mono">{stats.total}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-orange-400">Short-Term</span>
            <span className="text-white font-mono">{stats.shortTerm}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-blue-400">Long-Term</span>
            <span className="text-white font-mono">{stats.longTerm}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-purple-400">Episodic</span>
            <span className="text-white font-mono">{stats.episodic}</span>
          </div>
        </CardContent>
      </Card>

      {/* Categories */}
      <Card className="bg-slate-900 border-slate-700">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-slate-300">
            By Category
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Object.entries(stats.byCategory)
            .sort(([, a], [, b]) => b - a)
            .slice(0, 6)
            .map(([category, count]) => (
              <div key={category} className="space-y-1">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400 capitalize">{category}</span>
                  <span className="text-white font-mono">{count}</span>
                </div>
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${(count / stats.total) * 100}%`,
                      backgroundColor:
                        CATEGORY_COLORS[category as keyof typeof CATEGORY_COLORS] ||
                        '#6B7280',
                    }}
                  />
                </div>
              </div>
            ))}
        </CardContent>
      </Card>
    </div>
  );
}
