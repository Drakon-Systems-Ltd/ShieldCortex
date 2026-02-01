'use client';

import { useState } from 'react';
import { PipelineStatus } from './PipelineStatus';
import { QuarantinePreview } from './QuarantinePreview';
import { ThreatTimeline } from './ThreatTimeline';
import { DefenceStatsCard } from './DefenceStatsCard';

export function ShieldOverview() {
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h');

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Time Range Toggle */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold text-white">Defence Overview</h2>
        <div className="flex gap-1 bg-slate-800 rounded-lg p-0.5">
          {(['24h', '7d', '30d'] as const).map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-3 py-1 text-xs rounded-md transition-colors ${
                timeRange === range
                  ? 'bg-cyan-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Four-quadrant grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <PipelineStatus timeRange={timeRange} />
        <QuarantinePreview />
        <ThreatTimeline timeRange={timeRange} />
        <DefenceStatsCard timeRange={timeRange} />
      </div>
    </div>
  );
}
