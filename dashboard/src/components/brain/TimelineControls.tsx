'use client';

/**
 * Timeline Controls
 *
 * Provides timeline-based filtering and age visualization for memories.
 * Shows a slider to filter by time range and displays age distribution.
 */

import { useMemo, useState, useCallback } from 'react';
import { Memory } from '@/types/memory';

type ColorMode = 'category' | 'health' | 'age' | 'holographic';

interface TimelineControlsProps {
  memories: Memory[];
  onTimeRangeChange: (range: { start: Date | null; end: Date | null }) => void;
  colorMode: ColorMode;
  onColorModeChange: (mode: ColorMode) => void;
}

// Time presets for quick filtering
const TIME_PRESETS = [
  { label: 'All', hours: null },
  { label: '1h', hours: 1 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 24 * 7 },
  { label: '30d', hours: 24 * 30 },
];

export function TimelineControls({
  memories,
  onTimeRangeChange,
  colorMode,
  onColorModeChange,
}: TimelineControlsProps) {
  const [activePreset, setActivePreset] = useState<number | null>(null);

  // Calculate memory age distribution for the histogram
  const ageDistribution = useMemo(() => {
    if (!memories.length) return [];

    const now = Date.now();
    const buckets = [
      { label: '<1h', max: 60 * 60 * 1000, count: 0 },
      { label: '1-24h', max: 24 * 60 * 60 * 1000, count: 0 },
      { label: '1-7d', max: 7 * 24 * 60 * 60 * 1000, count: 0 },
      { label: '7-30d', max: 30 * 24 * 60 * 60 * 1000, count: 0 },
      { label: '>30d', max: Infinity, count: 0 },
    ];

    memories.forEach((memory) => {
      const age = now - new Date(memory.createdAt).getTime();
      for (const bucket of buckets) {
        if (age < bucket.max) {
          bucket.count++;
          break;
        }
      }
    });

    const maxCount = Math.max(...buckets.map((b) => b.count), 1);
    return buckets.map((b) => ({ ...b, height: (b.count / maxCount) * 100 }));
  }, [memories]);

  // Calculate oldest and newest memory dates
  const dateRange = useMemo(() => {
    if (!memories.length) return { oldest: null, newest: null };
    const dates = memories.map((m) => new Date(m.createdAt).getTime());
    return {
      oldest: new Date(Math.min(...dates)),
      newest: new Date(Math.max(...dates)),
    };
  }, [memories]);

  const handlePresetClick = useCallback(
    (hours: number | null, index: number) => {
      setActivePreset(index);
      if (hours === null) {
        onTimeRangeChange({ start: null, end: null });
      } else {
        const end = new Date();
        const start = new Date(end.getTime() - hours * 60 * 60 * 1000);
        onTimeRangeChange({ start, end });
      }
    },
    [onTimeRangeChange]
  );

  return (
    <div className="absolute bottom-4 right-4 bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-lg p-3 backdrop-blur-sm min-w-[200px]">
      {/* Color Mode Toggle */}
      <div className="mb-3">
        <div className="text-xs text-[var(--sc-text-secondary)] mb-1.5">Color Mode</div>
        <div className="flex gap-1">
          {[
            { value: 'category', label: 'Category', icon: '🎨' },
            { value: 'health', label: 'Health', icon: '💚' },
            { value: 'age', label: 'Age', icon: '⏰' },
            { value: 'holographic', label: 'Holo', icon: '✨' },
          ].map((mode) => (
            <button
              key={mode.value}
              onClick={() => onColorModeChange(mode.value as ColorMode)}
              className={`flex-1 px-2 py-1 text-[10px] rounded transition-colors ${
                colorMode === mode.value
                  ? mode.value === 'holographic' ? 'bg-[var(--sc-amber)] text-white' : 'bg-blue-600 text-white'
                  : 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] hover:bg-[var(--sc-bg-elevated)]'
              }`}
            >
              <span className="mr-0.5">{mode.icon}</span>
              {mode.label}
            </button>
          ))}
        </div>
      </div>

      {/* Time Filter Presets */}
      <div className="mb-3">
        <div className="text-xs text-[var(--sc-text-secondary)] mb-1.5">Time Filter</div>
        <div className="flex gap-1">
          {TIME_PRESETS.map((preset, i) => (
            <button
              key={preset.label}
              onClick={() => handlePresetClick(preset.hours, i)}
              className={`flex-1 px-2 py-1 text-[10px] rounded transition-colors ${
                activePreset === i
                  ? 'bg-[var(--sc-cyan)] text-white'
                  : 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] hover:bg-[var(--sc-bg-elevated)]'
              }`}
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Age Distribution Histogram */}
      <div>
        <div className="text-xs text-[var(--sc-text-secondary)] mb-1.5">Age Distribution</div>
        <div className="flex items-end gap-0.5 h-8">
          {ageDistribution.map((bucket) => (
            <div key={bucket.label} className="flex-1 flex flex-col items-center">
              <div
                className="w-full bg-gradient-to-t from-cyan-600 to-cyan-400 rounded-t transition-all"
                style={{ height: `${Math.max(bucket.height, 4)}%` }}
                title={`${bucket.label}: ${bucket.count} memories`}
              />
            </div>
          ))}
        </div>
        <div className="flex gap-0.5 mt-0.5">
          {ageDistribution.map((bucket) => (
            <div
              key={bucket.label}
              className="flex-1 text-[8px] text-[var(--sc-text-muted)] text-center truncate"
            >
              {bucket.label}
            </div>
          ))}
        </div>
      </div>

      {/* Date Range Info */}
      {dateRange.oldest && dateRange.newest && (
        <div className="mt-2 pt-2 border-t border-[var(--sc-border)] text-[9px] text-[var(--sc-text-muted)]">
          <div className="flex justify-between">
            <span>Oldest:</span>
            <span>{dateRange.oldest.toLocaleDateString()}</span>
          </div>
          <div className="flex justify-between">
            <span>Newest:</span>
            <span>{dateRange.newest.toLocaleDateString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Get age-based color for a memory
 * New (cyan) → Recent (green) → Old (amber) → Ancient (red)
 */
export function getAgeColor(createdAt: string | Date): string {
  const age = Date.now() - new Date(createdAt).getTime();
  const hours = age / (60 * 60 * 1000);

  if (hours < 1) {
    // Very new - bright cyan
    return '#22d3ee';
  } else if (hours < 24) {
    // Recent - green
    return '#22c55e';
  } else if (hours < 24 * 7) {
    // This week - yellow
    return '#eab308';
  } else if (hours < 24 * 30) {
    // This month - amber/orange
    return '#f97316';
  } else {
    // Old - red
    return '#ef4444';
  }
}
