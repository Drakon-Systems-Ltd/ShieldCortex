'use client';

import { useEffect, useState, useCallback } from 'react';
import { authFetch } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface ComponentScore {
  score: number;
  label: string;
  detail: string;
}

interface HealthData {
  overall: number;
  components: {
    freshness: ComponentScore;
    coverage: ComponentScore;
    consistency: ComponentScore;
    consolidation: ComponentScore;
  };
}

function scoreColour(score: number): string {
  if (score > 70) return '#22c55e';  // green-500
  if (score >= 40) return '#eab308'; // yellow-500
  return '#ef4444';                  // red-500
}

function scoreColourClass(score: number): string {
  if (score > 70) return 'bg-[var(--sc-cyan)]';
  if (score >= 40) return 'bg-[var(--sc-amber)]';
  return 'bg-[var(--sc-coral)]';
}

function scoreTrackClass(score: number): string {
  if (score > 70) return 'bg-[var(--sc-cyan)]/20';
  if (score >= 40) return 'bg-[var(--sc-amber)]/20';
  return 'bg-[var(--sc-coral)]/20';
}

/** SVG circular progress ring */
function ProgressRing({ score, size = 120, strokeWidth = 8 }: { score: number; size?: number; strokeWidth?: number }) {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const colour = scoreColour(score);

  return (
    <svg width={size} height={size} className="transform -rotate-90">
      {/* Background track */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke="rgba(255,255,255,0.06)"
        strokeWidth={strokeWidth}
      />
      {/* Progress arc */}
      <circle
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={colour}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        style={{ transition: 'stroke-dashoffset 0.6s ease' }}
      />
    </svg>
  );
}

/** Single sub-score bar */
function SubScoreBar({ component }: { component: ComponentScore }) {
  return (
    <div className="group relative">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-[var(--sc-text-secondary)]">{component.label}</span>
        <span className="text-xs font-medium text-[var(--sc-text-primary)]">{component.score}</span>
      </div>
      <div className={`h-1.5 rounded-full ${scoreTrackClass(component.score)}`}>
        <div
          className={`h-full rounded-full ${scoreColourClass(component.score)}`}
          style={{ width: `${component.score}%`, transition: 'width 0.6s ease' }}
        />
      </div>
      {/* Tooltip */}
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 rounded bg-[var(--sc-bg-elevated)] text-[10px] text-[var(--sc-text-primary)] whitespace-nowrap opacity-0 group-hover:opacity-100 pointer-events-none transition-opacity z-10 border border-white/10">
        {component.detail}
      </div>
    </div>
  );
}

export default function HealthScore() {
  const [data, setData] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const fetchHealth = useCallback(async () => {
    try {
      const res = await authFetch(`${API_BASE}/api/health-score`);
      if (!res.ok) throw new Error('Failed to fetch health score');
      const json: HealthData = await res.json();
      setData(json);
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 60_000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  if (loading) {
    return (
      <div className="bg-[#12121a] border border-white/10 rounded-xl p-5 w-[300px]">
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-4">Memory Health</h3>
        <div className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="bg-[#12121a] border border-white/10 rounded-xl p-5 w-[300px]">
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-4">Memory Health</h3>
        <div className="text-xs text-[var(--sc-coral)]">Failed to load health score</div>
      </div>
    );
  }

  const { overall, components } = data;

  return (
    <div className="bg-[#12121a] border border-white/10 rounded-xl p-5 w-[300px]">
      <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-4">Memory Health</h3>

      {/* Circular progress ring with score in centre */}
      <div className="flex justify-center mb-5">
        <div className="relative">
          <ProgressRing score={overall} />
          <div className="absolute inset-0 flex items-center justify-center">
            <span
              className="text-3xl font-bold"
              style={{ color: scoreColour(overall) }}
            >
              {overall}
            </span>
          </div>
        </div>
      </div>

      {/* Sub-scores */}
      <div className="space-y-3">
        <SubScoreBar component={components.freshness} />
        <SubScoreBar component={components.coverage} />
        <SubScoreBar component={components.consistency} />
        <SubScoreBar component={components.consolidation} />
      </div>
    </div>
  );
}
