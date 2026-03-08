'use client';

import { useMemo } from 'react';
import { useAgentTimeline } from '@/hooks/useAgents';

interface Props {
  identifier: string;
  timeRange: '24h' | '7d' | '30d';
}

const WIDTH = 500;
const HEIGHT = 120;
const PAD = { top: 10, right: 10, bottom: 20, left: 30 };
const INNER_W = WIDTH - PAD.left - PAD.right;
const INNER_H = HEIGHT - PAD.top - PAD.bottom;

export function TrustTimeline({ identifier, timeRange }: Props) {
  const { data, isLoading } = useAgentTimeline(identifier, timeRange);
  const points = useMemo(() => data?.points ?? [], [data?.points]);

  const { linePath, dots, xLabels } = useMemo(() => {
    if (points.length === 0) return { linePath: '', dots: [], xLabels: [] };

    const times = points.map((p) => new Date(p.timestamp).getTime());
    const minT = Math.min(...times);
    const maxT = Math.max(...times);
    const rangeT = maxT - minT || 1;

    const xScale = (t: number) => PAD.left + ((t - minT) / rangeT) * INNER_W;
    const yScale = (v: number) => PAD.top + (1 - v) * INNER_H;

    const pathParts = points.map((p, i) => {
      const x = xScale(times[i]);
      const y = yScale(p.trust_score);
      return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
    });

    const eventDots = points
      .map((p, i) => ({
        x: xScale(times[i]),
        y: yScale(p.trust_score),
        result: p.firewall_result,
        score: p.trust_score,
        time: p.timestamp,
      }))
      .filter((d) => d.result !== 'ALLOW');

    // X-axis labels (3-5 labels)
    const labelCount = Math.min(5, points.length);
    const labels = [];
    for (let i = 0; i < labelCount; i++) {
      const t = minT + (rangeT * i) / (labelCount - 1 || 1);
      const d = new Date(t);
      labels.push({
        x: xScale(t),
        label: timeRange === '24h'
          ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          : d.toLocaleDateString([], { month: 'short', day: 'numeric' }),
      });
    }

    return { linePath: pathParts.join(' '), dots: eventDots, xLabels: labels };
  }, [points, timeRange]);

  if (isLoading) {
    return <div className="h-[120px] flex items-center justify-center text-slate-500 text-xs">Loading timeline...</div>;
  }

  if (points.length === 0) {
    return <div className="h-[120px] flex items-center justify-center text-slate-500 text-xs">No data for this time range.</div>;
  }

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" preserveAspectRatio="xMidYMid meet">
      {/* Threshold lines */}
      <line
        x1={PAD.left} y1={PAD.top + (1 - 0.7) * INNER_H}
        x2={PAD.left + INNER_W} y2={PAD.top + (1 - 0.7) * INNER_H}
        stroke="#22c55e" strokeWidth="0.5" strokeDasharray="4 2" opacity="0.3"
      />
      <line
        x1={PAD.left} y1={PAD.top + (1 - 0.5) * INNER_H}
        x2={PAD.left + INNER_W} y2={PAD.top + (1 - 0.5) * INNER_H}
        stroke="#eab308" strokeWidth="0.5" strokeDasharray="4 2" opacity="0.3"
      />

      {/* Y-axis labels */}
      <text x={PAD.left - 4} y={PAD.top + (1 - 0.7) * INNER_H + 3} fill="#64748b" fontSize="8" textAnchor="end">0.7</text>
      <text x={PAD.left - 4} y={PAD.top + (1 - 0.5) * INNER_H + 3} fill="#64748b" fontSize="8" textAnchor="end">0.5</text>
      <text x={PAD.left - 4} y={PAD.top + 3} fill="#64748b" fontSize="8" textAnchor="end">1.0</text>
      <text x={PAD.left - 4} y={PAD.top + INNER_H + 3} fill="#64748b" fontSize="8" textAnchor="end">0.0</text>

      {/* Trust score line */}
      <path d={linePath} fill="none" stroke="#06b6d4" strokeWidth="1.5" />

      {/* Event dots */}
      {dots.map((d, i) => (
        <circle
          key={i}
          cx={d.x}
          cy={d.y}
          r="3"
          fill={d.result === 'BLOCK' ? '#ef4444' : '#eab308'}
          stroke="#0f172a"
          strokeWidth="1"
        >
          <title>{`${d.result} — trust: ${d.score.toFixed(2)} — ${new Date(d.time).toLocaleString()}`}</title>
        </circle>
      ))}

      {/* X-axis labels */}
      {xLabels.map((l, i) => (
        <text key={i} x={l.x} y={HEIGHT - 4} fill="#64748b" fontSize="8" textAnchor="middle">{l.label}</text>
      ))}
    </svg>
  );
}
