'use client';

import { useMemo } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { getCategoryColor } from '@/lib/category-colors';
import type { MemoryStats, MemoryCategory } from '@/types/memory';

interface KnowledgeMapPanelProps {
  stats: MemoryStats;
  onNavigate: (filter: { category?: string }) => void;
}

export function KnowledgeMapPanel({ stats, onNavigate }: KnowledgeMapPanelProps) {
  const data = useMemo(() => {
    return Object.entries(stats.byCategory)
      .map(([category, count]) => ({
        category,
        count,
        color: getCategoryColor(category as MemoryCategory),
        thin: count < 3,
      }))
      .sort((a, b) => b.count - a.count);
  }, [stats.byCategory]);

  if (data.length === 0) {
    return (
      <div className="bg-slate-900/50 rounded-lg p-4 text-slate-400 text-sm">
        No category data available.
      </div>
    );
  }

  return (
    <div className="bg-slate-900/50 rounded-lg p-4">
      <ResponsiveContainer width="100%" height={data.length * 36 + 20}>
        <BarChart data={data} layout="vertical" margin={{ left: 10, right: 30 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="category"
            width={100}
            tick={{ fill: '#94a3b8', fontSize: 12 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
            labelStyle={{ color: '#e2e8f0' }}
            itemStyle={{ color: '#e2e8f0' }}
          />
          <Bar
            dataKey="count"
            radius={[0, 4, 4, 0]}
            cursor="pointer"
            onClick={(_data, index) => {
              if (index !== undefined && data[index]) {
                onNavigate({ category: data[index].category });
              }
            }}
          >
            {data.map((entry, index) => (
              <Cell key={index} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* Thin coverage warnings */}
      {data.some(d => d.thin) && (
        <div className="mt-2 flex flex-wrap gap-2">
          {data.filter(d => d.thin).map(d => (
            <span key={d.category} className="text-xs text-amber-400 bg-amber-400/10 px-2 py-0.5 rounded">
              ⚠ {d.category} ({d.count})
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
