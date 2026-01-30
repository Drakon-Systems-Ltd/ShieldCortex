'use client';

import { useState } from 'react';
import { Eye, Clock, Copy, AlertTriangle, ChevronDown, ChevronRight } from 'lucide-react';
import { useQuality, useContradictions } from '@/hooks/useMemories';

interface QualityPanelProps {
  project?: string;
}

function Section({
  icon: Icon,
  title,
  count,
  children,
}: {
  icon: React.ComponentType<{ className?: string; size?: number }>;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-slate-800 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-slate-800/50 transition-colors"
      >
        {expanded ? <ChevronDown size={14} className="text-slate-400" /> : <ChevronRight size={14} className="text-slate-400" />}
        <Icon size={14} className="text-slate-400" />
        <span className="text-sm text-slate-200 flex-1 text-left">{title}</span>
        <span className="text-xs px-1.5 py-0.5 rounded bg-slate-700 text-slate-300">{count}</span>
      </button>
      {expanded && <div className="px-3 pb-3 space-y-1">{children}</div>}
    </div>
  );
}

export function QualityPanel({ project }: QualityPanelProps) {
  const { data: quality } = useQuality(project);
  const { data: contradictionsData } = useContradictions(project);

  const neverAccessed = quality?.neverAccessed;
  const stale = quality?.stale;
  const duplicates = quality?.duplicates;
  const contradictions = contradictionsData?.contradictions ?? [];

  return (
    <div className="space-y-2">
      <Section icon={Eye} title="Never Accessed" count={neverAccessed?.count ?? 0}>
        {neverAccessed?.items?.length ? (
          neverAccessed.items.map((item, i) => (
            <div key={i} className="text-xs text-slate-400 py-1 border-b border-slate-800/50 last:border-0">
              <span className="text-slate-300">{String(item.title || 'Untitled')}</span>
              {item.created_at ? (
                <span className="ml-2 text-slate-500">{String(item.created_at).slice(0, 10)}</span>
              ) : null}
            </div>
          ))
        ) : (
          <div className="text-xs text-slate-500">None found</div>
        )}
      </Section>

      <Section icon={Clock} title="Stale Memories" count={stale?.count ?? 0}>
        {stale?.items?.length ? (
          stale.items.map((item, i) => {
            const score = Number(item.decayed_score ?? 0);
            const color = score < 0.3 ? 'text-red-400' : score < 0.5 ? 'text-amber-400' : 'text-slate-400';
            return (
              <div key={i} className="text-xs text-slate-400 py-1 border-b border-slate-800/50 last:border-0 flex items-center gap-2">
                <span className={`${color} font-mono`}>{score.toFixed(2)}</span>
                <span className="text-slate-300">{String(item.title || 'Untitled')}</span>
              </div>
            );
          })
        ) : (
          <div className="text-xs text-slate-500">None found</div>
        )}
      </Section>

      <Section icon={Copy} title="Duplicates" count={duplicates?.count ?? 0}>
        {duplicates?.items?.length ? (
          duplicates.items.map((item, i) => (
            <div key={i} className="text-xs text-slate-400 py-1 border-b border-slate-800/50 last:border-0">
              <span className="text-slate-300">{String(item.title_a || 'Untitled')}</span>
              <span className="mx-1 text-slate-600">&harr;</span>
              <span className="text-slate-300">{String(item.title_b || 'Untitled')}</span>
            </div>
          ))
        ) : (
          <div className="text-xs text-slate-500">None found</div>
        )}
      </Section>

      <Section icon={AlertTriangle} title="Contradictions" count={contradictions.length}>
        {contradictions.length ? (
          contradictions.map((c, i) => (
            <div key={i} className="text-xs py-1 border-b border-slate-800/50 last:border-0">
              <div className="flex items-center gap-2 text-slate-400">
                <span className="font-mono text-amber-400">{c.score.toFixed(2)}</span>
                <span className="text-slate-300">{c.memoryATitle}</span>
                <span className="text-slate-600">&harr;</span>
                <span className="text-slate-300">{c.memoryBTitle}</span>
              </div>
              {c.reason && <div className="text-slate-500 mt-0.5 ml-10">{c.reason}</div>}
            </div>
          ))
        ) : (
          <div className="text-xs text-slate-500">None found</div>
        )}
      </Section>
    </div>
  );
}
