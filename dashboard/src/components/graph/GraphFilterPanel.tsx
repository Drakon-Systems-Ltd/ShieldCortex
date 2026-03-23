'use client';

import { useState } from 'react';
import { Filter, X } from 'lucide-react';

const ENTITY_COLORS: Record<string, string> = {
  tool: '#22d3ee',
  person: '#34d399',
  concept: '#f59e0b',
  language: '#a78bfa',
  file: '#64748b',
  service: '#f472b6',
  pattern: '#fb923c',
};

interface GraphFilterPanelProps {
  entityTypes: string[];
  predicates: string[];
  visibleEntityTypes: Set<string>;
  visiblePredicates: Set<string>;
  onToggleEntityType: (type: string) => void;
  onToggleRelationship: (predicate: string) => void;
  onReset: () => void;
}

export default function GraphFilterPanel({
  entityTypes,
  predicates,
  visibleEntityTypes,
  visiblePredicates,
  onToggleEntityType,
  onToggleRelationship,
  onReset,
}: GraphFilterPanelProps) {
  const [isOpen, setIsOpen] = useState(false);

  if (!isOpen) {
    return (
      <button
        onClick={() => setIsOpen(true)}
        className="flex items-center gap-1.5 rounded-xl border border-slate-800 bg-slate-950/80 px-3 py-1.5 text-[11px] text-slate-400 backdrop-blur-sm transition-colors hover:border-slate-700 hover:text-slate-300"
      >
        <Filter size={13} />
        Filters
      </button>
    );
  }

  return (
    <div className="w-[220px] rounded-2xl border border-slate-800 bg-slate-950/90 p-4 backdrop-blur-sm">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Filters</span>
        <button onClick={() => setIsOpen(false)} className="text-slate-500 hover:text-slate-300">
          <X size={14} />
        </button>
      </div>

      {/* Entity types */}
      <div className="mb-3">
        <div className="mb-2 text-[10px] uppercase tracking-[0.15em] text-slate-600">Entity Types</div>
        <div className="flex flex-col gap-1.5">
          {entityTypes.map((type) => {
            const active = visibleEntityTypes.has(type);
            return (
              <label
                key={type}
                className={`flex cursor-pointer items-center gap-2 text-xs ${active ? 'text-slate-300' : 'text-slate-600 line-through'}`}
                onClick={() => onToggleEntityType(type)}
              >
                <span
                  className={`flex h-3.5 w-3.5 items-center justify-center rounded-sm border ${
                    active
                      ? 'border-cyan-400/60 bg-cyan-400/15 text-[9px] text-cyan-400'
                      : 'border-slate-700'
                  }`}
                >
                  {active && '✓'}
                </span>
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ background: active ? (ENTITY_COLORS[type] ?? '#94a3b8') : '#475569' }}
                />
                {type}
              </label>
            );
          })}
        </div>
      </div>

      {/* Relationships */}
      <div className="mb-3">
        <div className="mb-2 text-[10px] uppercase tracking-[0.15em] text-slate-600">Relationships</div>
        <div className="flex flex-col gap-1.5">
          {predicates.map((pred) => {
            const active = visiblePredicates.has(pred);
            return (
              <label
                key={pred}
                className={`flex cursor-pointer items-center gap-2 text-xs ${active ? 'text-slate-300' : 'text-slate-600 line-through'}`}
                onClick={() => onToggleRelationship(pred)}
              >
                <span
                  className={`flex h-3.5 w-3.5 items-center justify-center rounded-sm border ${
                    active
                      ? 'border-cyan-400/60 bg-cyan-400/15 text-[9px] text-cyan-400'
                      : 'border-slate-700'
                  }`}
                >
                  {active && '✓'}
                </span>
                {pred.replace(/_/g, ' ')}
              </label>
            );
          })}
        </div>
      </div>

      <div className="border-t border-slate-800 pt-2.5">
        <button
          onClick={onReset}
          className="w-full rounded-lg border border-slate-700 bg-transparent px-3 py-1.5 text-[11px] text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-300"
        >
          Reset filters
        </button>
      </div>
    </div>
  );
}
