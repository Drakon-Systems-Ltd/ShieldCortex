'use client';

import { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import { Search, X } from 'lucide-react';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import { ConstellationGraph } from './ConstellationGraph';
import { EntityDetail } from './EntityDetail';
import {
  useFullGraph,
  useEntityNeighbourhood,
  useEntityMemories,
  useGraphSearch,
  type GraphEntity,
} from '@/hooks/useGraphData';
import { useDebouncedValue } from '@/hooks/useDebouncedValue';

// ── Component ──────────────────────────────────────────────

export default function UnifiedGraph() {
  const [selectedEntity, setSelectedEntity] = useState<GraphEntity | null>(null);
  const [searchInput, setSearchInput] = useState('');
  const [showDropdown, setShowDropdown] = useState(false);
  const debouncedSearch = useDebouncedValue(searchInput, 250);

  // Graph container sizing
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const [graphSize, setGraphSize] = useState({ width: 600, height: 500 });

  useEffect(() => {
    const el = graphContainerRef.current;
    if (!el) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        setGraphSize({ width: Math.floor(width), height: Math.max(Math.floor(height), 500) });
      }
    });

    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // ── Data fetching ────────────────────────────────────────

  const { data: fullGraph, isLoading } = useFullGraph();
  const { data: neighbourhood } = useEntityNeighbourhood(selectedEntity?.id ?? null);
  const { data: memories } = useEntityMemories(selectedEntity?.id ?? null);
  const { data: searchResults } = useGraphSearch(debouncedSearch);

  // ── Handlers ─────────────────────────────────────────────

  const handleSelectEntity = useCallback((entity: GraphEntity | null) => {
    setSelectedEntity(entity);
  }, []);

  const handleNavigate = useCallback((entityId: string) => {
    // Find entity in full graph data
    const entity = fullGraph?.entities.find((e) => e.id === entityId);
    if (entity) setSelectedEntity(entity);
  }, [fullGraph]);

  const handleSearchSelect = useCallback(
    (entityId: string) => {
      const entity = fullGraph?.entities.find((e) => e.id === entityId);
      if (entity) setSelectedEntity(entity);
      setSearchInput('');
      setShowDropdown(false);
    },
    [fullGraph],
  );

  // ── Derived data ─────────────────────────────────────────

  const relatedEntities = useMemo(() => {
    if (!neighbourhood) return [];
    return neighbourhood.nodes
      .filter((n) => !n.isFocal)
      .sort((a, b) => b.memoryCount - a.memoryCount)
      .slice(0, 15)
      .map((n) => ({ id: n.id, label: n.name, type: n.type, memoryCount: n.memoryCount }));
  }, [neighbourhood]);

  const entityForDetail = selectedEntity
    ? { id: selectedEntity.id, label: selectedEntity.name, type: selectedEntity.type, memoryCount: selectedEntity.memoryCount }
    : null;

  // ── Render ───────────────────────────────────────────────

  const showSidebar = selectedEntity !== null;

  return (
    <div className="flex flex-col gap-4">
      {/* Search bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--sc-text-muted)]" />
          <input
            type="text"
            value={searchInput}
            onChange={(e) => {
              setSearchInput(e.target.value);
              setShowDropdown(true);
            }}
            onFocus={() => searchInput.trim() && setShowDropdown(true)}
            placeholder="Search entities..."
            className="glass-card w-full py-2.5 pl-10 pr-10 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-cyan)]/40"
          />
          {searchInput && (
            <button
              type="button"
              onClick={() => {
                setSearchInput('');
                setShowDropdown(false);
              }}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]"
            >
              <X className="h-4 w-4" />
            </button>
          )}

          {/* Search dropdown */}
          {showDropdown && searchResults && searchResults.length > 0 && (
            <div className="absolute left-0 right-0 top-full z-50 mt-1 glass-card-strong overflow-hidden py-1">
              {searchResults.map((e) => (
                <button
                  type="button"
                  key={e.id}
                  onClick={() => handleSearchSelect(e.id)}
                  className="flex w-full items-center justify-between px-4 py-2 text-left transition-colors hover:bg-[var(--sc-surface-interactive)]"
                >
                  <span className="truncate text-sm text-[var(--sc-text-primary)]">{e.name}</span>
                  <div className="flex items-center gap-2">
                    <Badge variant="muted" className="text-[10px]">{e.type}</Badge>
                    <span className="text-xs tabular-nums text-[var(--sc-text-muted)]">{e.memoryCount}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Main content — graph + optional detail sidebar */}
      <div className={`grid gap-4 ${showSidebar ? 'grid-cols-1 md:grid-cols-[1fr_340px]' : 'grid-cols-1'}`}>
        {/* Graph */}
        <GlassCard className="relative min-h-[500px] overflow-hidden border-0 p-0">
          {isLoading && (
            <div className="absolute inset-0 z-10 flex items-center justify-center bg-[var(--sc-bg-deep)]/60">
              <div className="h-6 w-6 animate-spin rounded-full border-2 border-[var(--sc-cyan)] border-t-transparent" />
            </div>
          )}
          <div ref={graphContainerRef} className="h-full w-full" style={{ minHeight: 500 }}>
            {fullGraph && (
              <ConstellationGraph
                clusters={fullGraph.clusters}
                allTriples={fullGraph.triples}
                totalEntities={fullGraph.entities.length}
                totalConnections={fullGraph.totalConnections}
                width={graphSize.width}
                height={graphSize.height}
                onSelectEntity={handleSelectEntity}
                selectedEntityId={selectedEntity?.id}
              />
            )}
          </div>
        </GlassCard>

        {/* Detail sidebar — only when an entity is selected */}
        {showSidebar && entityForDetail && (
          <div className="min-h-[500px]">
            <EntityDetail
              entity={entityForDetail}
              relatedEntities={relatedEntities}
              recentMemories={memories ?? []}
              onNavigate={handleNavigate}
            />
          </div>
        )}
      </div>
    </div>
  );
}
