'use client';

/**
 * UnifiedGraph — Ego-centric knowledge graph navigator
 *
 * Focuses on ONE entity at a time, showing its direct neighbours.
 * Click any neighbour to re-centre on it. Always readable (~25 nodes max).
 * Search to jump to any entity. Back button for navigation history.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type MutableRefObject, type ReactElement } from 'react';
import dynamic from 'next/dynamic';
import { Search, X, ArrowLeft, Globe, ChevronRight } from 'lucide-react';
import type {
  ForceGraphMethods,
  ForceGraphProps,
  GraphData,
  LinkObject,
  NodeObject,
} from 'react-force-graph-2d';
import { authFetch } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// ── Constants ──────────────────────────────────────────────

const ENTITY_COLORS: Record<string, string> = {
  tool: '#22d3ee',
  person: '#34d399',
  concept: '#f59e0b',
  language: '#a78bfa',
  file: '#64748b',
  service: '#f472b6',
  pattern: '#fb923c',
};

const PREDICATE_COLORS: Record<string, string> = {
  uses: '#22d3ee',
  implements: '#34d399',
  depends_on: '#f59e0b',
  related_to: '#475569',
  part_of: '#a78bfa',
  created_by: '#f472b6',
  extends: '#fb923c',
  replaces: '#ef4444',
  fixes: '#10b981',
  configures: '#6366f1',
  prefers: '#f59e0b',
  avoids: '#ef4444',
};

const PREDICATE_LABELS: Record<string, string> = {
  uses: 'uses',
  implements: 'implements',
  depends_on: 'depends on',
  related_to: 'related to',
  extends: 'extends',
  replaces: 'replaces',
  fixes: 'fixes',
  configures: 'configures',
  prefers: 'prefers',
  avoids: 'avoids',
};

const DEFAULT_COLOR = '#94a3b8';

// ── Types ──────────────────────────────────────────────────

interface Entity {
  id: number;
  name: string;
  type: string;
  memoryCount: number;
  aliases: string[];
}

interface Triple {
  id: number;
  subject_id: number;
  object_id: number;
  predicate: string;
  subject_name: string;
  subject_type: string;
  object_name: string;
  object_type: string;
}

interface LinkedMemory {
  id: number;
  title: string;
  type: string;
  category: string;
  salience: number;
  created_at: string;
}

interface NeighbourhoodData {
  focal: Entity;
  neighbours: Entity[];
  triples: Triple[];
  totalConnections: number;
}

interface GraphNode {
  id: number;
  name: string;
  entityType: string;
  memoryCount: number;
  isFocal: boolean;
  val: number;
}

interface GraphLink {
  source: number;
  target: number;
  predicate: string;
}

type ForceGraphRef = ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>>;
type ForceGraphComponentProps = ForceGraphProps<GraphNode, GraphLink> & {
  ref?: MutableRefObject<ForceGraphRef | undefined>;
};
type ForceGraphComponent = (props: ForceGraphComponentProps) => ReactElement;

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false }) as unknown as ForceGraphComponent;

// ── Component ──────────────────────────────────────────────

export default function UnifiedGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<ForceGraphRef | undefined>(undefined);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  // Navigation state
  const [focalId, setFocalId] = useState<number | null>(null);
  const [history, setHistory] = useState<number[]>([]);
  const [neighbourhood, setNeighbourhood] = useState<NeighbourhoodData | null>(null);
  const [memories, setMemories] = useState<LinkedMemory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<Entity[]>([]);
  const [showSearch, setShowSearch] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Top entities for initial landing
  const [topEntities, setTopEntities] = useState<Entity[]>([]);

  // ── Resize observer ──────────────────────────────────────
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setDimensions({ width: el.clientWidth, height: el.clientHeight });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // ── Navigation helper (defined before effects that use it) ─
  const navigateTo = useCallback((entityId: number) => {
    setFocalId(prev => {
      if (prev !== null && prev !== entityId) {
        setHistory(h => [...h, prev]);
      }
      return entityId;
    });
  }, []);

  // ── Load top entities on mount (landing page) ────────────
  useEffect(() => {
    authFetch(`${API_BASE}/api/graph/entities?limit=30`)
      .then(r => r.json())
      .then(data => {
        const ents = (data.entities || []) as Entity[];
        setTopEntities(ents);
        // Auto-focus on the entity with most memories
        if (ents.length > 0) {
          navigateTo(ents[0].id);
        }
        setLoading(false);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Fetch neighbourhood when focal changes ───────────────
  useEffect(() => {
    if (focalId === null) return;

    setLoading(true);
    Promise.all([
      authFetch(`${API_BASE}/api/graph/entities/${focalId}/neighbourhood`).then(r => r.json()),
      authFetch(`${API_BASE}/api/graph/entities/${focalId}/memories`).then(r => r.json()),
    ])
      .then(([nbData, memData]) => {
        setNeighbourhood(nbData as NeighbourhoodData);
        setMemories((memData.memories || []) as LinkedMemory[]);
        setLoading(false);
        setError(null);
      })
      .catch(err => {
        setError(err.message);
        setLoading(false);
      });
  }, [focalId]);

  // ── Centre graph after data loads ─────────────────────────
  useEffect(() => {
    if (!neighbourhood || !graphRef.current) return;
    const timer = setTimeout(() => {
      graphRef.current?.zoomToFit(400, 60);
    }, 500);
    return () => clearTimeout(timer);
  }, [neighbourhood]);

  const goBack = useCallback(() => {
    setHistory(h => {
      if (h.length === 0) return h;
      const prev = h[h.length - 1];
      setFocalId(prev);
      return h.slice(0, -1);
    });
  }, []);

  // ── Search ────────────────────────────────────────────────
  useEffect(() => {
    if (!searchQuery.trim()) {
      setSearchResults([]);
      return;
    }

    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => {
      authFetch(`${API_BASE}/api/graph/search?q=${encodeURIComponent(searchQuery)}&limit=8`)
        .then(r => r.json())
        .then(data => setSearchResults((data.entities || []) as Entity[]))
        .catch(() => {});
    }, 200);

    return () => {
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, [searchQuery]);

  // ── Build graph data ──────────────────────────────────────
  const graphData = useMemo<GraphData<GraphNode, GraphLink>>(() => {
    if (!neighbourhood) return { nodes: [], links: [] };

    const allEntities = [neighbourhood.focal, ...neighbourhood.neighbours];
    const maxCount = Math.max(1, ...allEntities.map(e => e.memoryCount));
    const nodeIds = new Set(allEntities.map(e => e.id));

    const nodes: GraphNode[] = allEntities.map(e => {
      const isFocal = e.id === neighbourhood.focal.id;
      const ratio = e.memoryCount / maxCount;
      return {
        id: e.id,
        name: e.name,
        entityType: e.type,
        memoryCount: e.memoryCount,
        isFocal,
        val: isFocal ? 25 : 6 + Math.pow(ratio, 0.5) * 14,
      };
    });

    const links: GraphLink[] = neighbourhood.triples
      .filter(t => nodeIds.has(t.subject_id) && nodeIds.has(t.object_id))
      .map(t => ({
        source: t.subject_id,
        target: t.object_id,
        predicate: t.predicate,
      }));

    // Deduplicate links (same source-target pair)
    const seen = new Set<string>();
    const uniqueLinks = links.filter(l => {
      const key = `${l.source}-${l.target}`;
      const rev = `${l.target}-${l.source}`;
      if (seen.has(key) || seen.has(rev)) return false;
      seen.add(key);
      return true;
    });

    return { nodes, links: uniqueLinks };
  }, [neighbourhood]);

  // ── Force config ──────────────────────────────────────────
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg || graphData.nodes.length === 0) return;

    fg.d3Force('charge')?.strength(-300);
    fg.d3Force('link')?.distance((link: GraphLink) => {
      return link.predicate === 'related_to' ? 120 : 90;
    });
    fg.d3ReheatSimulation();
  }, [graphData]);

  // ── Canvas render: nodes ──────────────────────────────────
  const nodeCanvasObject = useCallback(
    (node: GraphNode, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const x = (node as unknown as { x: number }).x;
      const y = (node as unknown as { y: number }).y;
      if (x == null || y == null) return;

      const color = ENTITY_COLORS[node.entityType] || DEFAULT_COLOR;
      const radius = Math.max(4, node.val);

      // Glow for focal node
      if (node.isFocal) {
        ctx.beginPath();
        ctx.arc(x, y, radius + 6, 0, 2 * Math.PI);
        ctx.fillStyle = color + '20';
        ctx.fill();
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, 2 * Math.PI);
      ctx.fillStyle = node.isFocal ? color : color + 'cc';
      ctx.fill();

      if (node.isFocal) {
        ctx.lineWidth = 3;
        ctx.strokeStyle = '#ffffff';
        ctx.stroke();
      }

      // Labels — always visible (we only have ~25 nodes)
      const maxChars = node.isFocal ? 40 : 22;
      const label = node.name.length > maxChars ? node.name.slice(0, maxChars) + '\u2026' : node.name;
      const fontSize = node.isFocal
        ? Math.max(14, 16 / globalScale)
        : Math.max(11, 13 / globalScale);
      ctx.font = `${node.isFocal ? 'bold ' : ''}${fontSize}px Sans-Serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';

      const textWidth = ctx.measureText(label).width;
      const textY = y + radius + 4;
      const padding = 3;

      // Label background
      ctx.fillStyle = 'rgba(2, 6, 23, 0.9)';
      ctx.beginPath();
      ctx.roundRect(
        x - textWidth / 2 - padding,
        textY - padding,
        textWidth + padding * 2,
        fontSize + padding * 2,
        3,
      );
      ctx.fill();

      ctx.fillStyle = node.isFocal ? '#ffffff' : '#cbd5e1';
      ctx.fillText(label, x, textY);

      // Memory count badge
      if (node.memoryCount > 1) {
        const badge = `${node.memoryCount}`;
        const badgeFontSize = Math.max(8, 10 / globalScale);
        ctx.font = `${badgeFontSize}px Sans-Serif`;
        const badgeWidth = ctx.measureText(badge).width + 6;
        const badgeX = x + radius - 2;
        const badgeY = y - radius - 2;

        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.roundRect(badgeX - badgeWidth / 2, badgeY - badgeFontSize / 2 - 2, badgeWidth, badgeFontSize + 4, 4);
        ctx.fill();

        ctx.fillStyle = '#020617';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(badge, badgeX, badgeY);
      }
    },
    [],
  );

  // ── Canvas render: links ──────────────────────────────────
  const linkCanvasObject = useCallback(
    (link: LinkObject<GraphNode, GraphLink>, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const source = link.source as unknown as { x: number; y: number };
      const target = link.target as unknown as { x: number; y: number };
      if (!source?.x || !target?.x) return;

      const isRelatedTo = link.predicate === 'related_to';

      // Line
      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.strokeStyle = PREDICATE_COLORS[link.predicate] || '#475569';
      ctx.lineWidth = isRelatedTo ? 0.8 : 2;
      ctx.globalAlpha = isRelatedTo ? 0.2 : 0.7;
      ctx.stroke();
      ctx.globalAlpha = 1;

      // Edge label (only for meaningful predicates, when zoomed enough)
      if (!isRelatedTo && globalScale > 0.8) {
        const midX = (source.x + target.x) / 2;
        const midY = (source.y + target.y) / 2;
        const label = PREDICATE_LABELS[link.predicate] || link.predicate;
        const fontSize = Math.max(8, 10 / globalScale);
        ctx.font = `${fontSize}px Sans-Serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';

        const tw = ctx.measureText(label).width;
        ctx.fillStyle = 'rgba(2, 6, 23, 0.85)';
        ctx.beginPath();
        ctx.roundRect(midX - tw / 2 - 2, midY - fontSize / 2 - 1, tw + 4, fontSize + 2, 2);
        ctx.fill();

        ctx.fillStyle = PREDICATE_COLORS[link.predicate] || '#94a3b8';
        ctx.globalAlpha = 0.8;
        ctx.fillText(label, midX, midY);
        ctx.globalAlpha = 1;
      }
    },
    [],
  );

  const nodeLabel = useCallback(
    (node: GraphNode) =>
      `${node.name}\n${node.entityType} \u00b7 ${node.memoryCount} memories\nClick to explore`,
    [],
  );

  // ── Click handler ─────────────────────────────────────────
  const handleNodeClick = useCallback((node: GraphNode) => {
    if (node.isFocal) return;
    navigateTo(node.id);
  }, [navigateTo]);

  // ── Empty state ───────────────────────────────────────────
  if (!loading && topEntities.length === 0 && !focalId) {
    return (
      <div className="w-full h-full flex items-center justify-center">
        <div className="text-center max-w-md">
          <div className="text-slate-600 text-4xl mb-4">&#x1f578;</div>
          <h3 className="text-lg font-medium text-slate-300 mb-2">No knowledge graph yet</h3>
          <p className="text-sm text-slate-500">
            As memories are created, ShieldCortex automatically extracts entities and relationships.
            The graph will appear here once entities are detected.
          </p>
        </div>
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────
  const focal = neighbourhood?.focal;
  const neighbours = neighbourhood?.neighbours || [];

  // Group neighbours by predicate for the sidebar
  const neighboursByRelation = (() => {
    if (!neighbourhood) return [];
    const groups = new Map<string, { predicate: string; neighbours: Entity[]; direction: 'out' | 'in' }>();

    for (const t of neighbourhood.triples) {
      const isSubject = t.subject_id === neighbourhood.focal.id;
      const neighbourId = isSubject ? t.object_id : t.subject_id;
      const neighbour = neighbourhood.neighbours.find(n => n.id === neighbourId);
      if (!neighbour) continue;

      const key = `${t.predicate}-${isSubject ? 'out' : 'in'}`;
      if (!groups.has(key)) {
        groups.set(key, { predicate: t.predicate, neighbours: [], direction: isSubject ? 'out' : 'in' });
      }
      const group = groups.get(key)!;
      if (!group.neighbours.find(n => n.id === neighbour.id)) {
        group.neighbours.push(neighbour);
      }
    }

    return [...groups.values()].sort((a, b) => {
      if (a.predicate === 'related_to' && b.predicate !== 'related_to') return 1;
      if (a.predicate !== 'related_to' && b.predicate === 'related_to') return -1;
      return b.neighbours.length - a.neighbours.length;
    });
  })();

  return (
    <div className="w-full h-full flex flex-col overflow-hidden">
      {/* Top bar */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-slate-800 bg-slate-900/50 shrink-0">
        <button
          onClick={goBack}
          disabled={history.length === 0}
          className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:cursor-default transition-colors"
          title="Go back"
        >
          <ArrowLeft size={16} />
        </button>

        {focal && (
          <div className="flex items-center gap-1.5 text-sm min-w-0">
            <div
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{ backgroundColor: ENTITY_COLORS[focal.type] || DEFAULT_COLOR }}
            />
            <span className="font-semibold text-white truncate">{focal.name}</span>
            <span className="text-slate-500 shrink-0">{focal.type}</span>
            <span className="text-slate-600 shrink-0">&middot;</span>
            <span className="text-slate-500 shrink-0">{focal.memoryCount} memories</span>
            {neighbourhood && (
              <>
                <span className="text-slate-600 shrink-0">&middot;</span>
                <span className="text-slate-500 shrink-0">{neighbours.length} connections</span>
              </>
            )}
          </div>
        )}

        <div className="flex-1" />

        {/* Search */}
        <div className="relative">
          <button
            onClick={() => {
              setShowSearch(!showSearch);
              setTimeout(() => searchRef.current?.focus(), 100);
            }}
            className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title="Search entities"
          >
            <Search size={16} />
          </button>

          {showSearch && (
            <div className="absolute right-0 top-full mt-1 w-72 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-30">
              <div className="relative">
                <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  ref={searchRef}
                  type="text"
                  placeholder="Search entities..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Escape') { setShowSearch(false); setSearchQuery(''); }
                  }}
                  className="w-full pl-8 pr-8 py-2 text-sm bg-transparent border-b border-slate-700 text-white placeholder:text-slate-500 focus:outline-none"
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white"
                  >
                    <X size={12} />
                  </button>
                )}
              </div>
              <div className="max-h-64 overflow-y-auto">
                {searchResults.length > 0 ? (
                  searchResults.map(e => (
                    <button
                      key={e.id}
                      onClick={() => {
                        navigateTo(e.id);
                        setShowSearch(false);
                        setSearchQuery('');
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-sm text-slate-300 hover:bg-slate-700 transition-colors"
                    >
                      <div
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{ backgroundColor: ENTITY_COLORS[e.type] || DEFAULT_COLOR }}
                      />
                      <span className="truncate flex-1 text-left">{e.name}</span>
                      <span className="text-xs text-slate-500 shrink-0">{e.type}</span>
                      <span className="text-xs text-slate-600 shrink-0">{e.memoryCount}</span>
                    </button>
                  ))
                ) : searchQuery.trim() ? (
                  <div className="px-3 py-4 text-xs text-slate-500 text-center">No entities found</div>
                ) : (
                  <div className="px-3 py-2 text-xs text-slate-600">Type to search...</div>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1 text-xs text-slate-600" title="Graph shows all projects">
          <Globe size={11} />
          <span>Workspace-wide</span>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left sidebar */}
        <div className="w-[240px] shrink-0 border-r border-slate-800 bg-slate-900/30 flex flex-col overflow-hidden">
          {/* Top entities quick-nav */}
          <div className="p-3 border-b border-slate-800">
            <div className="text-[10px] uppercase tracking-wider text-slate-600 mb-2">Top Entities</div>
            <div className="flex flex-wrap gap-1">
              {topEntities.slice(0, 12).map(e => (
                <button
                  key={e.id}
                  onClick={() => navigateTo(e.id)}
                  className={`flex items-center gap-1 px-2 py-0.5 text-xs rounded-full border transition-colors ${
                    focalId === e.id
                      ? 'border-transparent text-white'
                      : 'border-slate-700 text-slate-500 hover:text-slate-300 hover:border-slate-600'
                  }`}
                  style={focalId === e.id ? { backgroundColor: (ENTITY_COLORS[e.type] || DEFAULT_COLOR) + '40', color: ENTITY_COLORS[e.type] } : {}}
                >
                  <div
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ backgroundColor: ENTITY_COLORS[e.type] || DEFAULT_COLOR }}
                  />
                  {e.name}
                </button>
              ))}
            </div>
          </div>

          {/* Relationships list */}
          <div className="flex-1 overflow-y-auto">
            {neighboursByRelation.length > 0 ? (
              neighboursByRelation.map(group => (
                <div key={`${group.predicate}-${group.direction}`} className="border-b border-slate-800/50">
                  <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider font-medium"
                    style={{ color: PREDICATE_COLORS[group.predicate] || '#94a3b8' }}>
                    {group.direction === 'out' ? '' : '\u2190 '}{PREDICATE_LABELS[group.predicate] || group.predicate}
                    {group.direction === 'out' ? ' \u2192' : ''}
                    <span className="text-slate-600 ml-1">({group.neighbours.length})</span>
                  </div>
                  {group.neighbours.map(n => (
                    <button
                      key={n.id}
                      onClick={() => navigateTo(n.id)}
                      className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-slate-400 hover:text-white hover:bg-slate-800/50 transition-colors"
                    >
                      <div
                        className="w-1.5 h-1.5 rounded-full shrink-0"
                        style={{ backgroundColor: ENTITY_COLORS[n.type] || DEFAULT_COLOR }}
                      />
                      <span className="truncate flex-1 text-left">{n.name}</span>
                      <span className="text-slate-600 tabular-nums shrink-0">{n.memoryCount}</span>
                      <ChevronRight size={10} className="text-slate-700 shrink-0" />
                    </button>
                  ))}
                </div>
              ))
            ) : loading ? (
              <div className="p-4 text-xs text-slate-500 text-center animate-pulse">Loading...</div>
            ) : (
              <div className="p-4 text-xs text-slate-500 text-center">No connections</div>
            )}
          </div>

          {/* Memories panel */}
          {memories.length > 0 && (
            <div className="border-t border-slate-800 max-h-[200px] overflow-y-auto">
              <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-slate-600 sticky top-0 bg-slate-900/80 backdrop-blur-sm">
                Memories ({memories.length})
              </div>
              {memories.slice(0, 15).map(m => (
                <div key={m.id} className="px-3 py-1.5 border-b border-slate-800/30">
                  <div className="text-xs text-slate-300 truncate">{m.title}</div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] text-slate-500">{m.category}</span>
                    <span className="text-[10px] text-slate-600 ml-auto">
                      {new Date(m.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Graph canvas */}
        <div ref={containerRef} className="flex-1 min-h-0 relative">
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center z-10">
              <div className="text-slate-400 animate-pulse text-sm">Loading...</div>
            </div>
          )}
          {error && (
            <div className="absolute inset-0 flex items-center justify-center z-10">
              <div className="text-red-400 text-sm">Error: {error}</div>
            </div>
          )}
          {!loading && !error && graphData.nodes.length > 0 && dimensions.width > 0 && (
            <ForceGraph2D
              ref={graphRef}
              graphData={graphData}
              width={dimensions.width}
              height={dimensions.height}
              backgroundColor="rgba(0,0,0,0)"
              nodeCanvasObject={nodeCanvasObject}
              nodeLabel={nodeLabel}
              onNodeClick={handleNodeClick}
              linkCanvasObject={linkCanvasObject}
              linkDirectionalArrowLength={6}
              linkDirectionalArrowRelPos={0.85}
              d3AlphaDecay={0.05}
              d3VelocityDecay={0.3}
              warmupTicks={80}
              cooldownTicks={150}
            />
          )}
        </div>
      </div>
    </div>
  );
}
