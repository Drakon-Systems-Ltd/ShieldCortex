'use client';

/**
 * UnifiedGraph — Ego-centric knowledge graph navigator
 *
 * Focuses on ONE entity at a time, showing its direct neighbours.
 * Click any neighbour to re-centre on it. Always readable (~25 nodes max).
 * Search to jump to any entity. Back button for navigation history.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent, type MutableRefObject, type ReactElement, type WheelEvent } from 'react';
import dynamic from 'next/dynamic';
import { Search, X, ArrowLeft, Globe, ChevronRight, Network, ListTree, Sparkles } from 'lucide-react';
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
  x?: number;
  y?: number;
  fx?: number;
  fy?: number;
  labelDirection?: 'left' | 'right' | 'center';
}

interface GraphLink {
  source: number;
  target: number;
  predicate: string;
}

type DisplayMode = 'outline' | 'map' | 'fractal';

interface BloomNode {
  id: number;
  name: string;
  entityType: string;
  memoryCount: number;
  x: number;
  y: number;
  radius: number;
}

interface BloomBranch {
  key: string;
  label: string;
  color: string;
  petalPath: string;
  stemPath: string;
  labelX: number;
  labelY: number;
  nodeStems: Array<{ key: string; path: string }>;
  nodes: BloomNode[];
}

interface BloomLayout {
  width: number;
  height: number;
  centerX: number;
  centerY: number;
  focalRadius: number;
  focalGlowRadius: number;
  branches: BloomBranch[];
  crossLinks: Array<{ key: string; path: string; color: string }>;
}

type ForceGraphRef = ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>>;
type ForceGraphComponentProps = ForceGraphProps<GraphNode, GraphLink> & {
  ref?: MutableRefObject<ForceGraphRef | undefined>;
};
type ForceGraphComponent = (props: ForceGraphComponentProps) => ReactElement;

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false }) as unknown as ForceGraphComponent;

function polarToCartesian(centerX: number, centerY: number, radius: number, angle: number) {
  return {
    x: centerX + Math.cos(angle) * radius,
    y: centerY + Math.sin(angle) * radius,
  };
}

// ── Component ──────────────────────────────────────────────

export default function UnifiedGraph() {
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<ForceGraphRef | undefined>(undefined);
  const bloomDragRef = useRef<{ startX: number; startY: number; offsetX: number; offsetY: number } | null>(null);
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
  const [displayMode, setDisplayMode] = useState<DisplayMode>('outline');
  const [bloomViewport, setBloomViewport] = useState({ scale: 1, offsetX: 0, offsetY: 0 });
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

  useEffect(() => {
    setBloomViewport({ scale: 1, offsetX: 0, offsetY: 0 });
    bloomDragRef.current = null;
  }, [displayMode, focalId]);

  const goBack = useCallback(() => {
    setHistory(h => {
      if (h.length === 0) return h;
      const prev = h[h.length - 1];
      setFocalId(prev);
      return h.slice(0, -1);
    });
  }, []);

  const handleBloomWheel = useCallback((event: WheelEvent<SVGSVGElement>) => {
    event.preventDefault();

    const rect = event.currentTarget.getBoundingClientRect();
    const pointerX = event.clientX - rect.left;
    const pointerY = event.clientY - rect.top;

    setBloomViewport((current) => {
      const zoomFactor = event.deltaY < 0 ? 1.12 : 0.9;
      const nextScale = Math.min(2.6, Math.max(0.65, current.scale * zoomFactor));
      if (Math.abs(nextScale - current.scale) < 0.0001) return current;

      const nextOffsetX = pointerX - ((pointerX - current.offsetX) * nextScale) / current.scale;
      const nextOffsetY = pointerY - ((pointerY - current.offsetY) * nextScale) / current.scale;

      return {
        scale: nextScale,
        offsetX: nextOffsetX,
        offsetY: nextOffsetY,
      };
    });
  }, []);

  const handleBloomMouseDown = useCallback((event: MouseEvent<SVGSVGElement>) => {
    bloomDragRef.current = {
      startX: event.clientX,
      startY: event.clientY,
      offsetX: bloomViewport.offsetX,
      offsetY: bloomViewport.offsetY,
    };
  }, [bloomViewport.offsetX, bloomViewport.offsetY]);

  const handleBloomMouseMove = useCallback((event: MouseEvent<SVGSVGElement>) => {
    const drag = bloomDragRef.current;
    if (!drag) return;

    setBloomViewport((current) => ({
      ...current,
      offsetX: drag.offsetX + (event.clientX - drag.startX),
      offsetY: drag.offsetY + (event.clientY - drag.startY),
    }));
  }, []);

  const endBloomDrag = useCallback(() => {
    bloomDragRef.current = null;
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

    const neighbourMeta = neighbourhood.neighbours.map((entity) => {
      const relatedTriples = neighbourhood.triples.filter((triple) =>
        triple.subject_id === entity.id || triple.object_id === entity.id,
      );
      const meaningfulTriples = relatedTriples.filter((triple) => triple.predicate !== 'related_to');
      const strongestPredicate = meaningfulTriples[0]?.predicate ?? relatedTriples[0]?.predicate ?? 'related_to';
      const score = entity.memoryCount * 10 + meaningfulTriples.length * 50 + relatedTriples.length;
      return {
        entity,
        strongestPredicate,
        hasMeaningfulLink: meaningfulTriples.length > 0,
        score,
      };
    });

    const prioritizedNeighbours = [
      ...neighbourMeta
        .filter((item) => item.hasMeaningfulLink)
        .sort((a, b) => b.score - a.score)
        .slice(0, 10),
      ...neighbourMeta
        .filter((item) => !item.hasMeaningfulLink)
        .sort((a, b) => b.score - a.score)
        .slice(0, 6),
    ];

    const visibleNeighbourIds = new Set(prioritizedNeighbours.map((item) => item.entity.id));
    const visibleEntities = [neighbourhood.focal, ...neighbourhood.neighbours.filter((entity) => visibleNeighbourIds.has(entity.id))];
    const maxCount = Math.max(1, ...visibleEntities.map((entity) => entity.memoryCount));
    const nodeIds = new Set(visibleEntities.map((entity) => entity.id));

    const positionedNodes = new Map<number, GraphNode>();
    positionedNodes.set(neighbourhood.focal.id, {
      id: neighbourhood.focal.id,
      name: neighbourhood.focal.name,
      entityType: neighbourhood.focal.type,
      memoryCount: neighbourhood.focal.memoryCount,
      isFocal: true,
      val: 28,
      x: 0,
      y: 0,
      fx: 0,
      fy: 0,
      labelDirection: 'center',
    });

    const setNode = (item: typeof prioritizedNeighbours[number], x: number, y: number) => {
      const ratio = item.entity.memoryCount / maxCount;
      positionedNodes.set(item.entity.id, {
        id: item.entity.id,
        name: item.entity.name,
        entityType: item.entity.type,
        memoryCount: item.entity.memoryCount,
        isFocal: false,
        val: 7 + Math.pow(ratio, 0.6) * 14,
        x,
        y,
        fx: x,
        fy: y,
        labelDirection: Math.abs(x) < 40 ? 'center' : (x > 0 ? 'right' : 'left'),
      });
    };

    if (displayMode === 'fractal') {
      const branchGroups = [...prioritizedNeighbours.reduce((map, item) => {
        const key = item.hasMeaningfulLink ? item.strongestPredicate : `ambient:${item.entity.type}`;
        if (!map.has(key)) {
          map.set(key, []);
        }
        map.get(key)!.push(item);
        return map;
      }, new Map<string, typeof prioritizedNeighbours>()).entries()]
        .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));

      branchGroups.forEach(([, items], branchIndex) => {
        const baseAngle = -Math.PI / 2 + (branchIndex / Math.max(branchGroups.length, 1)) * Math.PI * 2;
        items
          .sort((a, b) => b.score - a.score)
          .forEach((item, itemIndex) => {
            const wave = itemIndex === 0 ? 0 : (Math.ceil(itemIndex / 2) * 0.18) * (itemIndex % 2 === 0 ? -1 : 1);
            const branchAngle = baseAngle + wave;
            const radius = 165 + itemIndex * 78;
            const curl = (itemIndex % 3 === 0 ? 1 : -1) * (12 + itemIndex * 4);
            const x = Math.cos(branchAngle) * radius + Math.cos(branchAngle + Math.PI / 2) * curl;
            const y = Math.sin(branchAngle) * radius + Math.sin(branchAngle + Math.PI / 2) * curl;
            setNode(item, x, y);
          });
      });
    } else {
      const innerRing = prioritizedNeighbours.filter((item) => item.hasMeaningfulLink);
      const outerRing = prioritizedNeighbours.filter((item) => !item.hasMeaningfulLink);

      const placeRing = (
        ring: typeof prioritizedNeighbours,
        radiusX: number,
        radiusY: number,
      ) => {
        ring.forEach((item, index) => {
          const angle = ring.length === 1
            ? -Math.PI / 2
            : -Math.PI / 2 + (index / ring.length) * Math.PI * 2;
          const x = Math.cos(angle) * radiusX;
          const y = Math.sin(angle) * radiusY;
          setNode(item, x, y);
        });
      };

      placeRing(innerRing, 250, 180);
      placeRing(outerRing, 360, 255);
    }

    const nodes = [...positionedNodes.values()];

    const links: GraphLink[] = neighbourhood.triples
      .filter((triple) => nodeIds.has(triple.subject_id) && nodeIds.has(triple.object_id))
      .filter((triple) => triple.predicate !== 'related_to' || triple.subject_id === neighbourhood.focal.id || triple.object_id === neighbourhood.focal.id)
      .map((triple) => ({
        source: triple.subject_id,
        target: triple.object_id,
        predicate: triple.predicate,
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
  }, [displayMode, neighbourhood]);

  // ── Force config ──────────────────────────────────────────
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg || graphData.nodes.length === 0) return;

    fg.d3Force('charge')?.strength(0);
    fg.d3Force('center', null);
    fg.d3Force('link')?.distance((link: GraphLink) => {
      return link.predicate === 'related_to' ? 160 : 120;
    });
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
      const labelDirection = node.labelDirection ?? 'center';
      const isLeft = labelDirection === 'left';
      const isRight = labelDirection === 'right';
      const labelX = isLeft ? x - radius - 10 : isRight ? x + radius + 10 : x;
      const labelY = labelDirection === 'center' ? y + radius + 6 : y - fontSize / 2;
      ctx.textAlign = isLeft ? 'right' : isRight ? 'left' : 'center';
      ctx.textBaseline = labelDirection === 'center' ? 'top' : 'middle';

      const textWidth = ctx.measureText(label).width;
      const padding = 3;
      const textBoxX = isLeft
        ? labelX - textWidth - padding
        : isRight
          ? labelX - padding
          : labelX - textWidth / 2 - padding;
      const textBoxY = labelDirection === 'center'
        ? labelY - padding
        : labelY - fontSize / 2 - padding;

      // Label background
      ctx.fillStyle = 'rgba(2, 6, 23, 0.9)';
      ctx.beginPath();
      ctx.roundRect(
        textBoxX,
        textBoxY,
        textWidth + padding * 2,
        fontSize + padding * 2,
        3,
      );
      ctx.fill();

      ctx.fillStyle = node.isFocal ? '#ffffff' : '#cbd5e1';
      ctx.fillText(label, labelX, labelY);

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

      const isFractal = displayMode === 'fractal';
      const midX = (source.x + target.x) / 2;
      const midY = (source.y + target.y) / 2;
      const controlStrength = isFractal ? 0.14 : 0;
      const controlX = midX + (midX * controlStrength);
      const controlY = midY + (midY * controlStrength);

      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      if (isFractal) {
        ctx.quadraticCurveTo(controlX, controlY, target.x, target.y);
      } else {
        ctx.lineTo(target.x, target.y);
      }
      ctx.strokeStyle = PREDICATE_COLORS[link.predicate] || '#475569';
      ctx.lineWidth = isRelatedTo ? (isFractal ? 0.7 : 0.8) : (isFractal ? 1.7 : 2);
      ctx.globalAlpha = isRelatedTo ? (isFractal ? 0.12 : 0.2) : (isFractal ? 0.62 : 0.7);
      ctx.stroke();
      ctx.globalAlpha = 1;

      // Edge label (only for meaningful predicates, when zoomed enough)
      if (!isRelatedTo && globalScale > 0.8) {
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
    [displayMode],
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

  // ── Render helpers ────────────────────────────────────────
  const focal = neighbourhood?.focal;
  const neighbours = neighbourhood?.neighbours || [];
  const relationshipRows = useMemo(() => {
    if (!neighbourhood) return [];

    return neighbourhood.triples
      .map((triple) => {
        const outgoing = triple.subject_id === neighbourhood.focal.id;
        const neighbourId = outgoing ? triple.object_id : triple.subject_id;
        const neighbour = neighbourhood.neighbours.find((candidate) => candidate.id === neighbourId);
        if (!neighbour) return null;

        return {
          key: triple.id,
          direction: outgoing ? 'out' : 'in',
          predicate: triple.predicate,
          sentence: outgoing
            ? `${neighbourhood.focal.name} ${PREDICATE_LABELS[triple.predicate] || triple.predicate} ${neighbour.name}`
            : `${neighbour.name} ${PREDICATE_LABELS[triple.predicate] || triple.predicate} ${neighbourhood.focal.name}`,
          neighbour,
        };
      })
      .filter((row): row is {
        key: number;
        direction: 'out' | 'in';
        predicate: string;
        sentence: string;
        neighbour: Entity;
      } => Boolean(row))
      .sort((a, b) => {
        if (a.predicate === 'related_to' && b.predicate !== 'related_to') return 1;
        if (a.predicate !== 'related_to' && b.predicate === 'related_to') return -1;
        return b.neighbour.memoryCount - a.neighbour.memoryCount;
      });
  }, [neighbourhood]);

  const bloomLayout = useMemo<BloomLayout | null>(() => {
    if (!neighbourhood || dimensions.width <= 0 || dimensions.height <= 0) return null;

    const width = Math.max(dimensions.width, 900);
    const height = Math.max(dimensions.height, 620);
    const centerX = width * 0.5;
    const centerY = height * 0.72;

    const neighbourMeta = neighbourhood.neighbours.map((entity) => {
      const relatedTriples = neighbourhood.triples.filter((triple) =>
        triple.subject_id === entity.id || triple.object_id === entity.id,
      );
      const meaningfulTriples = relatedTriples.filter((triple) => triple.predicate !== 'related_to');
      const strongestPredicate = meaningfulTriples[0]?.predicate ?? relatedTriples[0]?.predicate ?? entity.type;
      const score = entity.memoryCount * 10 + meaningfulTriples.length * 48 + relatedTriples.length;
      return {
        entity,
        strongestPredicate,
        score,
      };
    });

    const prioritized = neighbourMeta
      .sort((a, b) => b.score - a.score)
      .slice(0, 16);

    const grouped = prioritized.reduce((map, item) => {
      const key = item.strongestPredicate;
      if (!map.has(key)) {
        map.set(key, []);
      }
      map.get(key)!.push(item);
      return map;
    }, new Map<string, typeof prioritized>());

    const branchEntries = [...grouped.entries()]
      .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
      .slice(0, 6);

    const maxCount = Math.max(1, neighbourhood.focal.memoryCount, ...prioritized.map((item) => item.entity.memoryCount));
    const branches: BloomBranch[] = branchEntries.map(([key, items], branchIndex) => {
      const color = PREDICATE_COLORS[key] || ENTITY_COLORS[items[0]?.entity.type || 'tool'] || DEFAULT_COLOR;
      const angle = branchEntries.length === 1
        ? -Math.PI / 2
        : (-Math.PI * 0.88) + (branchIndex / (branchEntries.length - 1)) * (Math.PI * 0.76);
      const petalLength = 210 + items.length * 18;
      const petalWidth = Math.min(0.24, 0.1 + items.length * 0.015);

      const startLeft = polarToCartesian(centerX, centerY, 44, angle - 0.08);
      const startRight = polarToCartesian(centerX, centerY, 44, angle + 0.08);
      const leftMid = polarToCartesian(centerX, centerY, petalLength * 0.62, angle - petalWidth);
      const rightMid = polarToCartesian(centerX, centerY, petalLength * 0.62, angle + petalWidth);
      const tip = polarToCartesian(centerX, centerY, petalLength, angle);
      const stemControl = polarToCartesian(centerX, centerY, petalLength * 0.42, angle);
      const branchAnchor = polarToCartesian(centerX, centerY, petalLength * 0.35, angle);

      const nodes: BloomNode[] = items.map((item, itemIndex) => {
        const ratio = item.entity.memoryCount / maxCount;
        const branchOffset = itemIndex === 0
          ? 0
          : Math.ceil(itemIndex / 2) * 0.13 * (itemIndex % 2 === 0 ? -1 : 1);
        const radius = 118 + itemIndex * 50;
        const bloomAngle = angle + branchOffset;
        const sway = 8 + itemIndex * 3;
        const anchor = polarToCartesian(centerX, centerY, radius, bloomAngle);
        const drift = polarToCartesian(0, 0, sway, bloomAngle + Math.PI / 2);
        return {
          id: item.entity.id,
          name: item.entity.name,
          entityType: item.entity.type,
          memoryCount: item.entity.memoryCount,
          x: anchor.x + drift.x,
          y: anchor.y + drift.y,
          radius: 8 + Math.pow(ratio, 0.55) * 12,
        };
      });

      const nodeStems = nodes.map((node, nodeIndex) => {
        const split = polarToCartesian(
          branchAnchor.x,
          branchAnchor.y,
          18 + nodeIndex * 8,
          angle + (nodeIndex === 0 ? 0 : (nodeIndex % 2 === 0 ? -0.18 : 0.18)),
        );
        return {
          key: `${key}-${node.id}`,
          path: `M ${branchAnchor.x} ${branchAnchor.y} Q ${split.x} ${split.y} ${node.x} ${node.y}`,
        };
      });

      return {
        key,
        label: PREDICATE_LABELS[key] || key.replace(/_/g, ' '),
        color,
        petalPath: [
          `M ${startLeft.x} ${startLeft.y}`,
          `Q ${leftMid.x} ${leftMid.y} ${tip.x} ${tip.y}`,
          `Q ${rightMid.x} ${rightMid.y} ${startRight.x} ${startRight.y}`,
          `Q ${centerX} ${centerY} ${startLeft.x} ${startLeft.y}`,
          'Z',
        ].join(' '),
        stemPath: [
          `M ${centerX} ${centerY}`,
          `Q ${stemControl.x} ${stemControl.y} ${tip.x} ${tip.y}`,
        ].join(' '),
        labelX: tip.x,
        labelY: tip.y - 10,
        nodeStems,
        nodes,
      };
    });

    const nodeLookup = new Map<number, BloomNode>();
    branches.forEach((branch) => {
      branch.nodes.forEach((node) => nodeLookup.set(node.id, node));
    });

    const visibleNodeIds = new Set(nodeLookup.keys());
    const crossLinks = neighbourhood.triples
      .filter((triple) =>
        visibleNodeIds.has(triple.subject_id) &&
        visibleNodeIds.has(triple.object_id) &&
        triple.subject_id !== neighbourhood.focal.id &&
        triple.object_id !== neighbourhood.focal.id &&
        triple.predicate !== 'related_to',
      )
      .slice(0, 10)
      .map((triple) => {
        const source = nodeLookup.get(triple.subject_id)!;
        const target = nodeLookup.get(triple.object_id)!;
        const control = polarToCartesian(
          centerX,
          centerY,
          Math.max(
            Math.hypot(source.x - centerX, source.y - centerY),
            Math.hypot(target.x - centerX, target.y - centerY),
          ) + 55,
          Math.atan2((source.y + target.y) / 2 - centerY, (source.x + target.x) / 2 - centerX),
        );

        return {
          key: `${triple.id}`,
          color: PREDICATE_COLORS[triple.predicate] || DEFAULT_COLOR,
          path: `M ${source.x} ${source.y} Q ${control.x} ${control.y} ${target.x} ${target.y}`,
        };
      });

    return {
      width,
      height,
      centerX,
      centerY,
      focalRadius: 30,
      focalGlowRadius: 46,
      branches,
      crossLinks,
    };
  }, [dimensions.height, dimensions.width, neighbourhood]);

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

        <div className="flex items-center rounded-lg border border-slate-700 bg-slate-900/80 p-0.5">
          <button
            onClick={() => setDisplayMode('outline')}
            className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs transition-colors ${
              displayMode === 'outline'
                ? 'bg-cyan-500/15 text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Readable relationship outline"
          >
            <ListTree size={12} />
            Read
          </button>
          <button
            onClick={() => setDisplayMode('map')}
            className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs transition-colors ${
              displayMode === 'map'
                ? 'bg-cyan-500/15 text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Graph canvas"
          >
            <Network size={12} />
            Map
          </button>
          <button
            onClick={() => setDisplayMode('fractal')}
            className={`flex items-center gap-1 rounded-md px-2 py-1 text-xs transition-colors ${
              displayMode === 'fractal'
                ? 'bg-cyan-500/15 text-cyan-300'
                : 'text-slate-400 hover:text-slate-200'
            }`}
            title="Fractal bloom layout"
          >
            <Sparkles size={12} />
            Bloom
          </button>
        </div>

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

        {displayMode === 'outline' ? (
          <div className="flex-1 min-h-0 overflow-y-auto bg-slate-950/20">
            {loading && (
              <div className="h-full flex items-center justify-center">
                <div className="text-slate-400 animate-pulse text-sm">Loading...</div>
              </div>
            )}
            {error && (
              <div className="h-full flex items-center justify-center">
                <div className="text-red-400 text-sm">Error: {error}</div>
              </div>
            )}
            {!loading && !error && focal && (
              <div className="mx-auto flex max-w-6xl flex-col gap-4 p-4">
                <div className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
                  <section className="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="text-[10px] uppercase tracking-[0.28em] text-slate-600">Focused Entity</div>
                        <div className="mt-2 flex items-center gap-2">
                          <div
                            className="h-3 w-3 rounded-full"
                            style={{ backgroundColor: ENTITY_COLORS[focal.type] || DEFAULT_COLOR }}
                          />
                          <h2 className="text-2xl font-semibold text-white">{focal.name}</h2>
                          <span className="rounded-full border border-slate-700 px-2 py-0.5 text-xs text-slate-400">
                            {focal.type}
                          </span>
                        </div>
                        {focal.aliases.length > 0 && (
                          <div className="mt-3 flex flex-wrap gap-1">
                            {focal.aliases.slice(0, 8).map((alias) => (
                              <span key={alias} className="rounded-full bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300">
                                {alias}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      <div className="grid grid-cols-2 gap-2 text-right">
                        <div className="rounded-xl border border-slate-800 bg-slate-950/50 px-3 py-2">
                          <div className="text-[10px] uppercase tracking-[0.22em] text-slate-600">Memories</div>
                          <div className="mt-1 text-xl font-semibold text-white">{focal.memoryCount}</div>
                        </div>
                        <div className="rounded-xl border border-slate-800 bg-slate-950/50 px-3 py-2">
                          <div className="text-[10px] uppercase tracking-[0.22em] text-slate-600">Direct Links</div>
                          <div className="mt-1 text-xl font-semibold text-white">{relationshipRows.length}</div>
                        </div>
                      </div>
                    </div>
                  </section>

                  <section className="rounded-2xl border border-slate-800 bg-slate-900/40 p-4">
                    <div className="text-[10px] uppercase tracking-[0.28em] text-slate-600">How To Read This</div>
                    <div className="mt-3 space-y-3 text-sm text-slate-300">
                      <p>This view turns the graph into readable statements and evidence instead of relying on overlapping labels.</p>
                      <p>Click any related entity to recenter the graph. Use <span className="font-medium text-cyan-300">Map</span> when you want spatial context, and <span className="font-medium text-cyan-300">Read</span> when you want meaning.</p>
                    </div>
                  </section>
                </div>

                <div className="grid gap-4 xl:grid-cols-[1.15fr_0.85fr]">
                  <section className="rounded-2xl border border-slate-800 bg-slate-900/30 p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-[10px] uppercase tracking-[0.28em] text-slate-600">Relationship Outline</div>
                        <div className="mt-1 text-sm text-slate-400">Readable connections grouped by meaning instead of force layout.</div>
                      </div>
                      <div className="text-xs text-slate-500">{relationshipRows.length} statements</div>
                    </div>

                    <div className="mt-4 space-y-4">
                      {neighboursByRelation.length > 0 ? neighboursByRelation.map((group) => {
                        const rows = relationshipRows.filter(
                          (row) => row.predicate === group.predicate && row.direction === group.direction,
                        );
                        return (
                          <div key={`${group.predicate}-${group.direction}`} className="rounded-xl border border-slate-800 bg-slate-950/40">
                            <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
                              <div className="text-sm font-medium" style={{ color: PREDICATE_COLORS[group.predicate] || '#94a3b8' }}>
                                {group.direction === 'out' ? `${focal.name} ${PREDICATE_LABELS[group.predicate] || group.predicate}...` : `... ${PREDICATE_LABELS[group.predicate] || group.predicate} ${focal.name}`}
                              </div>
                              <div className="text-xs text-slate-500">{rows.length}</div>
                            </div>
                            <div className="divide-y divide-slate-800/80">
                              {rows.map((row) => (
                                <button
                                  key={row.key}
                                  onClick={() => navigateTo(row.neighbour.id)}
                                  className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-900/60"
                                >
                                  <div
                                    className="h-2.5 w-2.5 rounded-full shrink-0"
                                    style={{ backgroundColor: ENTITY_COLORS[row.neighbour.type] || DEFAULT_COLOR }}
                                  />
                                  <div className="min-w-0 flex-1">
                                    <div className="truncate text-sm text-white">{row.sentence}</div>
                                    <div className="mt-1 flex items-center gap-2 text-[11px] text-slate-500">
                                      <span>{row.neighbour.type}</span>
                                      <span>&middot;</span>
                                      <span>{row.neighbour.memoryCount} memories</span>
                                    </div>
                                  </div>
                                  <ChevronRight size={14} className="shrink-0 text-slate-600" />
                                </button>
                              ))}
                            </div>
                          </div>
                        );
                      }) : (
                        <div className="rounded-xl border border-dashed border-slate-800 px-4 py-8 text-center text-sm text-slate-500">
                          No direct relationships for this entity yet.
                        </div>
                      )}
                    </div>
                  </section>

                  <section className="rounded-2xl border border-slate-800 bg-slate-900/30 p-4">
                    <div className="text-[10px] uppercase tracking-[0.28em] text-slate-600">Evidence Memories</div>
                    <div className="mt-1 text-sm text-slate-400">The actual memories backing this node and its relationships.</div>
                    <div className="mt-4 space-y-3">
                      {memories.length > 0 ? memories.map((memory) => (
                        <div key={memory.id} className="rounded-xl border border-slate-800 bg-slate-950/50 px-4 py-3">
                          <div className="truncate text-sm font-medium text-white">{memory.title}</div>
                          <div className="mt-2 flex items-center gap-2 text-[11px] text-slate-500">
                            <span className="rounded-full border border-slate-800 px-2 py-0.5 text-[10px] uppercase tracking-[0.16em] text-slate-400">
                              {memory.category}
                            </span>
                            <span>{new Date(memory.created_at).toLocaleDateString()}</span>
                            <span className="ml-auto">salience {Math.round(memory.salience * 100)}%</span>
                          </div>
                        </div>
                      )) : (
                        <div className="rounded-xl border border-dashed border-slate-800 px-4 py-8 text-center text-sm text-slate-500">
                          No linked memories found.
                        </div>
                      )}
                    </div>
                  </section>
                </div>
              </div>
            )}
          </div>
        ) : displayMode === 'fractal' ? (
          <div
            ref={containerRef}
            className="relative flex-1 min-h-0 overflow-hidden bg-[radial-gradient(circle_at_center,rgba(34,211,238,0.08),rgba(2,6,23,0.02)_28%,rgba(2,6,23,0)_56%)]"
          >
            <div className="absolute right-4 top-4 z-20 flex items-center gap-2">
              <div className="rounded-full border border-slate-800 bg-slate-950/70 px-3 py-1 text-[11px] text-slate-400">
                Wheel to zoom • drag to pan
              </div>
              <button
                onClick={() => setBloomViewport({ scale: 1, offsetX: 0, offsetY: 0 })}
                className="rounded-full border border-slate-700 bg-slate-950/70 px-3 py-1 text-[11px] text-slate-300 transition-colors hover:border-slate-600 hover:text-white"
              >
                Reset view
              </button>
            </div>
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
            {!loading && !error && bloomLayout && focal && (
              <svg
                width={dimensions.width}
                height={dimensions.height}
                viewBox={`0 0 ${bloomLayout.width} ${bloomLayout.height}`}
                className={`h-full w-full ${bloomDragRef.current ? 'cursor-grabbing' : 'cursor-grab'}`}
                onWheel={handleBloomWheel}
                onMouseDown={handleBloomMouseDown}
                onMouseMove={handleBloomMouseMove}
                onMouseUp={endBloomDrag}
                onMouseLeave={endBloomDrag}
              >
                <defs>
                  <filter id="bloom-glow" x="-40%" y="-40%" width="180%" height="180%">
                    <feGaussianBlur stdDeviation="14" result="blur" />
                    <feColorMatrix
                      in="blur"
                      type="matrix"
                      values="1 0 0 0 0
                              0 1 0 0 0
                              0 0 1 0 0
                              0 0 0 18 -8"
                    />
                  </filter>
                </defs>

                <g transform={`translate(${bloomViewport.offsetX} ${bloomViewport.offsetY}) scale(${bloomViewport.scale})`}>
                {bloomLayout.branches.map((branch, branchIndex) => (
                  <g key={branch.key}>
                    <path d={branch.petalPath} fill={`${branch.color}0a`} stroke="none" />
                    <path d={branch.stemPath} fill="none" stroke={`${branch.color}66`} strokeWidth={2} strokeLinecap="round" />
                    {branch.nodeStems.map((stem) => (
                      <path
                        key={stem.key}
                        d={stem.path}
                        fill="none"
                        stroke={`${branch.color}52`}
                        strokeWidth={1.2}
                        strokeLinecap="round"
                      />
                    ))}
                    <circle cx={branch.labelX} cy={branch.labelY + 8} r={22} fill={`${branch.color}0d`} />
                    <text
                      x={branch.labelX}
                      y={branch.labelY}
                      textAnchor="middle"
                      className="fill-slate-400 text-[11px] uppercase tracking-[0.22em]"
                    >
                      {branch.label}
                    </text>
                    <animateTransform
                      attributeName="transform"
                      type="rotate"
                      values={`0 ${bloomLayout.centerX} ${bloomLayout.centerY}; ${branchIndex % 2 === 0 ? 1.2 : -1.2} ${bloomLayout.centerX} ${bloomLayout.centerY}; 0 ${bloomLayout.centerX} ${bloomLayout.centerY}`}
                      dur={`${16 + branchIndex * 2}s`}
                      begin={`${branchIndex * -1.4}s`}
                      repeatCount="indefinite"
                    />
                  </g>
                ))}

                {bloomLayout.crossLinks.map((link) => (
                  <path
                    key={link.key}
                    d={link.path}
                    fill="none"
                    stroke={`${link.color}66`}
                    strokeWidth={1.3}
                    strokeDasharray="5 6"
                    opacity={0.65}
                  />
                ))}

                <circle
                  cx={bloomLayout.centerX}
                  cy={bloomLayout.centerY}
                  r={bloomLayout.focalGlowRadius}
                  fill={ENTITY_COLORS[focal.type] || DEFAULT_COLOR}
                  opacity={0.14}
                  filter="url(#bloom-glow)"
                />
                <circle
                  cx={bloomLayout.centerX}
                  cy={bloomLayout.centerY}
                  r={bloomLayout.focalRadius + 8}
                  fill="none"
                  stroke={`${ENTITY_COLORS[focal.type] || DEFAULT_COLOR}55`}
                  strokeWidth={1.5}
                />
                <circle
                  cx={bloomLayout.centerX}
                  cy={bloomLayout.centerY}
                  r={bloomLayout.focalRadius}
                  fill={ENTITY_COLORS[focal.type] || DEFAULT_COLOR}
                  stroke="#ffffff"
                  strokeWidth={2.5}
                />
                <text
                  x={bloomLayout.centerX}
                  y={bloomLayout.centerY + bloomLayout.focalRadius + 26}
                  textAnchor="middle"
                  className="fill-white text-[16px] font-semibold"
                >
                  {focal.name}
                </text>

                {bloomLayout.branches.flatMap((branch) => branch.nodes).map((node, nodeIndex) => (
                  <g
                    key={node.id}
                    onClick={() => navigateTo(node.id)}
                    className="cursor-pointer"
                  >
                    <animateTransform
                      attributeName="transform"
                      type="translate"
                      values={`0 0; ${(node.id % 7) - 3} ${((node.id % 5) - 2) * 1.4}; 0 0`}
                      dur={`${6 + (nodeIndex % 5)}s`}
                      begin={`${(nodeIndex % 6) * -0.8}s`}
                      repeatCount="indefinite"
                    />
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.radius + 5}
                      fill={ENTITY_COLORS[node.entityType] || DEFAULT_COLOR}
                      opacity={0.1}
                    />
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={node.radius}
                      fill={ENTITY_COLORS[node.entityType] || DEFAULT_COLOR}
                      opacity={0.95}
                    />
                    <rect
                      x={node.x - 14}
                      y={node.y - node.radius - 18}
                      rx={8}
                      width={28}
                      height={16}
                      fill={`${ENTITY_COLORS[node.entityType] || DEFAULT_COLOR}dd`}
                    />
                    <text
                      x={node.x}
                      y={node.y - node.radius - 7}
                      textAnchor="middle"
                      className="fill-slate-950 text-[10px] font-semibold"
                    >
                      {node.memoryCount}
                    </text>
                    <text
                      x={node.x}
                      y={node.y + node.radius + 18}
                      textAnchor="middle"
                      className="fill-slate-200 text-[12px]"
                    >
                      {node.name}
                    </text>
                  </g>
                ))}
                </g>
              </svg>
            )}
          </div>
        ) : (
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
        )}
      </div>
    </div>
  );
}
