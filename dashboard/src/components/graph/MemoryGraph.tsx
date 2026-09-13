'use client';

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { useRouter } from 'next/navigation';
import ForceGraph2D, { type ForceGraphMethods, type LinkObject, type NodeObject } from 'react-force-graph-2d';
import {
  Crosshair,
  List,
  Lock,
  LockOpen,
  Map as MapIcon,
  Maximize2,
  Minus,
  Plus,
  Route,
  RotateCcw,
} from 'lucide-react';
import { useDebouncedValue } from '@/hooks/useDebouncedValue';
import { useGraphOverview, useGraphPath, useGraphSearchV2, useNeighbourhoodV2 } from '@/hooks/useGraphV2';
import { useWebSocketEvent } from '@/components/MemoryWebSocketProvider';
import { useResolvedTheme } from '@/hooks/useTheme';
import {
  GRAPH_CANVAS,
  KNOWN_ENTITY_TYPES,
  entityTypeHex,
  memoryCategorySemantic,
  memoryLinkHex,
  semanticHex,
} from '@/lib/semantic-colours';
import {
  buildFocusData,
  buildMapData,
  entityNodeId,
  linkTooltip,
  linkWidth,
  withPreservedPositions,
  type V2GraphData,
  type V2Link,
  type V2Node,
} from '@/lib/graph/transforms';
import { GraphDrawer } from './GraphDrawer';
import { CardError } from '@/components/ds/CardError';
import { SearchInput } from '@/components/ds/Field';
import { Kbd } from '@/components/ds/Kbd';
import { cn } from '@/lib/utils';

type Mode = 'map' | 'focus' | 'path';

type FGNode = NodeObject & V2Node;
type FGLink = LinkObject & V2Link;

const PULSE_MS = 600;

const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)';

function subscribeReducedMotion(onChange: () => void): () => void {
  const mq = window.matchMedia(REDUCED_MOTION_QUERY);
  mq.addEventListener?.('change', onChange);
  return () => mq.removeEventListener?.('change', onChange);
}

function useReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribeReducedMotion,
    () => window.matchMedia(REDUCED_MOTION_QUERY).matches,
    () => false,
  );
}

/**
 * The v2 memory graph (brief §6, §13.3). One ForceGraph2D instance across
 * Map / Focus / Path modes; stable node identities and preserved positions on
 * every data swap; real data only — bounded entities + bundled live triples
 * in Map, memories with all three edge families in Focus.
 */
export default function MemoryGraph({ preview = false }: { preview?: boolean }) {
  const router = useRouter();
  const theme = useResolvedTheme();
  const reducedMotion = useReducedMotion();
  const palette = GRAPH_CANVAS[theme];

  // ── Mode + controls state ────────────────────────────────
  const [mode, setMode] = useState<Mode>('map');
  const [focusTrail, setFocusTrail] = useState<number[]>([]);
  const focusId = focusTrail.length > 0 ? focusTrail[focusTrail.length - 1] : null;
  const [depth, setDepth] = useState<1 | 2>(1);
  const [showMemories, setShowMemories] = useState(true);
  const [showWeak, setShowWeak] = useState(true);
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());
  const [minMentions, setMinMentions] = useState(1);
  const [legendOpen, setLegendOpen] = useState(!preview);
  const [listOpen, setListOpen] = useState(false);
  const [frozen, setFrozen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [hoverNode, setHoverNode] = useState<FGNode | null>(null);
  const [hoverLink, setHoverLink] = useState<FGLink | null>(null);
  const [pathFrom, setPathFrom] = useState<{ id: number; name: string } | null>(null);
  const [pathTo, setPathTo] = useState<{ id: number; name: string } | null>(null);
  const [searchText, setSearchText] = useState('');
  const debouncedSearch = useDebouncedValue(searchText, 250);

  // ── Data ─────────────────────────────────────────────────
  const overview = useGraphOverview(1, preview ? 150 : 400);
  const nbhd = useNeighbourhoodV2(focusId, { depth, includeMemories: showMemories });
  const path = useGraphPath(pathFrom?.id ?? null, pathTo?.id ?? null);
  const search = useGraphSearchV2(debouncedSearch);

  // ── Graph data with preserved positions ──────────────────
  const liveDataRef = useRef<V2GraphData | null>(null);
  // Focus auto-pins the focal node so the neighbourhood settles around a
  // fixed anchor; released when leaving Focus unless the user pinned it.
  const autoPinRef = useRef<string | null>(null);
  const userPinnedRef = useRef<Set<string>>(new Set());
  const graphData = useMemo<V2GraphData>(() => {
    let base: V2GraphData;
    if (mode === 'focus' && nbhd.data) {
      base = buildFocusData(nbhd.data, showMemories);
    } else if (overview.data) {
      base = buildMapData(overview.data, {
        hiddenTypes,
        hideWeakLinks: !showWeak,
        minMentions,
      });
    } else {
      base = { nodes: [], links: [] };
    }
    const preserved = withPreservedPositions(base, liveDataRef.current?.nodes);
    // Focus: seed nodes we have never positioned near the focal entity so the
    // neighbourhood settles around it instead of at d3's origin, far from the
    // focal node's preserved Map coordinates.
    if (mode === 'focus') {
      const focal = preserved.nodes.find((n) => n.isFocal);
      if (focal && focal.x !== undefined && focal.y !== undefined) {
        for (const n of preserved.nodes) {
          if (n.x === undefined) {
            // Deterministic golden-angle scatter — pure, and stable across renders.
            const angle = n.numericId * 2.39996;
            const radius = 24 + (n.numericId % 9) * 6;
            n.x = focal.x + Math.cos(angle) * radius;
            n.y = focal.y + Math.sin(angle) * radius;
          }
          // A previous focal's auto-pin is released when it stops being focal.
          if (autoPinRef.current === n.id && n.id !== focal.id && !userPinnedRef.current.has(n.id)) {
            n.fx = undefined;
            n.fy = undefined;
          }
        }
        focal.fx = focal.x;
        focal.fy = focal.y;
        autoPinRef.current = focal.id;
      }
    } else if (autoPinRef.current) {
      const pinned = preserved.nodes.find((n) => n.id === autoPinRef.current);
      if (pinned && !userPinnedRef.current.has(pinned.id)) {
        pinned.fx = undefined;
        pinned.fy = undefined;
      }
      autoPinRef.current = null;
    }
    liveDataRef.current = preserved;
    return preserved;
  }, [mode, nbhd.data, overview.data, showMemories, hiddenTypes, showWeak, minMentions]);

  const nodeById = useMemo(() => new Map(graphData.nodes.map((n) => [n.id, n])), [graphData]);

  // Adjacency for hover highlighting.
  const adjacency = useMemo(() => {
    const adj = new Map<string, Set<string>>();
    for (const l of graphData.links) {
      const s = typeof l.source === 'string' ? l.source : (l.source as V2Node).id;
      const t = typeof l.target === 'string' ? l.target : (l.target as V2Node).id;
      if (!adj.has(s)) adj.set(s, new Set());
      if (!adj.has(t)) adj.set(t, new Set());
      adj.get(s)!.add(t);
      adj.get(t)!.add(s);
    }
    return adj;
  }, [graphData]);

  // Label LOD: always label the top-degree nodes.
  const topLabelIds = useMemo(() => {
    const byDegree = [...graphData.nodes].sort(
      (a, b) => (adjacency.get(b.id)?.size ?? 0) - (adjacency.get(a.id)?.size ?? 0),
    );
    return new Set(byDegree.slice(0, 12).map((n) => n.id));
  }, [graphData, adjacency]);

  // Path highlight set.
  const pathIds = useMemo(() => {
    if (mode !== 'path' || !path.data?.path?.length) return null;
    return new Set(path.data.path.map((h) => entityNodeId(h.entityId)));
  }, [mode, path.data]);

  // Dimming: hover neighbourhood, or path highlight.
  const highlightSet = useMemo(() => {
    if (pathIds) return pathIds;
    if (hoverNode) {
      const set = new Set([hoverNode.id as string]);
      for (const n of adjacency.get(hoverNode.id as string) ?? []) set.add(n);
      return set;
    }
    return null;
  }, [pathIds, hoverNode, adjacency]);

  // ── Force graph instance ─────────────────────────────────
  const fgRef = useRef<ForceGraphMethods<FGNode, FGLink> | undefined>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 800, height: 560 });

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setSize({
          width: Math.max(200, Math.floor(entry.contentRect.width)),
          height: Math.max(preview ? 220 : 420, Math.floor(entry.contentRect.height)),
        });
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [preview]);

  // Configure forces once the instance exists: gentler charge in Map, a weak
  // per-entity-type x/y pull so types settle into readable regions (no hard
  // clustering), and link distances by edge family.
  useEffect(() => {
    const fg = fgRef.current;
    if (!fg) return;
    const chargeStrength = mode === 'focus' ? -120 : -50;
    fg.d3Force('charge')?.strength(chargeStrength);
    // Drop the library's default centre force: it drags the graph's centroid
    // to the origin, which yanks a Focus cluster away from the focal node's
    // preserved coordinates (verified via the d3-zoom transform: camera at the
    // focal point, nodes translated to ~0,0). Map stays anchored by the
    // type-centring force below; Focus stays where it was seeded.
    fg.d3Force('center', null as never);
    const linkForce = fg.d3Force('link') as { distance?: (fn: (l: FGLink) => number) => unknown } | undefined;
    linkForce?.distance?.((l: FGLink) =>
      l.kind === 'memory-entity' ? 28 : l.kind === 'memory-link' ? 46 : l.weakOnly ? 90 : 60,
    );

    if (mode === 'map') {
      const typeAngle = new Map<string, number>();
      KNOWN_ENTITY_TYPES.forEach((t, i) => typeAngle.set(t, (i / KNOWN_ENTITY_TYPES.length) * Math.PI * 2));
      const R = 220;
      let nodes: FGNode[] = [];
      const typeCentring = (alpha: number) => {
        for (const n of nodes) {
          if (n.kind !== 'entity') continue;
          const angle = typeAngle.get(n.subtype);
          if (angle === undefined) continue;
          const k = 0.015 * alpha;
          n.vx = (n.vx ?? 0) + (Math.cos(angle) * R - (n.x ?? 0)) * k;
          n.vy = (n.vy ?? 0) + (Math.sin(angle) * R - (n.y ?? 0)) * k;
        }
      };
      typeCentring.initialize = (ns: FGNode[]) => { nodes = ns; };
      fg.d3Force('typeCentring', typeCentring as never);
    } else {
      // Focus/Path keep the cluster where it was seeded (around the focal
      // node); the map-wide type pull would drag it back to the origin circle.
      fg.d3Force('typeCentring', null as never);
    }
  }, [mode, graphData]);

  // Entering Focus (or refocusing) pans the camera to the focal entity —
  // user-initiated navigation, not a camera reset; zoom level is untouched.
  useEffect(() => {
    if (mode !== 'focus' || !nbhd.data) return;
    // Frame the focus subgraph once it has largely settled. Entity neighbours
    // keep their preserved Map positions (§13.3), so the subgraph can span a
    // wide area — a fit is the only camera move that reliably shows it. This
    // is user-initiated navigation on an explicit Focus, not a camera reset.
    const t = setTimeout(() => {
      fgRef.current?.zoomToFit(reducedMotion ? 0 : 400, 96);
    }, reducedMotion ? 50 : 700);
    return () => clearTimeout(t);
  }, [mode, nbhd.data, reducedMotion]);

  // Freeze layout: pin every node at its current position, remembering which
  // pins are the user's own so unfreezing releases only ours.
  const toggleFrozen = useCallback(() => {
    setFrozen((f) => {
      const next = !f;
      for (const n of (liveDataRef.current?.nodes ?? []) as FGNode[]) {
        if (next) {
          if (n.fx == null) {
            n.fx = n.x;
            n.fy = n.y;
          } else {
            userPinnedRef.current.add(n.id);
          }
        } else if (!userPinnedRef.current.has(n.id)) {
          n.fx = undefined;
          n.fy = undefined;
        }
      }
      return next;
    });
  }, []);

  const releaseAllPins = useCallback(() => {
    userPinnedRef.current.clear();
    for (const n of (liveDataRef.current?.nodes ?? []) as FGNode[]) {
      // eslint-disable-next-line react-hooks/immutability -- these are OUR clones handed to d3-force, which owns and mutates them by contract; clearing fx/fy is how d3 unpins a node
      n.fx = undefined;
      n.fy = undefined;
    }
    setFrozen(false);
    fgRef.current?.d3ReheatSimulation();
  }, []);

  // ── Live pulse (memory_created / memory_accessed) ────────
  const pulseRef = useRef<Map<string, number>>(new Map());
  useWebSocketEvent(
    useCallback(
      (msg: unknown) => {
        if (reducedMotion) return;
        const obj = msg as { type?: string; data?: { entity_ids?: number[] } };
        if (obj?.type !== 'memory_created' && obj?.type !== 'memory_accessed') return;
        const now = performance.now();
        for (const id of obj.data?.entity_ids ?? []) {
          pulseRef.current.set(entityNodeId(id), now);
        }
      },
      [reducedMotion],
    ),
  );

  // ── Interactions ─────────────────────────────────────────
  const focusEntity = useCallback((entityId: number) => {
    setMode('focus');
    setFocusTrail((trail) => (trail[trail.length - 1] === entityId ? trail : [...trail, entityId]));
    setSelectedId(entityNodeId(entityId));
  }, []);

  const backOut = useCallback(() => {
    setSelectedId(null);
    setHoverNode(null);
    if (mode === 'path') {
      setMode('map');
      setPathFrom(null);
      setPathTo(null);
      return;
    }
    setFocusTrail((trail) => {
      const next = trail.slice(0, -1);
      if (next.length === 0) setMode('map');
      return next;
    });
  }, [mode]);

  const onNodeClick = useCallback(
    (node: FGNode, event: MouseEvent) => {
      if (preview) {
        router.push('/memory?tab=graph');
        return;
      }
      if (event.shiftKey && node.kind === 'entity') {
        // Shift-click builds a path: first pick = from, second = to.
        if (!pathFrom) {
          setMode('path');
          setPathFrom({ id: node.numericId, name: node.label });
        } else if (node.numericId !== pathFrom.id) {
          setMode('path');
          setPathTo({ id: node.numericId, name: node.label });
        }
        return;
      }
      setSelectedId(node.id);
    },
    [preview, router, pathFrom],
  );

  const onNodeDoubleClick = useCallback(
    (node: FGNode) => {
      if (preview) return;
      if (node.kind === 'entity') focusEntity(node.numericId);
    },
    [preview, focusEntity],
  );

  const onNodeDragEnd = useCallback((node: FGNode) => {
    // Drag pins (brief §6.3); release via "release pins".
    node.fx = node.x;
    node.fy = node.y;
    userPinnedRef.current.add(node.id);
  }, []);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const fg = fgRef.current;
      if (e.key === '/') {
        e.preventDefault();
        (containerRef.current?.querySelector('input[type="search"]') as HTMLInputElement | null)?.focus();
      } else if (e.key === '+' || e.key === '=') {
        fg?.zoom((fg.zoom() ?? 1) * 1.4, reducedMotion ? 0 : 200);
      } else if (e.key === '-') {
        fg?.zoom((fg.zoom() ?? 1) / 1.4, reducedMotion ? 0 : 200);
      } else if (e.key === '0') {
        fg?.zoomToFit(reducedMotion ? 0 : 300, 40);
      } else if (e.key.toLowerCase() === 'f' && selectedId) {
        const n = nodeById.get(selectedId);
        if (n?.kind === 'entity') focusEntity(n.numericId);
      } else if (e.key.toLowerCase() === 'p' && selectedId) {
        // Per-node pin toggle (§13.3): P pins the selected node in place,
        // or releases a node pinned by drag/freeze/P.
        const n = nodeById.get(selectedId);
        if (n) {
          if (n.fx != null) {
            n.fx = undefined;
            n.fy = undefined;
            userPinnedRef.current.delete(n.id);
          } else if (n.x !== undefined) {
            n.fx = n.x;
            n.fy = n.y;
            userPinnedRef.current.add(n.id);
          }
          fgRef.current?.d3ReheatSimulation();
        }
      } else if (e.key === 'Escape') {
        // First Esc clears the selection (closes the drawer); the next one
        // backs out of Focus/Path.
        if (selectedId) setSelectedId(null);
        else backOut();
      } else if (e.key === 'Enter' && selectedId) {
        const n = nodeById.get(selectedId);
        if (n?.kind === 'entity') focusEntity(n.numericId);
      }
    },
    [selectedId, nodeById, focusEntity, backOut, reducedMotion],
  );

  // ── Painting ─────────────────────────────────────────────
  const nodeRadius = useCallback((node: FGNode): number => {
    if (node.kind === 'memory') return 3 + node.size * 4;
    return Math.max(3.5, Math.min(14, 3 + Math.sqrt(node.size)));
  }, []);

  const paintNode = useCallback(
    (node: FGNode, ctx: CanvasRenderingContext2D, scale: number) => {
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      let r = nodeRadius(node);
      const dimmed = highlightSet ? !highlightSet.has(node.id) : false;
      const selected = node.id === selectedId;
      const hovered = hoverNode?.id === node.id;

      // One-shot live pulse: scale 1→1.3→1 over 600ms (reduced-motion gated
      // at dispatch, so nothing lands here when the user opted out).
      const pulseStart = pulseRef.current.get(node.id);
      if (pulseStart !== undefined) {
        const p = (performance.now() - pulseStart) / PULSE_MS;
        if (p >= 1) pulseRef.current.delete(node.id);
        else r *= 1 + 0.3 * Math.sin(Math.PI * Math.min(1, p));
      }

      ctx.globalAlpha = dimmed ? 0.15 : node.memory && node.memory.status !== 'active' ? 0.45 : 1;

      if (node.kind === 'entity') {
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = entityTypeHex(theme, node.subtype);
        ctx.fill();
        ctx.lineWidth = 1 / scale;
        ctx.strokeStyle = palette.nodeStroke;
        ctx.stroke();
        if (node.isFocal) {
          ctx.beginPath();
          ctx.arc(x, y, r + 3 / scale, 0, 2 * Math.PI);
          ctx.strokeStyle = palette.selectionRing;
          ctx.lineWidth = 1.5 / scale;
          ctx.stroke();
        }
      } else {
        // Memory: rounded square, ring colour from category semantics.
        const s = r;
        ctx.beginPath();
        ctx.roundRect(x - s, y - s, s * 2, s * 2, s * 0.45);
        ctx.fillStyle = theme === 'dark' ? '#1b2540' : '#e6ecf8';
        ctx.fill();
        ctx.lineWidth = 1.4 / Math.sqrt(scale);
        ctx.strokeStyle = semanticHex(theme, memoryCategorySemantic(node.subtype));
        ctx.stroke();
        if (node.memory?.pinned) {
          ctx.beginPath();
          ctx.arc(x + s * 0.9, y - s * 0.9, Math.max(1.2, s * 0.3), 0, 2 * Math.PI);
          ctx.fillStyle = palette.selectionRing;
          ctx.fill();
        }
      }

      if (selected || hovered) {
        ctx.beginPath();
        ctx.arc(x, y, r + 5 / scale, 0, 2 * Math.PI);
        ctx.strokeStyle = palette.selectionRing;
        ctx.lineWidth = (selected ? 2 : 1) / scale;
        ctx.setLineDash(hovered && !selected ? [2 / scale, 2 / scale] : []);
        ctx.stroke();
        ctx.setLineDash([]);
      }
      if (node.fx != null && !frozen) {
        ctx.beginPath();
        ctx.arc(x, y - r - 3 / scale, 1.5 / scale, 0, 2 * Math.PI);
        ctx.fillStyle = palette.labelMuted;
        ctx.fill();
      }

      const showLabel =
        !preview && (scale > 1.6 || hovered || selected || node.isFocal || topLabelIds.has(node.id));
      if (showLabel) {
        const label = node.label.length > 28 ? `${node.label.slice(0, 27)}…` : node.label;
        ctx.font = `${Math.max(10 / scale, 2.4)}px sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = hovered || selected ? palette.label : palette.labelMuted;
        ctx.fillText(label, x, y + r + 2 / scale);
      }
      ctx.globalAlpha = 1;
    },
    [nodeRadius, highlightSet, selectedId, hoverNode, theme, palette, topLabelIds, preview, frozen],
  );

  const paintPointerArea = useCallback(
    (node: FGNode, colour: string, ctx: CanvasRenderingContext2D) => {
      const r = nodeRadius(node) + 3;
      ctx.fillStyle = colour;
      ctx.beginPath();
      ctx.arc(node.x ?? 0, node.y ?? 0, r, 0, 2 * Math.PI);
      ctx.fill();
    },
    [nodeRadius],
  );

  const linkColour = useCallback(
    (link: FGLink): string => {
      const dimmed =
        highlightSet !== null &&
        !(
          highlightSet.has(typeof link.source === 'object' ? (link.source as V2Node).id : (link.source as string)) &&
          highlightSet.has(typeof link.target === 'object' ? (link.target as V2Node).id : (link.target as string))
        );
      if (dimmed) return palette.edgeDim;
      if (link.kind === 'memory-link') {
        return memoryLinkHex(theme, link.relationship ?? 'related');
      }
      if (link.kind === 'memory-entity') return semanticHex(theme, 'memory');
      if (link.triples?.some((t) => t.disputed)) return semanticHex(theme, 'warn');
      return palette.edge;
    },
    [highlightSet, palette, theme],
  );

  const linkDash = useCallback((link: FGLink): number[] | null => {
    if (link.kind === 'triple' && link.weakOnly) return [2, 3];
    if (link.kind === 'memory-link' && link.relationship === 'conflicts') return [3, 2];
    return null;
  }, []);

  const paintLinkLabel = useCallback(
    (link: FGLink, ctx: CanvasRenderingContext2D, scale: number) => {
      // Predicate labels appear on hover and when zoomed in (LOD).
      const isHovered = hoverLink === link;
      if (!isHovered && scale < 2.2) return;
      const s = link.source as unknown as FGNode;
      const t = link.target as unknown as FGNode;
      if (typeof s !== 'object' || typeof t !== 'object') return;
      let text: string | undefined;
      if (link.kind === 'triple') {
        const preds = [...new Set((link.triples ?? []).map((tr) => tr.predicate))];
        text = preds.slice(0, 2).join(', ') + (preds.length > 2 ? ` +${preds.length - 2}` : '');
      } else if (link.kind === 'memory-link') {
        text = link.relationship;
      } else if (isHovered) {
        text = link.role === 'mention' || !link.role ? 'mentions' : link.role;
      }
      if (!text) return;
      const mx = ((s.x ?? 0) + (t.x ?? 0)) / 2;
      const my = ((s.y ?? 0) + (t.y ?? 0)) / 2;
      ctx.font = `${Math.max(9 / scale, 2)}px sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = isHovered ? palette.label : palette.labelMuted;
      ctx.fillText(text, mx, my);
    },
    [hoverLink, palette],
  );

  // ── Derived UI info ──────────────────────────────────────
  const counts = overview.data?.counts;
  const visibleTypes = useMemo(() => {
    const types = new Set<string>();
    for (const n of graphData.nodes) if (n.kind === 'entity') types.add(n.subtype);
    for (const t of Object.keys(counts?.byType ?? {})) types.add(t);
    return [...types].sort();
  }, [graphData, counts]);

  const selectedNode = selectedId ? (nodeById.get(selectedId) ?? null) : null;
  const hoverTooltip = hoverLink
    ? linkTooltip(hoverLink, (id) => nodeById.get(id)?.label ?? id)
    : null;

  const truncationNotice =
    mode === 'map' && counts && counts.omittedEntities > 0
      ? `${counts.omittedEntities} more entities below the display cap — raise min mentions or use search.`
      : mode === 'focus' && nbhd.data && nbhd.data.counts.omittedNeighbours > 0
        ? `${nbhd.data.counts.omittedNeighbours} more neighbours not shown (capped view).`
        : null;

  // ── Render ───────────────────────────────────────────────
  if (overview.isError) {
    return (
      <CardError
        message={`The graph API is unreachable: ${overview.error instanceof Error ? overview.error.message : 'fetch failed'}`}
        onRetry={() => overview.refetch()}
      />
    );
  }

  const isEmpty = !overview.isLoading && (overview.data?.counts.totalEntities ?? 0) === 0;
  if (isEmpty) {
    return (
      <div className="flex h-[420px] flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-[var(--sc-border)] p-8 text-center">
        <p className="max-w-md text-sm text-[var(--sc-text-muted)]">
          Entities appear here as memories are captured and extracted. Backfill the graph from existing memories with:
        </p>
        <button
          type="button"
          onClick={() => { void navigator.clipboard?.writeText('shieldcortex memories enrich'); }}
          title="Copy command"
          className="rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-3 py-1.5 font-mono text-xs text-[var(--sc-text)] hover:border-[var(--sc-border-strong)]"
        >
          shieldcortex memories enrich
        </button>
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={cn('relative overflow-hidden rounded-lg border border-[var(--sc-border)]', preview ? 'h-[240px]' : 'h-[calc(100dvh-320px)] min-h-[480px]')}
      style={{ background: palette.background }}
      tabIndex={preview ? -1 : 0}
      onKeyDown={preview ? undefined : onKeyDown}
      role="application"
      aria-label="Memory knowledge graph. Keyboard: slash to search, plus and minus to zoom, zero to fit, F to focus the selected node, P to pin or unpin it, Escape to go back."
    >
      <ForceGraph2D
        ref={fgRef}
        width={size.width}
        height={size.height}
        graphData={graphData as { nodes: FGNode[]; links: FGLink[] }}
        backgroundColor={palette.background}
        warmupTicks={60}
        cooldownTime={reducedMotion ? 0 : 5000}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={paintPointerArea}
        nodeLabel={() => ''}
        linkColor={linkColour}
        linkWidth={(l) => linkWidth(l as FGLink)}
        linkLineDash={(l) => linkDash(l as FGLink)}
        linkDirectionalArrowLength={(l) =>
          (l as FGLink).kind === 'memory-link' && (l as FGLink).relationship === 'supersedes' ? 4 : 0
        }
        linkDirectionalArrowRelPos={0.9}
        linkCanvasObjectMode={() => 'after'}
        linkCanvasObject={paintLinkLabel}
        onNodeClick={onNodeClick as never}
        onNodeRightClick={((node: FGNode) => { if (node.kind === 'entity' && !preview) focusEntity(node.numericId); }) as never}
        onNodeHover={((n: FGNode | null) => setHoverNode(n)) as never}
        onLinkHover={((l: FGLink | null) => setHoverLink(l)) as never}
        onNodeDragEnd={onNodeDragEnd as never}
        onBackgroundClick={() => setSelectedId(null)}
        enableNodeDrag={!preview}
        onNodeDrag={undefined}
        autoPauseRedraw={false}
      />
      {/* Double-click focus: react-force-graph has no dblclick prop; emulate on the wrapper. */}
      <div
        className="pointer-events-none absolute inset-0"
        onDoubleClickCapture={() => {
          if (hoverNode) onNodeDoubleClick(hoverNode);
        }}
      />

      {!preview && (
        <>
          {/* ── Controls overlay (top-left) ── */}
          <div className="absolute left-3 top-3 z-10 flex max-w-[340px] flex-col gap-2">
            <div className="relative">
              <SearchInput
                placeholder="Jump to an entity… ( / )"
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                aria-label="Search entities in the graph"
                className="bg-[var(--sc-surface)]/95"
              />
              {debouncedSearch && (search.data?.length ?? 0) > 0 && (
                <ul className="absolute left-0 right-0 top-full z-20 mt-1 overflow-hidden rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface)] shadow-[var(--sc-shadow-drawer)]">
                  {search.data!.map((hit) => (
                    <li key={hit.id}>
                      <button
                        type="button"
                        className="flex w-full items-center justify-between px-3 py-1.5 text-left text-xs text-[var(--sc-text)] hover:bg-[var(--sc-surface-2)]"
                        onClick={() => {
                          setSearchText('');
                          if (mode === 'path' && pathFrom && !pathTo) {
                            setPathTo({ id: hit.id, name: hit.name });
                          } else {
                            focusEntity(hit.id);
                          }
                        }}
                      >
                        <span className="truncate">{hit.name}</span>
                        <span className="ml-2 shrink-0 text-[10px] text-[var(--sc-text-muted)]">
                          {hit.type} · {hit.memoryCount}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-1.5">
              <ModeButton active={mode === 'map'} onClick={() => { setMode('map'); setFocusTrail([]); setPathFrom(null); setPathTo(null); }} icon={<MapIcon size={13} aria-hidden />} label="Map" />
              <ModeButton active={mode === 'focus'} disabled={focusId === null} onClick={() => focusId !== null && setMode('focus')} icon={<Crosshair size={13} aria-hidden />} label="Focus" />
              <ModeButton active={mode === 'path'} onClick={() => setMode('path')} icon={<Route size={13} aria-hidden />} label="Path" />
              <span className="mx-1 h-4 w-px bg-[var(--sc-border)]" aria-hidden />
              <IconButton label="Zoom in (+)" onClick={() => fgRef.current?.zoom((fgRef.current.zoom() ?? 1) * 1.4, reducedMotion ? 0 : 200)}><Plus size={13} aria-hidden /></IconButton>
              <IconButton label="Zoom out (-)" onClick={() => fgRef.current?.zoom((fgRef.current.zoom() ?? 1) / 1.4, reducedMotion ? 0 : 200)}><Minus size={13} aria-hidden /></IconButton>
              <IconButton label="Fit graph (0)" onClick={() => fgRef.current?.zoomToFit(reducedMotion ? 0 : 300, 40)}><Maximize2 size={13} aria-hidden /></IconButton>
              <IconButton label={frozen ? 'Unfreeze layout' : 'Freeze layout'} onClick={toggleFrozen}>{frozen ? <Lock size={13} aria-hidden /> : <LockOpen size={13} aria-hidden />}</IconButton>
              <IconButton label="Release all pinned nodes" onClick={releaseAllPins}><RotateCcw size={13} aria-hidden /></IconButton>
              <IconButton label={listOpen ? 'Hide node list' : 'Show node list'} onClick={() => setListOpen((o) => !o)}><List size={13} aria-hidden /></IconButton>
            </div>

            {mode === 'focus' && focusTrail.length > 0 && (
              <nav aria-label="Focus trail" className="flex flex-wrap items-center gap-1 rounded-md bg-[var(--sc-surface)]/95 px-2 py-1 text-[11px] text-[var(--sc-text-muted)]">
                <button type="button" className="hover:text-[var(--sc-text)]" onClick={() => { setMode('map'); setFocusTrail([]); }}>Map</button>
                {focusTrail.map((id, i) => (
                  <span key={`${id}-${i}`} className="flex items-center gap-1">
                    <span aria-hidden>›</span>
                    <button
                      type="button"
                      className={cn('hover:text-[var(--sc-text)]', i === focusTrail.length - 1 && 'font-medium text-[var(--sc-text)]')}
                      onClick={() => setFocusTrail((t) => t.slice(0, i + 1))}
                    >
                      {nodeById.get(entityNodeId(id))?.label ?? `#${id}`}
                    </button>
                  </span>
                ))}
                <span className="mx-1 h-3 w-px bg-[var(--sc-border)]" aria-hidden />
                <label className="flex items-center gap-1">
                  <input type="checkbox" checked={depth === 2} onChange={(e) => setDepth(e.target.checked ? 2 : 1)} />
                  depth 2
                </label>
                <label className="flex items-center gap-1">
                  <input type="checkbox" checked={showMemories} onChange={(e) => setShowMemories(e.target.checked)} />
                  memories
                </label>
              </nav>
            )}

            {mode === 'path' && (
              <div className="space-y-1 rounded-md bg-[var(--sc-surface)]/95 px-2 py-1.5 text-[11px] text-[var(--sc-text-dim)]">
                <div>
                  Path: <strong>{pathFrom?.name ?? 'shift-click or search a start'}</strong> → <strong>{pathTo?.name ?? 'then pick a target'}</strong>
                  {(pathFrom || pathTo) && (
                    <button type="button" className="ml-2 underline" onClick={() => { setPathFrom(null); setPathTo(null); }}>reset</button>
                  )}
                </div>
                {path.isLoading && <div>Searching…</div>}
                {path.data?.message && <div>{path.data.message} (within 4 hops).</div>}
                {path.data?.path && path.data.path.length > 0 && (
                  <ol className="space-y-0.5">
                    {path.data.path.map((hop, i) => (
                      <li key={`${hop.entityId}-${i}`} className="flex items-center gap-1">
                        {i > 0 && (
                          <span className="font-mono text-[var(--sc-violet)]">
                            {hop.direction === 'reverse' ? `← ${hop.predicate.replace(/^~/, '')}` : `${hop.predicate} →`}
                          </span>
                        )}
                        <button type="button" className="underline-offset-2 hover:underline" onClick={() => setSelectedId(entityNodeId(hop.entityId))}>
                          {hop.entity}
                        </button>
                        {!nodeById.has(entityNodeId(hop.entityId)) && (
                          <span className="text-[var(--sc-text-muted)]">(below display threshold)</span>
                        )}
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            )}

            {mode === 'map' && (
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md bg-[var(--sc-surface)]/95 px-2 py-1.5 text-[11px] text-[var(--sc-text-dim)]">
                <label className="flex items-center gap-1.5">
                  min mentions
                  <input
                    type="range"
                    min={1}
                    max={20}
                    value={minMentions}
                    onChange={(e) => setMinMentions(Number(e.target.value))}
                    aria-label="Minimum mentions to display an entity"
                  />
                  <span className="tabular-nums">{minMentions}</span>
                </label>
                <label className="flex items-center gap-1">
                  <input type="checkbox" checked={showWeak} onChange={(e) => setShowWeak(e.target.checked)} />
                  weak links (related_to)
                </label>
              </div>
            )}
          </div>

          {/* ── Legend (persistent, collapsible) ── */}
          <div className="absolute bottom-3 left-3 z-10 rounded-md bg-[var(--sc-surface)]/95 p-2 text-[11px] text-[var(--sc-text-dim)]">
            <button type="button" className="font-medium text-[var(--sc-text)]" aria-expanded={legendOpen} onClick={() => setLegendOpen((o) => !o)}>
              Legend {legendOpen ? '▾' : '▸'}
            </button>
            {legendOpen && (
              <div className="mt-1.5 space-y-1.5">
                <div className="flex max-w-[260px] flex-wrap gap-1">
                  {visibleTypes.map((t) => {
                    const hidden = hiddenTypes.has(t);
                    return (
                      <button
                        key={t}
                        type="button"
                        aria-pressed={!hidden}
                        onClick={() =>
                          setHiddenTypes((prev) => {
                            const next = new Set(prev);
                            if (next.has(t)) next.delete(t);
                            else next.add(t);
                            return next;
                          })
                        }
                        className={cn(
                          'flex items-center gap-1 rounded-full border border-[var(--sc-border)] px-1.5 py-0.5',
                          hidden && 'opacity-40',
                        )}
                        title={hidden ? `Show ${t} entities` : `Hide ${t} entities`}
                      >
                        <span aria-hidden className="h-2 w-2 rounded-full" style={{ background: entityTypeHex(theme, t) }} />
                        {t}
                        {counts?.byType[t] !== undefined && <span className="tabular-nums text-[var(--sc-text-muted)]">{counts.byType[t]}</span>}
                      </button>
                    );
                  })}
                </div>
                <div className="space-y-0.5">
                  <div><span aria-hidden className="mr-1 inline-block h-0.5 w-4 align-middle" style={{ background: palette.edge }} /> entity relation (width = number of relations)</div>
                  <div><span aria-hidden className="mr-1 inline-block h-0.5 w-4 border-b border-dashed align-middle" style={{ borderColor: palette.edge }} /> weak (related_to)</div>
                  <div><span aria-hidden className="mr-1 inline-block h-0.5 w-4 align-middle" style={{ background: semanticHex(theme, 'memory') }} /> memory → entity</div>
                  <div><span aria-hidden className="mr-1 inline-block h-0.5 w-4 align-middle" style={{ background: semanticHex(theme, 'link') }} /> memory link (supersedes ➤)</div>
                  <div><span aria-hidden className="mr-1 inline-block h-0.5 w-4 border-b border-dashed align-middle" style={{ borderColor: semanticHex(theme, 'danger') }} /> conflicts</div>
                  <div><span aria-hidden className="mr-1 inline-block h-2 w-2 rounded-sm border align-middle" style={{ borderColor: semanticHex(theme, 'memory') }} /> memory (size = salience, dot = pinned)</div>
                </div>
              </div>
            )}
          </div>

          {/* ── Status line (bottom-right): honest counts + truncation ── */}
          <div className="absolute bottom-3 right-3 z-10 max-w-[300px] rounded-md bg-[var(--sc-surface)]/95 px-2 py-1 text-right text-[10px] text-[var(--sc-text-muted)]">
            {overview.isLoading && 'Loading graph…'}
            {mode === 'map' && counts && (
              <span>
                {graphData.nodes.length} entities · {graphData.links.length} relations shown
                {counts.omittedEdges > 0 ? ` · ${counts.omittedEdges} edges over cap` : ''}
              </span>
            )}
            {mode === 'focus' && nbhd.data && (
              <span>
                {graphData.nodes.filter((n) => n.kind === 'entity').length} entities ·{' '}
                {graphData.nodes.filter((n) => n.kind === 'memory').length} memories shown
              </span>
            )}
            {mode === 'focus' && nbhd.isError && (
              <span className="text-[var(--sc-warn)]">Neighbourhood unavailable — {nbhd.error instanceof Error ? nbhd.error.message : 'fetch failed'}</span>
            )}
            {truncationNotice && <div>{truncationNotice}</div>}
          </div>

          {/* ── Hover link tooltip ── */}
          {hoverTooltip && (
            <div className="pointer-events-none absolute left-1/2 top-3 z-10 max-w-md -translate-x-1/2 whitespace-pre-line rounded-md bg-[var(--sc-surface)]/95 px-3 py-1.5 text-center text-[11px] text-[var(--sc-text-dim)] shadow-[var(--sc-shadow-card)]">
              {hoverTooltip}
            </div>
          )}

          {/* ── Keyboard-accessible node list (shares selection) ── */}
          {listOpen && (
            <div
              className={cn(
                'absolute top-3 z-10 flex max-h-[70%] w-56 flex-col rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface)]/95 shadow-[var(--sc-shadow-card)]',
                // Step aside for the (non-modal) drawer so both stay usable.
                selectedNode ? 'right-3 md:right-[416px]' : 'right-3',
              )}
            >
              <div className="border-b border-[var(--sc-border)] px-2 py-1 text-[11px] font-medium text-[var(--sc-text)]">
                Nodes ({graphData.nodes.length})
              </div>
              <ul className="min-h-0 flex-1 overflow-y-auto py-1" aria-label="Graph nodes">
                {[...graphData.nodes]
                  .sort((a, b) => b.size - a.size)
                  .slice(0, 300)
                  .map((n) => (
                    <li key={n.id}>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedId(n.id);
                          if (n.x !== undefined && n.y !== undefined) fgRef.current?.centerAt(n.x, n.y, reducedMotion ? 0 : 300);
                        }}
                        onDoubleClick={() => n.kind === 'entity' && focusEntity(n.numericId)}
                        className={cn(
                          'flex w-full items-center gap-1.5 px-2 py-1 text-left text-[11px] text-[var(--sc-text-dim)] hover:bg-[var(--sc-surface-2)] focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[var(--sc-focus)]',
                          selectedId === n.id && 'bg-[var(--sc-primary-soft)] text-[var(--sc-text)]',
                        )}
                      >
                        <span
                          aria-hidden
                          className={cn('h-2 w-2 shrink-0', n.kind === 'entity' ? 'rounded-full' : 'rounded-sm')}
                          style={{ background: n.kind === 'entity' ? entityTypeHex(theme, n.subtype) : semanticHex(theme, memoryCategorySemantic(n.subtype)) }}
                        />
                        <span className="truncate">{n.label}</span>
                      </button>
                    </li>
                  ))}
              </ul>
              <div className="border-t border-[var(--sc-border)] px-2 py-1 text-[10px] text-[var(--sc-text-muted)]">
                <Kbd>Enter</Kbd> select · double-click to focus
              </div>
            </div>
          )}

          <GraphDrawer
            node={selectedNode}
            neighbourhood={nbhd.data}
            onClose={() => setSelectedId(null)}
            onFocus={focusEntity}
            onSelectEntity={(id) => setSelectedId(entityNodeId(id))}
            onPathFrom={(id) => {
              const n = nodeById.get(entityNodeId(id));
              setMode('path');
              setPathFrom({ id, name: n?.label ?? `#${id}` });
              setPathTo(null);
              setSelectedId(null);
            }}
          />
        </>
      )}
    </div>
  );
}

function ModeButton({ active, disabled, onClick, icon, label }: { active: boolean; disabled?: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button
      type="button"
      aria-pressed={active}
      disabled={disabled}
      onClick={onClick}
      className={cn(
        'flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] transition-colors focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]',
        active
          ? 'border-[var(--sc-primary)] bg-[var(--sc-primary-soft)] text-[var(--sc-primary)]'
          : 'border-[var(--sc-border)] bg-[var(--sc-surface)]/95 text-[var(--sc-text-dim)] hover:border-[var(--sc-border-strong)]',
        disabled && 'cursor-not-allowed opacity-40',
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function IconButton({ label, onClick, children }: { label: string; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface)]/95 p-1.5 text-[var(--sc-text-dim)] transition-colors hover:border-[var(--sc-border-strong)] hover:text-[var(--sc-text)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
    >
      {children}
    </button>
  );
}
