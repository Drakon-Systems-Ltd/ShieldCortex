'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import type { ForceGraphMethods, ForceGraphProps, NodeObject, LinkObject } from 'react-force-graph-2d';
import type { ClusterData, GraphEntity } from '@/hooks/useGraphData';
import { paintNode } from './constellation/renderNodes';
import { paintLink } from './constellation/renderLinks';
import { pickAnchor, applyAnchor } from './constellation/anchor';
import { PulseDriver } from './constellation/pulse';
import { INTENSITY, REDUCED_INTENSITY, isReducedMotion, loadIntensity, type IntensityLevel } from './constellation/intensity';
import { wireControls } from './constellation/controls';
import { PulseDebugPanel } from './PulseDebugPanel';
import { useGraphPulse } from '@/hooks/useGraphPulse';

// ── Types ─────────────────────────────────────────────────

type GNode = {
  id: string;
  name: string;
  type: string;
  memoryCount: number;
  colour: string;
  isCluster?: boolean;
  clusterType?: string;
  entityCount?: number;
  fx?: number;
  fy?: number;
  x?: number;
  y?: number;
};

type GLink = {
  source: string;
  target: string;
  predicate?: string;
  weight?: number;
};

type FGRef = ForceGraphMethods<NodeObject<GNode>, LinkObject<GNode, GLink>>;
type FGProps = ForceGraphProps<GNode, GLink> & { ref?: React.MutableRefObject<FGRef | undefined> };
type FGComponent = (props: FGProps) => React.ReactElement;

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false }) as unknown as FGComponent;

// ── Cluster colour fallback ───────────────────────────────

const CLUSTER_COLOURS: Record<string, string> = {
  tool: '#00e5cc',
  concept: '#ff4d4d',
  project: '#f59e0b',
  file: '#5a6480',
  service: '#a78bfa',
  person: '#34d399',
  language: '#a78bfa',
  pattern: '#fb923c',
};

// ── Props ─────────────────────────────────────────────────

export interface ConstellationGraphProps {
  clusters: ClusterData[];
  allTriples: { source: string; target: string; predicate: string }[];
  totalEntities: number;
  totalConnections: number;
  width: number;
  height: number;
  onSelectEntity?: (entity: GraphEntity | null) => void;
  selectedEntityId?: string | null;
}

// ── Helpers ───────────────────────────────────────────────

function buildEntityClusterMap(clusters: ClusterData[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const c of clusters) {
    for (const e of c.entities) map.set(e.id, c.type);
  }
  return map;
}

function countCrossClusterLinks(
  triples: { source: string; target: string }[],
  entityCluster: Map<string, string>,
): Map<string, number> {
  const counts = new Map<string, number>();
  for (const t of triples) {
    const s = entityCluster.get(t.source);
    const tg = entityCluster.get(t.target);
    if (s && tg && s !== tg) {
      const key = [s, tg].sort().join('::');
      counts.set(key, (counts.get(key) || 0) + 1);
    }
  }
  return counts;
}

/**
 * Legacy cluster paint — verbatim halo + scatter + label rendering from the
 * pre-modular ConstellationGraph. Preserved here so the cluster-level view
 * keeps its visual identity while entity-level paint moves to paintNode.
 */
function paintClusterLegacy(
  ctx: CanvasRenderingContext2D,
  node: GNode & { x: number; y: number },
  zoom: number,
  isHovered: boolean,
): void {
  const entCount = node.entityCount || 5;
  const baseR = 15 + Math.sqrt(entCount) * 3;
  const r = Math.min(baseR, 60);

  // Outer nebula
  const nebulaR = r * 3;
  const nebula = ctx.createRadialGradient(node.x, node.y, r * 0.5, node.x, node.y, nebulaR);
  nebula.addColorStop(0, node.colour + '15');
  nebula.addColorStop(0.4, node.colour + '08');
  nebula.addColorStop(1, node.colour + '00');
  ctx.beginPath();
  ctx.arc(node.x, node.y, nebulaR, 0, 2 * Math.PI);
  ctx.fillStyle = nebula;
  ctx.fill();

  // Inner core glow
  const core = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 0.8);
  core.addColorStop(0, node.colour + '28');
  core.addColorStop(0.6, node.colour + '10');
  core.addColorStop(1, node.colour + '02');
  ctx.beginPath();
  ctx.arc(node.x, node.y, r * 0.8, 0, 2 * Math.PI);
  ctx.fillStyle = core;
  ctx.fill();

  // Scatter star dots inside the halo
  const dotCount = Math.min(entCount, 40);
  const seed = node.id.charCodeAt(node.id.length - 1);
  for (let i = 0; i < dotCount; i++) {
    const angle = ((seed + i * 137.508) % 360) * (Math.PI / 180);
    const dist = r * 0.1 + r * 0.85 * Math.pow(((seed * 7 + i * 31) % 100) / 100, 0.6);
    const dx = node.x + Math.cos(angle) * dist;
    const dy = node.y + Math.sin(angle) * dist;
    const dr = 0.5 + ((i * 17 + seed) % 4) * 0.3;
    ctx.beginPath();
    ctx.arc(dx, dy, dr, 0, 2 * Math.PI);
    ctx.fillStyle = node.colour + (i < 5 ? 'dd' : i < 15 ? '88' : '44');
    ctx.fill();
  }

  // Hover dashed ring
  if (isHovered) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
    ctx.strokeStyle = node.colour + '50';
    ctx.lineWidth = 1.5;
    ctx.setLineDash([4, 4]);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // Type label
  const fontSize = Math.max(13 / Math.max(zoom, 0.3), 8);
  ctx.font = `600 ${fontSize}px Inter, system-ui, sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ctx.fillStyle = node.colour + 'bb';
  ctx.fillText(node.name, node.x, node.y + r + 8);

  // Entity count
  const countSize = Math.max(10 / Math.max(zoom, 0.3), 6);
  ctx.font = `400 ${countSize}px Inter, system-ui, sans-serif`;
  ctx.fillStyle = '#ffffff30';
  ctx.fillText(`${entCount} entities`, node.x, node.y + r + 8 + fontSize + 3);
}

// ── Component ─────────────────────────────────────────────

export function ConstellationGraph({
  clusters,
  allTriples,
  totalEntities,
  totalConnections,
  width,
  height,
  onSelectEntity,
  selectedEntityId,
}: ConstellationGraphProps) {
  const graphRef = useRef<FGRef | undefined>(undefined);
  const hoveredRef = useRef<string | null>(null);
  const zoomRef = useRef(1);
  // When a node is hovered, the set of {hovered} ∪ direct neighbours; null when
  // nothing is hovered. Drives the neighbourhood-focus dimming in render*.
  const neighbourhoodRef = useRef<Set<string> | null>(null);
  const [driver, setDriver] = useState<PulseDriver | null>(null);
  const [activeCluster, setActiveCluster] = useState<string | null>(null);
  const [anchorId, setAnchorId] = useState<string | null>(null);
  const [level, setLevel] = useState<IntensityLevel>('moderate');

  const reducedMotion = useMemo(() => isReducedMotion(), []);
  const settings = useMemo(
    () => (reducedMotion ? REDUCED_INTENSITY : INTENSITY[level]),
    [reducedMotion, level],
  );

  const entityClusterMap = useMemo(() => buildEntityClusterMap(clusters), [clusters]);

  // ── Level 1: Cluster map — fixed positions in a ring ────

  const clusterGraphData = useMemo(() => {
    const crossLinks = countCrossClusterLinks(allTriples, entityClusterMap);
    const radius = 150;

    const nodes: GNode[] = clusters.map((c, i) => {
      const angle = (i / clusters.length) * Math.PI * 2 - Math.PI / 2;
      return {
        id: `cluster::${c.type}`,
        name: c.type,
        type: c.type,
        memoryCount: c.entities.reduce((sum, e) => sum + e.memoryCount, 0),
        colour: c.colour,
        isCluster: true,
        clusterType: c.type,
        entityCount: c.entities.length,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
      } as GNode;
    });

    const links: GLink[] = [];
    for (const [key, count] of crossLinks.entries()) {
      const [a, b] = key.split('::');
      if (count > 5) {
        links.push({
          source: `cluster::${a}`,
          target: `cluster::${b}`,
          weight: Math.min(count / 100, 1),
        });
      }
    }

    return { nodes, links };
  }, [clusters, allTriples, entityClusterMap]);

  // ── Level 2: Detail data for active cluster ─────────────

  const detailGraphData = useMemo(() => {
    if (!activeCluster) return null;
    const cluster = clusters.find((c) => c.type === activeCluster);
    if (!cluster) return null;

    const entities = cluster.entities.slice(0, 100);
    const entityIds = new Set(entities.map((e) => e.id));

    const nodes: GNode[] = entities.map((e) => ({
      id: e.id,
      name: e.name,
      type: e.type,
      memoryCount: e.memoryCount,
      colour: cluster.colour,
    }));

    // Ghost nodes for other clusters
    const ghostCounts = new Map<string, number>();
    for (const t of allTriples) {
      if (entityIds.has(t.source) && !entityIds.has(t.target)) {
        const tc = entityClusterMap.get(t.target);
        if (tc && tc !== activeCluster) ghostCounts.set(tc, (ghostCounts.get(tc) || 0) + 1);
      }
      if (entityIds.has(t.target) && !entityIds.has(t.source)) {
        const sc = entityClusterMap.get(t.source);
        if (sc && sc !== activeCluster) ghostCounts.set(sc, (ghostCounts.get(sc) || 0) + 1);
      }
    }

    for (const [type, count] of ghostCounts.entries()) {
      if (count > 2) {
        nodes.push({
          id: `ghost::${type}`,
          name: type,
          type,
          memoryCount: count,
          colour: CLUSTER_COLOURS[type] || '#8892b0',
          isCluster: true,
          clusterType: type,
          entityCount: count,
        });
      }
    }

    const links: GLink[] = [];
    const seen = new Set<string>();
    for (const t of allTriples) {
      const srcIn = entityIds.has(t.source);
      const tgtIn = entityIds.has(t.target);

      if (srcIn && tgtIn) {
        const k = `${t.source}::${t.target}`;
        if (!seen.has(k)) { seen.add(k); links.push({ source: t.source, target: t.target, predicate: t.predicate }); }
      } else if (srcIn && !tgtIn) {
        const tc = entityClusterMap.get(t.target);
        if (tc && tc !== activeCluster && ghostCounts.has(tc)) {
          const k = `${t.source}::ghost::${tc}`;
          if (!seen.has(k)) { seen.add(k); links.push({ source: t.source, target: `ghost::${tc}` }); }
        }
      } else if (tgtIn && !srcIn) {
        const sc = entityClusterMap.get(t.source);
        if (sc && sc !== activeCluster && ghostCounts.has(sc)) {
          const k = `ghost::${sc}::${t.target}`;
          if (!seen.has(k)) { seen.add(k); links.push({ source: `ghost::${sc}`, target: t.target }); }
        }
      }
    }

    return { nodes, links };
  }, [activeCluster, clusters, allTriples, entityClusterMap]);

  const graphData = activeCluster && detailGraphData ? detailGraphData : clusterGraphData;

  // Node degree (link count) — drives label culling so only well-connected hub
  // nodes are labelled at low zoom, instead of every high-memory node at once.
  const nodeDegrees = useMemo(() => {
    const deg = new Map<string, number>();
    for (const l of graphData.links) {
      const s = typeof l.source === 'object' ? String((l.source as GNode).id) : String(l.source);
      const t = typeof l.target === 'object' ? String((l.target as GNode).id) : String(l.target);
      deg.set(s, (deg.get(s) ?? 0) + 1);
      deg.set(t, (deg.get(t) ?? 0) + 1);
    }
    return deg;
  }, [graphData.links]);

  // ── PulseDriver lifecycle ───────────────────────────────

  useEffect(() => {
    const initial = loadIntensity();
    setLevel(initial);
    const d = new PulseDriver({ intensity: initial });
    setDriver(d);
    const onIntensityChange = (e: Event) => {
      const next = (e as CustomEvent<IntensityLevel>).detail;
      if (next === 'subtle' || next === 'moderate' || next === 'strong') {
        setLevel(next);
        d.setIntensity(next);
      }
    };
    if (typeof window !== 'undefined') {
      window.addEventListener('shieldcortex:intensity-changed', onIntensityChange);
    }
    return () => {
      if (typeof window !== 'undefined') {
        window.removeEventListener('shieldcortex:intensity-changed', onIntensityChange);
      }
    };
  }, []);

  // Observe nodes so breathing kicks in for the active data set.
  useEffect(() => {
    driver?.observeNodes(graphData.nodes.map((n) => n.id));
  }, [driver, graphData.nodes]);

  // Wire WS / polling fallback to the driver.
  useGraphPulse(driver, true);

  // ── Anchor (the sun) ────────────────────────────────────

  useEffect(() => {
    const next = pickAnchor(
      graphData.nodes.map((n) => ({ id: n.id, name: n.name, memoryCount: n.memoryCount })),
      graphData.links,
    );
    if (next !== anchorId) {
      applyAnchor(graphData.nodes, next ?? '', anchorId);
      setAnchorId(next);
    }
    // graphData.nodes intentionally a dep — anchor must re-evaluate when zooming
    // between cluster level and entity level (different node set).
  }, [graphData.nodes, graphData.links, anchorId]);

  // ── Forces ──────────────────────────────────────────────

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    if (activeCluster) {
      fg.d3Force('charge')?.strength(-80);
      fg.d3Force('link')?.distance(40);
      fg.d3Force('center')?.strength(0.05);
    } else {
      fg.d3Force('charge')?.strength(-2000);
      fg.d3Force('link')?.distance(180);
      fg.d3Force('center')?.strength(0.03);
    }
  }, [activeCluster, graphData]);

  // Zoom-to-fit once on first load after simulation settles
  const hasInitialFit = useRef(false);
  useEffect(() => {
    if (hasInitialFit.current || !graphData.nodes.length) return;
    hasInitialFit.current = true;
    const t = setTimeout(() => graphRef.current?.zoomToFit(reducedMotion ? 0 : 600, 40), 1500);
    return () => clearTimeout(t);
  }, [graphData.nodes.length, reducedMotion]);

  const handleZoom = useCallback(({ k }: { k: number }) => { zoomRef.current = k; }, []);

  // ── Controls (drag-to-pin + shift-click unpin + double-click zoom) ──

  // wireControls captures the ref by closure and only reads `current` inside
  // event handlers (post-mount), never during render. The react-hooks/refs lint
  // rule can't statically prove that — disable for this one call. GNode's fx
  // is `number | undefined` (matches d3); controls.ts's PinnableNode allows
  // `null` for release, so cast through unknown.
  const controls = useMemo(
    // eslint-disable-next-line react-hooks/refs
    () => wireControls(graphRef as unknown as React.MutableRefObject<ForceGraphMethods<NodeObject<{ id: string; fx?: number | null; fy?: number | null; x?: number; y?: number }>> | undefined>),
    [],
  );

  const handleNodeClick = useCallback(
    (node: NodeObject<GNode>, event: MouseEvent) => {
      const gn = node as GNode;
      const outcome = controls.handleNodeClick(node, event);
      if (outcome !== 'single-click') return;

      if (gn.isCluster) {
        const type = (gn.clusterType || gn.type).replace('ghost::', '');
        setActiveCluster(type);
        onSelectEntity?.(null);
      } else {
        onSelectEntity?.({ id: gn.id, name: gn.name, type: gn.type, memoryCount: gn.memoryCount });
      }
    },
    [controls, onSelectEntity],
  );

  const handleBackgroundClick = useCallback(() => {
    if (activeCluster) {
      setActiveCluster(null);
      onSelectEntity?.(null);
    }
  }, [activeCluster, onSelectEntity]);

  // Background double-click — full reset: clear active cluster + selection,
  // then zoomToFit. The plan's intended gesture for "I'm lost, take me home."
  const handleBackgroundDoubleClick = useCallback(() => {
    controls.handleBackgroundDoubleClick(() => {
      setActiveCluster(null);
      onSelectEntity?.(null);
    });
  }, [controls, onSelectEntity]);

  const handleNodeHover = useCallback((node: NodeObject<GNode> | null) => {
    const id = node ? String((node as GNode).id) : null;
    hoveredRef.current = id;
    if (!id) {
      neighbourhoodRef.current = null;
      return;
    }
    const nb = new Set<string>([id]);
    for (const l of graphData.links) {
      const s = typeof l.source === 'object' ? String((l.source as GNode).id) : String(l.source);
      const t = typeof l.target === 'object' ? String((l.target as GNode).id) : String(l.target);
      if (s === id) nb.add(t);
      else if (t === id) nb.add(s);
    }
    neighbourhoodRef.current = nb;
  }, [graphData.links]);

  // ── Painting (hybrid: legacy cluster paint + new entity paint) ──

  const renderNode = useCallback(
    (node: NodeObject<GNode>, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const gn = node as GNode;
      if (gn.x === undefined || gn.y === undefined) return;
      const id = String(node.id);
      const isHovered = id === hoveredRef.current;
      const isSelected = selectedEntityId != null && id === selectedEntityId;
      const zoom = zoomRef.current;

      ctx.save();

      // Selected entity bloom (legacy behaviour — large white radial fade).
      if (isSelected && !gn.isCluster) {
        const mc = gn.memoryCount || 1;
        const r = 0.8 + Math.min(Math.log2(mc + 1) * 0.4, 2.5);
        const bloom = ctx.createRadialGradient(gn.x, gn.y, r, gn.x, gn.y, r * 8);
        bloom.addColorStop(0, '#ffffff18');
        bloom.addColorStop(1, '#ffffff00');
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, r * 8, 0, 2 * Math.PI);
        ctx.fillStyle = bloom;
        ctx.fill();
      }

      if (gn.isCluster) {
        paintClusterLegacy(ctx, gn as GNode & { x: number; y: number }, zoom, isHovered);
        ctx.restore();
        return;
      }

      // Neighbourhood focus: while a node is hovered, dim entities (and their
      // labels) outside its neighbourhood so the local structure stands out.
      const nb = neighbourhoodRef.current;
      if (nb && !nb.has(id)) ctx.globalAlpha = 0.18;

      // Entity branch — delegate to the new module.
      const energy = driver?.getEnergy(id) ?? 0;
      const recallEnergy = driver?.getRecallEnergy(id) ?? 0;
      const baseRadius = 0.8 + Math.min(Math.log2((gn.memoryCount ?? 0) + 1) * 0.4, 2.5);

      paintNode({
        ctx,
        globalScale,
        node: gn,
        intensity: settings,
        energy,
        recallEnergy,
        isAnchor: id === anchorId,
        isSelected,
        isHovered,
        baseRadius,
      });

      // Hover stroke ring (preserved from legacy entity paint).
      if (isHovered && !isSelected && id !== anchorId) {
        const r = baseRadius * (1 + energy * settings.breathAmp);
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, r, 0, 2 * Math.PI);
        ctx.strokeStyle = gn.colour;
        ctx.lineWidth = 0.7;
        ctx.stroke();
      }

      // Labels — culled by zoom AND node degree, so at default zoom only the
      // well-connected hubs are labelled (the old `mc > 100` blanket labelled
      // ~half the graph at once, which was the clutter). On hover, the whole
      // neighbourhood is labelled for context.
      const mc = gn.memoryCount || 1;
      const degree = nodeDegrees.get(id) ?? 0;
      const inNeighbourhood = nb?.has(id) ?? false;
      const show = isSelected || isHovered || inNeighbourhood ||
        (zoom >= 3) ||
        (zoom >= 1.5 && (mc > 30 || degree > 3)) ||
        (zoom >= 0.8 && degree > 6);

      if (show) {
        const r = baseRadius * (1 + energy * settings.breathAmp);
        const fs = Math.max((isSelected ? 11 : isHovered ? 10 : 8) / Math.max(zoom, 0.4), 5);
        ctx.font = `${fs}px Inter, system-ui, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        // Background pill so the label stays legible over nodes/links.
        const pad = 2.5 / Math.max(zoom, 0.4);
        const tw = ctx.measureText(gn.name).width;
        const ly = gn.y + r + 1.5;
        const lx = gn.x - tw / 2 - pad;
        ctx.fillStyle = 'rgba(6,10,20,0.6)';
        if (typeof ctx.roundRect === 'function') {
          ctx.beginPath();
          ctx.roundRect(lx, ly, tw + pad * 2, fs + pad, pad);
          ctx.fill();
        } else {
          ctx.fillRect(lx, ly, tw + pad * 2, fs + pad);
        }
        ctx.fillStyle = isSelected ? '#ffffff' : isHovered ? '#f4f7ff' : '#dde6ffcc';
        ctx.fillText(gn.name, gn.x, ly + pad / 2);
      }

      ctx.restore();
    },
    [selectedEntityId, anchorId, settings, driver, nodeDegrees],
  );

  // ── Link paint (delegates to module; ghost/cluster links keep faded look) ──

  const renderLink = useCallback(
    (link: LinkObject<GNode, GLink>, ctx: CanvasRenderingContext2D) => {
      const src = link.source as NodeObject<GNode>;
      const tgt = link.target as NodeObject<GNode>;
      if (typeof src !== 'object' || typeof tgt !== 'object') return;
      if (src.x === undefined || src.y === undefined || tgt.x === undefined || tgt.y === undefined) return;

      const srcId = String(src.id);
      const tgtId = String(tgt.id);
      const srcEnergy = driver?.getEnergy(srcId) ?? 0;
      const dstEnergy = driver?.getEnergy(tgtId) ?? 0;

      // Neighbourhood focus: when hovering, heavily fade links not touching the
      // hovered node so its connections read clearly.
      const hovered = hoveredRef.current;
      const connected = !hovered || srcId === hovered || tgtId === hovered;

      ctx.save();
      if (!connected) ctx.globalAlpha = 0.08;
      paintLink({
        ctx,
        link: {
          source: { x: src.x, y: src.y, colour: (src as GNode).colour, id: srcId },
          target: { x: tgt.x, y: tgt.y, colour: (tgt as GNode).colour, id: tgtId },
        },
        srcEnergy,
        dstEnergy,
      });
      ctx.restore();
    },
    [driver],
  );

  // Drive PulseDriver frames + pick particle edges each render frame.
  const particleEdges = useRef<Set<string>>(new Set());
  const onFramePre = useCallback(() => {
    if (!driver) return;
    driver.onFrame(performance.now());
    const picks = driver.pickParticleEdges(
      graphData.links.map((l) => ({ source: String(l.source), target: String(l.target) })),
      anchorId,
    );
    const next = new Set<string>();
    for (const p of picks) next.add(`${p.source}::${p.target}`);
    particleEdges.current = next;
  }, [driver, graphData.links, anchorId]);

  if (width < 10 || height < 10) return null;

  const activeClusterData = activeCluster ? clusters.find((c) => c.type === activeCluster) : null;

  return (
    <div className="relative h-full w-full">
      {activeCluster && (
        <button
          type="button"
          onClick={handleBackgroundClick}
          className="absolute left-4 top-4 z-20 flex items-center gap-2 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/90 px-3 py-1.5 text-xs text-[var(--sc-text-secondary)] backdrop-blur-sm transition-colors hover:border-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]"
        >
          <span>&larr;</span>
          <span>All clusters</span>
        </button>
      )}

      {activeClusterData && (
        <div className="absolute right-4 top-4 z-20 flex items-center gap-2 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/90 px-3 py-1.5 backdrop-blur-sm">
          <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: activeClusterData.colour }} />
          <span className="text-xs font-semibold text-[var(--sc-text-primary)]">{activeClusterData.type}</span>
          <span className="text-xs text-[var(--sc-text-muted)]">{activeClusterData.entities.length} entities</span>
        </div>
      )}

      <div onDoubleClick={handleBackgroundDoubleClick} style={{ position: 'relative' }}>
        <ForceGraph2D
          ref={graphRef}
          graphData={graphData}
          width={width}
          height={height}
          backgroundColor="rgba(0,0,0,0)"
          nodeCanvasObjectMode={() => 'replace'}
          nodeCanvasObject={renderNode}
          nodePointerAreaPaint={(node, colour, ctx) => {
            const gn = node as GNode;
            if (gn.x === undefined || gn.y === undefined) return;
            let hitR: number;
            if (gn.isCluster) {
              const entCount = gn.entityCount || 5;
              hitR = Math.min(15 + Math.sqrt(entCount) * 3, 60);
            } else {
              hitR = 4 + Math.min(Math.log2((gn.memoryCount || 1) + 1) * 0.5, 3);
            }
            ctx.beginPath();
            ctx.arc(gn.x, gn.y, hitR, 0, 2 * Math.PI);
            ctx.fillStyle = colour;
            ctx.fill();
          }}
          linkCanvasObjectMode={() => 'replace'}
          linkCanvasObject={renderLink}
          linkDirectionalParticles={(link) => {
            const l = link as LinkObject<GNode, GLink>;
            const src = typeof l.source === 'object' ? (l.source as GNode).id : String(l.source);
            const tgt = typeof l.target === 'object' ? (l.target as GNode).id : String(l.target);
            return particleEdges.current.has(`${src}::${tgt}`) ? 2 : 0;
          }}
          linkDirectionalParticleWidth={1.2}
          linkDirectionalParticleSpeed={0.005}
          onNodeClick={handleNodeClick}
          onNodeDragEnd={(node) => controls.handleNodeDragEnd(node as NodeObject<GNode>)}
          onNodeHover={handleNodeHover}
          onBackgroundClick={handleBackgroundClick}
          onZoom={handleZoom}
          onRenderFramePre={onFramePre}
          d3AlphaDecay={0.01}
          d3VelocityDecay={0.3}
          cooldownTicks={300}
          warmupTicks={80}
          nodeRelSize={1}
          enableNodeDrag={true}
          enableZoomInteraction={true}
          onEngineStop={() => {
            if (!hasInitialFit.current && graphData.nodes.length) {
              hasInitialFit.current = true;
              graphRef.current?.zoomToFit(reducedMotion ? 0 : 600, 40);
            }
          }}
        />
        <PulseDebugPanel driver={driver} />
      </div>

      <div className="absolute bottom-3 left-0 right-0 z-10 flex items-center justify-center gap-4 text-[11px] text-[var(--sc-text-muted)]">
        <span>{totalEntities.toLocaleString()} entities</span>
        <span className="text-[var(--sc-border)]">&middot;</span>
        <span>{totalConnections.toLocaleString()} connections</span>
        <span className="text-[var(--sc-border)]">&middot;</span>
        <span>{clusters.length} clusters</span>
        {activeClusterData && (
          <>
            <span className="text-[var(--sc-border)]">&middot;</span>
            <span style={{ color: activeClusterData.colour }}>
              {activeClusterData.entities.length} {activeCluster} entities
            </span>
          </>
        )}
      </div>
    </div>
  );
}
