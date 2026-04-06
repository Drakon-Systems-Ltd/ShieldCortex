'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import type { ForceGraphMethods, ForceGraphProps, NodeObject, LinkObject } from 'react-force-graph-2d';
import type { ClusterData, GraphEntity } from '@/hooks/useGraphData';

// ── Dynamic import ────────────────────────────────────────

type GNode = {
  id: string;
  name: string;
  type: string;
  memoryCount: number;
  colour: string;
  isCluster?: boolean;
  clusterType?: string;
  entityCount?: number;
  // Pre-set positions for cluster level
  fx?: number;
  fy?: number;
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

// ── Colours ───────────────────────────────────────────────

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
  const [activeCluster, setActiveCluster] = useState<string | null>(null);

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
        // Starting positions in a ring — forces will hold them apart
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
  }, [clusters, allTriples, entityClusterMap, width, height]);

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

  // ── Forces ──────────────────────────────────────────────

  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    if (activeCluster) {
      fg.d3Force('charge')?.strength(-80);
      fg.d3Force('link')?.distance(40);
      fg.d3Force('center')?.strength(0.05);
    } else {
      // Cluster view: strong repulsion to keep clusters well-spaced
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
    // Wait for simulation to run before fitting
    const t = setTimeout(() => graphRef.current?.zoomToFit(400, 80), 1500);
    return () => clearTimeout(t);
  }, [graphData.nodes.length]);

  const handleZoom = useCallback(({ k }: { k: number }) => { zoomRef.current = k; }, []);

  // ── Click handling ──────────────────────────────────────

  const handleNodeClick = useCallback(
    (node: NodeObject<GNode>) => {
      const gn = node as GNode;
      if (gn.isCluster) {
        const type = (gn.clusterType || gn.type).replace('ghost::', '');
        setActiveCluster(type);
        onSelectEntity?.(null);
      } else {
        onSelectEntity?.({ id: gn.id, name: gn.name, type: gn.type, memoryCount: gn.memoryCount });
      }
    },
    [onSelectEntity],
  );

  const handleBackgroundClick = useCallback(() => {
    if (activeCluster) {
      setActiveCluster(null);
      onSelectEntity?.(null);
    }
  }, [activeCluster, onSelectEntity]);

  const handleNodeHover = useCallback((node: NodeObject<GNode> | null) => {
    hoveredRef.current = node ? String((node as GNode).id) : null;
  }, []);

  // ── Painting ────────────────────────────────────────────

  const paintNode = useCallback(
    (node: NodeObject<GNode>, ctx: CanvasRenderingContext2D) => {
      const gn = node as GNode & { x: number; y: number };
      if (gn.x == null || gn.y == null) return;

      const isHovered = String(gn.id) === hoveredRef.current;
      const isSelected = selectedEntityId != null && String(gn.id) === selectedEntityId;
      const zoom = zoomRef.current;

      ctx.save();

      if (gn.isCluster) {
        // ── Cluster halo ──
        const entCount = gn.entityCount || 5;
        const baseR = 15 + Math.sqrt(entCount) * 3;
        const r = Math.min(baseR, 60);

        // Outer nebula
        const nebulaR = r * 3;
        const nebula = ctx.createRadialGradient(gn.x, gn.y, r * 0.5, gn.x, gn.y, nebulaR);
        nebula.addColorStop(0, gn.colour + '15');
        nebula.addColorStop(0.4, gn.colour + '08');
        nebula.addColorStop(1, gn.colour + '00');
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, nebulaR, 0, 2 * Math.PI);
        ctx.fillStyle = nebula;
        ctx.fill();

        // Inner core glow
        const core = ctx.createRadialGradient(gn.x, gn.y, 0, gn.x, gn.y, r * 0.8);
        core.addColorStop(0, gn.colour + '28');
        core.addColorStop(0.6, gn.colour + '10');
        core.addColorStop(1, gn.colour + '02');
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, r * 0.8, 0, 2 * Math.PI);
        ctx.fillStyle = core;
        ctx.fill();

        // Scatter star dots inside the halo
        const dotCount = Math.min(entCount, 40);
        const seed = gn.id.charCodeAt(gn.id.length - 1);
        for (let i = 0; i < dotCount; i++) {
          const angle = ((seed + i * 137.508) % 360) * (Math.PI / 180);
          const dist = r * 0.1 + r * 0.85 * Math.pow(((seed * 7 + i * 31) % 100) / 100, 0.6);
          const dx = gn.x + Math.cos(angle) * dist;
          const dy = gn.y + Math.sin(angle) * dist;
          const dr = 0.5 + ((i * 17 + seed) % 4) * 0.3;
          ctx.beginPath();
          ctx.arc(dx, dy, dr, 0, 2 * Math.PI);
          ctx.fillStyle = gn.colour + (i < 5 ? 'dd' : i < 15 ? '88' : '44');
          ctx.fill();
        }

        // Hover: bright ring
        if (isHovered) {
          ctx.beginPath();
          ctx.arc(gn.x, gn.y, r, 0, 2 * Math.PI);
          ctx.strokeStyle = gn.colour + '50';
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
        ctx.fillStyle = gn.colour + 'bb';
        ctx.fillText(gn.name, gn.x, gn.y + r + 8);

        // Count
        const countSize = Math.max(10 / Math.max(zoom, 0.3), 6);
        ctx.font = `400 ${countSize}px Inter, system-ui, sans-serif`;
        ctx.fillStyle = '#ffffff30';
        ctx.fillText(`${entCount} entities`, gn.x, gn.y + r + 8 + fontSize + 3);

      } else {
        // ── Entity dot ──
        const mc = gn.memoryCount || 1;
        const r = 0.8 + Math.min(Math.log2(mc + 1) * 0.4, 2.5);

        // Glow
        const glowR = r * 3.5;
        const glow = ctx.createRadialGradient(gn.x, gn.y, r * 0.2, gn.x, gn.y, glowR);
        glow.addColorStop(0, gn.colour + (isSelected ? '50' : '20'));
        glow.addColorStop(1, gn.colour + '00');
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, glowR, 0, 2 * Math.PI);
        ctx.fillStyle = glow;
        ctx.fill();

        // Selected bloom
        if (isSelected) {
          const bloom = ctx.createRadialGradient(gn.x, gn.y, r, gn.x, gn.y, r * 8);
          bloom.addColorStop(0, '#ffffff18');
          bloom.addColorStop(1, '#ffffff00');
          ctx.beginPath();
          ctx.arc(gn.x, gn.y, r * 8, 0, 2 * Math.PI);
          ctx.fillStyle = bloom;
          ctx.fill();
        }

        // Dot
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, r, 0, 2 * Math.PI);
        ctx.fillStyle = isSelected ? '#ffffff' : gn.colour;
        ctx.fill();

        if (isSelected) {
          ctx.strokeStyle = '#ffffff';
          ctx.lineWidth = 1;
          ctx.stroke();
        } else if (isHovered) {
          ctx.strokeStyle = gn.colour;
          ctx.lineWidth = 0.7;
          ctx.stroke();
        }

        // Labels
        const show = isSelected || isHovered ||
          (zoom >= 3) ||
          (zoom >= 1.5 && mc > 30) ||
          (zoom >= 0.8 && mc > 100);

        if (show) {
          const fs = Math.max((isSelected ? 11 : isHovered ? 10 : 8) / Math.max(zoom, 0.4), 5);
          ctx.font = `${fs}px Inter, system-ui, sans-serif`;
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          ctx.fillStyle = isSelected ? '#ffffff' : isHovered ? '#f0f4ffcc' : '#f0f4ff66';
          ctx.fillText(gn.name, gn.x, gn.y + r + 2);
        }
      }

      ctx.restore();
    },
    [selectedEntityId],
  );

  const linkColour = useCallback(
    (link: LinkObject<GNode, GLink>) => {
      if (!activeCluster) {
        const w = (link as GLink).weight || 0.05;
        return `rgba(136, 146, 176, ${(w * 0.12 + 0.02).toFixed(3)})`;
      }
      const src = typeof link.source === 'object' ? (link.source as GNode).id : String(link.source);
      const tgt = typeof link.target === 'object' ? (link.target as GNode).id : String(link.target);
      if (src.startsWith('ghost::') || tgt.startsWith('ghost::')) return 'rgba(136, 146, 176, 0.03)';
      if (selectedEntityId && (src === selectedEntityId || tgt === selectedEntityId)) return 'rgba(0, 229, 204, 0.25)';
      return 'rgba(136, 146, 176, 0.05)';
    },
    [activeCluster, selectedEntityId],
  );

  const linkWidth = useCallback(
    (link: LinkObject<GNode, GLink>) => activeCluster ? 0.3 : Math.max(((link as GLink).weight || 0.05) * 1.5, 0.2),
    [activeCluster],
  );

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

      <ForceGraph2D
        ref={graphRef}
        graphData={graphData}
        width={width}
        height={height}
        backgroundColor="rgba(0,0,0,0)"
        nodeCanvasObjectMode={() => 'replace'}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={(node, colour, ctx) => {
          const gn = node as GNode & { x: number; y: number };
          if (gn.x == null || gn.y == null) return;
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
        linkColor={linkColour}
        linkWidth={linkWidth}
        onNodeClick={handleNodeClick}
        onNodeHover={handleNodeHover}
        onBackgroundClick={handleBackgroundClick}
        onZoom={handleZoom}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.3}
        cooldownTicks={300}
        warmupTicks={80}
        nodeRelSize={1}
        enableNodeDrag={true}
        enableZoomInteraction={true}
        onEngineStop={() => {
          // Only auto-fit on first engine stop (initial layout)
          if (!hasInitialFit.current && graphData.nodes.length) {
            hasInitialFit.current = true;
            graphRef.current?.zoomToFit(400, 80);
          }
        }}
      />

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
