'use client';

import { useCallback, useEffect, useMemo, useRef, type ReactElement, type MutableRefObject } from 'react';
import dynamic from 'next/dynamic';
import type { ForceGraphMethods, ForceGraphProps, NodeObject, LinkObject } from 'react-force-graph-2d';
import type { GraphNode, GraphLink } from '@/hooks/useGraphData';

// ── Dynamic import ────────────────────────────────────────

type FGRef = ForceGraphMethods<NodeObject<GraphNode>, LinkObject<GraphNode, GraphLink>>;
type FGProps = ForceGraphProps<GraphNode, GraphLink> & { ref?: MutableRefObject<FGRef | undefined> };
type FGComponent = (props: FGProps) => ReactElement;

const ForceGraph2D = dynamic(() => import('react-force-graph-2d'), { ssr: false }) as unknown as FGComponent;

// ── Colour map ────────────────────────────────────────────

const TYPE_COLOURS: Record<string, string> = {
  tool: '#00e5cc',
  concept: '#ff4d4d',
  project: '#f59e0b',
  file: '#5a6480',
  service: '#a78bfa',
  person: '#34d399',
  language: '#a78bfa',
  pattern: '#fb923c',
};

const DEFAULT_COLOUR = '#8892b0';

function colourForType(type: string): string {
  return TYPE_COLOURS[type] || DEFAULT_COLOUR;
}

/** Tiny dots — constellation / neuron style. Range: 1.5px to 5px */
function nodeRadius(node: GraphNode): number {
  return 1.5 + Math.min(Math.log2(Math.max(node.memoryCount, 1) + 1) * 0.6, 3.5);
}

// ── Props ─────────────────────────────────────────────────

export interface LocalGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  selectedId?: string;
  onSelectEntity: (node: GraphNode) => void;
  width: number;
  height: number;
  fitTrigger?: number;
}

// ── Component ─────────────────────────────────────────────

export function LocalGraph({ nodes, links, selectedId, onSelectEntity, width, height, fitTrigger }: LocalGraphProps) {
  const graphRef = useRef<FGRef | undefined>(undefined);
  const hoveredRef = useRef<string | null>(null);
  const zoomRef = useRef(1);

  // Track zoom level for semantic label visibility
  const handleZoom = useCallback(({ k }: { k: number }) => {
    zoomRef.current = k;
  }, []);

  // Neighbour set for dimming
  const selectedNeighbours = useMemo(() => {
    if (!selectedId) return new Set<string>();
    const neighbours = new Set<string>();
    for (const link of links) {
      const src = typeof link.source === 'object' ? (link.source as GraphNode).id : link.source;
      const tgt = typeof link.target === 'object' ? (link.target as GraphNode).id : link.target;
      if (src === selectedId) neighbours.add(String(tgt));
      if (tgt === selectedId) neighbours.add(String(src));
    }
    return neighbours;
  }, [selectedId, links]);

  const paintNode = useCallback(
    (node: NodeObject<GraphNode>, ctx: CanvasRenderingContext2D) => {
      const gn = node as GraphNode & { x: number; y: number };
      if (gn.x == null || gn.y == null) return;

      const r = nodeRadius(gn);
      const nodeId = String(gn.id);
      const isSelected = nodeId === selectedId;
      const isHovered = nodeId === hoveredRef.current;
      const isNeighbour = selectedNeighbours.has(nodeId);
      const hasFocus = !!selectedId;
      const dimmed = hasFocus && !isSelected && !isNeighbour;
      const zoom = zoomRef.current;

      ctx.save();

      if (dimmed) ctx.globalAlpha = 0.15;

      const colour = colourForType(gn.type);

      // Soft glow behind node (subtle, like a star)
      if (!dimmed) {
        const glowR = r * 3;
        const gradient = ctx.createRadialGradient(gn.x, gn.y, r * 0.5, gn.x, gn.y, glowR);
        gradient.addColorStop(0, colour + '30'); // 19% opacity
        gradient.addColorStop(1, colour + '00'); // transparent
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, glowR, 0, 2 * Math.PI);
        ctx.fillStyle = gradient;
        ctx.fill();
      }

      // Brighter glow for selected
      if (isSelected) {
        const selGlow = r * 5;
        const selGrad = ctx.createRadialGradient(gn.x, gn.y, r, gn.x, gn.y, selGlow);
        selGrad.addColorStop(0, '#ffffff20');
        selGrad.addColorStop(1, '#ffffff00');
        ctx.beginPath();
        ctx.arc(gn.x, gn.y, selGlow, 0, 2 * Math.PI);
        ctx.fillStyle = selGrad;
        ctx.fill();
      }

      // Node dot
      ctx.beginPath();
      ctx.arc(gn.x, gn.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = colour;
      ctx.fill();

      // Selected: white ring
      if (isSelected) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }

      // Hovered: slightly larger ring
      if (isHovered && !isSelected) {
        ctx.strokeStyle = colour;
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Labels — semantic zoom: show based on zoom level + node importance
      // Zoom < 1: only selected/hovered
      // Zoom 1-2: selected + hovered + top entities (>100 memories)
      // Zoom 2-4: all non-dimmed nodes with >20 memories
      // Zoom 4+: all non-dimmed nodes
      const alwaysShow = isSelected || isHovered;
      const showByZoom =
        !dimmed && (
          (zoom >= 4) ||
          (zoom >= 2 && gn.memoryCount > 20) ||
          (zoom >= 1 && gn.memoryCount > 100)
        );

      if (alwaysShow || showByZoom) {
        const label = gn.name;
        const baseFontSize = isSelected ? 12 : isHovered ? 11 : 10;
        const fontSize = Math.max(baseFontSize / Math.max(zoom, 0.5), 6);
        ctx.font = `${fontSize}px Inter, system-ui, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = isSelected ? '#ffffff' : isHovered ? '#f0f4ff' : '#f0f4ffaa';
        ctx.fillText(label, gn.x, gn.y + r + 2);
      }

      ctx.restore();
    },
    [selectedId, selectedNeighbours],
  );

  const linkColour = useCallback(
    (link: LinkObject<GraphNode, GraphLink>) => {
      if (!selectedId) return 'rgba(136, 146, 176, 0.08)';
      const src = typeof link.source === 'object' ? (link.source as GraphNode).id : link.source;
      const tgt = typeof link.target === 'object' ? (link.target as GraphNode).id : link.target;
      if (String(src) === selectedId || String(tgt) === selectedId) return 'rgba(0, 229, 204, 0.35)';
      return 'rgba(136, 146, 176, 0.03)';
    },
    [selectedId],
  );

  const handleNodeClick = useCallback(
    (node: NodeObject<GraphNode>) => onSelectEntity(node as GraphNode),
    [onSelectEntity],
  );

  const handleNodeHover = useCallback((node: NodeObject<GraphNode> | null) => {
    hoveredRef.current = node ? String((node as GraphNode).id) : null;
  }, []);

  // Configure forces — strong repulsion for spread-out constellation look
  useEffect(() => {
    const fg = graphRef.current;
    if (!fg) return;
    fg.d3Force('charge')?.strength(-200);
    fg.d3Force('link')?.distance(80);
    fg.d3Force('center')?.strength(0.03);
  }, [nodes]);

  // Zoom to fit when fitTrigger changes
  useEffect(() => {
    if (fitTrigger && graphRef.current) {
      graphRef.current.zoomToFit(400, 60);
    }
  }, [fitTrigger]);

  if (width < 10 || height < 10) return null;

  return (
    <ForceGraph2D
      ref={graphRef}
      graphData={{ nodes, links }}
      width={width}
      height={height}
      backgroundColor="rgba(0,0,0,0)"
      nodeCanvasObjectMode={() => 'replace'}
      nodeCanvasObject={paintNode}
      linkColor={linkColour}
      linkWidth={0.5}
      onNodeClick={handleNodeClick}
      onNodeHover={handleNodeHover}
      onZoom={handleZoom}
      d3AlphaDecay={0.015}
      d3VelocityDecay={0.25}
      cooldownTicks={300}
      warmupTicks={80}
      nodeRelSize={1}
      enableNodeDrag={true}
      enableZoomInteraction={true}
      onEngineStop={() => graphRef.current?.zoomToFit(400, 60)}
    />
  );
}
