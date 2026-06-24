import { computeNodeRadius } from './renderMath';
import type { IntensitySettings } from './intensity';

export interface NodePaintInput {
  ctx: CanvasRenderingContext2D;
  globalScale: number; // force-graph zoom level
  node: {
    id: string;
    x?: number;
    y?: number;
    name?: string;
    colour: string;
    memoryCount: number;
    isCluster?: boolean;
    clusterType?: string;
    entityCount?: number;
  };
  intensity: IntensitySettings;
  energy: number;        // Layer C breathing + Layer A spike
  recallEnergy: number;  // Layer B glow
  isAnchor: boolean;
  isSelected: boolean;
  isHovered: boolean;
  baseRadius: number;
}

export interface NodePaintOpts {
  /** Test-only: invoked once per paint with the computed values. */
  _paintHook?: (info: { nodeId: string; radius: number; energy: number; recallEnergy: number }) => void;
}

const SUN_COLOUR = '#d9faf5'; // bright cyan-white — the focal cortex core
const RECALL_GLOW_COLOUR = '#a78bfa'; // CIC violet — recall = integrity region (matches the palette)

/**
 * Paint one node. Preserves existing cluster-halo + inner-core-glow + label
 * behaviour from the legacy ConstellationGraph and adds:
 *   - Breathing modulation of the node radius (via energy)
 *   - Warm recall glow ring on memory.accessed events
 *   - Distinct sun ring + halo for the current anchor
 */
export function paintNode(input: NodePaintInput, opts: NodePaintOpts = {}): void {
  const { ctx, node, intensity, energy, recallEnergy, isAnchor, isSelected, baseRadius } = input;
  if (node.x === undefined || node.y === undefined) return;

  const r = computeNodeRadius({ baseRadius, energy, breathAmp: intensity.breathAmp });
  opts._paintHook?.({ nodeId: node.id, radius: r, energy, recallEnergy });

  // Outer halo (always-on; brighter for anchor and on selected).
  const haloR = r * (isAnchor ? 5 : 3.5);
  const haloAlphaHex = isAnchor ? '40' : isSelected ? '50' : '20';
  const halo = ctx.createRadialGradient(node.x, node.y, r * 0.2, node.x, node.y, haloR);
  halo.addColorStop(0, node.colour + haloAlphaHex);
  halo.addColorStop(1, node.colour + '00');
  ctx.beginPath();
  ctx.arc(node.x, node.y, haloR, 0, Math.PI * 2);
  ctx.fillStyle = halo;
  ctx.fill();

  // Warm recall ring (Layer B).
  if (recallEnergy > 0.05) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, r * 1.6, 0, Math.PI * 2);
    ctx.strokeStyle = RECALL_GLOW_COLOUR;
    ctx.globalAlpha = Math.min(0.7, recallEnergy);
    ctx.lineWidth = 1.5;
    ctx.stroke();
    ctx.globalAlpha = 1;
  }

  // Anchor sun overrides node colour with a warm fill + ring.
  if (isAnchor) {
    ctx.beginPath();
    ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
    ctx.fillStyle = SUN_COLOUR;
    ctx.fill();
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = '#00e5cc';
    ctx.stroke();
    return;
  }

  // Satellite — colour from cluster.
  ctx.beginPath();
  ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
  ctx.fillStyle = node.colour;
  ctx.fill();
  if (isSelected) {
    ctx.lineWidth = 1.5;
    ctx.strokeStyle = '#ffffff';
    ctx.stroke();
  }
}
