import { computeLinkAlpha, computeLinkWidth } from './renderMath';

export interface LinkPaintInput {
  ctx: CanvasRenderingContext2D;
  link: {
    source: { x?: number; y?: number; colour?: string; id: string };
    target: { x?: number; y?: number; colour?: string; id: string };
  };
  srcEnergy: number;
  dstEnergy: number;
}

const FALLBACK_COLOUR = '#7dd3fc';

/**
 * Paint one link as a gradient stroke (source colour → target colour) using
 * additive blending so overlapping links bloom into one another. Width and
 * alpha are modulated by max(srcEnergy, dstEnergy) — energy is the sole
 * modulation signal (GraphLink has no edge weight; see spec §5.4).
 */
export function paintLink(input: LinkPaintInput): void {
  const { ctx, link, srcEnergy, dstEnergy } = input;
  const s = link.source;
  const t = link.target;
  if (s.x === undefined || s.y === undefined || t.x === undefined || t.y === undefined) return;

  const previousOp = ctx.globalCompositeOperation;
  ctx.globalCompositeOperation = 'lighter';

  const gradient = ctx.createLinearGradient(s.x, s.y, t.x, t.y);
  gradient.addColorStop(0, (s.colour ?? FALLBACK_COLOUR));
  gradient.addColorStop(1, (t.colour ?? FALLBACK_COLOUR));

  ctx.strokeStyle = gradient;
  ctx.globalAlpha = computeLinkAlpha(srcEnergy, dstEnergy);
  ctx.lineWidth = computeLinkWidth(srcEnergy, dstEnergy);
  ctx.beginPath();
  ctx.moveTo(s.x, s.y);
  ctx.lineTo(t.x, t.y);
  ctx.stroke();

  ctx.globalAlpha = 1;
  ctx.globalCompositeOperation = previousOp;
}
