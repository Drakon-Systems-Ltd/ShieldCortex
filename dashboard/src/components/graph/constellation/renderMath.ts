/**
 * Pure visual math used by renderNodes.ts and renderLinks.ts. Kept separate
 * so the formulas can be unit-tested without a canvas or React.
 */

export interface NodeRadiusInput {
  baseRadius: number;
  energy: number;
  breathAmp: number;
}

const clamp = (x: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, x));

export function computeNodeRadius(input: NodeRadiusInput): number {
  const raw = input.baseRadius * (1 + input.energy * input.breathAmp);
  // Guarantee a positive radius even if a runaway negative energy is fed in.
  return Math.max(input.baseRadius * 0.2, raw);
}

/**
 * 0.35 floor + 0.6 × max(srcEnergy, dstEnergy), clamped to [0,1].
 * Per spec §5.4 — energy is the sole modulation signal (no edgeWeight field).
 */
export function computeLinkAlpha(srcEnergy: number, dstEnergy: number): number {
  const peak = Math.max(srcEnergy, dstEnergy);
  return clamp(0.35 + 0.6 * peak, 0, 1);
}

/** 1.0 + max(srcEnergy, dstEnergy) × 0.8 — clamped to a sensible band. */
export function computeLinkWidth(srcEnergy: number, dstEnergy: number): number {
  const peak = Math.max(srcEnergy, dstEnergy);
  return clamp(1.0 + 0.8 * peak, 0.5, 3);
}
