/**
 * Living Constellation — motion intensity config + per-browser persistence.
 *
 * Three levels (subtle / moderate / strong) scale every animation parameter
 * (breath period, breath amplitude, particle cap, decay rates). Loaded from
 * localStorage on the client; server-side rendering and tests inject a
 * Storage shim instead.
 */

export type IntensityLevel = 'subtle' | 'moderate' | 'strong';

export interface IntensitySettings {
  /** ms — one full sine cycle of the always-on breathing layer */
  breathPeriod: number;
  /** fraction of base radius — peak excursion of breathing */
  breathAmp: number;
  /** hard cap on edges that may render directional particles at once */
  particleCap: number;
  /** per-frame multiplier for memory.created spikes (~2s tail at moderate) */
  decayCreate: number;
  /** per-frame multiplier for memory.accessed glows (~1s tail at moderate) */
  decayRecall: number;
}

export const INTENSITY: Record<IntensityLevel, IntensitySettings> = {
  subtle:   { breathPeriod: 6000, breathAmp: 0.03, particleCap: 20,  decayCreate: 0.98, decayRecall: 0.96 },
  moderate: { breathPeriod: 3000, breathAmp: 0.08, particleCap: 60,  decayCreate: 0.96, decayRecall: 0.93 },
  strong:   { breathPeriod: 1600, breathAmp: 0.14, particleCap: 120, decayCreate: 0.94, decayRecall: 0.90 },
};

const STORAGE_KEY = 'shieldcortex.graph.intensity';
const VALID = new Set<IntensityLevel>(['subtle', 'moderate', 'strong']);

function isLevel(v: unknown): v is IntensityLevel {
  return typeof v === 'string' && VALID.has(v as IntensityLevel);
}

/** Read the current intensity; returns 'moderate' on any failure path. */
export function loadIntensity(storage?: Storage | undefined): IntensityLevel {
  const s = storage ?? (typeof window !== 'undefined' ? window.localStorage : undefined);
  if (!s) return 'moderate';
  const v = s.getItem(STORAGE_KEY);
  return isLevel(v) ? v : 'moderate';
}

/** Persist the new intensity; emits a window CustomEvent so live graphs react. */
export function saveIntensity(level: IntensityLevel, storage?: Storage | undefined): void {
  const s = storage ?? (typeof window !== 'undefined' ? window.localStorage : undefined);
  if (!s) return;
  s.setItem(STORAGE_KEY, level);
  if (typeof window !== 'undefined' && typeof CustomEvent !== 'undefined') {
    window.dispatchEvent(new CustomEvent('shieldcortex:intensity-changed', { detail: level }));
  }
}
