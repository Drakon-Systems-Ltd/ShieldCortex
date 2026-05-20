import { INTENSITY, type IntensityLevel, type IntensitySettings } from './intensity.js';

export type PulseEventType = 'memory.created' | 'memory.accessed';

export interface PulseEvent {
  type: PulseEventType;
  entityId: string;
}

export interface PulseDriverOpts {
  intensity: IntensityLevel;
  /** Optional clock override for tests. Defaults to performance.now-equivalent. */
  now?: () => number;
}

/**
 * Frame-driven energy model for nodes.
 * Layer A (memory.created spikes), B (memory.accessed glows), and C (breathing)
 * are composed into a single per-node energy value in (-amp, 1 + amp].
 */
export class PulseDriver {
  private level: IntensityLevel;
  private settings: IntensitySettings;
  private knownNodes = new Set<string>();
  private phase = new Map<string, number>();
  private spikeEnergy = new Map<string, number>(); // Layer A + B contribution
  private breathOffset = new Map<string, number>(); // last computed Layer C
  private now: () => number;
  private lastFrameAt = 0;

  constructor(opts: PulseDriverOpts) {
    this.level = opts.intensity;
    this.settings = INTENSITY[opts.intensity];
    this.now = opts.now ?? (typeof performance !== 'undefined' ? () => performance.now() : Date.now);
  }

  setIntensity(level: IntensityLevel): void {
    this.level = level;
    this.settings = INTENSITY[level];
  }

  /** Register node ids so breathing kicks in. Safe to call repeatedly. */
  observeNodes(ids: Iterable<string>): void {
    for (const id of ids) {
      if (!this.knownNodes.has(id)) {
        this.knownNodes.add(id);
        this.phase.set(id, hashStringTo01(id) * Math.PI * 2);
      }
    }
  }

  /** External pulse trigger (Layer A / B will be implemented in 3b / 3c). */
  dispatch(_e: PulseEvent): void {
    // wired in Task 3b/3c
  }

  /** Compute energies for this frame. */
  onFrame(t: number): void {
    this.lastFrameAt = t;
    const { breathPeriod, breathAmp } = this.settings;
    const omega = (Math.PI * 2) / breathPeriod;
    for (const id of this.knownNodes) {
      const phi = this.phase.get(id) ?? 0;
      this.breathOffset.set(id, Math.sin(omega * t + phi) * breathAmp);
    }
  }

  /** Energy for one node — sum of breathing + spike contributions. */
  getEnergy(id: string): number {
    if (!this.knownNodes.has(id)) return 0;
    const breath = this.breathOffset.get(id) ?? 0;
    const spike = this.spikeEnergy.get(id) ?? 0;
    return breath + spike;
  }
}

/** Stable 0..1 hash for per-node breathing phase. */
function hashStringTo01(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 16777619) >>> 0;
  }
  return (h % 100000) / 100000;
}
