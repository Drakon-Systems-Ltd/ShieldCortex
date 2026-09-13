import { INTENSITY, type IntensityLevel, type IntensitySettings } from './intensity';

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
  private recallEnergy = new Map<string, number>();
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

  /** External pulse trigger. */
  dispatch(e: PulseEvent): void {
    if (!this.knownNodes.has(e.entityId)) return;
    if (e.type === 'memory.created')  this.spikeEnergy.set(e.entityId, 1.0);
    if (e.type === 'memory.accessed') this.recallEnergy.set(e.entityId, 1.0);
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
    // Decay Layer A (memory.created) spikes once per frame.
    const decay = this.settings.decayCreate;
    for (const [id, e] of this.spikeEnergy) {
      const next = e * decay;
      if (next < 1e-3) this.spikeEnergy.delete(id);
      else this.spikeEnergy.set(id, next);
    }
    const decayR = this.settings.decayRecall;
    for (const [id, e] of this.recallEnergy) {
      const next = e * decayR;
      if (next < 1e-3) this.recallEnergy.delete(id);
      else this.recallEnergy.set(id, next);
    }
  }

  /** Energy for one node — sum of breathing + spike contributions. */
  getEnergy(id: string): number {
    if (!this.knownNodes.has(id)) return 0;
    const breath = this.breathOffset.get(id) ?? 0;
    const spike = this.spikeEnergy.get(id) ?? 0;
    return breath + spike;
  }

  getRecallEnergy(id: string): number {
    return this.knownNodes.has(id) ? this.recallEnergy.get(id) ?? 0 : 0;
  }

  /**
   * Rank edges for directional-particle rendering.
   * @param links Edges as `{source, target}` (string ids; passed through).
   * @param anchorId Current sun id, or null. Used as tie-break.
   * @param overrideCap Optional explicit cap (defaults to INTENSITY[level].particleCap).
   */
  pickParticleEdges<L extends { source: string | { id: string }; target: string | { id: string } }>(
    links: L[],
    anchorId: string | null,
    overrideCap?: number,
  ): L[] {
    const cap = overrideCap ?? this.settings.particleCap;
    if (cap <= 0 || links.length === 0) return [];

    const epId = (e: L['source']) => (typeof e === 'string' ? e : e.id);
    type Scored = { link: L; score: number; anchorAdjacent: 0 | 1 };
    const scored: Scored[] = links.map((link) => {
      const s = epId(link.source);
      const t = epId(link.target);
      const sE = Math.max(this.getEnergy(s), this.getRecallEnergy(s));
      const tE = Math.max(this.getEnergy(t), this.getRecallEnergy(t));
      const score = Math.max(sE, tE);
      const anchorAdjacent = anchorId !== null && (s === anchorId || t === anchorId) ? 1 : 0;
      return { link, score, anchorAdjacent };
    });

    scored.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return b.anchorAdjacent - a.anchorAdjacent;
    });

    return scored.slice(0, cap).map((s) => s.link);
  }
}

/** Stable 0..1 hash for per-node breathing phase (full 32-bit FNV-1a range). */
function hashStringTo01(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 16777619) >>> 0;
  }
  return h / 0x100000000;
}
