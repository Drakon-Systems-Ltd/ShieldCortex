/**
 * CIC cognitive regions — the "second brain" colour map.
 *
 * Each region is a functional domain of the cortex with its own phosphor
 * identity, so a glance tells the observer WHAT the brain is doing. Bloom and
 * activation in the cortex/nav are keyed to these. The colour IS information.
 *
 * Source of truth for the hex values is globals.css (`--cic-*`); the resolved
 * values are duplicated here only for the canvas graph, which paints to a 2D
 * context and cannot read CSS custom properties.
 */
export type CicRegion = 'memory' | 'defence' | 'quarantine' | 'integrity';

export interface RegionMeta {
  /** CSS custom-property name carrying this region's phosphor colour. */
  token: string;
  /** Resolved hex — for canvas painting (ConstellationGraph) where var() is unavailable. */
  hex: string;
  /** Resolved glow colour (rgba) for canvas bloom. */
  glow: string;
  /** Human label shown in chrome. */
  label: string;
  /** One-line meaning. */
  meaning: string;
}

export const REGIONS: Record<CicRegion, RegionMeta> = {
  memory: {
    token: '--cic-cyan',
    hex: '#00e5cc',
    glow: 'rgba(0, 229, 204, 0.35)',
    label: 'MEMORY',
    meaning: 'vault · recall · the living graph',
  },
  defence: {
    token: '--cic-coral',
    hex: '#ff4d4d',
    glow: 'rgba(255, 77, 77, 0.35)',
    label: 'DEFENCE',
    meaning: 'shield · interception · the 6 layers',
  },
  quarantine: {
    token: '--cic-amber',
    hex: '#f5a623',
    glow: 'rgba(245, 166, 35, 0.32)',
    label: 'QUARANTINE',
    meaning: 'isolation hold · pending review',
  },
  integrity: {
    token: '--cic-violet',
    hex: '#a78bfa',
    glow: 'rgba(167, 139, 250, 0.32)',
    label: 'INTEGRITY',
    meaning: 'consolidation · links · contradictions',
  },
};

/** CSS var() reference for a region's phosphor colour, e.g. `var(--cic-cyan)`. */
export function regionVar(region: CicRegion): string {
  return `var(${REGIONS[region].token})`;
}

/**
 * Map an entity/memory category or graph cluster type to a cognitive region, so
 * the cortex graph colours each neuron by what it relates to. Falls back to
 * 'memory' (the default cortical tissue).
 */
export function regionForCluster(type: string): CicRegion {
  const t = type.toLowerCase();
  if (['error', 'threat', 'defence', 'security', 'block', 'credential'].some((k) => t.includes(k))) return 'defence';
  if (['quarantine', 'pending', 'suppressed', 'review'].some((k) => t.includes(k))) return 'quarantine';
  if (['pattern', 'architecture', 'relationship', 'link', 'concept', 'tool', 'service'].some((k) => t.includes(k))) return 'integrity';
  return 'memory';
}
