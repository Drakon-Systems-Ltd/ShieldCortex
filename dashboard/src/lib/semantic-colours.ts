/**
 * v2 semantic colour map — the single source for MEANING-keyed colour, in both
 * themes. Replaces lib/cic/regions.ts.
 *
 * Two consumer kinds:
 *  1. CSS/JSX — use `var(--sc-…)` via {@link SEMANTIC_TOKENS}.
 *  2. Canvas (the graph) — canvas 2D contexts cannot read CSS custom
 *     properties per draw call, so {@link semanticHex} / {@link entityTypeHex}
 *     resolve concrete values for the active resolved theme.
 *
 * Semantics (brief §3.6): blue = memory/neutral · green = allowed/healthy ·
 * amber = quarantine/pending/warn · red = blocked/threat/fail only ·
 * violet = links/integrity/consolidation.
 */

import type { ResolvedTheme } from '@/hooks/useTheme';

export type Semantic = 'memory' | 'ok' | 'warn' | 'danger' | 'link' | 'muted';

export const SEMANTIC_TOKENS: Record<Semantic, string> = {
  memory: 'var(--sc-primary)',
  ok: 'var(--sc-ok)',
  warn: 'var(--sc-warn)',
  danger: 'var(--sc-danger)',
  link: 'var(--sc-violet)',
  muted: 'var(--sc-text-muted)',
};

/** Values mirror globals.css `:root` / `.dark`. Keep in sync when tokens change. */
const SEMANTIC_HEX: Record<ResolvedTheme, Record<Semantic, string>> = {
  light: {
    memory: '#2563eb',
    ok: '#15803d',
    warn: '#b45309',
    danger: '#dc2626',
    link: '#7c3aed',
    muted: '#5b6a89',
  },
  dark: {
    memory: '#3b82f6',
    ok: '#4ade80',
    warn: '#f5a623',
    danger: '#f0564f',
    link: '#a78bfa',
    muted: '#8291b1',
  },
};

export function semanticHex(theme: ResolvedTheme, semantic: Semantic): string {
  return SEMANTIC_HEX[theme][semantic];
}

/** Canvas chrome for the graph, per theme (canvas cannot read CSS vars). */
export const GRAPH_CANVAS: Record<ResolvedTheme, {
  background: string;
  label: string;
  labelMuted: string;
  edge: string;
  edgeDim: string;
  selectionRing: string;
  nodeStroke: string;
}> = {
  light: {
    background: '#f6f8fc',
    label: '#111a2e',
    labelMuted: '#5b6a89',
    edge: 'rgba(60, 74, 102, 0.34)',
    edgeDim: 'rgba(60, 74, 102, 0.10)',
    selectionRing: '#2563eb',
    nodeStroke: '#ffffff',
  },
  dark: {
    background: '#0a0e1a',
    label: '#e7edf9',
    labelMuted: '#8291b1',
    edge: 'rgba(170, 183, 209, 0.30)',
    edgeDim: 'rgba(170, 183, 209, 0.09)',
    selectionRing: '#60a5fa',
    nodeStroke: '#0a0e1a',
  },
};

/**
 * Stable entity-type palette (graph nodes, legend, filter chips). Distinct
 * hues, AA-adequate against both canvas backgrounds at node sizes; unknown
 * types fall back to slate.
 */
const ENTITY_TYPE_HEX: Record<ResolvedTheme, Record<string, string>> = {
  light: {
    tool: '#2563eb',
    concept: '#0d9488',
    project: '#b45309',
    file: '#64748b',
    service: '#7c3aed',
    person: '#15803d',
    language: '#c026d3',
    pattern: '#e11d48',
  },
  dark: {
    tool: '#60a5fa',
    concept: '#2dd4bf',
    project: '#fbbf24',
    file: '#94a3b8',
    service: '#a78bfa',
    person: '#4ade80',
    language: '#e879f9',
    pattern: '#fb7185',
  },
};

const FALLBACK_ENTITY_HEX: Record<ResolvedTheme, string> = {
  light: '#475569',
  dark: '#cbd5e1',
};

export const KNOWN_ENTITY_TYPES = Object.keys(ENTITY_TYPE_HEX.dark);

/**
 * Stable memory-category palette (Timeline day cards, category filter chips).
 * A distinct domain from entity types above — "pattern" means something
 * different in each — kept as its own theme-aware map rather than collapsed
 * into the 6-bucket {@link Semantic} set, which would make categories that
 * are meant to be visually distinguishable at a glance (architecture vs.
 * context vs. note, say) render identically.
 */
const MEMORY_CATEGORY_HEX: Record<ResolvedTheme, Record<string, string>> = {
  light: {
    architecture: '#2563eb',
    error: '#dc2626',
    pattern: '#7c3aed',
    preference: '#b45309',
    learning: '#15803d',
    context: '#4f46e5',
    todo: '#c2410c',
    note: '#64748b',
    relationship: '#be185d',
    custom: '#475569',
  },
  dark: {
    architecture: '#60a5fa',
    error: '#f0564f',
    pattern: '#a78bfa',
    preference: '#fbbf24',
    learning: '#4ade80',
    context: '#818cf8',
    todo: '#fb923c',
    note: '#94a3b8',
    relationship: '#f472b6',
    custom: '#cbd5e1',
  },
};

export function memoryCategoryHex(theme: ResolvedTheme, category: string): string {
  const c = (category || '').toLowerCase();
  return MEMORY_CATEGORY_HEX[theme][c] ?? MEMORY_CATEGORY_HEX[theme].custom;
}

export function entityTypeHex(theme: ResolvedTheme, type: string): string {
  return ENTITY_TYPE_HEX[theme][type?.toLowerCase()] ?? FALLBACK_ENTITY_HEX[theme];
}

/** Memory-category ring colour (graph memory nodes) — semantic families. */
export function memoryCategorySemantic(category: string): Semantic {
  const c = (category || '').toLowerCase();
  if (['error', 'threat', 'security'].some((k) => c.includes(k))) return 'danger';
  if (['todo', 'review'].some((k) => c.includes(k))) return 'warn';
  if (['relationship', 'link', 'pattern', 'architecture'].some((k) => c.includes(k))) return 'link';
  if (['learning', 'preference'].some((k) => c.includes(k))) return 'ok';
  return 'memory';
}

/** Memory-link relationship colours (all three edge families, brief §6.1). */
export function memoryLinkHex(theme: ResolvedTheme, relationship: string): string {
  if (relationship === 'conflicts') return SEMANTIC_HEX[theme].danger;
  return SEMANTIC_HEX[theme].link;
}
