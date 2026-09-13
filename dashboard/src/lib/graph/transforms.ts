/**
 * Pure data transforms for the v2 memory graph (brief §6, §13.3).
 *
 * API payloads → force-graph data with:
 *  - namespaced stable node ids (`e:<id>` entities, `m:<id>` memories) so an
 *    entity and a memory can never collide and identities survive mode swaps;
 *  - parallel triples between the same entity pair bundled into ONE drawn
 *    link whose width comes from the REAL bundled-triple count (never an
 *    invented weight) and whose tooltip lists each predicate with its real
 *    confidence and disputed flag;
 *  - memory→entity role edges and memory↔memory relationship links as their
 *    own families;
 *  - position preservation across data swaps (d3 mutates node objects; we
 *    always hand it fresh clones and copy coordinates over by id, so React
 *    Query caches are never mutated and layout stays stable).
 */

// ── API payload shapes ─────────────────────────────────────

export interface OverviewEntity {
  id: number;
  name: string;
  type: string;
  memoryCount: number;
}

export interface OverviewTriple {
  id: number;
  subjectId: number;
  objectId: number;
  predicate: string;
  confidence: number;
  disputed: boolean;
}

export interface OverviewPayload {
  entities: OverviewEntity[];
  triples: OverviewTriple[];
  counts: {
    byType: Record<string, number>;
    byPredicate: Record<string, number>;
    totalEntities: number;
    totalEdges: number;
    omittedEntities: number;
    omittedEdges: number;
  };
}

export interface NeighbourhoodTriple {
  id: number;
  subject_id: number;
  object_id: number;
  predicate: string;
  confidence: number;
  disputed: boolean;
}

export interface GraphMemory {
  id: number;
  title: string;
  type: string;
  category: string;
  salience: number;
  trust_score: number;
  status: string;
  pinned: number;
  project: string | null;
  created_at: string;
}

export interface NeighbourhoodPayload {
  focal: { id: number; name: string; type: string; memoryCount: number };
  neighbours: Array<{ id: number; name: string; type: string; memoryCount: number; depth: number }>;
  triples: NeighbourhoodTriple[];
  memories?: GraphMemory[];
  memoryEntities?: Array<{ memory_id: number; entity_id: number; role: string }>;
  memoryLinks?: Array<{ id: number; source_id: number; target_id: number; relationship: string; strength: number }>;
  counts: {
    totalNeighbours: number;
    omittedNeighbours: number;
    totalEdges: number;
    omittedEdges: number;
    totalMemories: number;
    omittedMemories: number;
  };
}

// ── Graph data shapes ──────────────────────────────────────

export interface V2Node {
  id: string; // 'e:<id>' | 'm:<id>'
  kind: 'entity' | 'memory';
  numericId: number;
  label: string;
  /** entity type, or memory category */
  subtype: string;
  /** entity memoryCount, or memory salience [0..1] */
  size: number;
  isFocal?: boolean;
  memory?: GraphMemory;
  // d3 mutates these in place on OUR clones only:
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface BundledTriple {
  predicate: string;
  confidence: number;
  disputed: boolean;
  /** relative to the link's source→target orientation */
  direction: 'forward' | 'reverse';
}

export interface V2Link {
  id: string;
  kind: 'triple' | 'memory-entity' | 'memory-link';
  source: string;
  target: string;
  /** triple bundles */
  triples?: BundledTriple[];
  /** true when every bundled predicate is related_to (drawn thin + dashed) */
  weakOnly?: boolean;
  /** memory-entity role */
  role?: string;
  /** memory-link relationship + real strength */
  relationship?: string;
  strength?: number;
}

export interface V2GraphData {
  nodes: V2Node[];
  links: V2Link[];
}

export const entityNodeId = (id: number): string => `e:${id}`;
export const memoryNodeId = (id: number): string => `m:${id}`;

// ── Map default (step-3 polish, 2026-09-13) ─────────────────

/** Target band for the number of entities the default Map shows at once. */
export const MAP_DEFAULT_TARGET_MIN = 120;
export const MAP_DEFAULT_TARGET_MAX = 150;

/**
 * Pick a default `minMentions` for Map mode from the real memoryCount
 * distribution of the loaded entities (not a hardcoded constant): at 400
 * loaded entities and a fixed minMentions of 1, Map painted a hairball —
 * every node ~3px, labels overlapping. Rule: sort the loaded entities'
 * memoryCount descending and read off the value at the rank in the middle of
 * the target band (≈135th); filtering with `memoryCount >= that value`
 * (`buildMapData`'s existing `>=` semantics) then keeps roughly that many
 * entities, landing inside [MAP_DEFAULT_TARGET_MIN, MAP_DEFAULT_TARGET_MAX]
 * for the shipped fixture (400 loaded → threshold 8 → 147 shown). Below the
 * target band there is nothing to trim, so show everything (threshold 1).
 * This is only the *default* — the min-mentions slider still overrides it.
 */
export function computeDefaultMinMentions(entities: Array<{ memoryCount: number }>): number {
  if (entities.length <= MAP_DEFAULT_TARGET_MAX) return 1;
  const counts = entities.map((e) => e.memoryCount).sort((a, b) => b - a);
  const targetRank = Math.floor((MAP_DEFAULT_TARGET_MIN + MAP_DEFAULT_TARGET_MAX) / 2);
  const idx = Math.min(targetRank, counts.length - 1);
  return Math.max(1, counts[idx]);
}

// ── Builders ───────────────────────────────────────────────

function bundleTriples(
  triples: Array<{ subjectId: number; objectId: number; predicate: string; confidence: number; disputed: boolean }>,
  present: Set<string>,
): V2Link[] {
  const bundles = new Map<string, V2Link>();
  for (const t of triples) {
    const s = entityNodeId(t.subjectId);
    const o = entityNodeId(t.objectId);
    if (!present.has(s) || !present.has(o)) continue;
    // Unordered pair key so a→b and b→a share one drawn link.
    const [lo, hi] = s < o ? [s, o] : [o, s];
    const key = `${lo}|${hi}`;
    let link = bundles.get(key);
    if (!link) {
      link = { id: key, kind: 'triple', source: lo, target: hi, triples: [], weakOnly: true };
      bundles.set(key, link);
    }
    link.triples!.push({
      predicate: t.predicate,
      confidence: t.confidence,
      disputed: t.disputed,
      direction: s === lo ? 'forward' : 'reverse',
    });
    if (t.predicate !== 'related_to') link.weakOnly = false;
  }
  return [...bundles.values()];
}

export interface MapFilterOpts {
  /** hidden entity types */
  hiddenTypes?: Set<string>;
  /** drop links whose every predicate is related_to */
  hideWeakLinks?: boolean;
  minMentions?: number;
}

/** Map mode: bounded entities + bundled live triples (no memories). */
export function buildMapData(overview: OverviewPayload, opts: MapFilterOpts = {}): V2GraphData {
  const hidden = opts.hiddenTypes ?? new Set<string>();
  const minMentions = opts.minMentions ?? 0;
  const nodes: V2Node[] = overview.entities
    .filter((e) => !hidden.has(e.type) && e.memoryCount >= minMentions)
    .map((e) => ({
      id: entityNodeId(e.id),
      kind: 'entity',
      numericId: e.id,
      label: e.name,
      subtype: e.type,
      size: e.memoryCount,
    }));
  const present = new Set(nodes.map((n) => n.id));
  let links = bundleTriples(overview.triples, present);
  if (opts.hideWeakLinks) links = links.filter((l) => !l.weakOnly);
  return { nodes, links };
}

/** Focus mode: focal + neighbours (+ optional memories with all three edge families). */
export function buildFocusData(nbhd: NeighbourhoodPayload, showMemories: boolean): V2GraphData {
  const nodes: V2Node[] = [
    {
      id: entityNodeId(nbhd.focal.id),
      kind: 'entity',
      numericId: nbhd.focal.id,
      label: nbhd.focal.name,
      subtype: nbhd.focal.type,
      size: nbhd.focal.memoryCount,
      isFocal: true,
    },
    ...nbhd.neighbours.map((n) => ({
      id: entityNodeId(n.id),
      kind: 'entity' as const,
      numericId: n.id,
      label: n.name,
      subtype: n.type,
      size: n.memoryCount,
    })),
  ];

  const links: V2Link[] = [];
  const present = new Set(nodes.map((n) => n.id));
  links.push(
    ...bundleTriples(
      nbhd.triples.map((t) => ({
        subjectId: t.subject_id,
        objectId: t.object_id,
        predicate: t.predicate,
        confidence: t.confidence,
        disputed: t.disputed,
      })),
      present,
    ),
  );

  if (showMemories && nbhd.memories) {
    for (const m of nbhd.memories) {
      nodes.push({
        id: memoryNodeId(m.id),
        kind: 'memory',
        numericId: m.id,
        label: m.title,
        subtype: m.category,
        size: m.salience,
        memory: m,
      });
    }
    const nodeIds = new Set(nodes.map((n) => n.id));
    for (const me of nbhd.memoryEntities ?? []) {
      const s = memoryNodeId(me.memory_id);
      const t = entityNodeId(me.entity_id);
      if (!nodeIds.has(s) || !nodeIds.has(t)) continue;
      links.push({ id: `me:${me.memory_id}:${me.entity_id}`, kind: 'memory-entity', source: s, target: t, role: me.role });
    }
    for (const ml of nbhd.memoryLinks ?? []) {
      const s = memoryNodeId(ml.source_id);
      const t = memoryNodeId(ml.target_id);
      if (!nodeIds.has(s) || !nodeIds.has(t)) continue;
      links.push({
        id: `ml:${ml.id}`,
        kind: 'memory-link',
        source: s,
        target: t,
        relationship: ml.relationship,
        strength: ml.strength,
      });
    }
  }

  return { nodes, links };
}

// ── Path mode (review item 4) ──────────────────────────────

/** One hop of a `/api/graph/paths` response, as drawn (real fields only). */
export interface PathHopInput {
  entity: string;
  entityId: number;
  /** legacy field: `~pred` on reverse hops */
  predicate: string;
  direction: 'forward' | 'reverse' | '';
  entityType?: string;
  memoryCount?: number;
  confidence?: number | null;
  disputed?: boolean;
}

/**
 * Merge a found path into the current graph so EVERY hop is on the canvas,
 * even entities the Map filters/caps omitted. Hop entities missing from
 * `base` are added (type/memoryCount from the payload); consecutive hops
 * whose pair has no drawn link get one bundled-triple link built from the
 * hop's real predicate/confidence/disputed. Existing nodes and links are
 * untouched (positions preserved downstream by withPreservedPositions).
 */
export function buildPathData(base: V2GraphData, path: PathHopInput[]): V2GraphData {
  if (path.length === 0) return base;
  const nodes = [...base.nodes];
  const links = [...base.links];
  const present = new Set(nodes.map((n) => n.id));
  const linkIds = new Set(links.map((l) => l.id));

  for (const hop of path) {
    const id = entityNodeId(hop.entityId);
    if (present.has(id)) continue;
    present.add(id);
    nodes.push({
      id,
      kind: 'entity',
      numericId: hop.entityId,
      label: hop.entity,
      subtype: hop.entityType ?? 'unknown',
      size: hop.memoryCount ?? 0,
    });
  }

  for (let i = 1; i < path.length; i++) {
    const prev = entityNodeId(path[i - 1].entityId);
    const cur = entityNodeId(path[i].entityId);
    const [lo, hi] = prev < cur ? [prev, cur] : [cur, prev];
    const key = `${lo}|${hi}`;
    if (linkIds.has(key)) continue;
    linkIds.add(key);
    const hop = path[i];
    const predicate = hop.predicate.replace(/^~/, '');
    // A forward hop is prev→cur (subject prev); reverse is cur→prev.
    const subject = hop.direction === 'reverse' ? cur : prev;
    links.push({
      id: key,
      kind: 'triple',
      source: lo,
      target: hi,
      triples: [
        {
          predicate,
          confidence: hop.confidence ?? 0,
          disputed: hop.disputed ?? false,
          direction: subject === lo ? 'forward' : 'reverse',
        },
      ],
      weakOnly: predicate === 'related_to',
    });
  }
  return { nodes, links };
}

// ── Map truncation breakdown (review item 9) ───────────────

/**
 * Why loaded Map entities are not on screen, split honestly: hidden by a
 * type chip vs. below the min-mentions threshold. An entity hidden by BOTH
 * counts once, under "type" (re-enabling the chip is the first thing that
 * would change).
 */
export function hiddenBreakdown(
  entities: Array<{ type: string; memoryCount: number }>,
  hiddenTypes: Set<string>,
  minMentions: number,
): { hiddenByType: number; belowThreshold: number } {
  let hiddenByType = 0;
  let belowThreshold = 0;
  for (const e of entities) {
    if (hiddenTypes.has(e.type)) hiddenByType++;
    else if (e.memoryCount < minMentions) belowThreshold++;
  }
  return { hiddenByType, belowThreshold };
}

/**
 * Clone `next` for the force graph, carrying positions/pins over from the
 * previous simulation nodes by id. The returned objects are fresh — d3 may
 * mutate them freely; the inputs (React Query cache) are untouched.
 */
export function withPreservedPositions(next: V2GraphData, prevNodes: V2Node[] | undefined): V2GraphData {
  const prev = new Map((prevNodes ?? []).map((n) => [n.id, n]));
  const nodes = next.nodes.map((n) => {
    const clone: V2Node = { ...n };
    const old = prev.get(n.id);
    if (old) {
      clone.x = old.x;
      clone.y = old.y;
      clone.vx = old.vx;
      clone.vy = old.vy;
      clone.fx = old.fx;
      clone.fy = old.fy;
    }
    return clone;
  });
  const links = next.links.map((l) => ({ ...l, triples: l.triples ? [...l.triples] : undefined }));
  return { nodes, links };
}

/** Real drawn width from real data: bundled count (triples) or strength (links). */
export function linkWidth(link: V2Link): number {
  if (link.kind === 'triple') return Math.min(4, 0.6 + (link.triples?.length ?? 1) * 0.6);
  if (link.kind === 'memory-link') return Math.min(3.5, 0.8 + (link.strength ?? 0.5) * 2);
  return 0.6;
}

/** One-line hover summary for a link — predicates with confidence, honestly labelled. */
export function linkTooltip(link: V2Link, labelOf: (id: string) => string): string {
  const s = labelOf(typeof link.source === 'string' ? link.source : (link.source as V2Node).id);
  const t = labelOf(typeof link.target === 'string' ? link.target : (link.target as V2Node).id);
  if (link.kind === 'triple') {
    const parts = (link.triples ?? []).map((tr) => {
      const arrow = tr.direction === 'forward' ? `${s} ${tr.predicate} ${t}` : `${t} ${tr.predicate} ${s}`;
      return `${arrow} (${Math.round(tr.confidence * 100)}%${tr.disputed ? ', disputed' : ''})`;
    });
    return parts.join('\n');
  }
  if (link.kind === 'memory-link') {
    return `${s} ${link.relationship} ${t} (strength ${Math.round((link.strength ?? 0) * 100)}%)`;
  }
  return `${s} mentions ${t}${link.role && link.role !== 'mention' ? ` (${link.role})` : ''}`;
}
