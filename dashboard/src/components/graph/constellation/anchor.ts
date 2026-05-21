/**
 * Living Constellation — anchor (the "sun") selection and pin application.
 *
 * pickAnchor: pure ranker — `memoryCount × edgeCount`, ties broken
 * alphabetically by name for determinism. salience is intentionally NOT used
 * (it's per-memory, not per-entity — see spec §5.1).
 *
 * applyAnchor: mutates force-graph nodes' fx/fy to pin the new sun at (0,0)
 * and release the previous sun. User drag-pins on other nodes are preserved.
 */

export interface AnchorableNode {
  id: string;
  name: string;
  memoryCount: number;
  // force-graph runtime fields (optional — applyAnchor mutates these):
  fx?: number | null;
  fy?: number | null;
  x?: number;
  y?: number;
}

export interface AnchorableLink {
  source: string | { id: string };
  target: string | { id: string };
}

function endpointId(e: AnchorableLink['source']): string {
  return typeof e === 'string' ? e : e.id;
}

/**
 * Returns the node id maximising `memoryCount × edgeCount`, falling back to
 * `memoryCount` alone when no node has any edges (e.g. a lone node, or an
 * all-isolated graph). Ties broken alphabetically by name. Returns null only
 * when the graph is empty or every node has memoryCount === 0.
 */
export function pickAnchor(nodes: AnchorableNode[], links: AnchorableLink[]): string | null {
  if (nodes.length === 0) return null;

  const ids = new Set(nodes.map((n) => n.id));
  const degree = new Map<string, number>();
  for (const link of links) {
    const s = endpointId(link.source);
    const t = endpointId(link.target);
    if (ids.has(s)) degree.set(s, (degree.get(s) ?? 0) + 1);
    if (ids.has(t)) degree.set(t, (degree.get(t) ?? 0) + 1);
  }

  // Primary ranking: memoryCount × edgeCount (score must be > 0).
  let bestNode: AnchorableNode | null = null;
  let bestScore = 0;
  for (const node of nodes) {
    const score = node.memoryCount * (degree.get(node.id) ?? 0);
    if (score === 0) continue;
    if (
      bestNode === null ||
      score > bestScore ||
      (score === bestScore && node.name.localeCompare(bestNode.name) < 0)
    ) {
      bestNode = node;
      bestScore = score;
    }
  }
  if (bestNode) return bestNode.id;

  // Fallback (covers the lone-node case): rank by memoryCount alone.
  // Nodes with memoryCount === 0 are still excluded so an all-isolated,
  // all-empty graph returns null.
  let bestMc = 0;
  for (const node of nodes) {
    if (node.memoryCount === 0) continue;
    if (
      bestNode === null ||
      node.memoryCount > bestMc ||
      (node.memoryCount === bestMc && node.name.localeCompare(bestNode.name) < 0)
    ) {
      bestNode = node;
      bestMc = node.memoryCount;
    }
  }
  return bestNode?.id ?? null;
}

/** Minimal shape `applyAnchor` needs — any node carrying `id` + optional `fx`/`fy`. */
export interface PinnableNode {
  id: string;
  fx?: number | null;
  fy?: number | null;
}

/**
 * Pin the new anchor at (0,0) and release the previous one.
 * Other pinned nodes (from drag-to-pin) are untouched.
 */
export function applyAnchor<T extends PinnableNode>(
  nodes: T[],
  newAnchorId: string,
  previousAnchorId: string | null,
): void {
  // Look up the new anchor first; if it doesn't exist, this call is a no-op
  // (don't accidentally release the previous anchor).
  const next = nodes.find((n) => n.id === newAnchorId);
  if (!next) return;

  // Release the previous anchor (unless it's the same node).
  if (previousAnchorId && previousAnchorId !== newAnchorId) {
    const prev = nodes.find((n) => n.id === previousAnchorId);
    if (prev) {
      prev.fx = null;
      prev.fy = null;
    }
  }

  // Pin the new anchor at the origin.
  next.fx = 0;
  next.fy = 0;
}
