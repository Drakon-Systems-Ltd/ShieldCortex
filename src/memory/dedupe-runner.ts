import { findDuplicateMemoryPairs, type DuplicateMemoryPair } from './consolidate.js';
import { deleteMemory } from './store.js';
import { backupMemoriesDb } from './backup.js';

export interface DedupeOptions {
  /** Optional project scope. */
  project?: string;
  /** When true (default) only count + sample pairs, no merges. */
  dryRun?: boolean;
  /** Cap on pairs returned/processed. Default 200. */
  limit?: number;
}

export interface DedupeGroupSummary {
  keepId: number;
  keepTitle: string;
  removeIds: number[];
  /** Average pairwise similarity score (text-based, 0..1). */
  similarity: string;
}

export interface DedupeResult {
  options: { project: string | null; dryRun: boolean; limit: number };
  pairsFound: number;
  groups: DedupeGroupSummary[];
  merged?: number;
  backupPath?: string;
}

/**
 * Group pairs into clusters by treating "duplicate" as a transitive
 * relation: if A↔B and B↔C are both flagged, A,B,C cluster together. The
 * representative of each cluster is `recommendedKeepId` (highest salience
 * tie-broken by most recent).
 */
function clusterPairs(pairs: DuplicateMemoryPair[]): DedupeGroupSummary[] {
  // Union-find over memory ids.
  const parent = new Map<number, number>();
  const find = (id: number): number => {
    if (!parent.has(id)) parent.set(id, id);
    let cur = id;
    while (parent.get(cur)! !== cur) cur = parent.get(cur)!;
    return cur;
  };
  const union = (a: number, b: number) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };

  const memoryById = new Map<number, DuplicateMemoryPair['memoryA']>();
  const similarityById = new Map<number, string>();

  for (const pair of pairs) {
    union(pair.memoryA.id, pair.memoryB.id);
    memoryById.set(pair.memoryA.id, pair.memoryA);
    memoryById.set(pair.memoryB.id, pair.memoryB);
    similarityById.set(pair.memoryA.id, pair.similarity);
    similarityById.set(pair.memoryB.id, pair.similarity);
  }

  const clusters = new Map<number, number[]>();
  for (const id of memoryById.keys()) {
    const root = find(id);
    if (!clusters.has(root)) clusters.set(root, []);
    clusters.get(root)!.push(id);
  }

  const groups: DedupeGroupSummary[] = [];
  for (const [, ids] of clusters) {
    if (ids.length < 2) continue;
    // Highest salience wins; tie → most recent.
    let keepId = ids[0];
    for (const id of ids) {
      const a = memoryById.get(id)!;
      const b = memoryById.get(keepId)!;
      const aS = a.salience ?? 0;
      const bS = b.salience ?? 0;
      const aT = new Date(a.createdAt ?? 0).getTime();
      const bT = new Date(b.createdAt ?? 0).getTime();
      if (aS > bS || (aS === bS && aT > bT)) keepId = id;
    }
    const removeIds = ids.filter((id) => id !== keepId);
    groups.push({
      keepId,
      keepTitle: memoryById.get(keepId)!.title,
      removeIds,
      similarity: similarityById.get(keepId) ?? '',
    });
  }

  return groups.sort((a, b) => b.removeIds.length - a.removeIds.length);
}

/**
 * Find near-duplicate long-term memories (text-based: title similarity +
 * content overlap, via the existing findDuplicateMemoryPairs heuristic) and
 * optionally merge them by keeping the highest-salience representative and
 * deleting the rest. Backs up the live DB before any merge.
 */
export async function dedupeMemories(rawOptions: DedupeOptions = {}): Promise<DedupeResult> {
  const options = {
    project: rawOptions.project ?? null,
    dryRun: rawOptions.dryRun ?? true,
    limit: rawOptions.limit ?? 200,
  };

  const pairs = findDuplicateMemoryPairs({
    project: options.project ?? undefined,
    limit: options.limit,
  });

  const groups = clusterPairs(pairs);
  const result: DedupeResult = {
    options,
    pairsFound: pairs.length,
    groups,
  };

  if (options.dryRun || groups.length === 0) return result;

  result.backupPath = await backupMemoriesDb('pre-dedupe');

  let merged = 0;
  for (const group of groups) {
    for (const id of group.removeIds) {
      if (deleteMemory(id, { type: 'cli', identifier: 'maintenance:dedupe' })) merged++;
    }
  }
  result.merged = merged;
  return result;
}
