/**
 * Reciprocal Rank Fusion (RRF).
 *
 * Combines ordered rank lists from multiple retrievers (e.g. BM25, vector,
 * graph) into a single fused ranking. Robust to heterogeneous score scales:
 * the only thing that matters is each retriever's rank order.
 *
 *   score(d) = Σ_i  w_i / (k + rank_i(d))
 *
 * - rank_i(d) is the 1-indexed position of d in retriever i's list.
 * - w_i is the optional weight for retriever i (default 1).
 * - k is a smoothing constant. Cormack et al. (2009) recommend 60.
 *
 * The function returns the union of ids across all rank lists, sorted by
 * fused score descending. Ties break by id ascending for stable output.
 */

export interface RankList {
  /** Identifier for this retriever (e.g. 'fts', 'vector', 'graph'). */
  name: string;
  /** Ordered ids, best-first. May be empty. Duplicates within a list are deduplicated, keeping the first occurrence. */
  ids: number[];
  /** Multiplicative weight on this retriever's contribution. Defaults to 1. */
  weight?: number;
}

export interface RrfOptions {
  /** RRF smoothing constant. Default 60. */
  k?: number;
}

export interface RrfContribution {
  name: string;
  /** 1-indexed rank within that retriever's list. */
  rank: number;
  /** weight / (k + rank) — this contribution's addition to the final score. */
  weighted: number;
}

export interface RrfResult {
  id: number;
  score: number;
  contributions: RrfContribution[];
}

const DEFAULT_K = 60;

export function reciprocalRankFusion(
  rankLists: readonly RankList[],
  options: RrfOptions = {},
): RrfResult[] {
  const k = options.k ?? DEFAULT_K;
  const accumulator = new Map<number, { score: number; contributions: RrfContribution[] }>();

  for (const list of rankLists) {
    if (list.ids.length === 0) continue;
    const weight = list.weight ?? 1;
    const seen = new Set<number>();
    list.ids.forEach((id, idx) => {
      if (seen.has(id)) return; // dedupe within a single rank list, keep first
      seen.add(id);
      const rank = idx + 1;
      const weighted = weight / (k + rank);
      const entry = accumulator.get(id);
      const contribution: RrfContribution = { name: list.name, rank, weighted };
      if (entry) {
        entry.score += weighted;
        entry.contributions.push(contribution);
      } else {
        accumulator.set(id, { score: weighted, contributions: [contribution] });
      }
    });
  }

  const results: RrfResult[] = Array.from(accumulator.entries()).map(([id, { score, contributions }]) => ({
    id,
    score,
    contributions,
  }));

  results.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.id - b.id; // stable tie-break by id ascending
  });

  return results;
}
