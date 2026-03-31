/**
 * LLM-Powered Memory Reranking — v4.0.0
 *
 * Optional hybrid recall: after embedding-based retrieval returns top-N candidates,
 * send them to an LLM to rerank by relevance to the query.
 */

import type { SearchResult } from './types.js';

export interface RerankConfig {
  enabled: boolean;
  model: string;       // e.g. "sonnet", "gpt-4o-mini"
  maxCandidates: number;
}

export const DEFAULT_RERANK_CONFIG: RerankConfig = {
  enabled: false,
  model: 'sonnet',
  maxCandidates: 20,
};

/**
 * Build the reranking prompt for the LLM.
 */
export function buildRerankPrompt(query: string, candidates: { id: number; title: string; content: string }[]): string {
  const candidateList = candidates
    .map((c, i) => `[${i + 1}] ID=${c.id} | Title: ${c.title}\n${c.content.slice(0, 200)}`)
    .join('\n\n');

  return `Given the query: "${query}"

Rank the following memory candidates by relevance to the query. Return ONLY a JSON array of memory IDs in order of relevance (most relevant first).

Candidates:
${candidateList}

Response format: [id1, id2, id3, ...]`;
}

/**
 * Parse the LLM response to extract the reranked order.
 * Returns array of memory IDs in relevance order.
 */
export function parseRerankResponse(response: string): number[] {
  try {
    // Try to extract JSON array from the response
    const match = response.match(/\[[\d,\s]+\]/);
    if (match) {
      return JSON.parse(match[0]);
    }
    // Fallback: extract numbers in order
    const numbers = response.match(/\d+/g);
    return numbers ? numbers.map(Number) : [];
  } catch {
    return [];
  }
}

/**
 * Rerank search results using an LLM.
 * This is a framework function — the actual LLM call is delegated to a caller-provided function.
 */
export async function rerankResults(
  query: string,
  results: SearchResult[],
  llmCall: (prompt: string) => Promise<string>,
  config: RerankConfig = DEFAULT_RERANK_CONFIG,
): Promise<SearchResult[]> {
  if (!config.enabled || results.length <= 1) {
    return results;
  }

  const candidates = results.slice(0, config.maxCandidates).map(r => ({
    id: r.memory.id,
    title: r.memory.title,
    content: r.memory.content,
  }));

  const prompt = buildRerankPrompt(query, candidates);

  try {
    const response = await llmCall(prompt);
    const rankedIds = parseRerankResponse(response);

    if (rankedIds.length === 0) {
      return results; // Fallback to original order
    }

    // Build a map for O(1) lookup
    const resultMap = new Map(results.map(r => [r.memory.id, r]));
    const reranked: SearchResult[] = [];

    // Add results in LLM-determined order
    for (const id of rankedIds) {
      const result = resultMap.get(id);
      if (result) {
        reranked.push(result);
        resultMap.delete(id);
      }
    }

    // Append any results not mentioned by the LLM
    for (const remaining of resultMap.values()) {
      reranked.push(remaining);
    }

    return reranked;
  } catch {
    // If LLM reranking fails, return original order
    return results;
  }
}
