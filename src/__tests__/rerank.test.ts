/**
 * Tests for LLM Memory Reranking (v4.0.0)
 */

import { describe, it, expect } from '@jest/globals';

describe('Memory Reranking', () => {
  it('should build a rerank prompt with candidates', async () => {
    const { buildRerankPrompt } = await import('../memory/rerank.js');
    const prompt = buildRerankPrompt('test query', [
      { id: 1, title: 'Memory A', content: 'Content A' },
      { id: 2, title: 'Memory B', content: 'Content B' },
    ]);
    expect(prompt).toContain('test query');
    expect(prompt).toContain('Memory A');
    expect(prompt).toContain('Memory B');
    expect(prompt).toContain('ID=1');
    expect(prompt).toContain('ID=2');
  });

  it('should parse a valid rerank response', async () => {
    const { parseRerankResponse } = await import('../memory/rerank.js');
    const ids = parseRerankResponse('[3, 1, 2]');
    expect(ids).toEqual([3, 1, 2]);
  });

  it('should extract array from wrapped response', async () => {
    const { parseRerankResponse } = await import('../memory/rerank.js');
    const ids = parseRerankResponse('Here are the rankings: [2, 1, 3] based on relevance.');
    expect(ids).toEqual([2, 1, 3]);
  });

  it('should return empty array for unparseable response', async () => {
    const { parseRerankResponse } = await import('../memory/rerank.js');
    const ids = parseRerankResponse('I cannot rank these.');
    expect(ids).toEqual([]);
  });

  it('should return original results when disabled', async () => {
    const { rerankResults, DEFAULT_RERANK_CONFIG } = await import('../memory/rerank.js');
    const results = [
      { memory: { id: 1, title: 'A' } as any, relevanceScore: 0.9 },
      { memory: { id: 2, title: 'B' } as any, relevanceScore: 0.8 },
    ];
    const reranked = await rerankResults('query', results, async () => '[2, 1]', { ...DEFAULT_RERANK_CONFIG, enabled: false });
    expect(reranked).toBe(results); // Same reference = not modified
  });

  it('should rerank results using LLM when enabled', async () => {
    const { rerankResults } = await import('../memory/rerank.js');
    const results = [
      { memory: { id: 1, title: 'A', content: 'Alpha' } as any, relevanceScore: 0.9 },
      { memory: { id: 2, title: 'B', content: 'Beta' } as any, relevanceScore: 0.8 },
      { memory: { id: 3, title: 'C', content: 'Gamma' } as any, relevanceScore: 0.7 },
    ];
    const reranked = await rerankResults('query', results, async () => '[3, 1, 2]', {
      enabled: true,
      model: 'test',
      maxCandidates: 20,
    });
    expect(reranked[0].memory.id).toBe(3);
    expect(reranked[1].memory.id).toBe(1);
    expect(reranked[2].memory.id).toBe(2);
  });

  it('should fallback gracefully on LLM error', async () => {
    const { rerankResults } = await import('../memory/rerank.js');
    const results = [
      { memory: { id: 1, title: 'A', content: 'Alpha' } as any, relevanceScore: 0.9 },
    ];
    const reranked = await rerankResults('query', results, async () => { throw new Error('LLM down'); }, {
      enabled: true,
      model: 'test',
      maxCandidates: 20,
    });
    expect(reranked).toEqual(results);
  });
});
