/**
 * Contradiction Surfacing Tests
 *
 * Tests that contradictions are properly included in search results
 * and displayed in recall output.
 */

import { describe, it, expect } from '@jest/globals';
import type { SearchResult, Memory } from '../memory/types.js';
import { formatRecallResult } from '../tools/recall.js';

function makeMemory(overrides: Partial<Memory> = {}): Memory {
  return {
    id: 1,
    type: 'long_term',
    category: 'architecture',
    title: 'Use PostgreSQL',
    content: 'Decided to use PostgreSQL for the database',
    project: 'test',
    tags: [],
    salience: 0.8,
    accessCount: 1,
    lastAccessed: new Date(),
    createdAt: new Date(),
    decayedScore: 0.7,
    metadata: {},
    scope: 'project',
    transferable: false,
    ...overrides,
  };
}

describe('SearchResult contradictions field', () => {
  it('should allow contradictions on SearchResult', () => {
    const result: SearchResult = {
      memory: makeMemory(),
      relevanceScore: 0.9,
      contradictions: [
        { memoryId: 2, title: 'Use SQLite', score: 0.8 },
      ],
    };

    expect(result.contradictions).toBeDefined();
    expect(result.contradictions).toHaveLength(1);
    expect(result.contradictions![0].memoryId).toBe(2);
    expect(result.contradictions![0].title).toBe('Use SQLite');
    expect(result.contradictions![0].score).toBe(0.8);
  });

  it('should allow SearchResult without contradictions', () => {
    const result: SearchResult = {
      memory: makeMemory(),
      relevanceScore: 0.9,
    };

    expect(result.contradictions).toBeUndefined();
  });
});

describe('formatRecallResult with contradictions', () => {
  it('should show contradiction warnings in formatted output', () => {
    const mem1 = makeMemory({ id: 1, title: 'Use PostgreSQL' });
    const mem2 = makeMemory({ id: 2, title: 'Use SQLite' });

    const contradictions = new Map<number, { memoryId: number; title: string; score: number }[]>();
    contradictions.set(1, [{ memoryId: 2, title: 'Use SQLite', score: 0.8 }]);

    const output = formatRecallResult({
      success: true,
      memories: [mem1, mem2],
      contradictions,
      count: 2,
    });

    expect(output).toContain('CONTRADICTS');
    expect(output).toContain('"Use SQLite"');
    expect(output).toContain('ID 2');
  });

  it('should not show contradiction warning for memories without contradictions', () => {
    const mem = makeMemory({ id: 3, title: 'Some memory' });

    const output = formatRecallResult({
      success: true,
      memories: [mem],
      count: 1,
    });

    expect(output).not.toContain('CONTRADICTS');
  });
});
