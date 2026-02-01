/**
 * Trust Scoring Tests
 *
 * Tests for source trust scoring and hierarchy.
 */

import { describe, it, expect } from '@jest/globals';

describe('Trust Source Scorer', () => {
  it('should score user:direct as 1.0', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    const result = scoreSource({ type: 'user', identifier: 'direct' });
    expect(result.score).toBe(1.0);
  });

  it('should score email source as 0.4', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    const result = scoreSource({ type: 'email', identifier: 'inbox' });
    expect(result.score).toBe(0.4);
  });

  it('should score web source as 0.3', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    const result = scoreSource({ type: 'web', identifier: 'scraper' });
    expect(result.score).toBe(0.3);
  });

  it('should score agent source as 0.1', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    const result = scoreSource({ type: 'agent', identifier: 'assistant' });
    expect(result.score).toBe(0.1);
  });

  it('should score user:approved as 0.9', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    const result = scoreSource({ type: 'user', identifier: 'approved' });
    expect(result.score).toBe(0.9);
  });

  it('should include trust hierarchy in result', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    const result = scoreSource({ type: 'web', identifier: 'scraper' });
    expect(result.hierarchy).toBeDefined();
    expect(result.hierarchy.length).toBeGreaterThan(0);
    // Last entry should show the current source's score
    expect(result.hierarchy[result.hierarchy.length - 1]).toContain('web:scraper');
    expect(result.hierarchy[result.hierarchy.length - 1]).toContain('0.3');
  });

  it('should return correct source in result', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    const source = { type: 'email' as const, identifier: 'test@example.com' };
    const result = scoreSource(source);
    expect(result.source).toEqual(source);
  });
});
