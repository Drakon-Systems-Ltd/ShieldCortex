/**
 * Tests for Memory Staleness Scoring (v4.0.0)
 */

import { describe, it, expect } from '@jest/globals';

describe('Memory Staleness', () => {
  it('should report 0 days for a memory created now', async () => {
    const { memoryAgeDays } = await import('../memory/staleness.js');
    expect(memoryAgeDays(Date.now())).toBe(0);
  });

  it('should report correct days for older memories', async () => {
    const { memoryAgeDays } = await import('../memory/staleness.js');
    const threeDaysAgo = Date.now() - 3 * 86_400_000;
    expect(memoryAgeDays(threeDaysAgo)).toBe(3);
  });

  it('should return "today" for fresh memories', async () => {
    const { memoryAge } = await import('../memory/staleness.js');
    expect(memoryAge(Date.now())).toBe('today');
  });

  it('should return "yesterday" for 1-day-old memories', async () => {
    const { memoryAge } = await import('../memory/staleness.js');
    const yesterday = Date.now() - 86_400_000;
    expect(memoryAge(yesterday)).toBe('yesterday');
  });

  it('should return "X days ago" for 2-6 day old memories', async () => {
    const { memoryAge } = await import('../memory/staleness.js');
    const fiveDaysAgo = Date.now() - 5 * 86_400_000;
    expect(memoryAge(fiveDaysAgo)).toBe('5 days ago');
  });

  it('should return freshness score of 1.0 for today', async () => {
    const { memoryFreshnessScore } = await import('../memory/staleness.js');
    expect(memoryFreshnessScore(Date.now())).toBe(1.0);
  });

  it('should return declining freshness for older memories', async () => {
    const { memoryFreshnessScore } = await import('../memory/staleness.js');
    const sevenDaysAgo = Date.now() - 7 * 86_400_000;
    const score = memoryFreshnessScore(sevenDaysAgo);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThan(1);
    // ~0.5 for 7-day half-life
    expect(score).toBeGreaterThan(0.3);
    expect(score).toBeLessThan(0.7);
  });

  it('should return null warning for fresh memories', async () => {
    const { memoryFreshnessWarning } = await import('../memory/staleness.js');
    expect(memoryFreshnessWarning(Date.now())).toBeNull();
  });

  it('should return null warning for 1-day old memories', async () => {
    const { memoryFreshnessWarning } = await import('../memory/staleness.js');
    expect(memoryFreshnessWarning(Date.now() - 86_400_000)).toBeNull();
  });

  it('should return warning for 3+ day old memories', async () => {
    const { memoryFreshnessWarning } = await import('../memory/staleness.js');
    const threeDaysAgo = Date.now() - 3 * 86_400_000;
    const warning = memoryFreshnessWarning(threeDaysAgo);
    expect(warning).not.toBeNull();
    expect(warning).toContain('⚠️');
  });

  it('should return "very stale" warning for 30+ day old memories', async () => {
    const { memoryFreshnessWarning } = await import('../memory/staleness.js');
    const thirtyDaysAgo = Date.now() - 30 * 86_400_000;
    const warning = memoryFreshnessWarning(thirtyDaysAgo);
    expect(warning).toContain('Very stale');
  });
});
