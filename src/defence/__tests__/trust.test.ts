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

  it('should score agent source using hierarchy scorer', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    // Unknown origin defaults to 0.3 base
    const result = scoreSource({ type: 'agent', identifier: 'assistant' });
    expect(result.score).toBe(0.3);
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

  // Load-bearing invariants for the write-bypass fix (Feature #2). The synthetic
  // source for unattributed writes MUST stay strictly below the 0.5–0.7
  // auto-quarantine band, or every source-less write (dashboard, consolidate,
  // quarantine-promote) starts THROWING MemoryBlockedError. If TYPE_SCORES
  // changes and breaks these, the bypass fix's safety assumption is gone.
  it('scores the unattributed-write source (web:unattributed) at 0.3 — below the quarantine band', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    expect(scoreSource({ type: 'web', identifier: 'unattributed' }).score).toBe(0.3);
    expect(scoreSource({ type: 'web', identifier: 'unattributed' }).score).toBeLessThan(0.5);
  });

  it('pins file:import below the quarantine band (0.4) and dashboard (api:dashboard) at 0.7', async () => {
    const { scoreSource } = await import('../trust/source-scorer.js');
    // The generic `file` type is 0.6 — INSIDE the 0.5–0.7 auto-quarantine band,
    // which would wrongly quarantine every imported row. file:import is pinned
    // to 0.4 (BASE_SCORES override): below the band, so a benign backup restore
    // succeeds, but still scanned + low-trust.
    expect(scoreSource({ type: 'file', identifier: 'import' }).score).toBe(0.4);
    expect(scoreSource({ type: 'file', identifier: 'import' }).score).toBeLessThan(0.5);
    expect(scoreSource({ type: 'api', identifier: 'dashboard' }).score).toBe(0.7);
  });

  it('derives untrusted-inbound types from the score table with agent exempted', async () => {
    const {
      isUntrustedInboundType,
      TYPE_SCORES,
      UNTRUSTED_INBOUND_FLOOR,
    } = await import('../trust/source-scorer.js');

    expect(isUntrustedInboundType('web')).toBe(true);
    expect(isUntrustedInboundType('email')).toBe(true);
    expect(isUntrustedInboundType('tool_response')).toBe(true);
    expect(isUntrustedInboundType('agent')).toBe(false);
    expect(isUntrustedInboundType('file')).toBe(false);
    expect(isUntrustedInboundType('cli')).toBe(false);
    expect(isUntrustedInboundType('mystery')).toBe(true);

    for (const [type, score] of Object.entries(TYPE_SCORES)) {
      if (type === 'agent') {
        expect(isUntrustedInboundType(type)).toBe(false);
      } else {
        expect(isUntrustedInboundType(type)).toBe(score < UNTRUSTED_INBOUND_FLOOR);
      }
    }
  });
});
