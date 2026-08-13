/**
 * Phase E — per-rule extraction confidence (threat-graph design doc,
 * "Policing the memory graph").
 *
 * The extractor emits a `confidence` on every triple so consumers can finally
 * discriminate a verb-pattern assertion ("X uses Y") from a mere co-occurrence
 * ("X and Y appeared together"). Verb-pattern rules are high-confidence (0.8);
 * co-occurrence (`related_to`) is low-confidence (0.3).
 *
 * extractFromMemory is pure — no DB needed.
 */

import { describe, expect, it } from '@jest/globals';
import { extractFromMemory } from '../graph/extract.js';

function triple(title: string, content: string, predicate: string) {
  const { triples } = extractFromMemory(title, content, 'note');
  return triples.find((t) => t.predicate === predicate);
}

describe('Phase E — per-rule triple confidence', () => {
  it('stamps verb-pattern triples (uses) at high confidence 0.8', () => {
    const t = triple('Stack', 'React uses TypeScript throughout.', 'uses');
    expect(t).toBeDefined();
    expect(t!.confidence).toBe(0.8);
  });

  it('stamps depends_on at 0.8', () => {
    const t = triple('Deps', 'Prisma depends on PostgreSQL for storage.', 'depends_on');
    expect(t).toBeDefined();
    expect(t!.confidence).toBe(0.8);
  });

  it('stamps replaces at 0.8', () => {
    const t = triple('Swap', 'We replaced Webpack with Vite last week.', 'replaces');
    expect(t).toBeDefined();
    expect(t!.confidence).toBe(0.8);
  });

  it('stamps configures at 0.8', () => {
    const t = triple('Config', 'Express configured with Redis for sessions.', 'configures');
    expect(t).toBeDefined();
    expect(t!.confidence).toBe(0.8);
  });

  it('stamps co-occurrence (related_to) at low confidence 0.3', () => {
    // Two tools in one memory with no verb pattern between them → co-occurrence.
    const t = triple('Notes', 'Touched both Docker and Vercel today.', 'related_to');
    expect(t).toBeDefined();
    expect(t!.confidence).toBe(0.3);
  });

  it('every emitted triple carries a numeric confidence', () => {
    const { triples } = extractFromMemory(
      'Big note',
      'The dashboard uses React. Prisma depends on PostgreSQL. Touched Docker and Vercel.',
      'note',
    );
    expect(triples.length).toBeGreaterThan(0);
    for (const t of triples) {
      expect(typeof t.confidence).toBe('number');
      expect(t.confidence).toBeGreaterThan(0);
      expect(t.confidence).toBeLessThanOrEqual(1);
    }
  });
});
