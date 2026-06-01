import { describe, it, expect } from '@jest/globals';

/**
 * Task 4 of the memory-quality fix.
 *
 * The SessionStart boot preamble ordered high-priority memories by raw
 * `salience DESC, last_accessed DESC`. With ~80% of rows pinned at raw
 * salience=1.0 that ordering was a giant tie — meaningless. The fix orders by
 * *effective* salience (recency × access × pin × downvote_penalty) via the
 * pure helper orderByEffectiveSalience, so fresh/relevant memories rank above
 * stale 1.0 ones.
 *
 * The helper is imported from scripts/lib/session-context.mjs (NOT the hook
 * entrypoint, which runs a stdin/process.exit IIFE on import).
 */

describe('orderByEffectiveSalience: boot preamble ranks by effective salience', () => {
  const NOW = Date.parse('2026-06-01T00:00:00Z');

  it('a fresh low-base memory outranks a stale high-base one', async () => {
    const { orderByEffectiveSalience } = await import('../../scripts/lib/session-context.mjs');
    const stale = {
      id: 'stale',
      salience: 1.0,
      last_accessed: '2026-03-01T00:00:00Z',
      access_count: 0,
      pinned: 0,
      downvote_count: 0,
    };
    const fresh = {
      id: 'fresh',
      salience: 0.4,
      last_accessed: '2026-06-01T00:00:00Z',
      access_count: 0,
      pinned: 0,
      downvote_count: 0,
    };
    // Raw `salience DESC` would put `stale` first; effective ordering flips it.
    const ordered = orderByEffectiveSalience([stale, fresh], { now: NOW });
    expect(ordered[0]).toBe(fresh);
  });

  it('a pinned memory outranks an identical unpinned one', async () => {
    const { orderByEffectiveSalience } = await import('../../scripts/lib/session-context.mjs');
    const base = {
      salience: 0.7,
      last_accessed: '2026-06-01T00:00:00Z',
      access_count: 0,
      downvote_count: 0,
    };
    const unpinned = { ...base, id: 'unpinned', pinned: 0 };
    const pinned = { ...base, id: 'pinned', pinned: 1 };
    const ordered = orderByEffectiveSalience([unpinned, pinned], { now: NOW });
    expect(ordered[0]).toBe(pinned);
  });

  it('does not mutate the input array (returns a new sorted array)', async () => {
    const { orderByEffectiveSalience } = await import('../../scripts/lib/session-context.mjs');
    const a = {
      id: 'a',
      salience: 0.2,
      last_accessed: '2026-03-01T00:00:00Z',
      access_count: 0,
      pinned: 0,
      downvote_count: 0,
    };
    const b = {
      id: 'b',
      salience: 0.9,
      last_accessed: '2026-06-01T00:00:00Z',
      access_count: 0,
      pinned: 0,
      downvote_count: 0,
    };
    const input = [a, b];
    const ordered = orderByEffectiveSalience(input, { now: NOW });
    expect(input).toEqual([a, b]); // original order preserved
    expect(ordered).not.toBe(input); // new array
    expect(ordered[0]).toBe(b);
  });
});
