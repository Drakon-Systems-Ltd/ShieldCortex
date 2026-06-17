/**
 * Feature #2 — the remaining content-WRITE paths must also be scanned.
 *
 * updateMemory (content/title replace) and enrichMemory (append recall-query-
 * derived text) wrote to `memories` with NO defence scan — the same bug class
 * addMemory/import/merge closed, on the UPDATE/append paths. updateMemory is
 * reachable via remember-dedup + dashboard PATCH; enrichMemory via the recall
 * side-effect (the query string becomes the appended payload). Both must scan
 * the new content and refuse poison (mirroring mergeMemories).
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase } from '../database/init.js';
import { addMemory, updateMemory, getMemoryById, MemoryBlockedError } from '../memory/store.js';
import { enrichMemory } from '../memory/lifecycle.js';

const CRED = 'AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

describe('updateMemory — re-scans content/title on change (Feature #2)', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('blocks a content change carrying a credential, leaving the row unchanged', () => {
    const mem = addMemory({ title: 'note', content: 'a perfectly benign note' }, undefined, { type: 'user', identifier: 'direct' });
    expect(() => updateMemory(mem.id, { content: `secrets: ${CRED}` })).toThrow(MemoryBlockedError);
    expect(getMemoryById(mem.id)!.content).toBe('a perfectly benign note'); // rolled back / untouched
  });

  it('allows a benign content change', () => {
    const mem = addMemory({ title: 'note', content: 'original benign content' }, undefined, { type: 'user', identifier: 'direct' });
    const updated = updateMemory(mem.id, { content: 'updated benign content' });
    expect(updated?.content).toBe('updated benign content');
  });

  it('does not scan when only non-content fields change (e.g. pinned)', () => {
    const mem = addMemory({ title: 'note', content: 'benign' }, undefined, { type: 'user', identifier: 'direct' });
    expect(() => updateMemory(mem.id, { pinned: true })).not.toThrow();
  });
});

describe('enrichMemory — re-scans appended content (Feature #2)', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('refuses enrichment whose appended content carries a credential (row unchanged)', () => {
    const mem = addMemory({ title: 'deploy', content: 'deploy runbook staging bucket policy notes' }, undefined, { type: 'user', identifier: 'direct' });
    const before = getMemoryById(mem.id)!.content;
    // Shares enough words to pass the similarity gate (0.3–0.8), then carries a credential.
    const result = enrichMemory(mem.id, `deploy runbook staging bucket ${CRED}`, 'search');
    expect(result.enriched).toBe(false);
    expect(result.reason ?? '').toMatch(/defence/i);
    expect(getMemoryById(mem.id)!.content).toBe(before); // not poisoned
  });
});
