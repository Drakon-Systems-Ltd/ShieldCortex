import { beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * Phase 17 A4 — `remember` must not silently discard new content on a
 * near-duplicate hit.
 *
 * Before the fix, when searchMemories returned an existing memory with
 * relevanceScore > 0.9, remember returned "Updated existing similar memory"
 * but NEVER wrote anything — the new (richer) content was lost while the
 * report claimed an update. The dedupe branch must now genuinely update the
 * existing memory with the new content.
 *
 * This drives the exact branch by mocking searchMemories to force the >0.9
 * dedupe hit (deterministic; the composite relevance score is hard to push
 * past 0.9 without an embedding model present).
 */

const existingMemory = {
  id: 42,
  uuid: 'u-42',
  title: 'Postgres connection pool sizing',
  content: 'Use a pool size of 10 for the API service.',
  type: 'long_term' as const,
  category: 'architecture' as const,
  salience: 0.7,
  tags: [] as string[],
};

const updateMemoryMock = jest.fn((_id: number, updates: { content?: string }) => ({
  ...existingMemory,
  content: updates.content ?? existingMemory.content,
}));
const addMemoryMock = jest.fn();

async function loadRemember() {
  jest.unstable_mockModule('../memory/store.js', () => ({
    addMemory: addMemoryMock,
    updateMemory: updateMemoryMock,
    searchMemories: jest.fn(async () => [
      { memory: { ...existingMemory }, relevanceScore: 0.97, recallEligibility: { eligible: true, reasons: [] } },
    ]),
    detectRelationships: jest.fn(() => []),
    createMemoryLink: jest.fn(),
    getLastTruncationInfo: jest.fn(() => undefined),
  }));
  jest.unstable_mockModule('../context/project-context.js', () => ({
    resolveProject: (p?: string) => p ?? null,
  }));
  jest.unstable_mockModule('../memory/save-filter.js', () => ({
    shouldFilterMemory: () => ({ allowed: true }),
  }));
  return import('../tools/remember.js');
}

describe('remember dedupe genuinely updates the existing memory', () => {
  beforeEach(() => {
    jest.resetModules();
    updateMemoryMock.mockClear();
    addMemoryMock.mockClear();
  });

  it('calls updateMemory with the NEW content instead of silently discarding it', async () => {
    const { executeRemember } = await loadRemember();

    const NEW_DETAIL = 'Bumped pool size to 20 after load testing showed connection starvation.';
    const newContent = `Use a pool size of 10 for the API service. ${NEW_DETAIL}`;

    const result = await executeRemember({
      title: 'Postgres connection pool sizing',
      content: newContent,
    });

    expect(result.success).toBe(true);
    // The dedupe path must perform a REAL update of the existing memory...
    expect(updateMemoryMock).toHaveBeenCalledTimes(1);
    expect(updateMemoryMock.mock.calls[0][0]).toBe(42);
    expect((updateMemoryMock.mock.calls[0][1] as { content?: string }).content).toBe(newContent);
    // ...and must NOT mint a brand-new duplicate row.
    expect(addMemoryMock).not.toHaveBeenCalled();
    // The returned memory reflects the updated content.
    expect(result.memory!.id).toBe(42);
  });
});
