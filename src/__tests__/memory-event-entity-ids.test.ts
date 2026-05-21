import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory } from '../memory/store.js';
import {
  memoryEvents,
  type MemoryEvent,
  type MemoryCreatedEvent,
} from '../api/events.js';

describe('memory_created event payload', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
  });
  afterEach(() => closeDatabase());

  it('includes entity_ids for entities extracted from the memory', async () => {
    const received: MemoryCreatedEvent[] = [];
    const listener = (e: MemoryEvent) => {
      if (e.type === 'memory_created') received.push(e as MemoryCreatedEvent);
    };
    memoryEvents.onMemoryEvent(listener);
    try {
      // Content with names the extractor actually recognises (TOOLS_AND_SERVICES
      // dictionary lists `PostgreSQL` and `Docker` exactly — `Postgres` does not match).
      addMemory({
        type: 'long_term',
        category: 'architecture',
        title: 'PostgreSQL + Docker rollout decision',
        content: 'We decided to use PostgreSQL and Docker for the new SaaS billing service.',
        project: '*',
      });
      await new Promise((r) => setTimeout(r, 10));
      expect(received).toHaveLength(1);
      const event = received[0];
      expect(event.data.memory.id).toBeGreaterThan(0);
      expect(Array.isArray(event.data.entity_ids)).toBe(true);
      expect(event.data.entity_ids.length).toBeGreaterThan(0); // load-bearing
      const db = getDatabase();
      const rows = db
        .prepare('SELECT entity_id FROM memory_entities WHERE memory_id = ?')
        .all(event.data.memory.id) as { entity_id: number }[];
      expect([...event.data.entity_ids].sort()).toEqual(
        rows.map((r) => r.entity_id).sort()
      );
    } finally {
      memoryEvents.offMemoryEvent(listener);
    }
  });
});
