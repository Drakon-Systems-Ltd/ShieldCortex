/**
 * Tests for the hook-side session capture wrapper at
 * `scripts/lib/session-capture.mjs`. Runs the real `.mjs` module via
 * dynamic import + a real `:memory:` better-sqlite3 DB seeded with the
 * SC schema so we exercise the same constraints production hits.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';

// `.mjs` import — Jest with ESM support resolves this at runtime.
// @ts-expect-error — JS module with no .d.ts
import { recordSessionEvent, recordSessionEvents } from '../../scripts/lib/session-capture.mjs';

beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('recordSessionEvent (mjs wrapper)', () => {
  it('inserts a valid event and returns the new row id', () => {
    const db = getDatabase();
    const id = recordSessionEvent(db, {
      session_id: 's-mjs-1',
      ts: '2026-05-10T10:00:00Z',
      kind: 'prompt',
      payload: { text: 'hello from hook' },
      project: 'shieldcortex',
    });
    expect(typeof id).toBe('number');
    expect(id).toBeGreaterThan(0);

    const row = db
      .prepare('SELECT session_id, kind, project, payload FROM session_events WHERE id = ?')
      .get(id) as Record<string, unknown>;
    expect(row.session_id).toBe('s-mjs-1');
    expect(row.kind).toBe('prompt');
    expect(row.project).toBe('shieldcortex');
    expect(JSON.parse(row.payload as string)).toEqual({ text: 'hello from hook' });
  });

  it('returns null (no row written) when session_id is missing', () => {
    const db = getDatabase();
    const result = recordSessionEvent(db, {
      ts: '2026-05-10T10:00:00Z',
      kind: 'prompt',
      payload: { text: 'orphan' },
    });
    expect(result).toBeNull();
    const count = (
      db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }
    ).c;
    expect(count).toBe(0);
  });

  it('returns null when kind is not in the valid set', () => {
    const db = getDatabase();
    const result = recordSessionEvent(db, {
      session_id: 's',
      ts: '2026-05-10T10:00:00Z',
      kind: 'totally-fake-kind',
      payload: { x: 1 },
    });
    expect(result).toBeNull();
  });

  it('returns {error} on SQL constraint violation rather than throwing', () => {
    const db = getDatabase();
    // ts is NOT NULL — passing null would fail the constraint at SQL level.
    const result = recordSessionEvent(db, {
      session_id: 's',
      ts: null as unknown as string,
      kind: 'prompt',
      payload: { x: 1 },
    });
    // Validator returns null before SQL because ts is invalid.
    expect(result).toBeNull();
  });

  it('accepts a pre-stringified payload as-is', () => {
    const db = getDatabase();
    const id = recordSessionEvent(db, {
      session_id: 's',
      ts: '2026-05-10T10:00:00Z',
      kind: 'hook_fire',
      payload: 'literal-string-payload',
    });
    const row = db
      .prepare('SELECT payload FROM session_events WHERE id = ?')
      .get(id) as { payload: string };
    expect(row.payload).toBe('literal-string-payload');
  });
});

describe('recordSessionEvents (batch, mjs wrapper)', () => {
  it('inserts multiple events atomically', () => {
    const db = getDatabase();
    const ids = recordSessionEvents(db, [
      { session_id: 's-b', ts: '2026-05-10T11:00:00Z', kind: 'prompt', payload: { text: 'q' } },
      { session_id: 's-b', ts: '2026-05-10T11:00:01Z', kind: 'response', payload: { text: 'a' } },
    ]);
    expect(ids).toHaveLength(2);
    const count = (
      db.prepare("SELECT COUNT(*) AS c FROM session_events WHERE session_id = 's-b'").get() as { c: number }
    ).c;
    expect(count).toBe(2);
  });

  it('rolls back if any event in the batch is invalid', () => {
    const db = getDatabase();
    expect(() =>
      recordSessionEvents(db, [
        { session_id: 's-rb', ts: '2026-05-10T12:00:00Z', kind: 'prompt', payload: { text: 'ok' } },
        { session_id: 's-rb', ts: '2026-05-10T12:00:01Z', kind: 'bogus', payload: { text: 'bad' } },
      ]),
    ).toThrow();
    const count = (
      db.prepare("SELECT COUNT(*) AS c FROM session_events WHERE session_id = 's-rb'").get() as { c: number }
    ).c;
    expect(count).toBe(0);
  });

  it('returns [] for empty input without opening a transaction', () => {
    expect(recordSessionEvents(getDatabase(), [])).toEqual([]);
  });
});
