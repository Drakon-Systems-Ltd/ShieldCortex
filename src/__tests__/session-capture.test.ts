/**
 * Session capture — schema + write API tests.
 *
 * Covers v4.17 Step B foundation: the `session_events` table exists on
 * every newly-initialised DB, `recordEvent()` writes one row, and the
 * batch variant runs atomically so partial failures don't leak.
 *
 * Hermetic — each test starts a fresh `:memory:` DB via `initDatabase`
 * so schema changes are exercised the same way they hit production.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  initDatabase,
  closeDatabase,
  getDatabase,
} from '../database/init.js';
import {
  recordEvent,
  recordEvents,
  type SessionEventInput,
} from '../sessions/capture.js';
import { getTimeline } from '../sessions/timeline.js';

beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('session_events schema', () => {
  it('creates the session_events table on init', () => {
    const db = getDatabase();
    const row = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'session_events'")
      .get() as { name?: string } | undefined;
    expect(row?.name).toBe('session_events');
  });

  it('table has the expected columns', () => {
    const db = getDatabase();
    const cols = db
      .prepare("PRAGMA table_info(session_events)")
      .all() as Array<{ name: string; type: string; notnull: number }>;
    const colMap = new Map(cols.map((c) => [c.name, c]));
    expect(colMap.has('id')).toBe(true);
    expect(colMap.has('session_id')).toBe(true);
    expect(colMap.has('project')).toBe(true);
    expect(colMap.has('ts')).toBe(true);
    expect(colMap.has('kind')).toBe(true);
    expect(colMap.has('actor')).toBe(true);
    expect(colMap.has('payload')).toBe(true);
    expect(colMap.has('duration_ms')).toBe(true);
    expect(colMap.has('audit_id')).toBe(true);
    expect(colMap.has('created_at')).toBe(true);
    // session_id, ts, kind, payload must be NOT NULL — the four invariants of an event row
    expect(colMap.get('session_id')?.notnull).toBe(1);
    expect(colMap.get('ts')?.notnull).toBe(1);
    expect(colMap.get('kind')?.notnull).toBe(1);
    expect(colMap.get('payload')?.notnull).toBe(1);
  });

  it('rejects an invalid kind via CHECK constraint', () => {
    const db = getDatabase();
    expect(() =>
      db
        .prepare(
          `INSERT INTO session_events (session_id, ts, kind, payload) VALUES (?, ?, ?, ?)`,
        )
        .run('s1', new Date().toISOString(), 'unknown_kind', '{}'),
    ).toThrow();
  });

  it('creates idx_session_events_session and idx_session_events_project indexes', () => {
    const db = getDatabase();
    const indexes = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'session_events'")
      .all() as Array<{ name: string }>;
    const names = new Set(indexes.map((i) => i.name));
    expect(names.has('idx_session_events_session')).toBe(true);
    expect(names.has('idx_session_events_project')).toBe(true);
  });
});

describe('recordEvent', () => {
  it('writes a single event row and returns the inserted id', () => {
    const id = recordEvent({
      session_id: 's-2026-05-10',
      ts: '2026-05-10T12:34:56Z',
      kind: 'prompt',
      payload: { text: 'hello world' },
    });
    expect(id).toBeGreaterThan(0);

    const row = getDatabase()
      .prepare('SELECT * FROM session_events WHERE id = ?')
      .get(id) as Record<string, unknown>;
    expect(row.session_id).toBe('s-2026-05-10');
    expect(row.kind).toBe('prompt');
    expect(JSON.parse(row.payload as string)).toEqual({ text: 'hello world' });
    expect(row.ts).toBe('2026-05-10T12:34:56Z');
  });

  it('persists optional fields (project, actor, duration_ms, audit_id)', () => {
    const id = recordEvent({
      session_id: 's-2',
      ts: '2026-05-10T13:00:00Z',
      kind: 'tool_call',
      payload: { tool: 'Bash', args: { cmd: 'ls' } },
      project: 'shieldcortex',
      actor: 'assistant',
      duration_ms: 42,
      audit_id: null,
    });
    const row = getDatabase()
      .prepare('SELECT project, actor, duration_ms, audit_id FROM session_events WHERE id = ?')
      .get(id) as Record<string, unknown>;
    expect(row.project).toBe('shieldcortex');
    expect(row.actor).toBe('assistant');
    expect(row.duration_ms).toBe(42);
    expect(row.audit_id).toBeNull();
  });

  it('defaults project, actor, duration_ms, audit_id to null when omitted', () => {
    const id = recordEvent({
      session_id: 's-3',
      ts: '2026-05-10T14:00:00Z',
      kind: 'response',
      payload: { text: 'ok' },
    });
    const row = getDatabase()
      .prepare('SELECT project, actor, duration_ms, audit_id FROM session_events WHERE id = ?')
      .get(id) as Record<string, unknown>;
    expect(row.project).toBeNull();
    expect(row.actor).toBeNull();
    expect(row.duration_ms).toBeNull();
    expect(row.audit_id).toBeNull();
  });

  it('serialises non-string payload to JSON', () => {
    const id = recordEvent({
      session_id: 's-4',
      ts: '2026-05-10T15:00:00Z',
      kind: 'tool_result',
      payload: { ok: true, count: 5, items: ['a', 'b'] },
    });
    const row = getDatabase()
      .prepare('SELECT payload FROM session_events WHERE id = ?')
      .get(id) as { payload: string };
    expect(typeof row.payload).toBe('string');
    expect(JSON.parse(row.payload)).toEqual({ ok: true, count: 5, items: ['a', 'b'] });
  });

  it('accepts a pre-stringified payload as-is', () => {
    const id = recordEvent({
      session_id: 's-5',
      ts: '2026-05-10T16:00:00Z',
      kind: 'hook_fire',
      payload: 'raw-string-payload',
    });
    const row = getDatabase()
      .prepare('SELECT payload FROM session_events WHERE id = ?')
      .get(id) as { payload: string };
    expect(row.payload).toBe('raw-string-payload');
  });
});

describe('recordEvents (batch)', () => {
  it('inserts multiple events in a single transaction', () => {
    const inputs: SessionEventInput[] = [
      { session_id: 's-batch', ts: '2026-05-10T17:00:00Z', kind: 'prompt', payload: { text: 'q1' } },
      { session_id: 's-batch', ts: '2026-05-10T17:00:01Z', kind: 'response', payload: { text: 'a1' } },
      { session_id: 's-batch', ts: '2026-05-10T17:00:02Z', kind: 'tool_call', payload: { tool: 'Read' } },
    ];
    const ids = recordEvents(inputs);
    expect(ids).toHaveLength(3);
    expect(new Set(ids).size).toBe(3); // all unique

    const count = (
      getDatabase()
        .prepare("SELECT COUNT(*) as c FROM session_events WHERE session_id = 's-batch'")
        .get() as { c: number }
    ).c;
    expect(count).toBe(3);
  });

  it('rolls back the entire batch if any single insert fails', () => {
    const goodFirst: SessionEventInput = {
      session_id: 's-rb',
      ts: '2026-05-10T18:00:00Z',
      kind: 'prompt',
      payload: { text: 'q' },
    };
    // `bogus_kind` violates the CHECK constraint — the batch must rollback,
    // leaving zero rows from the attempted batch in the table.
    const badSecond = {
      session_id: 's-rb',
      ts: '2026-05-10T18:00:01Z',
      kind: 'bogus_kind' as 'prompt',
      payload: { text: 'fail' },
    };
    expect(() => recordEvents([goodFirst, badSecond])).toThrow();

    const count = (
      getDatabase()
        .prepare("SELECT COUNT(*) as c FROM session_events WHERE session_id = 's-rb'")
        .get() as { c: number }
    ).c;
    expect(count).toBe(0);
  });

  it('returns empty array for empty input without a transaction overhead', () => {
    expect(recordEvents([])).toEqual([]);
  });
});

describe('getTimeline', () => {
  it('returns events for a session sorted by ts ascending', () => {
    recordEvents([
      { session_id: 's-tl', ts: '2026-05-10T19:00:02Z', kind: 'response', payload: { text: 'a1' } },
      { session_id: 's-tl', ts: '2026-05-10T19:00:00Z', kind: 'prompt', payload: { text: 'q1' } },
      { session_id: 's-tl', ts: '2026-05-10T19:00:01Z', kind: 'tool_call', payload: { tool: 'Read' } },
    ]);
    const tl = getTimeline('s-tl');
    expect(tl.map((e) => e.kind)).toEqual(['prompt', 'tool_call', 'response']);
  });

  it('returns parsed payload (object), not raw JSON string', () => {
    recordEvent({
      session_id: 's-parse',
      ts: '2026-05-10T20:00:00Z',
      kind: 'prompt',
      payload: { text: 'hello', extra: 7 },
    });
    const [event] = getTimeline('s-parse');
    expect(typeof event.payload).toBe('object');
    expect(event.payload).toEqual({ text: 'hello', extra: 7 });
  });

  it('handles pre-stringified non-JSON payloads without throwing', () => {
    recordEvent({
      session_id: 's-raw',
      ts: '2026-05-10T20:30:00Z',
      kind: 'hook_fire',
      payload: 'not-json',
    });
    const [event] = getTimeline('s-raw');
    // Fall-through: when payload isn't JSON, surface the raw string.
    expect(event.payload).toBe('not-json');
  });

  it('returns empty array for unknown session', () => {
    expect(getTimeline('nope')).toEqual([]);
  });

  it('isolates sessions — does not bleed events across session_id', () => {
    recordEvent({
      session_id: 's-A',
      ts: '2026-05-10T21:00:00Z',
      kind: 'prompt',
      payload: { text: 'A' },
    });
    recordEvent({
      session_id: 's-B',
      ts: '2026-05-10T21:00:00Z',
      kind: 'prompt',
      payload: { text: 'B' },
    });
    const a = getTimeline('s-A');
    const b = getTimeline('s-B');
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
    expect((a[0].payload as { text: string }).text).toBe('A');
    expect((b[0].payload as { text: string }).text).toBe('B');
  });
});
