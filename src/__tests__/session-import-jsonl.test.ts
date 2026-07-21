/**
 * JSONL transcript importer tests.
 *
 * Tests the pure `parseTranscriptLine` mapper in isolation, then the
 * file-level `importJsonlTranscript` end-to-end against the fixture
 * at `src/__fixtures__/jsonl/sample-claude-session.jsonl`. Idempotent
 * re-import is verified by running the importer twice on the same
 * file and asserting row counts are stable.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  initDatabase,
  closeDatabase,
  getDatabase,
} from '../database/init.js';
import {
  parseTranscriptLine,
  importJsonlTranscript,
} from '../sessions/import-jsonl.js';
import { getTimeline } from '../sessions/timeline.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE = resolve(__dirname, '..', '__fixtures__', 'jsonl', 'sample-claude-session.jsonl');

beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('parseTranscriptLine — pure mapper', () => {
  it('maps user text block to a single prompt event', () => {
    const events = parseTranscriptLine({
      type: 'user',
      sessionId: 's1',
      timestamp: '2026-05-10T10:00:00Z',
      message: { role: 'user', content: [{ type: 'text', text: 'hi' }] },
    });
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe('prompt');
    expect(events[0].session_id).toBe('s1');
    // #110 review: timestamps are normalised to canonical ISO-8601 UTC with
    // milliseconds ('…T10:00:00.000Z'), no longer passed through verbatim.
    expect(events[0].ts).toBe('2026-05-10T10:00:00.000Z');
    expect(events[0].payload).toEqual({ text: 'hi' });
  });

  it('maps assistant text block to a response event', () => {
    const events = parseTranscriptLine({
      type: 'assistant',
      sessionId: 's1',
      timestamp: '2026-05-10T10:00:01Z',
      message: { role: 'assistant', content: [{ type: 'text', text: 'sure' }] },
    });
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe('response');
    expect(events[0].actor).toBe('assistant');
  });

  it('maps assistant tool_use block to a tool_call event with id + name + input preserved', () => {
    const events = parseTranscriptLine({
      type: 'assistant',
      sessionId: 's1',
      timestamp: '2026-05-10T10:00:02Z',
      message: {
        role: 'assistant',
        content: [{ type: 'tool_use', id: 'toolu_xyz', name: 'Bash', input: { command: 'ls' } }],
      },
    });
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe('tool_call');
    expect(events[0].payload).toEqual({
      tool_use_id: 'toolu_xyz',
      name: 'Bash',
      input: { command: 'ls' },
    });
  });

  it('maps user tool_result block to a tool_result event correlated by tool_use_id', () => {
    const events = parseTranscriptLine({
      type: 'user',
      sessionId: 's1',
      timestamp: '2026-05-10T10:00:03Z',
      message: {
        role: 'user',
        content: [{ type: 'tool_result', tool_use_id: 'toolu_xyz', content: 'output text' }],
      },
    });
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe('tool_result');
    expect(events[0].payload).toEqual({ tool_use_id: 'toolu_xyz', content: 'output text' });
  });

  it('skips thinking blocks (not replayable in v1)', () => {
    const events = parseTranscriptLine({
      type: 'assistant',
      sessionId: 's1',
      timestamp: '2026-05-10T10:00:04Z',
      message: { role: 'assistant', content: [{ type: 'thinking', thinking: 'reasoning…' }] },
    });
    expect(events).toEqual([]);
  });

  it('emits one event per block in a multi-block message', () => {
    const events = parseTranscriptLine({
      type: 'assistant',
      sessionId: 's1',
      timestamp: '2026-05-10T10:00:05Z',
      message: {
        role: 'assistant',
        content: [
          { type: 'text', text: 'one moment' },
          { type: 'tool_use', id: 'tu1', name: 'Read', input: { path: '/etc/hostname' } },
        ],
      },
    });
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.kind)).toEqual(['response', 'tool_call']);
  });

  it('returns empty for non-conversation line types (ai-title, attachment, system, queue-operation)', () => {
    expect(parseTranscriptLine({ type: 'ai-title', sessionId: 's1', aiTitle: 't' })).toEqual([]);
    expect(parseTranscriptLine({ type: 'attachment', sessionId: 's1', timestamp: 't' })).toEqual([]);
    expect(parseTranscriptLine({ type: 'system', sessionId: 's1' })).toEqual([]);
    expect(parseTranscriptLine({ type: 'queue-operation', sessionId: 's1' })).toEqual([]);
  });

  it('returns empty when message.content is missing or empty', () => {
    expect(
      parseTranscriptLine({
        type: 'user',
        sessionId: 's1',
        timestamp: '2026-05-10T10:00:00Z',
        message: { role: 'user', content: [] },
      }),
    ).toEqual([]);
    expect(
      parseTranscriptLine({
        type: 'user',
        sessionId: 's1',
        timestamp: '2026-05-10T10:00:00Z',
        message: { role: 'user' },
      }),
    ).toEqual([]);
  });

  it('returns empty for missing required fields (sessionId / timestamp)', () => {
    expect(
      parseTranscriptLine({
        type: 'user',
        timestamp: '2026-05-10T10:00:00Z',
        message: { role: 'user', content: [{ type: 'text', text: 'hi' }] },
      }),
    ).toEqual([]);
    expect(
      parseTranscriptLine({
        type: 'user',
        sessionId: 's1',
        message: { role: 'user', content: [{ type: 'text', text: 'hi' }] },
      }),
    ).toEqual([]);
  });
});

describe('importJsonlTranscript — end-to-end against fixture', () => {
  it('imports the sample fixture and returns expected counts', () => {
    const result = importJsonlTranscript(FIXTURE);
    expect(result.sessionId).toBe('sess-001');
    // 8 fixture lines: 1 user-text, 1 thinking (skipped), 1 assistant-text,
    // 1 tool_use, 1 tool_result, 1 ai-title (skipped), 1 attachment (skipped),
    // 1 user-text → 5 events ingested, 3 lines skipped.
    expect(result.eventCount).toBe(5);
    expect(result.skipped).toBe(3);
  });

  it('writes events with the expected kinds in timestamp order', () => {
    importJsonlTranscript(FIXTURE);
    const tl = getTimeline('sess-001');
    expect(tl.map((e) => e.kind)).toEqual([
      'prompt',
      'response',
      'tool_call',
      'tool_result',
      'prompt',
    ]);
  });

  it('re-imports the same file idempotently (no duplicate rows)', () => {
    importJsonlTranscript(FIXTURE);
    const firstCount = (
      getDatabase().prepare("SELECT COUNT(*) as c FROM session_events").get() as { c: number }
    ).c;

    importJsonlTranscript(FIXTURE);
    const secondCount = (
      getDatabase().prepare("SELECT COUNT(*) as c FROM session_events").get() as { c: number }
    ).c;

    expect(secondCount).toBe(firstCount);
  });

  it('sets content_hash on all imported rows (live capture leaves it null)', () => {
    importJsonlTranscript(FIXTURE);
    const rows = getDatabase()
      .prepare('SELECT content_hash FROM session_events')
      .all() as Array<{ content_hash: string | null }>;
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.every((r) => typeof r.content_hash === 'string' && r.content_hash.length === 64)).toBe(true);
  });

  it('throws on missing file with a clear error', () => {
    expect(() => importJsonlTranscript('/nope/missing.jsonl')).toThrow(/not found|ENOENT/i);
  });

  it('skips blank lines and malformed JSON without aborting the import', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'sc-import-'));
    const path = join(tmp, 'mixed.jsonl');
    writeFileSync(
      path,
      [
        '{"type":"user","sessionId":"s2","timestamp":"2026-05-10T11:00:00Z","message":{"role":"user","content":[{"type":"text","text":"good line"}]}}',
        '',
        'not-json',
        '{"type":"user","sessionId":"s2","timestamp":"2026-05-10T11:00:01Z","message":{"role":"user","content":[{"type":"text","text":"after malformed"}]}}',
      ].join('\n'),
    );
    try {
      const result = importJsonlTranscript(path);
      expect(result.eventCount).toBe(2);
      // 1 malformed JSON line counts as skipped; blank lines do not.
      expect(result.skipped).toBe(1);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('timestamp normalisation (#110 review) — importer ENFORCES ISO-Z', () => {
  // The retention purge compares `ts` LEXICALLY; verbatim passthrough let an
  // epoch-millis string sort before every '2026-…' row (→ purged as
  // "infinitely old" immediately) and offset-bearing ISO misorder at
  // boundaries. Every accepted timestamp must round-trip through
  // Date.parse → toISOString().

  it('normalises an epoch-millis timestamp to the correct ISO instant — NOT purged as ancient', async () => {
    // A recent instant (1 day ago) expressed as epoch millis.
    const recentMs = Date.now() - 24 * 60 * 60 * 1000;
    const events = parseTranscriptLine({
      type: 'user',
      sessionId: 's-epoch',
      timestamp: String(recentMs),
      message: { role: 'user', content: [{ type: 'text', text: 'epoch line' }] },
    });
    expect(events).toHaveLength(1);
    expect(events[0].ts).toBe(new Date(recentMs).toISOString());

    // End-to-end: insert it and prove the 30-day purge does NOT delete it.
    const { recordEvent } = await import('../sessions/capture.js');
    const { purgeOldSessionEvents } = await import('../sessions/retention.js');
    recordEvent(events[0]);
    const deleted = purgeOldSessionEvents(30);
    expect(deleted).toBe(0);
    const count = (
      getDatabase().prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }
    ).c;
    expect(count).toBe(1);
  });

  it('normalises offset-bearing ISO to the equivalent Z instant', () => {
    const events = parseTranscriptLine({
      type: 'user',
      sessionId: 's-offset',
      timestamp: '2026-07-21T01:00:00+09:00',
      message: { role: 'user', content: [{ type: 'text', text: 'offset line' }] },
    });
    expect(events).toHaveLength(1);
    expect(events[0].ts).toBe('2026-07-20T16:00:00.000Z');
  });

  it('rejects a garbage timestamp: counted malformed, nothing inserted', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'sc-import-badts-'));
    const path = join(tmp, 'bad-ts.jsonl');
    writeFileSync(
      path,
      [
        '{"type":"user","sessionId":"s3","timestamp":"soon-ish","message":{"role":"user","content":[{"type":"text","text":"bad ts"}]}}',
        '{"type":"user","sessionId":"s3","timestamp":"2026-05-10T12:00:00Z","message":{"role":"user","content":[{"type":"text","text":"good ts"}]}}',
      ].join('\n'),
    );
    try {
      const result = importJsonlTranscript(path);
      expect(result.eventCount).toBe(1); // only the good line
      expect(result.malformed).toBe(1); // the garbage-timestamp line
      const rows = getDatabase()
        .prepare('SELECT ts, payload FROM session_events')
        .all() as Array<{ ts: string; payload: string }>;
      expect(rows).toHaveLength(1);
      expect(rows[0].ts).toBe('2026-05-10T12:00:00.000Z'); // normalised on insert
      expect(rows[0].payload).toContain('good ts');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
