/**
 * Tests for the LongMemEval dataset loader. Covers JSONL + JSON-array
 * forms, the most common malformed-input cases, and the toy fixture
 * round-trip so CI catches accidental edits to the canonical fixture.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import {
  loadDataset,
  DatasetLoadError,
} from '../../benchmark/longmemeval/load.js';

let tempDir: string;

beforeEach(() => {
  tempDir = mkdtempSync(join(tmpdir(), 'sc-bench-load-'));
});

afterEach(() => {
  rmSync(tempDir, { recursive: true, force: true });
});

function writeFixture(name: string, content: string): string {
  const path = join(tempDir, name);
  writeFileSync(path, content);
  return path;
}

const validQuestion = {
  question_id: 'q1',
  question: 'What database did we pick?',
  answer_session_ids: ['s-arch'],
  haystack_sessions: [
    {
      session_id: 's-arch',
      turns: [
        { role: 'user', content: 'PostgreSQL discussion' },
        { role: 'assistant', content: 'Recommend PostgreSQL.' },
      ],
    },
  ],
};

describe('loadDataset', () => {
  it('reads JSONL with one question per line', () => {
    const path = writeFixture(
      'data.jsonl',
      [JSON.stringify(validQuestion), JSON.stringify({ ...validQuestion, question_id: 'q2' })].join('\n'),
    );
    const result = loadDataset(path);
    expect(result).toHaveLength(2);
    expect(result[0].question_id).toBe('q1');
    expect(result[1].question_id).toBe('q2');
  });

  it('reads JSON array form', () => {
    const path = writeFixture(
      'data.json',
      JSON.stringify([validQuestion, { ...validQuestion, question_id: 'q2' }]),
    );
    const result = loadDataset(path);
    expect(result).toHaveLength(2);
  });

  it('skips blank lines in JSONL', () => {
    const path = writeFixture(
      'data.jsonl',
      [JSON.stringify(validQuestion), '', '   ', JSON.stringify({ ...validQuestion, question_id: 'q2' })].join('\n'),
    );
    expect(loadDataset(path)).toHaveLength(2);
  });

  it('throws DatasetLoadError when file is missing', () => {
    expect(() => loadDataset(join(tempDir, 'nope.jsonl'))).toThrow(DatasetLoadError);
  });

  it('throws on malformed JSONL line', () => {
    const path = writeFixture('bad.jsonl', '{not json}');
    expect(() => loadDataset(path)).toThrow(/Failed to parse JSONL line 1/);
  });

  it('throws when answer_session_ids is missing', () => {
    const { answer_session_ids: _ignored, ...incomplete } = validQuestion;
    void _ignored;
    const path = writeFixture('bad.jsonl', JSON.stringify(incomplete));
    expect(() => loadDataset(path)).toThrow(/missing or malformed answer_session_ids/);
  });

  it('throws when a turn has invalid role', () => {
    const broken = {
      ...validQuestion,
      haystack_sessions: [
        {
          session_id: 's',
          turns: [{ role: 'system', content: 'nope' }],
        },
      ],
    };
    const path = writeFixture('bad.jsonl', JSON.stringify(broken));
    expect(() => loadDataset(path)).toThrow(/invalid role: system/);
  });

  it('preserves optional ts on turns when present', () => {
    const withTs = {
      ...validQuestion,
      haystack_sessions: [
        {
          session_id: 's',
          turns: [{ role: 'user', content: 'hi', ts: '2026-01-01T00:00:00Z' }],
        },
      ],
    };
    const path = writeFixture('data.jsonl', JSON.stringify(withTs));
    const result = loadDataset(path);
    expect(result[0].haystack_sessions[0].turns[0].ts).toBe('2026-01-01T00:00:00Z');
  });

  it('round-trips the canonical toy fixture without errors', () => {
    // Locks the toy fixture's shape — accidental edits surface here
    // before they break the smoke test.
    const __dirname = dirname(fileURLToPath(import.meta.url));
    const fixturePath = resolve(
      __dirname,
      '..',
      '..',
      'benchmark',
      'longmemeval',
      'fixtures',
      'toy-dataset.jsonl',
    );
    const result = loadDataset(fixturePath);
    expect(result.length).toBeGreaterThanOrEqual(3);
    for (const q of result) {
      expect(typeof q.question_id).toBe('string');
      expect(typeof q.question).toBe('string');
      expect(Array.isArray(q.answer_session_ids)).toBe(true);
      expect(Array.isArray(q.haystack_sessions)).toBe(true);
      expect(q.haystack_sessions.length).toBeGreaterThan(0);
    }
  });
});
