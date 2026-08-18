import { describe, expect, it } from '@jest/globals';
import { convertQuestion } from '../../../benchmark/longmemeval/scripts/convert-upstream.ts';
import { loadDataset } from '../../../benchmark/longmemeval/load.ts';
import { writeFileSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('LongMemEval Track D convert/load', () => {
  const upstream = {
    question_id: 'u1',
    question: 'What DB did we pick?',
    question_type: 'single-session-user',
    answer_session_ids: ['sess-a'],
    haystack_session_ids: ['sess-a', 'sess-b'],
    haystack_dates: ['2024-01-01', '2024-01-02'],
    haystack_sessions: [
      [
        { role: 'user', content: 'Which database?' },
        { role: 'assistant', content: 'PostgreSQL with JSONB.', has_answer: true },
      ],
      [
        { role: 'user', content: 'Frontend?' },
        { role: 'assistant', content: 'React.' },
      ],
    ],
  };

  it('convertQuestion maps official Turn[][] to harness sessions', () => {
    const q = convertQuestion(upstream, 0);
    expect(q.question_id).toBe('u1');
    expect(q.answer_session_ids).toEqual(['sess-a']);
    expect(q.haystack_sessions).toHaveLength(2);
    expect(q.haystack_sessions[0].session_id).toBe('sess-a');
    expect(q.haystack_sessions[0].turns[1].content).toContain('PostgreSQL');
  });

  it('loadDataset accepts official shape without pre-convert', () => {
    const dir = mkdtempSync(join(tmpdir(), 'lme-d-'));
    const path = join(dir, 'one.jsonl');
    writeFileSync(path, JSON.stringify(upstream) + '\n');
    const qs = loadDataset(path);
    expect(qs).toHaveLength(1);
    expect(qs[0].haystack_sessions[0].session_id).toBe('sess-a');
    expect(qs[0].haystack_sessions[1].turns[0].role).toBe('user');
  });

  it('loadDataset still loads toy fixture', () => {
    const qs = loadDataset('benchmark/longmemeval/fixtures/toy-dataset.jsonl');
    expect(qs.length).toBeGreaterThanOrEqual(5);
  });
});
