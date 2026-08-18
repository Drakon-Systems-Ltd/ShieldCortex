import { describe, expect, it } from '@jest/globals';
import { classifyDataset, renderScorecard } from '../../../benchmark/longmemeval/scorecard.js';
import type { BenchmarkReport } from '../../../benchmark/longmemeval/types.js';

function report(over: Partial<BenchmarkReport> & { path: string; q: number }): BenchmarkReport {
  return {
    dataset_path: over.path,
    k_top: 10,
    generated_at: '2026-08-18T00:00:00.000Z',
    engines: [
      {
        engine: 'rrf',
        question_count: over.q,
        recall_at_5: 0.92,
        recall_at_10: 0.928,
        mrr: 0.86,
        duration_ms: 1000,
        per_question: [],
      },
      {
        engine: 'legacy',
        question_count: over.q,
        recall_at_5: 0.006,
        recall_at_10: 0.006,
        mrr: 0.006,
        duration_ms: 1000,
        per_question: [],
      },
    ],
  };
}

describe('scorecard dataset honesty', () => {
  it('classifies toy / subset / full paths', () => {
    expect(classifyDataset(report({ path: 'benchmark/longmemeval/fixtures/toy-dataset.jsonl', q: 5 }))).toBe(
      'toy',
    );
    expect(
      classifyDataset(
        report({ path: '/home/u/.cache/shieldcortex/benchmark/longmemeval/longmemeval-s-subset50.jsonl', q: 50 }),
      ),
    ).toBe('subset');
    expect(
      classifyDataset(
        report({ path: '/home/u/.cache/shieldcortex/benchmark/longmemeval/longmemeval-s-full.jsonl', q: 500 }),
      ),
    ).toBe('full');
    // question-count fallback when path is odd but count is 500
    expect(classifyDataset(report({ path: '/tmp/custom-lme.jsonl', q: 500 }))).toBe('full');
  });

  it('full-S scorecard never claims toy-only or "not evaluated yet"', () => {
    const md = renderScorecard(
      report({ path: '/home/u/.cache/shieldcortex/benchmark/longmemeval/longmemeval-s-full.jsonl', q: 500 }),
    );
    expect(md).toMatch(/Dataset class: \*\*full\*\*/);
    expect(md).toMatch(/THIS RUN = full LongMemEval-S/);
    expect(md).toMatch(/full LongMemEval-S\):\*\* 92\.00%/);
    expect(md).not.toMatch(/small toy fixture/);
    expect(md).not.toMatch(/has not been evaluated against that corpus yet/);
    expect(md).not.toMatch(/500-question fixture/);
  });

  it('toy scorecard still forbids quoting as LongMemEval-S', () => {
    const md = renderScorecard(report({ path: 'fixtures/toy-dataset.jsonl', q: 5 }));
    expect(md).toMatch(/TOY FIXTURE/);
    expect(md).toMatch(/Not\*\* LongMemEval-S/);
  });
});
