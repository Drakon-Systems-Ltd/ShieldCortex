/**
 * Runs a single ranker engine over the dataset and returns a scorecard.
 *
 * Each question gets a fresh `:memory:` SQLite DB so questions never
 * leak into each other. The DB is closed after every question to keep
 * memory pressure bounded — for 500-question runs this matters.
 */

import { initDatabase, closeDatabase } from '../../src/database/init.js';
import { searchMemoriesExplained } from '../../src/memory/search-recall.js';
import { DEFAULT_CONFIG, type RankerEngine } from '../../src/memory/types.js';
import { ingestQuestion } from './ingest.js';
import { firstHitRank, summarise } from './score.js';
import type {
  EngineScorecard,
  LongMemEvalQuestion,
  QuestionResult,
} from './types.js';

export interface RunEngineOptions {
  engine: RankerEngine;
  questions: readonly LongMemEvalQuestion[];
  /** Top-k cap fed to the ranker. Defaults to 10 (the larger of R@5 / R@10). */
  topK?: number;
  /** Project name used for ingest scoping. Defaults to a per-engine string. */
  project?: string;
  /** Optional progress callback fired after each question. */
  onProgress?: (done: number, total: number, questionId: string) => void;
}

export async function runEngine(opts: RunEngineOptions): Promise<EngineScorecard> {
  const topK = opts.topK ?? 10;
  const project = opts.project ?? `bench-${opts.engine}`;
  const start = Date.now();
  const perQuestion: QuestionResult[] = [];

  for (let i = 0; i < opts.questions.length; i++) {
    const question = opts.questions[i];

    closeDatabase();
    initDatabase(':memory:');

    try {
      const ingest = ingestQuestion(question, project);

      const results = await searchMemoriesExplained(
        {
          query: question.question,
          project,
          limit: topK,
          // includeDecayed:true so the salience filter can never silently
          // drop a freshly-ingested memory from a long-tail session.
          includeDecayed: true,
        },
        {
          ...DEFAULT_CONFIG,
          ranker: {
            engine: opts.engine,
            rrfK: 60,
            weights: { fts: 0.4, vector: 0.6, graph: 0.3 },
          },
        },
      );

      const retrievedMemoryIds = results.map((r) => r.memory.id);
      const retrievedSessionIds = retrievedMemoryIds
        .map((id) => ingest.memoryToSession.get(id))
        .filter((s): s is string => typeof s === 'string');
      const goldSet = new Set(question.answer_session_ids);

      perQuestion.push({
        question_id: question.question_id,
        retrieved_memory_ids: retrievedMemoryIds,
        retrieved_session_ids: retrievedSessionIds,
        first_hit_rank: firstHitRank(retrievedSessionIds, goldSet),
        gold_session_count: question.answer_session_ids.length,
      });
    } finally {
      closeDatabase();
    }

    opts.onProgress?.(i + 1, opts.questions.length, question.question_id);
  }

  return summarise(perQuestion, opts.engine, Date.now() - start);
}
