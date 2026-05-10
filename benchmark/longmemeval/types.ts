/**
 * Internal data model for the LongMemEval-S harness.
 *
 * The official LongMemEval-S file (ICLR 2025, Wu et al.) uses a similar
 * shape under different field names. `load.ts` normalises both the
 * official JSONL and our toy fixture into this canonical form so the
 * runner doesn't have to know which source it's reading.
 *
 * "Gold sessions" are the sessions the question's answer can be derived
 * from. Retrieval is judged by whether memories from those sessions
 * appear in the top-k results — not by the answer text itself, since
 * we're benchmarking *retrieval quality*, not generation quality.
 */

export interface HaystackTurn {
  role: 'user' | 'assistant';
  content: string;
  /**
   * Optional original timestamp. If present, ingest preserves order;
   * otherwise turns are ingested in array order with a synthetic offset.
   */
  ts?: string;
}

export interface HaystackSession {
  session_id: string;
  turns: HaystackTurn[];
}

export interface LongMemEvalQuestion {
  question_id: string;
  question: string;
  /** Session ids whose turns contain the answer — the gold retrieval set. */
  answer_session_ids: string[];
  /** All sessions ingested before retrieval (gold + distractors). */
  haystack_sessions: HaystackSession[];
}

export interface QuestionResult {
  question_id: string;
  /** Top-k retrieved memory ids (in order). */
  retrieved_memory_ids: number[];
  /** Mapped back to source sessions via memory metadata. */
  retrieved_session_ids: string[];
  /**
   * 1-indexed rank of the first retrieved memory whose session_id is in
   * `answer_session_ids`. `null` if no hit appears within the top-k.
   */
  first_hit_rank: number | null;
  /** Number of gold sessions in the haystack (for reference). */
  gold_session_count: number;
}

export interface EngineScorecard {
  engine: 'rrf' | 'legacy';
  question_count: number;
  /** Recall @ 5 — fraction of questions with a gold hit in top-5. */
  recall_at_5: number;
  /** Recall @ 10. */
  recall_at_10: number;
  /** Mean Reciprocal Rank — 1/first_hit_rank averaged over all questions. */
  mrr: number;
  /** Per-question breakdown for diff/debug. */
  per_question: QuestionResult[];
  /** Wall-clock time the engine took for the full sweep. */
  duration_ms: number;
}

export interface BenchmarkReport {
  dataset_path: string;
  k_top: number;
  generated_at: string;
  engines: EngineScorecard[];
}
