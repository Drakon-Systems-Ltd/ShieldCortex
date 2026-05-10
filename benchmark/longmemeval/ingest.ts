/**
 * Ingest a question's haystack into a fresh ShieldCortex DB.
 *
 * One memory per turn. `metadata.session_id` is the bridge that lets
 * the runner map retrieved memories back to their source sessions for
 * recall scoring. Project is held constant per question so memories
 * from different questions don't pollute each other when the harness
 * reuses an in-memory DB across questions.
 */

import type { Memory } from '../../src/memory/types.js';
import { addMemory } from '../../src/memory/store.js';
import type { LongMemEvalQuestion } from './types.js';

export interface IngestResult {
  /** Number of memories actually written to the DB. */
  ingested: number;
  /** Memory id → session_id, for fast lookups during scoring. */
  memoryToSession: Map<number, string>;
}

export function ingestQuestion(
  question: LongMemEvalQuestion,
  project: string,
): IngestResult {
  const memoryToSession = new Map<number, string>();
  let ingested = 0;

  for (const session of question.haystack_sessions) {
    for (const turn of session.turns) {
      const title = buildTitle(turn.role, turn.content);
      const memory: Memory = addMemory({
        title,
        content: turn.content,
        category: 'note',
        project,
        type: 'long_term',
        // Salience kept moderate so memories stay above the default
        // salienceThreshold (0.2) and are eligible for recall.
        salience: 0.5,
        metadata: {
          session_id: session.session_id,
          role: turn.role,
          ts: turn.ts ?? null,
        },
      });
      memoryToSession.set(memory.id, session.session_id);
      ingested++;
    }
  }

  return { ingested, memoryToSession };
}

function buildTitle(role: string, content: string): string {
  const trimmed = content.replace(/\s+/g, ' ').trim();
  const max = 80;
  const snippet = trimmed.length > max ? trimmed.slice(0, max - 1) + '…' : trimmed;
  return `[${role}] ${snippet}`;
}
