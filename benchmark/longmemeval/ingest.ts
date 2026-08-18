/**
 * Ingest a question's haystack into a fresh ShieldCortex DB.
 *
 * One memory per turn. `metadata.session_id` is the bridge that lets
 * the runner map retrieved memories back to their source sessions for
 * recall scoring.
 *
 * Defence stays ON (product-honest). Turns blocked by the firewall are
 * skipped and counted — they never enter the ranker's corpus, same as prod.
 */

import type { Memory } from '../../src/memory/types.js';
import { addMemory, MemoryBlockedError } from '../../src/memory/store.js';
import type { LongMemEvalQuestion } from './types.js';

export interface IngestResult {
  /** Number of memories actually written to the DB. */
  ingested: number;
  /** Turns skipped because defence blocked them. */
  blocked: number;
  /** Memory id → session_id, for fast lookups during scoring. */
  memoryToSession: Map<number, string>;
}

export function ingestQuestion(
  question: LongMemEvalQuestion,
  project: string,
): IngestResult {
  const memoryToSession = new Map<number, string>();
  let ingested = 0;
  let blocked = 0;

  for (const session of question.haystack_sessions) {
    for (const turn of session.turns) {
      const title = buildTitle(turn.role, turn.content);
      try {
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
            sourceType: 'benchmark',
            capture_layer: 'L0',
          },
        });
        memoryToSession.set(memory.id, session.session_id);
        ingested++;
      } catch (err) {
        if (err instanceof MemoryBlockedError) {
          blocked++;
          continue;
        }
        throw err;
      }
    }
  }

  return { ingested, blocked, memoryToSession };
}

function buildTitle(role: string, content: string): string {
  const trimmed = content.replace(/\s+/g, ' ').trim();
  const max = 80;
  const snippet = trimmed.length > max ? trimmed.slice(0, max - 1) + '…' : trimmed;
  return `[${role}] ${snippet}`;
}
