/**
 * Dataset loader for LongMemEval-S.
 *
 * Accepts two on-disk forms:
 *
 *   - **JSONL** — one question object per line. Used by both the
 *     official LongMemEval-S release and our toy fixture.
 *   - **JSON array** — a single JSON file containing an array of
 *     questions. Convenient for hand-edited fixtures.
 *
 * Field-name normalisation: the canonical internal shape is in
 * `types.ts`. The official dataset uses the same field names this
 * loader expects (`question_id`, `question`, `answer_session_ids`,
 * `haystack_sessions` with `session_id` + `turns` containing `role` +
 * `content`). Older snapshots that nested differently aren't supported
 * — convert them before pointing this harness at them.
 */

import { readFileSync, existsSync } from 'fs';
import type {
  HaystackSession,
  HaystackTurn,
  LongMemEvalQuestion,
} from './types.js';

export class DatasetLoadError extends Error {
  constructor(message: string, public readonly path?: string) {
    super(path ? `${message} (path: ${path})` : message);
    this.name = 'DatasetLoadError';
  }
}

export function loadDataset(path: string): LongMemEvalQuestion[] {
  if (!existsSync(path)) {
    throw new DatasetLoadError('Dataset file not found', path);
  }
  const raw = readFileSync(path, 'utf-8');

  // Try JSON array first — if it parses to an array of objects, use it.
  // Fall through to JSONL on parse failure or wrong shape.
  const trimmed = raw.trim();
  let candidates: unknown[] | null = null;
  if (trimmed.startsWith('[')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) candidates = parsed;
    } catch {
      // not JSON array; treat as JSONL
    }
  }

  if (!candidates) {
    candidates = trimmed
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line, idx) => {
        try {
          return JSON.parse(line);
        } catch (err) {
          throw new DatasetLoadError(
            `Failed to parse JSONL line ${idx + 1}: ${(err as Error).message}`,
            path,
          );
        }
      });
  }

  return candidates.map((c, idx) => normaliseQuestion(c, idx, path));
}

function normaliseQuestion(
  raw: unknown,
  index: number,
  path: string,
): LongMemEvalQuestion {
  if (!raw || typeof raw !== 'object') {
    throw new DatasetLoadError(`Question at index ${index} is not an object`, path);
  }
  const obj = raw as Record<string, unknown>;

  const question_id = stringField(obj, 'question_id', index, path);
  const question = stringField(obj, 'question', index, path);

  const answerIdsRaw = obj.answer_session_ids;
  if (!Array.isArray(answerIdsRaw) || !answerIdsRaw.every((v) => typeof v === 'string')) {
    throw new DatasetLoadError(
      `Question "${question_id}" missing or malformed answer_session_ids`,
      path,
    );
  }
  const answer_session_ids = answerIdsRaw.slice() as string[];

  const haystackRaw = obj.haystack_sessions;
  if (!Array.isArray(haystackRaw)) {
    throw new DatasetLoadError(
      `Question "${question_id}" missing haystack_sessions`,
      path,
    );
  }
  const haystack_sessions: HaystackSession[] = haystackRaw.map((s, sIdx) =>
    normaliseSession(s, question_id, sIdx, path),
  );

  return { question_id, question, answer_session_ids, haystack_sessions };
}

function normaliseSession(
  raw: unknown,
  questionId: string,
  sessionIdx: number,
  path: string,
): HaystackSession {
  if (!raw || typeof raw !== 'object') {
    throw new DatasetLoadError(
      `Question "${questionId}" session ${sessionIdx} is not an object`,
      path,
    );
  }
  const obj = raw as Record<string, unknown>;
  const session_id = stringField(obj, 'session_id', sessionIdx, path);
  const turnsRaw = obj.turns;
  if (!Array.isArray(turnsRaw)) {
    throw new DatasetLoadError(
      `Session "${session_id}" missing turns array`,
      path,
    );
  }
  const turns: HaystackTurn[] = turnsRaw.map((t, tIdx) =>
    normaliseTurn(t, session_id, tIdx, path),
  );
  return { session_id, turns };
}

function normaliseTurn(
  raw: unknown,
  sessionId: string,
  turnIdx: number,
  path: string,
): HaystackTurn {
  if (!raw || typeof raw !== 'object') {
    throw new DatasetLoadError(
      `Session "${sessionId}" turn ${turnIdx} is not an object`,
      path,
    );
  }
  const obj = raw as Record<string, unknown>;
  const role = obj.role;
  if (role !== 'user' && role !== 'assistant') {
    throw new DatasetLoadError(
      `Session "${sessionId}" turn ${turnIdx} has invalid role: ${String(role)}`,
      path,
    );
  }
  const content = stringField(obj, 'content', turnIdx, path);
  const ts = typeof obj.ts === 'string' ? obj.ts : undefined;
  return ts ? { role, content, ts } : { role, content };
}

function stringField(
  obj: Record<string, unknown>,
  field: string,
  index: number,
  path: string,
): string {
  const value = obj[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new DatasetLoadError(
      `Field "${field}" missing or empty at index ${index}`,
      path,
    );
  }
  return value;
}
