/**
 * JSONL transcript importer for Claude Code session files.
 *
 * Claude Code writes session transcripts to `~/.claude/projects/<slug>/
 * <session-uuid>.jsonl`. Each line is a JSON object. Conversation lines
 * have shape `{type, sessionId, timestamp, message: {role, content}}`
 * where `content` is an Anthropic SDK content-block array
 * (`text|thinking|tool_use|tool_result`).
 *
 * Mapping to `session_events.kind`:
 *
 *   user.text         → prompt
 *   assistant.text    → response
 *   assistant.tool_use → tool_call
 *   user.tool_result  → tool_result
 *   thinking          → (skipped — not user-replayable in v1)
 *
 * Non-conversation lines (`ai-title`, `attachment`, `system`,
 * `queue-operation`, etc.) are skipped. Idempotent on re-import: each
 * row carries a sha256 `content_hash` of `kind|payload`, and the
 * `idx_session_events_dedupe` UNIQUE index drops collisions silently
 * via `INSERT OR IGNORE`.
 *
 * Lossy by design — agentmemory documents the same scope:
 *   - Anthropic-internal cache markers, partial-message frames, and
 *     non-string tool_result encodings beyond plain text are not
 *     preserved.
 *   - Things we WILL preserve: prompts, assistant text, tool name +
 *     args + result, and timestamps.
 */

import { openSync, readSync, closeSync, existsSync } from 'fs';
import { StringDecoder } from 'string_decoder';
import { createHash } from 'crypto';
import { getDatabase } from '../database/init.js';
import type { SessionEventInput, SessionEventKind } from './capture.js';

export interface TranscriptLine {
  type?: string;
  sessionId?: string;
  timestamp?: string;
  message?: {
    role?: 'user' | 'assistant';
    content?: ContentBlock[];
  };
}

type ContentBlock =
  | { type: 'text'; text?: string }
  | { type: 'thinking'; thinking?: string }
  | { type: 'tool_use'; id?: string; name?: string; input?: unknown }
  | { type: 'tool_result'; tool_use_id?: string; content?: unknown }
  | { type: string; [key: string]: unknown };

export interface ImportResult {
  sessionId: string | null;
  eventCount: number;
  /** Lines that produced zero events — non-conversation types + parse errors. */
  skipped: number;
  /** Lines whose JSON parsed but were rejected (missing required fields, unknown block types). */
  malformed: number;
}

interface ImportRow extends SessionEventInput {
  content_hash: string;
}

/**
 * Pure mapper: one transcript line → 0..N `SessionEventInput`s.
 *
 * Exported so unit tests can exercise the mapping in isolation without
 * standing up a database. Returns `[]` for any line that doesn't yield
 * replayable events (thinking blocks, ai-title, missing fields, etc.) —
 * the caller treats an empty array as "skipped".
 */
export function parseTranscriptLine(line: unknown): SessionEventInput[] {
  if (!line || typeof line !== 'object') return [];
  const l = line as TranscriptLine;

  // Only conversation lines yield events.
  if (l.type !== 'user' && l.type !== 'assistant') return [];
  if (typeof l.sessionId !== 'string' || l.sessionId.length === 0) return [];
  if (typeof l.timestamp !== 'string' || l.timestamp.length === 0) return [];

  const content = l.message?.content;
  if (!Array.isArray(content) || content.length === 0) return [];

  const events: SessionEventInput[] = [];
  for (const block of content) {
    const event = blockToEvent(block, l);
    if (event) events.push(event);
  }
  return events;
}

function blockToEvent(
  block: ContentBlock,
  line: TranscriptLine,
): SessionEventInput | null {
  const session_id = line.sessionId as string;
  const ts = line.timestamp as string;

  if (block.type === 'thinking') return null;

  if (block.type === 'text' && line.type === 'user') {
    const text = typeof block.text === 'string' ? block.text : '';
    if (!text) return null;
    return { session_id, ts, kind: 'prompt', payload: { text } };
  }

  if (block.type === 'text' && line.type === 'assistant') {
    const text = typeof block.text === 'string' ? block.text : '';
    if (!text) return null;
    return {
      session_id,
      ts,
      kind: 'response',
      payload: { text },
      actor: 'assistant',
    };
  }

  if (block.type === 'tool_use' && line.type === 'assistant') {
    const toolBlock = block as { id?: string; name?: string; input?: unknown };
    return {
      session_id,
      ts,
      kind: 'tool_call',
      payload: {
        tool_use_id: toolBlock.id ?? null,
        name: toolBlock.name ?? null,
        input: toolBlock.input ?? null,
      },
      actor: 'assistant',
    };
  }

  if (block.type === 'tool_result' && line.type === 'user') {
    const tr = block as { tool_use_id?: string; content?: unknown };
    return {
      session_id,
      ts,
      kind: 'tool_result',
      payload: {
        tool_use_id: tr.tool_use_id ?? null,
        content: tr.content ?? null,
      },
    };
  }

  return null;
}

/** SHA-256 of `kind|payload-as-canonical-json`. 64-char hex string. */
function hashEvent(kind: SessionEventKind, payload: unknown): string {
  const canonical = typeof payload === 'string' ? payload : JSON.stringify(payload ?? null);
  return createHash('sha256').update(`${kind}|${canonical}`).digest('hex');
}

const INSERT_OR_IGNORE_SQL = `
  INSERT OR IGNORE INTO session_events
    (session_id, project, ts, kind, actor, payload, duration_ms, audit_id, content_hash)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

/** 64 KB read chunks — small enough to bound peak memory on huge transcripts, big enough to keep syscall overhead negligible. */
const READ_CHUNK_BYTES = 64 * 1024;

/**
 * Flush rows to disk in transaction batches of this size. The full file is
 * NOT held in memory; instead we keep at most one chunk-worth of parsed
 * rows pending. Mid-file failure leaves earlier chunks committed, which is
 * fine because `INSERT OR IGNORE` makes a re-run idempotent.
 */
const FLUSH_BATCH_ROWS = 2000;

/**
 * Import one JSONL file. Streams the file in 64 KB chunks via `readSync`
 * and a `StringDecoder` (which handles UTF-8 sequences that span chunk
 * boundaries) so a 500 MB transcript archive doesn't load into a single
 * string. Parsed rows flush to SQLite in {@link FLUSH_BATCH_ROWS}-sized
 * transactional batches.
 *
 * Malformed lines do NOT throw — they're counted and skipped so a single
 * bad row never blocks the rest of the file. Idempotent on re-import via
 * the `INSERT OR IGNORE` + `idx_session_events_dedupe` UNIQUE index.
 */
export function importJsonlTranscript(path: string): ImportResult {
  if (!existsSync(path)) {
    throw new Error(`JSONL transcript not found: ${path}`);
  }

  const db = getDatabase();
  const stmt = db.prepare(INSERT_OR_IGNORE_SQL);
  const countStmt = db.prepare('SELECT COUNT(*) AS c FROM session_events');

  const flush = db.transaction((batch: readonly ImportRow[]) => {
    for (const row of batch) {
      stmt.run(
        row.session_id,
        row.project ?? null,
        row.ts,
        row.kind,
        row.actor ?? null,
        typeof row.payload === 'string' ? row.payload : JSON.stringify(row.payload ?? null),
        row.duration_ms ?? null,
        row.audit_id ?? null,
        row.content_hash,
      );
    }
  });

  let sessionId: string | null = null;
  let eventCount = 0;
  let skipped = 0;
  let malformed = 0;
  let inserted = 0;

  const pending: ImportRow[] = [];

  const drain = (): void => {
    if (pending.length === 0) return;
    const before = (countStmt.get() as { c: number }).c;
    flush(pending);
    const after = (countStmt.get() as { c: number }).c;
    inserted += after - before;
    pending.length = 0;
  };

  const processLine = (line: string): void => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return; // blank — not counted as skipped
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      malformed++;
      skipped++;
      return;
    }
    const events = parseTranscriptLine(parsed);
    if (events.length === 0) {
      skipped++;
      return;
    }
    if (sessionId === null && events[0]?.session_id) {
      sessionId = events[0].session_id;
    }
    for (const event of events) {
      pending.push({ ...event, content_hash: hashEvent(event.kind, event.payload) });
      eventCount++;
    }
  };

  const fd = openSync(path, 'r');
  try {
    const buf = Buffer.alloc(READ_CHUNK_BYTES);
    const decoder = new StringDecoder('utf8');
    let leftover = '';
    let position = 0;

    while (true) {
      const bytesRead = readSync(fd, buf, 0, READ_CHUNK_BYTES, position);
      if (bytesRead === 0) break;
      position += bytesRead;

      // StringDecoder buffers partial UTF-8 sequences across chunk boundaries.
      const text = leftover + decoder.write(buf.subarray(0, bytesRead));
      const lastNewline = text.lastIndexOf('\n');
      if (lastNewline === -1) {
        leftover = text;
        continue;
      }
      const complete = text.slice(0, lastNewline);
      leftover = text.slice(lastNewline + 1);
      for (const rawLine of complete.split('\n')) {
        processLine(rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine);
      }
      if (pending.length >= FLUSH_BATCH_ROWS) drain();
    }
    // Anything decoder still has buffered (impossible for valid UTF-8, but
    // handle the malformed-bytes-at-EOF case gracefully).
    const tail = leftover + decoder.end();
    if (tail.length > 0) {
      for (const rawLine of tail.split('\n')) {
        processLine(rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine);
      }
    }
  } finally {
    closeSync(fd);
  }

  drain();

  // `eventCount` reflects the total events parsed from this file regardless
  // of whether the dedupe index dropped them. Duplicates surface in `skipped`
  // so callers see one consistent "anything not inserted" tally.
  return {
    sessionId,
    eventCount,
    skipped: skipped + (eventCount - inserted),
    malformed,
  };
}
