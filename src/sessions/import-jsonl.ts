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

import { readFileSync, existsSync } from 'fs';
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

/**
 * Import one JSONL file. Wraps the whole import in a single transaction
 * so a mid-file error rolls back cleanly — better-sqlite3's transaction
 * helper restores DB state if the callback throws. Malformed lines do
 * NOT throw — they're counted and skipped so a single bad row never
 * blocks the rest of the file.
 */
export function importJsonlTranscript(path: string): ImportResult {
  if (!existsSync(path)) {
    throw new Error(`JSONL transcript not found: ${path}`);
  }

  const raw = readFileSync(path, 'utf-8');
  const lines = raw.split(/\r?\n/);

  const rows: ImportRow[] = [];
  let sessionId: string | null = null;
  let skipped = 0;
  let malformed = 0;

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (trimmed.length === 0) continue; // blank lines aren't skipped — they're just whitespace

    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      malformed++;
      skipped++;
      continue;
    }

    const events = parseTranscriptLine(parsed);
    if (events.length === 0) {
      skipped++;
      continue;
    }

    if (sessionId === null && events[0]?.session_id) {
      sessionId = events[0].session_id;
    }

    for (const event of events) {
      rows.push({
        ...event,
        content_hash: hashEvent(event.kind, event.payload),
      });
    }
  }

  if (rows.length === 0) {
    return { sessionId, eventCount: 0, skipped, malformed };
  }

  const db = getDatabase();
  const stmt = db.prepare(INSERT_OR_IGNORE_SQL);
  const before = (
    db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }
  ).c;

  const tx = db.transaction((batch: readonly ImportRow[]) => {
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
  tx(rows);

  const after = (
    db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }
  ).c;
  const inserted = after - before;

  // `eventCount` reflects the total events parsed from this file regardless
  // of whether the dedupe index dropped them. Caller can compare to
  // `inserted` (via row count diff) to see how many were duplicates.
  return {
    sessionId,
    eventCount: rows.length,
    skipped: skipped + (rows.length - inserted),
    malformed,
  };
}
