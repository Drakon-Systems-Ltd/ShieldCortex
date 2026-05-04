import { existsSync, openSync, readSync, closeSync, statSync } from 'fs';
import { homedir } from 'os';

const DEFAULT_MAX_BYTES = 1024 * 1024;
const DEFAULT_MAX_LINES = 5000;
const SLASH_DROP_LEN = 200;

function isSingleLineSlashCommand(text) {
  if (!text || text[0] !== '/') return false;
  if (text.length >= SLASH_DROP_LEN) return false;
  if (text.includes('\n')) return false;
  return true;
}

function extractText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .filter((c) => c && c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text)
      .join('\n');
  }
  return '';
}

/**
 * Read the tail of a Claude Code transcript JSONL and return the
 * concatenated user+assistant text plus telemetry metadata.
 *
 * Replaces three duplicated readers in pre-compact-hook and session-end-hook
 * that all hard-coded `slice(-50)` and a blanket `startsWith('/')` filter.
 *
 * @param {string|null|undefined} transcriptPath  Path (may start with `~`).
 * @param {object} [opts]
 * @param {number} [opts.maxBytes=1MiB]   Tail-byte ceiling — bounds memory on huge transcripts.
 * @param {number} [opts.maxLines=5000]   Hard line cap after JSONL parse.
 * @param {boolean} [opts.keepSlashCommandProse=true]
 *        true  → drop only single-line slash invocations under 200 chars
 *        false → drop any message starting with `/` (legacy strict)
 * @returns {{ text: string, messageCount: number, bytesRead: number, rawLineCount: number }}
 */
export function readTranscriptText(transcriptPath, opts = {}) {
  const empty = { text: '', messageCount: 0, bytesRead: 0, rawLineCount: 0 };
  if (!transcriptPath || typeof transcriptPath !== 'string') return empty;

  const resolvedPath = transcriptPath.replace(/^~/, homedir());
  if (!existsSync(resolvedPath)) return empty;

  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxLines = opts.maxLines ?? DEFAULT_MAX_LINES;
  const keepSlashProse = opts.keepSlashCommandProse !== false;

  let raw;
  let bytesRead = 0;
  let truncated = false;
  try {
    const stat = statSync(resolvedPath);
    const fileSize = stat.size;
    bytesRead = Math.min(fileSize, Math.max(0, maxBytes));
    truncated = bytesRead < fileSize;

    if (bytesRead === 0) return empty;

    const fd = openSync(resolvedPath, 'r');
    try {
      const buf = Buffer.alloc(bytesRead);
      readSync(fd, buf, 0, bytesRead, fileSize - bytesRead);
      raw = buf.toString('utf-8');
    } finally {
      closeSync(fd);
    }
  } catch {
    return empty;
  }

  let lines = raw.split('\n');
  // If we sliced from the middle of the file, the first line is likely a
  // partial JSON fragment — drop it rather than emit a parse error.
  if (truncated && lines.length > 0) {
    lines = lines.slice(1);
  }
  // Trim a trailing empty line from a clean newline-terminated file.
  if (lines.length > 0 && lines[lines.length - 1] === '') {
    lines = lines.slice(0, -1);
  }

  // Hard cap: keep the most recent N lines.
  if (lines.length > maxLines) {
    lines = lines.slice(lines.length - maxLines);
  }
  const rawLineCount = lines.length;

  const messages = [];
  for (const line of lines) {
    if (!line) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      continue;
    }
    const role = entry.type || entry.message?.role;
    if (role !== 'user' && role !== 'assistant') continue;

    const text = extractText(entry.message?.content);
    if (!text) continue;

    if (keepSlashProse) {
      if (isSingleLineSlashCommand(text)) continue;
    } else if (text[0] === '/') {
      continue;
    }

    messages.push(text);
  }

  return {
    text: messages.join('\n\n'),
    messageCount: messages.length,
    bytesRead,
    rawLineCount,
  };
}
