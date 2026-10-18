/**
 * Realtime audit plane — shared cursor grammar and typed plain-file reader
 * (#579 Slice 1A).
 *
 * The realtime ledger's '<file>:<line>' cursor used to be parsed
 * permissively: `Number()` on the text after the last ':' and no check on
 * the file part. A hand-edited or corrupted cursor could then either stall
 * silently (a file part that sorts after every realtime file) or silently
 * replay from the first file (which re-increments edge counts). The strict
 * classifier below admits only the two canonical shapes the ledger and
 * clearGraph ever write; anything else is `malformed`, and the ledger reports
 * and halts on it instead of guessing.
 *
 * `readPlainRealtimeFile` never throws: a stat or read failure is a typed
 * `unavailable` outcome so the ledger can hold at that file instead of
 * skipping past it. Oversize stays its own outcome — the existing floor
 * policy is unchanged and distinct from the hold.
 */

import fs from 'fs';
import path from 'path';

/** Plain (uncompressed) realtime day file. No gz grammar. */
export const REALTIME_PLAIN_RE = /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/;

/** Cursor line marking a whole file as consumed without reading it. */
export const FILE_CONSUMED_LINE = 9_999_999_999;

const CURSOR_LINE_RE = /^(0|[1-9]\d{0,9})$/;

export type RealtimeCursor =
  | { kind: 'empty' }
  | { kind: 'valid'; file: string; line: number }
  | { kind: 'malformed' };

/**
 * Classify a stored cursor. `''` is the canonical initial state; otherwise
 * the text before the LAST ':' must be a plain realtime file name and the
 * text after it a canonical non-negative integer no larger than the
 * consumed-file sentinel.
 */
export function parseRealtimeCursor(raw: string): RealtimeCursor {
  // The column is TEXT NOT NULL, but an external writer could store a BLOB.
  if (typeof raw !== 'string') return { kind: 'malformed' };
  if (raw === '') return { kind: 'empty' };
  const idx = raw.lastIndexOf(':');
  if (idx < 0) return { kind: 'malformed' };
  const file = raw.slice(0, idx);
  const lineText = raw.slice(idx + 1);
  if (!REALTIME_PLAIN_RE.test(file) || !CURSOR_LINE_RE.test(lineText)) return { kind: 'malformed' };
  const line = Number(lineText);
  if (line > FILE_CONSUMED_LINE) return { kind: 'malformed' };
  return { kind: 'valid', file, line };
}

/** Filesystem operations the realtime plane uses; injectable by tests. */
export interface RealtimePlaneFs {
  readdir(dir: string): string[];
  stat(filePath: string): { size: number };
  readFile(filePath: string): string;
}

export const nodeRealtimePlaneFs: RealtimePlaneFs = {
  readdir: (dir) => fs.readdirSync(dir),
  stat: (filePath) => fs.statSync(filePath),
  readFile: (filePath) => fs.readFileSync(filePath, 'utf-8'),
};

export type PlainReadOutcome =
  | { kind: 'ok'; content: string }
  | { kind: 'oversize'; size: number }
  | { kind: 'unavailable'; stage: 'stat' | 'read'; code: string };

function errorCode(e: unknown): string {
  const code = (e as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'OTHER';
}

/**
 * Stat (following symlinks, as before) then read one plain realtime file.
 * Never throws.
 */
export function readPlainRealtimeFile(
  dir: string,
  name: string,
  maxBytes: number,
  fsOps: RealtimePlaneFs = nodeRealtimePlaneFs,
): PlainReadOutcome {
  const filePath = path.join(dir, name);
  let size: number;
  try {
    size = fsOps.stat(filePath).size;
  } catch (e) {
    return { kind: 'unavailable', stage: 'stat', code: errorCode(e) };
  }
  if (size > maxBytes) return { kind: 'oversize', size };
  try {
    return { kind: 'ok', content: fsOps.readFile(filePath) };
  } catch (e) {
    return { kind: 'unavailable', stage: 'read', code: errorCode(e) };
  }
}
