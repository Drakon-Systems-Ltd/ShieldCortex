/**
 * Terminal-only detail for an audit finding: which rule fired and on which line.
 *
 * Kept OFF the `AuditFinding` object on purpose. `audit --json` and the SARIF
 * export serialise findings as they are, and consumers parse that shape; the
 * human report needed more than the shape carries (issue #514), so the extra
 * detail rides beside the finding in a WeakMap instead of inside it. Nothing
 * here is reachable from `JSON.stringify`, and an entry dies with its finding.
 *
 * Everything in a detail is derived from a file the audit does not trust: its
 * name and its text. Both are attacker-chosen, so the excerpt is display-
 * sanitised here and the command is shell-quoted here, not at the print site.
 */

import { sanitiseDisplayField } from '../cli/term-ui.js';
import type { AuditFinding } from './types.js';

export interface AuditFindingDetail {
  /** Detector rule ids, most specific first. Never empty. */
  ruleIds: string[];
  /** 1-based line of the text the rule fires on, when it can be found. */
  line?: number;
  /** That line, sanitised, trimmed and length-capped for a terminal. */
  excerpt?: string;
  /** The one command to run next for this file, safe to copy and paste. */
  nextCommand?: string;
}

const DETAILS = new WeakMap<AuditFinding, AuditFindingDetail>();

export function attachFindingDetail(finding: AuditFinding, detail: AuditFindingDetail): AuditFinding {
  DETAILS.set(finding, detail);
  return finding;
}

export function getFindingDetail(finding: AuditFinding): AuditFindingDetail | undefined {
  return DETAILS.get(finding);
}

/**
 * Quote one argument for a POSIX shell, or undefined if it cannot be offered.
 *
 * Single quotes, because inside them the shell expands nothing: a file named
 * `$(id).md` or carrying backticks stays text. A single quote in the name is
 * written as close-quote, escaped quote, reopen. Double quotes -- what this
 * printed at first -- still run `$(...)` and backticks.
 *
 * A name with a control character gets NO command. It could be quoted, but it
 * cannot be shown on one terminal line without changing it, and a command that
 * differs from what is displayed is worse than none.
 */
export function shellQuoteArg(value: string): string | undefined {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f-\x9f\u2028\u2029]/.test(value)) return undefined;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

const MAX_LINES_SEARCHED = 5000;
const MAX_LINE_LENGTH = 2000;
const EXCERPT_LENGTH = 100;

/**
 * How far a layout rule can reach from its marker to its payload. The skill
 * scanner's marker rules allow 500 characters between the two; the window has
 * to cover that, or a payload pushed down by blank lines has no line number.
 */
const WINDOW_CHARS = 700;
const WINDOW_LINES = 40;

function clip(line: string): string {
  const flat = sanitiseDisplayField(line.replace(/\s+/g, ' ').trim());
  return flat.length > EXCERPT_LENGTH ? `${flat.slice(0, EXCERPT_LENGTH - 1)}…` : flat;
}

/**
 * The line `fires` is about: the first single line it is true for, else the
 * last line of the smallest multi-line window it is true for.
 *
 * The window matters for rules that read layout. "A `---`, then blank lines,
 * then the text" fires on no single line; the smallest window that fires ends
 * on the payload, which is the line the operator needs to read.
 *
 * Bounded: capped line count and length, one probe per start line plus at most
 * WINDOW_LINES to shrink, and only ever run for a file already flagged.
 */
export function locateFirstMatch(
  content: string,
  fires: (text: string) => boolean,
): { line: number; excerpt: string } | undefined {
  const lines = content.split(/\r?\n/).slice(0, MAX_LINES_SEARCHED).map((l) => l.slice(0, MAX_LINE_LENGTH));
  const safe = (text: string): boolean => {
    try { return fires(text); } catch { return false; }
  };

  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim() && safe(lines[i])) return { line: i + 1, excerpt: clip(lines[i]) };
  }

  for (let start = 0; start < lines.length; start++) {
    let end = start;
    let chars = lines[start].length;
    while (end + 1 < lines.length && end - start + 1 < WINDOW_LINES && chars < WINDOW_CHARS) {
      end += 1;
      chars += lines[end].length + 1;
    }
    if (end === start || !safe(lines.slice(start, end + 1).join('\n'))) continue;

    // Shrink from the right: the first end that still fires is the payload.
    for (let last = start + 1; last <= end; last++) {
      if (safe(lines.slice(start, last + 1).join('\n'))) {
        return { line: last + 1, excerpt: clip(lines[last]) };
      }
    }
  }
  return undefined;
}
