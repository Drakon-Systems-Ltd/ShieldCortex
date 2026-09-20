/**
 * Terminal-only detail for an audit finding: which rule fired and on which line.
 *
 * Kept OFF the `AuditFinding` object on purpose. `audit --json` and the SARIF
 * export serialise findings as they are, and consumers parse that shape; the
 * human report needed more than the shape carries (issue #514), so the extra
 * detail rides beside the finding in a WeakMap instead of inside it. Nothing
 * here is reachable from `JSON.stringify`, and an entry dies with its finding.
 */

import type { AuditFinding } from './types.js';

export interface AuditFindingDetail {
  /** Detector rule ids, most specific first. Never empty. */
  ruleIds: string[];
  /** 1-based line of the first text the rule fires on, when it can be found. */
  line?: number;
  /** That line, trimmed and length-capped for a terminal. */
  excerpt?: string;
  /** The one command to run next for this file. */
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

const MAX_LINES_SEARCHED = 5000;
const MAX_LINE_LENGTH = 2000;
const EXCERPT_LENGTH = 100;

function clip(line: string): string {
  const flat = line.trim().replace(/\s+/g, ' ');
  return flat.length > EXCERPT_LENGTH ? `${flat.slice(0, EXCERPT_LENGTH - 1)}…` : flat;
}

/**
 * First line on which `fires` is true, else the first three-line window (for
 * rules that read layout, e.g. a `---` marker and the line after it).
 *
 * Bounded: a capped number of lines, each capped in length, and only ever run
 * for a file the pipeline has already flagged.
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
  for (let i = 0; i + 2 < lines.length; i++) {
    if (safe(`${lines[i]}\n${lines[i + 1]}\n${lines[i + 2]}`)) {
      // Report the last non-blank line of the window: for a marker rule that is
      // the text the marker was hiding, which is what the operator needs to read.
      const offset = lines[i + 2].trim() ? 2 : lines[i + 1].trim() ? 1 : 0;
      return { line: i + 1 + offset, excerpt: clip(lines[i + offset]) };
    }
  }
  return undefined;
}
