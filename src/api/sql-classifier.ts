/**
 * SQL Console Query Classifier
 *
 * Categorises an SQL query as read / write / reject for the local dashboard
 * SQL console. Used by visualization-server's `/api/sql` endpoint to enforce
 * a defensive allow-list that the original `startsWith()` check could bypass
 * via a CTE prefix (e.g. `WITH t AS (SELECT 1) INSERT INTO ...`).
 *
 * Design goals:
 *  - Fail closed: anything we cannot classify becomes `reject`.
 *  - No SQL grammar: just a defensive peek past leading comments and CTEs
 *    to find the FIRST real keyword.
 *  - Cheap and synchronous — runs in the request hot path.
 */
export type SqlClassification =
  | { kind: 'read' }
  | { kind: 'write'; operation: 'INSERT' | 'UPDATE' | 'DELETE' | 'REPLACE' | 'ALTER' | 'CREATE' }
  | { kind: 'destroy'; operation: 'DROP' | 'TRUNCATE' }
  | { kind: 'reject'; reason: string };

const READ_KEYWORDS = new Set(['SELECT', 'PRAGMA', 'EXPLAIN', 'VALUES']);
const WRITE_KEYWORDS = new Set(['INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'ALTER', 'CREATE']);
const DESTROY_KEYWORDS = new Set(['DROP', 'TRUNCATE']);

/**
 * Strip SQL comments (line + block) and leading whitespace from the start of
 * a query string. Returns the cleaned query with all leading noise removed.
 *
 * Note: this only strips LEADING comments/whitespace — we don't try to scrub
 * comments inside string literals or anywhere else, because we only care
 * about identifying the first real token.
 */
function stripLeadingNoise(query: string): string {
  let i = 0;
  const n = query.length;
  while (i < n) {
    const ch = query[i];
    // whitespace
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      i++;
      continue;
    }
    // line comment: -- ... \n
    if (ch === '-' && query[i + 1] === '-') {
      i += 2;
      while (i < n && query[i] !== '\n') i++;
      continue;
    }
    // block comment: /* ... */
    if (ch === '/' && query[i + 1] === '*') {
      i += 2;
      while (i < n && !(query[i] === '*' && query[i + 1] === '/')) i++;
      if (i < n) i += 2; // skip closing */
      continue;
    }
    break;
  }
  return query.slice(i);
}

/**
 * Skip past a balanced-parenthesis block starting at `start` (which should
 * point AT the opening '('). Returns the index just past the matching ')',
 * or -1 if no matching paren is found.
 *
 * Aware of single-quoted string literals (SQL standard '' escape) and
 * double-quoted identifiers (SQLite). Bracket [] and backtick `` quoting
 * are also handled because SQLite accepts them.
 */
function skipParenBlock(query: string, start: number): number {
  if (query[start] !== '(') return -1;
  let depth = 0;
  let i = start;
  const n = query.length;
  while (i < n) {
    const ch = query[i];
    if (ch === '(') {
      depth++;
      i++;
      continue;
    }
    if (ch === ')') {
      depth--;
      i++;
      if (depth === 0) return i;
      continue;
    }
    if (ch === "'") {
      // skip single-quoted string with SQL '' escape
      i++;
      while (i < n) {
        if (query[i] === "'") {
          if (query[i + 1] === "'") {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
      continue;
    }
    if (ch === '"') {
      i++;
      while (i < n && query[i] !== '"') i++;
      if (i < n) i++;
      continue;
    }
    if (ch === '`') {
      i++;
      while (i < n && query[i] !== '`') i++;
      if (i < n) i++;
      continue;
    }
    if (ch === '[') {
      i++;
      while (i < n && query[i] !== ']') i++;
      if (i < n) i++;
      continue;
    }
    // inline comments inside the CTE body
    if (ch === '-' && query[i + 1] === '-') {
      i += 2;
      while (i < n && query[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && query[i + 1] === '*') {
      i += 2;
      while (i < n && !(query[i] === '*' && query[i + 1] === '/')) i++;
      if (i < n) i += 2;
      continue;
    }
    i++;
  }
  return -1;
}

/**
 * Read the next uppercase keyword token at `i`, skipping leading
 * whitespace/comments first. Returns the keyword and the index just past it,
 * or null if no identifier token is present.
 */
function readNextKeyword(query: string, i: number): { keyword: string; nextIndex: number } | null {
  const trimmed = stripLeadingNoise(query.slice(i));
  if (!trimmed) return null;
  const offset = query.length - trimmed.length;
  const match = /^([A-Za-z_][A-Za-z0-9_]*)/.exec(trimmed);
  if (!match) return null;
  return {
    keyword: match[1].toUpperCase(),
    nextIndex: offset + match[1].length,
  };
}

/**
 * Walk past a CTE list (`WITH [RECURSIVE] name [(...)] AS (...) [, ...]`)
 * and return the index at the first real statement keyword.
 * Returns -1 if the structure doesn't look like a valid CTE list.
 */
function skipCteList(query: string, afterWithIndex: number): number {
  let i = afterWithIndex;
  const n = query.length;

  // optional RECURSIVE
  const first = readNextKeyword(query, i);
  if (!first) return -1;
  if (first.keyword === 'RECURSIVE') {
    i = first.nextIndex;
  }

  // parse one or more "<name> [(...)] AS (...)" groups, comma separated
  while (i < n) {
    // CTE name (identifier)
    const nameStripped = stripLeadingNoise(query.slice(i));
    if (!nameStripped) return -1;
    i = n - nameStripped.length;
    // name can be bracketed/quoted; for our purposes we just need to consume it
    const ch = query[i];
    if (ch === '"' || ch === '`' || ch === '[') {
      const close = ch === '[' ? ']' : ch;
      i++;
      while (i < n && query[i] !== close) i++;
      if (i < n) i++;
    } else {
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(query.slice(i));
      if (!m) return -1;
      i += m[0].length;
    }

    // optional column list (col1, col2, ...)
    const afterName = stripLeadingNoise(query.slice(i));
    i = n - afterName.length;
    if (query[i] === '(') {
      const end = skipParenBlock(query, i);
      if (end < 0) return -1;
      i = end;
    }

    // mandatory AS
    const asKeyword = readNextKeyword(query, i);
    if (!asKeyword || asKeyword.keyword !== 'AS') return -1;
    i = asKeyword.nextIndex;

    // optional MATERIALIZED / NOT MATERIALIZED
    const maybeMat = readNextKeyword(query, i);
    if (maybeMat && maybeMat.keyword === 'NOT') {
      const next = readNextKeyword(query, maybeMat.nextIndex);
      if (next && next.keyword === 'MATERIALIZED') {
        i = next.nextIndex;
      }
    } else if (maybeMat && maybeMat.keyword === 'MATERIALIZED') {
      i = maybeMat.nextIndex;
    }

    // mandatory ( CTE body )
    const stripped = stripLeadingNoise(query.slice(i));
    i = n - stripped.length;
    if (query[i] !== '(') return -1;
    const bodyEnd = skipParenBlock(query, i);
    if (bodyEnd < 0) return -1;
    i = bodyEnd;

    // comma → another CTE, else we're done
    const after = stripLeadingNoise(query.slice(i));
    i = n - after.length;
    if (query[i] === ',') {
      i++;
      continue;
    }
    break;
  }

  return i;
}

/**
 * Classify a query as read / write / destroy / reject.
 *
 * Fail-closed: any structure we can't confidently classify becomes `reject`.
 */
export function classifySqlQuery(rawQuery: string): SqlClassification {
  if (typeof rawQuery !== 'string' || rawQuery.trim().length === 0) {
    return { kind: 'reject', reason: 'Empty query' };
  }

  const stripped = stripLeadingNoise(rawQuery);
  if (!stripped) {
    return { kind: 'reject', reason: 'Empty query after stripping comments' };
  }

  const first = readNextKeyword(rawQuery, rawQuery.length - stripped.length);
  if (!first) {
    return { kind: 'reject', reason: 'Could not identify leading keyword' };
  }

  let leadIndex = first.nextIndex;
  let leadKeyword = first.keyword;

  // Peek past CTE prefix (the security-critical bit)
  if (leadKeyword === 'WITH') {
    const afterCte = skipCteList(rawQuery, first.nextIndex);
    if (afterCte < 0) {
      return { kind: 'reject', reason: 'Malformed CTE prefix' };
    }
    const realFirst = readNextKeyword(rawQuery, afterCte);
    if (!realFirst) {
      return { kind: 'reject', reason: 'No statement after CTE prefix' };
    }
    leadKeyword = realFirst.keyword;
    leadIndex = realFirst.nextIndex;
  }

  // Also reject any DROP/TRUNCATE anywhere in the query as defense-in-depth.
  // (visualization-server's outer check already does this, but classify it
  // here too so the function is correct on its own.)
  if (DESTROY_KEYWORDS.has(leadKeyword)) {
    return { kind: 'destroy', operation: leadKeyword as 'DROP' | 'TRUNCATE' };
  }

  if (WRITE_KEYWORDS.has(leadKeyword)) {
    return { kind: 'write', operation: leadKeyword as 'INSERT' | 'UPDATE' | 'DELETE' | 'REPLACE' | 'ALTER' | 'CREATE' };
  }

  if (READ_KEYWORDS.has(leadKeyword)) {
    return { kind: 'read' };
  }

  void leadIndex; // not needed by callers, but useful while debugging
  return { kind: 'reject', reason: `Unrecognised leading keyword: ${leadKeyword}` };
}
