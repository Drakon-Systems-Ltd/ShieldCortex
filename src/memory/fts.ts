/**
 * Shared FTS5 + JSON helpers used across memory store modules.
 *
 * Lifted out of store.ts so the memory module split can avoid
 * circular imports and silent helper duplication.
 */

/**
 * Escape FTS5 query to prevent syntax errors.
 *
 * FTS5 interprets:
 * - "word-word" as "column:value" syntax
 * - AND, OR, NOT as boolean operators
 * - &, | as boolean operators
 *
 * We quote individual terms to search them literally. Apostrophes are
 * split on because the porter unicode61 tokenizer treats them as word
 * separators during indexing ("don't" → "don" + "t"); queries must
 * split the same way to match indexed tokens.
 */
export function escapeFts5Query(query: string): string {
  return query
    .split(/\s+/)
    .filter((term) => term.length > 0)
    .map((term) => {
      if (term.includes("'")) {
        const parts = term.split("'").filter((p) => p.length > 0);
        return parts.map((p) => {
          if (/[^a-zA-Z0-9_]/.test(p)) return `"${p.replace(/"/g, '""')}"`;
          return p;
        }).join(' ');
      }

      const upperTerm = term.toUpperCase();
      if (upperTerm === 'AND' || upperTerm === 'OR' || upperTerm === 'NOT') {
        return `"${term}"`;
      }
      if (/[^a-zA-Z0-9_]/.test(term)) {
        return `"${term.replace(/"/g, '""')}"`;
      }
      return term;
    })
    .filter(Boolean)
    .join(' ');
}

/**
 * Safely parse JSON with fallback — prevents corrupted DB values from
 * crashing queries. Returns the fallback for null, undefined, empty
 * string, or any parse error.
 */
export function safeJsonParse<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
