/**
 * One admission predicate for every prompt-recall candidate plane (#720).
 *
 * The FTS, category-boost and vector planes each SELECT from `memories`. When
 * each spelled its own WHERE clause, the #717 vector plane could admit a row
 * the FTS plane would never surface (Tars, #720 review): a same-project private
 * row with no lexical tie to the prompt. Every plane now builds its WHERE from
 * `recallAdmissionClause`, so a scope rule added here (e.g. #718's lane
 * admission, once it moves into SQL) binds all planes at once, and every plane
 * projects `recallRowColumns` so rows are indistinguishable downstream.
 *
 * Parameter order for the clause is always [project, minSalience].
 */

/**
 * @param {string} [alias] table alias including the dot, e.g. 'm.'
 * @returns {string} SQL boolean expression with two `?` placeholders
 */
export function recallAdmissionClause(alias = '') {
  return `(${alias}project = ? OR ${alias}scope = 'global')
      AND COALESCE(${alias}status, 'active') = 'active'
      AND ${alias}salience >= ?`;
}

/**
 * Columns every recall plane projects. pinned/access_count/last_accessed/
 * downvote_count feed compareRecallResults' effective salience; COALESCE on
 * downvote_count for DBs that pre-date the 4.25 migration.
 *
 * @param {string} [alias]
 */
export function recallRowColumns(alias = '') {
  return `${alias}id, ${alias}title, ${alias}content, ${alias}category, ${alias}salience,
      ${alias}pinned, ${alias}access_count, ${alias}last_accessed,
      ${alias}trust_score, ${alias}sensitivity_level, ${alias}metadata, ${alias}reviewed_at,
      COALESCE(${alias}downvote_count, 0) AS downvote_count`;
}

/**
 * The FTS plane: OR-of-terms MATCH, BM25 order, admission clause applied.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {{ project: string, ftsQuery: string, limit: number, minSalience: number }} opts
 * @returns {Array<object>} rows best-first, each with `rank`
 */
export function selectFtsCandidates(db, { project, ftsQuery, limit, minSalience }) {
  if (!ftsQuery || !ftsQuery.trim()) return [];
  return db.prepare(`
    SELECT ${recallRowColumns('m.')}, fts.rank
    FROM memories m
    JOIN memories_fts fts ON m.id = fts.rowid
    WHERE memories_fts MATCH ?
      AND ${recallAdmissionClause('m.')}
    ORDER BY fts.rank
    LIMIT ?
  `).all(ftsQuery, project, minSalience, limit);
}
