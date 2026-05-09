/**
 * Graph-based retrieval: turn a free-text query into a ranked list of
 * memories by walking the knowledge graph (entities + triples).
 *
 * The retriever is side-effect-free — it only reads. It does NOT insert
 * new entities, mutate aliases, or write any state. That's the
 * contract that lets it stand alongside FTS and vector retrievers in the
 * RRF orchestrator without polluting the graph during a query.
 *
 * Algorithm:
 *   1. Tokenize the query, drop stop-words and tokens shorter than
 *      `MIN_TOKEN_LEN`.
 *   2. Resolve each token to seed entities (case-insensitive name,
 *      alias, then Levenshtein for tokens at least `MIN_FUZZY_LEN` chars).
 *   3. BFS over the triples table up to `maxHops`. Track shortest hop
 *      and incoming-edge confidence for every entity reached. Seeds have
 *      hop=0 and implicit confidence 1.0.
 *   4. For every memory mentioning a reached entity (via the
 *      `memory_entities` table), accumulate score:
 *           Σ  incomingConf / (hop + 1)
 *   5. Optional `project` filter via the JOIN.
 *   6. Sort by score desc, ties by memoryId asc, cap at `limit`.
 */

import type { Database as SqliteDatabase } from 'better-sqlite3';
import { levenshtein } from '../../graph/resolve.js';

const DEFAULT_STOP_WORDS = new Set<string>([
  'the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
  'and', 'or', 'but', 'not', 'no', 'to', 'of', 'in', 'on', 'at', 'for',
  'with', 'by', 'from', 'as', 'this', 'that', 'these', 'those',
  'it', 'its', 'has', 'have', 'had', 'do', 'does', 'did', 'can',
  'could', 'should', 'would', 'will', 'shall', 'may', 'might', 'must',
  'i', 'me', 'my', 'we', 'us', 'our', 'you', 'your', 'they', 'them',
  'he', 'him', 'his', 'she', 'her', 'their',
]);

const MIN_TOKEN_LEN = 3;
const MIN_FUZZY_LEN = 6;
const MAX_FUZZY_DISTANCE = 2;
const DEFAULT_MAX_HOPS = 2;
const DEFAULT_LIMIT = 50;

export interface GraphRankResult {
  memoryId: number;
  score: number;
}

export interface GraphRankOptions {
  /** Maximum hops from seed entities. Default 2. */
  maxHops?: number;
  /** Maximum result rows. Default 50. */
  limit?: number;
  /** Filter to memories within this project. */
  project?: string;
  /** Override stop-word set. Default is a small built-in English list. */
  stopWords?: Set<string>;
}

interface EntityInfo {
  /** Shortest hop distance found so far. */
  hop: number;
  /** Best (highest) incoming-edge confidence at the recorded hop. */
  incomingConf: number;
}

export function graphRankFromQuery(
  query: string,
  db: SqliteDatabase,
  options: GraphRankOptions = {},
): GraphRankResult[] {
  if (typeof query !== 'string' || query.trim().length === 0) return [];

  const maxHops = options.maxHops ?? DEFAULT_MAX_HOPS;
  const limit = options.limit ?? DEFAULT_LIMIT;
  const stopWords = options.stopWords ?? DEFAULT_STOP_WORDS;

  const tokens = tokenize(query, stopWords);
  if (tokens.length === 0) return [];

  const reach = resolveSeeds(tokens, db);
  if (reach.size === 0) return [];

  expandHops(reach, maxHops, db);

  return aggregateMemoryScores(reach, db, options.project, limit);
}

function tokenize(query: string, stopWords: Set<string>): string[] {
  return query
    .toLowerCase()
    .split(/[^\p{L}\p{N}_-]+/u)
    .filter((t) => t.length >= MIN_TOKEN_LEN && !stopWords.has(t));
}

function resolveSeeds(tokens: string[], db: SqliteDatabase): Map<number, EntityInfo> {
  // Pull every entity once. Fine for typical ShieldCortex DBs (hundreds of
  // entities). Switch to per-token SQL probes if this becomes a hotspot.
  const all = db
    .prepare('SELECT id, name, aliases FROM entities')
    .all() as Array<{ id: number; name: string; aliases: string | null }>;

  // Pre-compute alias lookups.
  const parsedAliases = all.map((row) => {
    let aliases: string[] = [];
    if (row.aliases) {
      try {
        const parsed = JSON.parse(row.aliases);
        if (Array.isArray(parsed)) {
          aliases = parsed.filter((a): a is string => typeof a === 'string');
        }
      } catch {
        // Malformed JSON in the aliases column — treat as no aliases.
      }
    }
    return { id: row.id, name: row.name, lname: row.name.toLowerCase(), aliases };
  });

  const reach = new Map<number, EntityInfo>();
  const recordSeed = (id: number) => {
    if (!reach.has(id)) reach.set(id, { hop: 0, incomingConf: 1.0 });
  };

  for (const token of tokens) {
    let matched = false;

    // 1. Exact name match (case-insensitive).
    for (const e of parsedAliases) {
      if (e.lname === token) {
        recordSeed(e.id);
        matched = true;
      }
    }
    if (matched) continue;

    // 2. Alias match.
    for (const e of parsedAliases) {
      if (e.aliases.some((a) => a.toLowerCase() === token)) {
        recordSeed(e.id);
        matched = true;
      }
    }
    if (matched) continue;

    // 3. Fuzzy match — only for tokens of MIN_FUZZY_LEN+ to avoid false
    //    positives on short words.
    if (token.length >= MIN_FUZZY_LEN) {
      for (const e of parsedAliases) {
        if (Math.abs(e.lname.length - token.length) > MAX_FUZZY_DISTANCE) continue;
        if (levenshtein(token, e.lname) <= MAX_FUZZY_DISTANCE) {
          recordSeed(e.id);
        }
      }
    }
  }

  return reach;
}

function expandHops(
  reach: Map<number, EntityInfo>,
  maxHops: number,
  db: SqliteDatabase,
): void {
  if (maxHops <= 0) return;

  let frontier = new Set<number>(reach.keys());
  for (let hop = 0; hop < maxHops; hop++) {
    if (frontier.size === 0) break;
    const ids = Array.from(frontier);
    const placeholders = ids.map(() => '?').join(',');
    const rows = db
      .prepare(
        `
        SELECT subject_id AS src, object_id AS dst, confidence
        FROM triples
        WHERE subject_id IN (${placeholders})
        UNION ALL
        SELECT object_id AS src, subject_id AS dst, confidence
        FROM triples
        WHERE object_id IN (${placeholders})
        `,
      )
      .all(...ids, ...ids) as Array<{ src: number; dst: number; confidence: number }>;

    const next = new Set<number>();
    for (const row of rows) {
      const dstHop = hop + 1;
      const existing = reach.get(row.dst);
      if (!existing) {
        reach.set(row.dst, { hop: dstHop, incomingConf: row.confidence });
        next.add(row.dst);
      } else if (existing.hop === dstHop && row.confidence > existing.incomingConf) {
        // Same shortest hop reached by a higher-confidence edge — keep the better one.
        existing.incomingConf = row.confidence;
      }
    }
    frontier = next;
  }
}

function aggregateMemoryScores(
  reach: Map<number, EntityInfo>,
  db: SqliteDatabase,
  project: string | undefined,
  limit: number,
): GraphRankResult[] {
  const entityIds = Array.from(reach.keys());
  if (entityIds.length === 0) return [];

  const placeholders = entityIds.map(() => '?').join(',');
  const params: unknown[] = [...entityIds];
  let sql = `
    SELECT me.memory_id, me.entity_id, m.project
    FROM memory_entities me
    JOIN memories m ON m.id = me.memory_id
    WHERE me.entity_id IN (${placeholders})
  `;
  if (project) {
    sql += ' AND m.project = ?';
    params.push(project);
  }
  const rows = db.prepare(sql).all(...params) as Array<{
    memory_id: number;
    entity_id: number;
    project: string | null;
  }>;

  const scoreByMemory = new Map<number, number>();
  for (const row of rows) {
    const info = reach.get(row.entity_id);
    if (!info) continue; // shouldn't happen, but be defensive
    const contribution = info.incomingConf / (info.hop + 1);
    scoreByMemory.set(
      row.memory_id,
      (scoreByMemory.get(row.memory_id) ?? 0) + contribution,
    );
  }

  return Array.from(scoreByMemory.entries())
    .map(([memoryId, score]) => ({ memoryId, score }))
    .sort((a, b) => b.score - a.score || a.memoryId - b.memoryId)
    .slice(0, limit);
}
