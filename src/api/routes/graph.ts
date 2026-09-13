import type { Express, Request, Response } from 'express';
import { getDatabase } from '../../database/init.js';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;

type BFSNode = {
  id: number;
  name: string;
  type: string;
  memoryCount: number;
  parentId: number | null;
  predicate: string;
  direction: 'forward' | 'reverse' | '';
  confidence: number | null;
  disputed: boolean;
  sourceMemoryId: number | null;
};

function parseAliases(raw: unknown): string[] {
  try {
    return JSON.parse((raw as string) || '[]');
  } catch {
    return [];
  }
}

/**
 * Strict bounded-integer query parser (dashboard-v2 brief §13.2). Every
 * numeric query param flows through here so no NaN, float or out-of-range
 * value can reach a SQLite LIMIT/OFFSET. Two distinct rules, in order:
 *   1. anything that is not a plain (optionally negative) integer string —
 *      missing, empty, float, exponent, text, non-string — falls back to
 *      `dflt`;
 *   2. the resulting integer is then CLAMPED to [min, max]. A negative or
 *      oversized integer therefore clamps to the bound; it does NOT fall
 *      back to the default (`limit=-5` → min, not dflt).
 */
function boundedInt(raw: unknown, opts: { min: number; max: number; dflt: number }): number {
  let n = opts.dflt;
  if (typeof raw === 'string' && raw.trim() !== '' && /^-?\d+$/.test(raw.trim())) {
    n = parseInt(raw.trim(), 10);
  }
  if (!Number.isFinite(n) || !Number.isInteger(n)) n = opts.dflt;
  return Math.min(opts.max, Math.max(opts.min, n));
}

/**
 * Strict entity/memory id parser used for every `:id`, `fromId` and `toId`:
 * a plain decimal string that is a positive safe integer. `12junk`, `-1`,
 * `0`, `1e3`, `1.5` and anything non-string are all rejected (undefined),
 * unlike `parseInt`, which happily accepts `12junk` as 12.
 */
function parseId(raw: unknown): number | undefined {
  if (typeof raw !== 'string' || !/^\d{1,15}$/.test(raw)) return undefined;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n >= 1 ? n : undefined;
}

function stringParam(raw: unknown): string | undefined {
  return typeof raw === 'string' && raw.trim() !== '' ? raw : undefined;
}

/** A client error the handlers translate to HTTP 400 (everything else is 500). */
class BadRequest extends Error {}

const PROJECT_MAX_LENGTH = 256;

/**
 * `?project=` is either absent (global view) or exactly one non-empty
 * string. Express parses `project=a&project=b` / `project[x]=y` into an
 * array/object; treating that as "no filter" would silently widen scope, so
 * a malformed supplied value is a 400, never a fallback.
 */
function projectParam(raw: unknown): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string') throw new BadRequest('project must be a single string');
  const p = raw.trim();
  if (p === '') return undefined;
  if (p.length > PROJECT_MAX_LENGTH) throw new BadRequest('project is too long');
  return p;
}

function fail(res: Response, error: unknown): void {
  if (error instanceof BadRequest) {
    res.status(400).json({ error: error.message });
    return;
  }
  res.status(500).json({ error: (error as Error).message });
}

/**
 * Project scoping (brief §13.2): entities carry no project column, so an
 * entity is in scope iff it is linked (memory_entities) to ≥1 memory whose
 * `project` equals the filter. Returns a SQL fragment referencing the given
 * entity-table alias; binds ONE parameter (the project).
 */
function entityScopeSql(alias: string): string {
  return `EXISTS (
  SELECT 1 FROM memory_entities me_scope
  JOIN memories m_scope ON m_scope.id = me_scope.memory_id
  WHERE me_scope.entity_id = ${alias}.id AND m_scope.project = ?
)`;
}
const ENTITY_PROJECT_SCOPE_SQL = entityScopeSql('e');

const OVERVIEW_ENTITY_MAX = 800;
const OVERVIEW_ENTITY_DEFAULT = 400;
const OVERVIEW_EDGE_CAP = 4000;
const NEIGHBOURHOOD_MAX = 150;
const NEIGHBOURHOOD_DEFAULT = 50;
const NEIGHBOURHOOD_MEMORY_MAX = 100;
const NEIGHBOURHOOD_MEMORY_DEFAULT = 40;
const ENTITY_TRIPLES_MAX = 1000;
const ENTITY_TRIPLES_DEFAULT = 200;
/** BFS work bound for /paths: distinct entities visited before giving up. */
export const PATH_VISIT_BUDGET = 2000;
/** Per-node fan-out read by the BFS (rows beyond this mark the search truncated). */
export const PATH_FANOUT_LIMIT = 500;
const PATH_MAX_DEPTH = 4;

interface EntityRow {
  id: number;
  name: string;
  type: string;
  memory_count: number;
  aliases?: unknown;
}

interface TripleRow {
  id: number;
  subject_id: number;
  object_id: number;
  predicate: string;
  confidence: number;
  disputed: number;
  created_at: string;
  subject_name?: string;
  subject_type?: string;
  object_name?: string;
  object_type?: string;
}

/** Memory fields safe for graph payloads: metadata only, never `content`.
 *  (Server-wide RESTRICTED redaction also applies on top — redact-response.ts.) */
const MEMORY_GRAPH_COLUMNS =
  'm.id, m.title, m.type, m.category, m.salience, m.trust_score, m.status, m.pinned, m.project, m.created_at';

/** Live triples among a node set: both endpoints present, suspended excluded,
 *  deterministic order (meaningful before related_to, then newest, id desc). */
function triplesAmong(db: ReturnType<typeof getDatabase>, ids: number[], cap: number): { triples: TripleRow[]; total: number } {
  if (ids.length === 0) return { triples: [], total: 0 };
  const placeholders = ids.map(() => '?').join(',');
  const where = `t.subject_id IN (${placeholders}) AND t.object_id IN (${placeholders}) AND t.valid_to IS NULL`;
  const total = (db.prepare(`SELECT COUNT(*) as c FROM triples t WHERE ${where}`).get(...ids, ...ids) as { c: number }).c;
  const triples = db.prepare(`
    SELECT t.id, t.subject_id, t.object_id, t.predicate, t.confidence, t.disputed, t.created_at
    FROM triples t
    WHERE ${where}
    ORDER BY CASE WHEN t.predicate != 'related_to' THEN 0 ELSE 1 END, t.created_at DESC, t.id DESC
    LIMIT ?
  `).all(...ids, ...ids, cap) as TripleRow[];
  return { triples, total };
}

export function registerGraphRoutes(app: Express, requireNotLocked: Middleware): void {
  app.get('/api/graph/entities', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const type = stringParam(req.query.type);
      const project = projectParam(req.query.project);
      const minMentions = boundedInt(req.query.minMentions, { min: 0, max: 1_000_000, dflt: 0 });
      const limit = boundedInt(req.query.limit, { min: 1, max: 5000, dflt: 100 });
      const offset = boundedInt(req.query.offset, { min: 0, max: 10_000_000, dflt: 0 });

      let whereClause = 'WHERE 1=1';
      const params: unknown[] = [];

      if (type) {
        whereClause += ' AND e.type = ?';
        params.push(type);
      }
      if (minMentions > 0) {
        whereClause += ' AND e.memory_count >= ?';
        params.push(minMentions);
      }
      if (project) {
        whereClause += ` AND ${ENTITY_PROJECT_SCOPE_SQL}`;
        params.push(project);
      }

      const total = (db.prepare(`SELECT COUNT(*) as count FROM entities e ${whereClause}`).get(...params) as { count: number }).count;
      const rows = db.prepare(
        `SELECT e.* FROM entities e ${whereClause} ORDER BY e.memory_count DESC, e.id ASC LIMIT ? OFFSET ?`,
      ).all(...params, limit, offset) as Record<string, unknown>[];

      res.json({
        entities: rows.map((row) => ({
          id: row.id,
          name: row.name,
          type: row.type,
          memoryCount: row.memory_count ?? 0,
          aliases: parseAliases(row.aliases),
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        })),
        total,
        offset,
        limit,
        hasMore: offset + limit < total,
      });
    } catch (error) {
      fail(res, error);
    }
  });

  /**
   * Bounded one-round-trip Map payload (brief §6.4/§13.2): top entities by
   * mention count (project-scoped when asked) plus the live triples whose BOTH
   * endpoints made the cut. Hard caps with truncation counts — the UI states
   * what was omitted instead of silently dropping it.
   */
  app.get('/api/graph/overview', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const project = projectParam(req.query.project);
      const minMentions = boundedInt(req.query.minMentions, { min: 0, max: 1_000_000, dflt: 1 });
      const limit = boundedInt(req.query.limit, { min: 1, max: OVERVIEW_ENTITY_MAX, dflt: OVERVIEW_ENTITY_DEFAULT });

      let whereClause = 'WHERE e.memory_count >= ?';
      const params: unknown[] = [minMentions];
      if (project) {
        whereClause += ` AND ${ENTITY_PROJECT_SCOPE_SQL}`;
        params.push(project);
      }

      const totalEntities = (db.prepare(`SELECT COUNT(*) as c FROM entities e ${whereClause}`).get(...params) as { c: number }).c;
      const entities = db.prepare(
        `SELECT e.id, e.name, e.type, e.memory_count FROM entities e ${whereClause}
         ORDER BY e.memory_count DESC, e.id ASC LIMIT ?`,
      ).all(...params, limit) as EntityRow[];

      const ids = entities.map((e) => e.id);
      const { triples, total: totalEdges } = triplesAmong(db, ids, OVERVIEW_EDGE_CAP);

      const byType: Record<string, number> = {};
      for (const e of entities) byType[e.type] = (byType[e.type] ?? 0) + 1;
      const byPredicate: Record<string, number> = {};
      for (const t of triples) byPredicate[t.predicate] = (byPredicate[t.predicate] ?? 0) + 1;

      res.json({
        entities: entities.map((e) => ({ id: e.id, name: e.name, type: e.type, memoryCount: e.memory_count })),
        triples: triples.map((t) => ({
          id: t.id,
          subjectId: t.subject_id,
          objectId: t.object_id,
          predicate: t.predicate,
          confidence: t.confidence,
          disputed: t.disputed === 1,
        })),
        counts: {
          byType,
          byPredicate,
          totalEntities,
          totalEdges,
          omittedEntities: Math.max(0, totalEntities - entities.length),
          omittedEdges: Math.max(0, totalEdges - triples.length),
        },
      });
    } catch (error) {
      fail(res, error);
    }
  });

  app.get('/api/graph/entities/:id/triples', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseId(req.params.id);
      if (id === undefined) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }
      const limit = boundedInt(req.query.limit, { min: 1, max: ENTITY_TRIPLES_MAX, dflt: ENTITY_TRIPLES_DEFAULT });
      const project = projectParam(req.query.project);

      // valid_to IS NULL: a suspended (operator-rejected) edge is not a live
      // relation, so it must not appear in the entity's triples listing.
      // Parenthesised: AND binds tighter than OR. Optional project scope uses
      // the both-endpoints rule (subject AND object in scope).
      let where = 'WHERE (t.subject_id = ? OR t.object_id = ?) AND t.valid_to IS NULL';
      const params: unknown[] = [id, id];
      if (project) {
        where += ` AND ${entityScopeSql('s')} AND ${entityScopeSql('o')}`;
        params.push(project, project);
      }
      const from = `FROM triples t
        JOIN entities s ON s.id = t.subject_id
        JOIN entities o ON o.id = t.object_id
        ${where}`;
      const total = (db.prepare(`SELECT COUNT(*) as c ${from}`).get(...params) as { c: number }).c;
      const rows = db.prepare(`
        SELECT t.*, s.name as subject_name, s.type as subject_type,
               o.name as object_name, o.type as object_type
        ${from}
        ORDER BY t.created_at DESC, t.id DESC
        LIMIT ?
      `).all(...params, limit) as Record<string, unknown>[];

      res.json({ triples: rows, total, limit, hasMore: total > rows.length });
    } catch (error) {
      fail(res, error);
    }
  });

  app.get('/api/graph/entities/:id/memories', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseId(req.params.id);
      if (id === undefined) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }
      const limit = boundedInt(req.query.limit, { min: 1, max: 200, dflt: 50 });
      const project = projectParam(req.query.project);

      const projectClause = project ? 'AND m.project = ?' : '';
      const params: unknown[] = project ? [id, project, limit] : [id, limit];
      const rows = db.prepare(`
        SELECT ${MEMORY_GRAPH_COLUMNS}
        FROM memories m
        JOIN memory_entities me ON me.memory_id = m.id
        WHERE me.entity_id = ? ${projectClause}
        ORDER BY m.salience DESC, m.created_at DESC, m.id ASC
        LIMIT ?
      `).all(...params) as Record<string, unknown>[];

      res.json({ memories: rows });
    } catch (error) {
      fail(res, error);
    }
  });

  /**
   * Focus-mode payload (brief §6.2/§13.3). v2 additions over the legacy shape:
   * ALL neighbours capped (not just related_to fill-in) with deterministic
   * meaningful-first ordering; optional depth 2 under the same node budget;
   * optional focal memories + memory→entity edges + memory↔memory links
   * (metadata only, never content); project scoping; truncation counts.
   */
  app.get('/api/graph/entities/:id/neighbourhood', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseId(req.params.id);
      if (id === undefined) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }
      const depth = boundedInt(req.query.depth, { min: 1, max: 2, dflt: 1 });
      const limit = boundedInt(req.query.limit, { min: 1, max: NEIGHBOURHOOD_MAX, dflt: NEIGHBOURHOOD_DEFAULT });
      const includeMemories = req.query.includeMemories === '1' || req.query.includeMemories === 'true';
      const memLimit = boundedInt(req.query.memLimit, { min: 1, max: NEIGHBOURHOOD_MEMORY_MAX, dflt: NEIGHBOURHOOD_MEMORY_DEFAULT });
      const project = projectParam(req.query.project);

      // With a project scope the focal must itself be in scope, otherwise an
      // out-of-project entity's name/aliases/edges would leak through the
      // focal slot. Same "linked to ≥1 memory of that project" rule as every
      // other node; an out-of-scope focal is indistinguishable from a missing one.
      const focalScope = project ? `AND ${ENTITY_PROJECT_SCOPE_SQL}` : '';
      const focal = db.prepare(
        `SELECT e.id, e.name, e.type, e.memory_count as memoryCount, e.aliases FROM entities e WHERE e.id = ? ${focalScope}`,
      ).get(...(project ? [id, project] : [id])) as Record<string, unknown> | undefined;
      if (!focal) {
        return res.status(404).json({ error: 'Entity not found' });
      }
      focal.aliases = parseAliases(focal.aliases);

      // Ordered candidate neighbours of one node: meaningful predicates first,
      // then related_to; within each class by neighbour prominence. Project
      // scope filters the NEIGHBOUR. LIMIT is bound to the remaining node
      // budget so a hub with thousands of edges never materialises them all;
      // the separate COUNT supplies the honest total for truncation counts.
      const projectJoin = project ? `AND ${entityScopeSql('n')}` : '';
      const neighbourFrom = `
        FROM triples t
        JOIN entities n ON n.id = CASE WHEN t.subject_id = ? THEN t.object_id ELSE t.subject_id END
        WHERE (t.subject_id = ? OR t.object_id = ?) AND t.valid_to IS NULL AND n.id != ?
          ${projectJoin}`;
      const neighboursOf = db.prepare(`
        SELECT n.id, n.name, n.type, n.memory_count,
               MIN(CASE WHEN t.predicate != 'related_to' THEN 0 ELSE 1 END) as cls
        ${neighbourFrom}
        GROUP BY n.id
        ORDER BY cls ASC, n.memory_count DESC, n.id ASC
        LIMIT ?
      `);
      const countNeighboursOf = db.prepare(`SELECT COUNT(DISTINCT n.id) as c ${neighbourFrom}`);

      const nodeSet = new Map<number, EntityRow & { depth: number }>();
      const focalRow: EntityRow & { depth: number } = {
        id: focal.id as number,
        name: focal.name as string,
        type: focal.type as string,
        memory_count: focal.memoryCount as number,
        depth: 0,
      };
      nodeSet.set(id, focalRow);

      const scopeArgs = (nodeId: number) => (project ? [nodeId, nodeId, nodeId, nodeId, project] : [nodeId, nodeId, nodeId, nodeId]);
      const remaining = () => Math.max(0, limit - (nodeSet.size - 1));
      const totalNeighbours = (countNeighboursOf.get(...scopeArgs(id)) as { c: number }).c;
      const depth1 = neighboursOf.all(...scopeArgs(id), remaining()) as (EntityRow & { cls: number })[];
      for (const n of depth1) {
        if (remaining() === 0) break;
        nodeSet.set(n.id, { ...n, depth: 1 });
      }

      if (depth === 2) {
        const firstRing = [...nodeSet.values()].filter((n) => n.depth === 1);
        for (const ring of firstRing) {
          if (remaining() === 0) break;
          // Over-fetch by the nodes already present (they do not consume
          // budget but may occupy the top rows); the loop still stops at the budget.
          const second = neighboursOf.all(...scopeArgs(ring.id), remaining() + nodeSet.size) as (EntityRow & { cls: number })[];
          for (const n of second) {
            if (remaining() === 0) break;
            if (!nodeSet.has(n.id)) nodeSet.set(n.id, { ...n, depth: 2 });
          }
        }
      }

      const ids = [...nodeSet.keys()];
      const { triples, total: totalEdges } = triplesAmong(db, ids, OVERVIEW_EDGE_CAP);

      // Legacy consumers read subject/object names off each triple row.
      const nameOf = (nid: number) => nodeSet.get(nid);
      const tripleRows = triples.map((t) => ({
        id: t.id,
        subject_id: t.subject_id,
        object_id: t.object_id,
        predicate: t.predicate,
        confidence: t.confidence,
        disputed: t.disputed === 1,
        subject_name: nameOf(t.subject_id)?.name,
        subject_type: nameOf(t.subject_id)?.type,
        object_name: nameOf(t.object_id)?.name,
        object_type: nameOf(t.object_id)?.type,
      }));

      let memories: Record<string, unknown>[] = [];
      let memoryEntities: Record<string, unknown>[] = [];
      let memoryLinks: Record<string, unknown>[] = [];
      let totalMemories = 0;
      if (includeMemories) {
        const projectClause = project ? 'AND m.project = ?' : '';
        const countParams: unknown[] = project ? [id, project] : [id];
        totalMemories = (db.prepare(`
          SELECT COUNT(*) as c FROM memories m
          JOIN memory_entities me ON me.memory_id = m.id
          WHERE me.entity_id = ? ${projectClause}
        `).get(...countParams) as { c: number }).c;

        const memParams: unknown[] = project ? [id, project, memLimit] : [id, memLimit];
        memories = db.prepare(`
          SELECT ${MEMORY_GRAPH_COLUMNS}
          FROM memories m
          JOIN memory_entities me ON me.memory_id = m.id
          WHERE me.entity_id = ? ${projectClause}
          ORDER BY m.salience DESC, m.created_at DESC, m.id ASC
          LIMIT ?
        `).all(...memParams) as Record<string, unknown>[];

        const memIds = memories.map((m) => m.id as number);
        if (memIds.length > 0) {
          const mPh = memIds.map(() => '?').join(',');
          const ePh = ids.map(() => '?').join(',');
          memoryEntities = db.prepare(`
            SELECT memory_id, entity_id, role FROM memory_entities
            WHERE memory_id IN (${mPh}) AND entity_id IN (${ePh})
          `).all(...memIds, ...ids) as Record<string, unknown>[];

          memoryLinks = db.prepare(`
            SELECT id, source_id, target_id, relationship, strength FROM memory_links
            WHERE source_id IN (${mPh}) AND target_id IN (${mPh})
          `).all(...memIds, ...memIds) as Record<string, unknown>[];
        }
      }

      const neighbours = [...nodeSet.values()]
        .filter((n) => n.id !== id)
        .map((n) => ({ id: n.id, name: n.name, type: n.type, memoryCount: n.memory_count, depth: n.depth }));

      res.json({
        focal,
        neighbours,
        triples: tripleRows,
        totalConnections: totalEdges,
        ...(includeMemories ? { memories, memoryEntities, memoryLinks } : {}),
        counts: {
          totalNeighbours,
          omittedNeighbours: Math.max(0, totalNeighbours - neighbours.filter((n) => n.depth === 1).length),
          totalEdges,
          omittedEdges: Math.max(0, totalEdges - tripleRows.length),
          totalMemories,
          omittedMemories: Math.max(0, totalMemories - memories.length),
        },
      });
    } catch (error) {
      fail(res, error);
    }
  });

  app.get('/api/graph/triples', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const predicate = stringParam(req.query.predicate);
      const project = projectParam(req.query.project);
      const limit = boundedInt(req.query.limit, { min: 1, max: 10000, dflt: 100 });
      const offset = boundedInt(req.query.offset, { min: 0, max: 10_000_000, dflt: 0 });

      // valid_to IS NULL: suspended (operator-rejected) edges are excluded from
      // the browser list AND its total, matching the live-graph views. One
      // clause flows into both the COUNT and the paginated SELECT below.
      // Optional project scope: both endpoints must be in scope (§13.2).
      let whereClause = 'WHERE t.valid_to IS NULL';
      const params: unknown[] = [];
      if (predicate) {
        whereClause += ' AND t.predicate = ?';
        params.push(predicate);
      }
      if (project) {
        whereClause += ` AND ${entityScopeSql('s')} AND ${entityScopeSql('o')}`;
        params.push(project, project);
      }
      const from = `FROM triples t
        JOIN entities s ON s.id = t.subject_id
        JOIN entities o ON o.id = t.object_id
        ${whereClause}`;

      const total = (db.prepare(`SELECT COUNT(*) as count ${from}`).get(...params) as { count: number }).count;
      const triples = db.prepare(`
        SELECT t.*, s.name as subject_name, s.type as subject_type,
               o.name as object_name, o.type as object_type
        ${from}
        ORDER BY t.created_at DESC, t.id DESC
        LIMIT ? OFFSET ?
      `).all(...params, limit, offset) as Record<string, unknown>[];

      res.json({ triples, total, offset, limit, hasMore: offset + limit < total });
    } catch (error) {
      fail(res, error);
    }
  });

  app.get('/api/graph/search', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const q = typeof req.query.q === 'string' ? req.query.q : '';
      const limit = boundedInt(req.query.limit, { min: 1, max: 100, dflt: 20 });
      const project = projectParam(req.query.project);
      if (!q) {
        return res.status(400).json({ error: 'Query parameter "q" is required' });
      }

      let whereClause = 'WHERE LOWER(e.name) LIKE ?';
      const params: unknown[] = [`%${q.toLowerCase()}%`];
      if (project) {
        whereClause += ` AND ${ENTITY_PROJECT_SCOPE_SQL}`;
        params.push(project);
      }

      const rows = db.prepare(
        `SELECT e.* FROM entities e ${whereClause} ORDER BY e.memory_count DESC, e.id ASC LIMIT ?`,
      ).all(...params, limit) as Record<string, unknown>[];

      res.json({
        entities: rows.map((row) => ({
          id: row.id,
          name: row.name,
          type: row.type,
          memoryCount: row.memory_count ?? 0,
          aliases: parseAliases(row.aliases),
        })),
      });
    } catch (error) {
      fail(res, error);
    }
  });

  app.get('/api/graph/paths', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      // v2: numeric ids preferred (entities are only UNIQUE(name,type), so a
      // name can be ambiguous); legacy name params retained.
      const fromIdRaw = req.query.fromId;
      const toIdRaw = req.query.toId;
      const fromName = typeof req.query.from === 'string' ? req.query.from : '';
      const toName = typeof req.query.to === 'string' ? req.query.to : '';
      const project = projectParam(req.query.project);

      if ((fromIdRaw === undefined && !fromName) || (toIdRaw === undefined && !toName)) {
        return res.status(400).json({ error: 'Provide "fromId"/"toId" (preferred) or "from"/"to" query parameters' });
      }
      // A supplied id must parse strictly (positive safe integer) — `12junk`
      // is a client error, not a lookup miss.
      const fromId = fromIdRaw === undefined ? undefined : parseId(fromIdRaw);
      const toId = toIdRaw === undefined ? undefined : parseId(toIdRaw);
      if ((fromIdRaw !== undefined && fromId === undefined) || (toIdRaw !== undefined && toId === undefined)) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }

      // Endpoint resolution, every BFS candidate and the source-memory lookup
      // all apply the same project rule as the other routes, so a scoped path
      // can neither start, end nor pass through an out-of-project entity.
      const scope = project ? `AND ${ENTITY_PROJECT_SCOPE_SQL}` : '';
      const scopeArgs = project ? [project] : [];
      type Endpoint = { id: number; name: string; type: string; memory_count: number };
      const resolve = (id: number | undefined, name: string): Endpoint | undefined => {
        if (id !== undefined) {
          return db.prepare(`SELECT e.id, e.name, e.type, e.memory_count FROM entities e WHERE e.id = ? ${scope}`)
            .get(id, ...scopeArgs) as Endpoint | undefined;
        }
        if (!name) return undefined;
        return db.prepare(
          `SELECT e.id, e.name, e.type, e.memory_count FROM entities e WHERE LOWER(e.name) = LOWER(?) ${scope} ORDER BY e.memory_count DESC, e.id ASC`,
        ).get(name, ...scopeArgs) as Endpoint | undefined;
      };

      const fromRow = resolve(fromId, fromName);
      if (!fromRow) {
        return res.status(404).json({ error: `Entity ${fromId !== undefined ? `#${fromId}` : `"${fromName}"`} not found` });
      }
      const toRow = resolve(toId, toName);
      if (!toRow) {
        return res.status(404).json({ error: `Entity ${toId !== undefined ? `#${toId}` : `"${toName}"`} not found` });
      }

      if (fromRow.id === toRow.id) {
        return res.json({
          path: [{
            entity: fromRow.name, entityId: fromRow.id, predicate: '(self)', direction: '',
            entityType: fromRow.type, memoryCount: fromRow.memory_count, confidence: null, disputed: false,
          }],
          sourceMemories: [],
          truncated: false,
        });
      }

      // Bounded bidirectional BFS: depth ≤ PATH_MAX_DEPTH, distinct visited
      // nodes ≤ PATH_VISIT_BUDGET, per-node fan-out ≤ PATH_FANOUT_LIMIT.
      // Exceeding either budget sets `truncated` so "no path" is never
      // mistaken for "no path exists".
      type Hop = {
        next_id: number; predicate: string; confidence: number; disputed: number;
        source_memory_id: number | null; name: string; type: string; memory_count: number;
      };
      const hopColumns = 't.predicate, t.confidence, t.disputed, t.source_memory_id, e.name, e.type, e.memory_count';
      const outgoingStmt = db.prepare(
        `SELECT t.object_id as next_id, ${hopColumns}
         FROM triples t JOIN entities e ON e.id = t.object_id
         WHERE t.subject_id = ? AND t.valid_to IS NULL ${scope}
         ORDER BY t.id ASC LIMIT ?`,
      );
      const incomingStmt = db.prepare(
        `SELECT t.subject_id as next_id, ${hopColumns}
         FROM triples t JOIN entities e ON e.id = t.subject_id
         WHERE t.object_id = ? AND t.valid_to IS NULL ${scope}
         ORDER BY t.id ASC LIMIT ?`,
      );

      const visited = new Map<number, BFSNode>();
      visited.set(fromRow.id, {
        id: fromRow.id,
        name: fromRow.name,
        type: fromRow.type,
        memoryCount: fromRow.memory_count,
        parentId: null,
        predicate: '',
        direction: '',
        confidence: null,
        disputed: false,
        sourceMemoryId: null,
      });

      let frontier: number[] = [fromRow.id];
      let found = false;
      let truncated = false;

      const expand = (nodeId: number, rows: Hop[], direction: 'forward' | 'reverse', nextFrontier: number[]): void => {
        if (rows.length > PATH_FANOUT_LIMIT) truncated = true;
        for (const row of rows.slice(0, PATH_FANOUT_LIMIT)) {
          if (visited.has(row.next_id)) continue;
          if (visited.size >= PATH_VISIT_BUDGET) {
            truncated = true;
            return;
          }
          visited.set(row.next_id, {
            id: row.next_id,
            name: row.name,
            type: row.type,
            memoryCount: row.memory_count,
            parentId: nodeId,
            // Legacy field keeps the ~ prefix on reverse hops; the `direction`
            // field is the honest signal (a reverse hop is not a reversed claim).
            predicate: direction === 'forward' ? row.predicate : `~${row.predicate}`,
            direction,
            confidence: row.confidence,
            disputed: row.disputed === 1,
            sourceMemoryId: row.source_memory_id,
          });
          nextFrontier.push(row.next_id);
          if (row.next_id === toRow.id) {
            found = true;
            return;
          }
        }
      };

      for (let depth = 0; depth < PATH_MAX_DEPTH && !found; depth++) {
        const nextFrontier: number[] = [];
        for (const nodeId of frontier) {
          if (visited.size >= PATH_VISIT_BUDGET) {
            truncated = true;
            break;
          }
          expand(nodeId, outgoingStmt.all(nodeId, ...scopeArgs, PATH_FANOUT_LIMIT + 1) as Hop[], 'forward', nextFrontier);
          if (found) break;
          expand(nodeId, incomingStmt.all(nodeId, ...scopeArgs, PATH_FANOUT_LIMIT + 1) as Hop[], 'reverse', nextFrontier);
          if (found) break;
        }
        frontier = nextFrontier;
        if (frontier.length === 0) break;
      }

      if (!found) {
        return res.json({
          path: [],
          sourceMemories: [],
          truncated,
          message: truncated ? 'No path found within the search budget' : 'No path found',
        });
      }

      // Each hop carries the REAL entity type/memoryCount and the REAL triple
      // confidence/disputed (review item 4): the client draws the path from
      // this payload alone, so it must be drawable without inventing data.
      type PathHop = {
        entity: string; entityId: number; predicate: string; direction: string;
        entityType: string; memoryCount: number; confidence: number | null; disputed: boolean;
      };
      const path: PathHop[] = [];
      const sourceMemoryIds: number[] = [];
      let current: BFSNode | undefined = visited.get(toRow.id);

      while (current) {
        path.unshift({
          entity: current.name,
          entityId: current.id,
          predicate: current.predicate,
          direction: current.direction,
          entityType: current.type,
          memoryCount: current.memoryCount,
          confidence: current.confidence,
          disputed: current.disputed,
        });
        if (current.sourceMemoryId) sourceMemoryIds.push(current.sourceMemoryId);
        current = current.parentId !== null ? visited.get(current.parentId) : undefined;
      }

      const sourceMemories = sourceMemoryIds.length > 0
        ? db.prepare(
          `SELECT id, title FROM memories WHERE id IN (${sourceMemoryIds.map(() => '?').join(',')})
           ${project ? 'AND project = ?' : ''} ORDER BY id ASC`,
        ).all(...sourceMemoryIds, ...scopeArgs)
        : [];

      res.json({ path, sourceMemories, truncated });
    } catch (error) {
      fail(res, error);
    }
  });
}
