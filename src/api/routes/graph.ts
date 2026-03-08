import type { Express, Request, Response } from 'express';
import { getDatabase } from '../../database/init.js';

type Middleware = (_req: Request, res: Response, next: (err?: unknown) => void) => void;

type BFSNode = {
  id: number;
  name: string;
  parentId: number | null;
  predicate: string;
  sourceMemoryId: number | null;
};

function parseAliases(raw: unknown): string[] {
  try {
    return JSON.parse((raw as string) || '[]');
  } catch {
    return [];
  }
}

export function registerGraphRoutes(app: Express, requireNotLocked: Middleware): void {
  app.get('/api/graph/entities', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const type = typeof req.query.type === 'string' ? req.query.type : undefined;
      const minMentions = typeof req.query.minMentions === 'string' ? parseInt(req.query.minMentions, 10) : 0;
      const limit = typeof req.query.limit === 'string' ? Math.min(parseInt(req.query.limit, 10), 500) : 100;
      const offset = typeof req.query.offset === 'string' ? parseInt(req.query.offset, 10) : 0;

      let whereClause = 'WHERE 1=1';
      const params: unknown[] = [];

      if (type) {
        whereClause += ' AND type = ?';
        params.push(type);
      }
      if (minMentions > 0) {
        whereClause += ' AND memory_count >= ?';
        params.push(minMentions);
      }

      const total = (db.prepare(`SELECT COUNT(*) as count FROM entities ${whereClause}`).get(...params) as { count: number }).count;
      const rows = db.prepare(
        `SELECT * FROM entities ${whereClause} ORDER BY memory_count DESC LIMIT ? OFFSET ?`,
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
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/graph/entities/:id/triples', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseInt(req.params.id as string, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }

      const rows = db.prepare(`
        SELECT t.*, s.name as subject_name, s.type as subject_type,
               o.name as object_name, o.type as object_type
        FROM triples t
        JOIN entities s ON s.id = t.subject_id
        JOIN entities o ON o.id = t.object_id
        WHERE t.subject_id = ? OR t.object_id = ?
        ORDER BY t.created_at DESC
      `).all(id, id) as Record<string, unknown>[];

      res.json({ triples: rows });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/graph/entities/:id/memories', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseInt(req.params.id as string, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }

      const rows = db.prepare(`
        SELECT m.id, m.title, m.type, m.category, m.salience, m.created_at
        FROM memories m
        JOIN memory_entities me ON me.memory_id = m.id
        WHERE me.entity_id = ?
        ORDER BY m.salience DESC, m.created_at DESC
        LIMIT 50
      `).all(id) as Record<string, unknown>[];

      res.json({ memories: rows });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/graph/entities/:id/neighbourhood', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const id = parseInt(req.params.id as string, 10);
      if (Number.isNaN(id)) {
        return res.status(400).json({ error: 'Invalid entity ID' });
      }

      const focal = db.prepare(
        'SELECT id, name, type, memory_count as memoryCount, aliases FROM entities WHERE id = ?',
      ).get(id) as Record<string, unknown> | undefined;
      if (!focal) {
        return res.status(404).json({ error: 'Entity not found' });
      }
      focal.aliases = parseAliases(focal.aliases);

      const triplesAll = db.prepare(`
        SELECT t.id, t.subject_id, t.object_id, t.predicate,
               s.name as subject_name, s.type as subject_type, s.memory_count as subject_count,
               o.name as object_name, o.type as object_type, o.memory_count as object_count
        FROM triples t
        JOIN entities s ON s.id = t.subject_id
        JOIN entities o ON o.id = t.object_id
        WHERE (t.subject_id = ? OR t.object_id = ?)
        ORDER BY
          CASE WHEN t.predicate != 'related_to' THEN 0 ELSE 1 END,
          CASE WHEN t.subject_id = ? THEN o.memory_count ELSE s.memory_count END DESC
      `).all(id, id, id) as Record<string, unknown>[];

      const neighbourIds = new Map<number, { predicate: string; count: number }>();
      const meaningfulTriples: Record<string, unknown>[] = [];
      const relatedToTriples: Record<string, unknown>[] = [];

      for (const triple of triplesAll) {
        const neighbourId = triple.subject_id === id ? triple.object_id as number : triple.subject_id as number;
        const count = triple.subject_id === id ? triple.object_count as number : triple.subject_count as number;
        if (neighbourId === id) continue;

        if (triple.predicate !== 'related_to') {
          meaningfulTriples.push(triple);
          if (!neighbourIds.has(neighbourId)) {
            neighbourIds.set(neighbourId, { predicate: triple.predicate as string, count });
          }
        } else {
          relatedToTriples.push(triple);
        }
      }

      for (const triple of relatedToTriples) {
        if (neighbourIds.size >= 25) break;
        const neighbourId = triple.subject_id === id ? triple.object_id as number : triple.subject_id as number;
        const count = triple.subject_id === id ? triple.object_count as number : triple.subject_count as number;
        if (!neighbourIds.has(neighbourId)) {
          neighbourIds.set(neighbourId, { predicate: 'related_to', count });
        }
      }

      const includedTriples = [
        ...meaningfulTriples.filter((triple) => {
          const neighbourId = triple.subject_id === id ? triple.object_id as number : triple.subject_id as number;
          return neighbourIds.has(neighbourId);
        }),
        ...relatedToTriples.filter((triple) => {
          const neighbourId = triple.subject_id === id ? triple.object_id as number : triple.subject_id as number;
          return neighbourIds.has(neighbourId);
        }),
      ];

      const seenTriples = new Set<number>();
      const uniqueTriples = includedTriples.filter((triple) => {
        if (seenTriples.has(triple.id as number)) return false;
        seenTriples.add(triple.id as number);
        return true;
      });

      const neighbours: Record<string, unknown>[] = [];
      if (neighbourIds.size > 0) {
        const ids = [...neighbourIds.keys()];
        const placeholders = ids.map(() => '?').join(',');
        const rows = db.prepare(`
          SELECT id, name, type, memory_count as memoryCount, aliases
          FROM entities WHERE id IN (${placeholders})
        `).all(...ids) as Record<string, unknown>[];
        for (const row of rows) {
          row.aliases = parseAliases(row.aliases);
          neighbours.push(row);
        }
      }

      res.json({
        focal,
        neighbours,
        triples: uniqueTriples,
        totalConnections: triplesAll.length,
      });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/graph/triples', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const predicate = typeof req.query.predicate === 'string' ? req.query.predicate : undefined;
      const limit = typeof req.query.limit === 'string' ? Math.min(parseInt(req.query.limit, 10), 10000) : 100;
      const offset = typeof req.query.offset === 'string' ? parseInt(req.query.offset, 10) : 0;

      let whereClause = '';
      const params: unknown[] = [];
      if (predicate) {
        whereClause = 'WHERE t.predicate = ?';
        params.push(predicate);
      }

      const total = (db.prepare(`SELECT COUNT(*) as count FROM triples t ${whereClause}`).get(...params) as { count: number }).count;
      const triples = db.prepare(`
        SELECT t.*, s.name as subject_name, s.type as subject_type,
               o.name as object_name, o.type as object_type
        FROM triples t
        JOIN entities s ON s.id = t.subject_id
        JOIN entities o ON o.id = t.object_id
        ${whereClause}
        ORDER BY t.created_at DESC
        LIMIT ? OFFSET ?
      `).all(...params, limit, offset) as Record<string, unknown>[];

      res.json({ triples, total, offset, limit, hasMore: offset + limit < total });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/graph/search', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const q = typeof req.query.q === 'string' ? req.query.q : '';
      if (!q) {
        return res.status(400).json({ error: 'Query parameter "q" is required' });
      }

      const rows = db.prepare(
        `SELECT * FROM entities WHERE LOWER(name) LIKE ? ORDER BY memory_count DESC LIMIT 20`,
      ).all(`%${q.toLowerCase()}%`) as Record<string, unknown>[];

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
      res.status(500).json({ error: (error as Error).message });
    }
  });

  app.get('/api/graph/paths', requireNotLocked, (req: Request, res: Response) => {
    try {
      const db = getDatabase();
      const fromName = typeof req.query.from === 'string' ? req.query.from : '';
      const toName = typeof req.query.to === 'string' ? req.query.to : '';

      if (!fromName || !toName) {
        return res.status(400).json({ error: 'Both "from" and "to" query parameters are required' });
      }

      const fromRow = db.prepare('SELECT * FROM entities WHERE LOWER(name) = LOWER(?)').get(fromName) as { id: number; name: string } | undefined;
      if (!fromRow) {
        return res.status(404).json({ error: `Entity "${fromName}" not found` });
      }

      const toRow = db.prepare('SELECT * FROM entities WHERE LOWER(name) = LOWER(?)').get(toName) as { id: number; name: string } | undefined;
      if (!toRow) {
        return res.status(404).json({ error: `Entity "${toName}" not found` });
      }

      if (fromRow.id === toRow.id) {
        return res.json({ path: [{ entity: fromRow.name, predicate: '(self)' }], sourceMemories: [] });
      }

      const maxDepth = 4;
      const visited = new Map<number, BFSNode>();
      visited.set(fromRow.id, {
        id: fromRow.id,
        name: fromRow.name,
        parentId: null,
        predicate: '',
        sourceMemoryId: null,
      });

      let frontier: number[] = [fromRow.id];
      let found = false;

      for (let depth = 0; depth < maxDepth && !found; depth++) {
        const nextFrontier: number[] = [];
        for (const nodeId of frontier) {
          const outgoing = db.prepare(
            'SELECT t.object_id as next_id, t.predicate, t.source_memory_id, e.name FROM triples t JOIN entities e ON e.id = t.object_id WHERE t.subject_id = ?',
          ).all(nodeId) as Array<{ next_id: number; predicate: string; source_memory_id: number | null; name: string }>;
          for (const row of outgoing) {
            if (!visited.has(row.next_id)) {
              visited.set(row.next_id, {
                id: row.next_id,
                name: row.name,
                parentId: nodeId,
                predicate: row.predicate,
                sourceMemoryId: row.source_memory_id,
              });
              nextFrontier.push(row.next_id);
              if (row.next_id === toRow.id) {
                found = true;
                break;
              }
            }
          }
          if (found) break;

          const incoming = db.prepare(
            'SELECT t.subject_id as next_id, t.predicate, t.source_memory_id, e.name FROM triples t JOIN entities e ON e.id = t.subject_id WHERE t.object_id = ?',
          ).all(nodeId) as Array<{ next_id: number; predicate: string; source_memory_id: number | null; name: string }>;
          for (const row of incoming) {
            if (!visited.has(row.next_id)) {
              visited.set(row.next_id, {
                id: row.next_id,
                name: row.name,
                parentId: nodeId,
                predicate: `~${row.predicate}`,
                sourceMemoryId: row.source_memory_id,
              });
              nextFrontier.push(row.next_id);
              if (row.next_id === toRow.id) {
                found = true;
                break;
              }
            }
          }
          if (found) break;
        }
        frontier = nextFrontier;
        if (frontier.length === 0) break;
      }

      if (!found) {
        return res.json({ path: [], sourceMemories: [], message: 'No path found' });
      }

      const path: Array<{ entity: string; predicate: string }> = [];
      const sourceMemoryIds: number[] = [];
      let current: BFSNode | undefined = visited.get(toRow.id);

      while (current) {
        path.unshift({ entity: current.name, predicate: current.predicate });
        if (current.sourceMemoryId) sourceMemoryIds.push(current.sourceMemoryId);
        current = current.parentId !== null ? visited.get(current.parentId) : undefined;
      }

      const sourceMemories = sourceMemoryIds.length > 0
        ? db.prepare(`SELECT id, title FROM memories WHERE id IN (${sourceMemoryIds.map(() => '?').join(',')})`).all(...sourceMemoryIds)
        : [];

      res.json({ path, sourceMemories });
    } catch (error) {
      res.status(500).json({ error: (error as Error).message });
    }
  });
}
