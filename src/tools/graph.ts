/**
 * Knowledge Graph query tools
 *
 * Provides BFS traversal, entity listing, and path-finding
 * over the entities/triples tables.
 */

import { getDatabase } from '../database/init.js';

interface EntityInfo {
  id: number;
  name: string;
  type: string;
  memoryCount: number;
  aliases?: string[];
}

interface Connection {
  predicate: string;
  direction: 'outgoing' | 'incoming';
  entity: { id: number; name: string; type: string };
  depth: number;
}

function mcpText(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

/**
 * Traverse the knowledge graph from a starting entity using BFS.
 */
export function handleGraphQuery(args: {
  entity: string;
  depth?: number;
  predicates?: string[];
}) {
  const db = getDatabase();
  const maxDepth = args.depth ?? 2;
  const predicateFilter = args.predicates ?? null;

  // Find entity
  const entityRow = db.prepare(
    'SELECT * FROM entities WHERE LOWER(name) = LOWER(?)'
  ).get(args.entity) as any;

  if (!entityRow) {
    return mcpText({ error: `Entity "${args.entity}" not found in knowledge graph.` });
  }

  const rootEntity: EntityInfo = {
    id: entityRow.id,
    name: entityRow.name,
    type: entityRow.type,
    memoryCount: entityRow.memory_count ?? 0,
  };

  // BFS
  const connections: Connection[] = [];
  const visited = new Set<number>([entityRow.id]);
  let frontier: number[] = [entityRow.id];

  for (let d = 1; d <= maxDepth; d++) {
    const nextFrontier: number[] = [];

    for (const nodeId of frontier) {
      // Outgoing
      const outgoing = db.prepare(
        'SELECT t.*, e.name, e.type FROM triples t JOIN entities e ON e.id = t.object_id WHERE t.subject_id = ?'
      ).all(nodeId) as any[];

      for (const row of outgoing) {
        if (predicateFilter && !predicateFilter.includes(row.predicate)) continue;
        connections.push({
          predicate: row.predicate,
          direction: 'outgoing',
          entity: { id: row.object_id, name: row.name, type: row.type },
          depth: d,
        });
        if (!visited.has(row.object_id)) {
          visited.add(row.object_id);
          nextFrontier.push(row.object_id);
        }
      }

      // Incoming
      const incoming = db.prepare(
        'SELECT t.*, e.name, e.type FROM triples t JOIN entities e ON e.id = t.subject_id WHERE t.object_id = ?'
      ).all(nodeId) as any[];

      for (const row of incoming) {
        if (predicateFilter && !predicateFilter.includes(row.predicate)) continue;
        connections.push({
          predicate: row.predicate,
          direction: 'incoming',
          entity: { id: row.subject_id, name: row.name, type: row.type },
          depth: d,
        });
        if (!visited.has(row.subject_id)) {
          visited.add(row.subject_id);
          nextFrontier.push(row.subject_id);
        }
      }
    }

    frontier = nextFrontier;
    if (frontier.length === 0) break;
  }

  return mcpText({ entity: rootEntity, connections });
}

/**
 * List entities in the knowledge graph.
 */
export function handleGraphEntities(args: {
  type?: string;
  minMentions?: number;
  limit?: number;
}) {
  const db = getDatabase();
  const minMentions = args.minMentions ?? 1;
  const limit = args.limit ?? 50;

  let query = 'SELECT * FROM entities WHERE 1=1';
  const params: any[] = [];

  if (args.type) {
    query += ' AND type = ?';
    params.push(args.type);
  }

  query += ' AND memory_count >= ?';
  params.push(minMentions);

  query += ' ORDER BY memory_count DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(query).all(...params) as any[];

  const entities: EntityInfo[] = rows.map((r) => {
    let aliases: string[] = [];
    try {
      aliases = JSON.parse(r.aliases || '[]');
    } catch {
      aliases = [];
    }
    return {
      id: r.id,
      name: r.name,
      type: r.type,
      memoryCount: r.memory_count ?? 0,
      aliases,
    };
  });

  return mcpText({ entities });
}

/**
 * Find paths between two entities via BFS.
 */
export function handleGraphExplain(args: {
  from: string;
  to: string;
  maxDepth?: number;
}) {
  const db = getDatabase();
  const maxDepth = args.maxDepth ?? 4;

  // Resolve entities
  const fromRow = db.prepare(
    'SELECT * FROM entities WHERE LOWER(name) = LOWER(?)'
  ).get(args.from) as any;

  if (!fromRow) {
    return mcpText({ error: `Source entity "${args.from}" not found.` });
  }

  const toRow = db.prepare(
    'SELECT * FROM entities WHERE LOWER(name) = LOWER(?)'
  ).get(args.to) as any;

  if (!toRow) {
    return mcpText({ error: `Target entity "${args.to}" not found.` });
  }

  if (fromRow.id === toRow.id) {
    return mcpText({ paths: [{ hops: [{ entity: fromRow.name, predicate: '(self)' }] }], sourceMemories: [] });
  }

  // BFS to find path
  interface BFSNode {
    id: number;
    name: string;
    parentId: number | null;
    predicate: string;
    sourceMemoryId: number | null;
  }

  const visited = new Map<number, BFSNode>();
  visited.set(fromRow.id, { id: fromRow.id, name: fromRow.name, parentId: null, predicate: '', sourceMemoryId: null });

  let frontier: number[] = [fromRow.id];
  let found = false;

  for (let d = 0; d < maxDepth && !found; d++) {
    const nextFrontier: number[] = [];

    for (const nodeId of frontier) {
      // Outgoing
      const outgoing = db.prepare(
        'SELECT t.object_id as next_id, t.predicate, t.source_memory_id, e.name FROM triples t JOIN entities e ON e.id = t.object_id WHERE t.subject_id = ?'
      ).all(nodeId) as any[];

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
          if (row.next_id === toRow.id) { found = true; break; }
        }
      }
      if (found) break;

      // Incoming
      const incoming = db.prepare(
        'SELECT t.subject_id as next_id, t.predicate, t.source_memory_id, e.name FROM triples t JOIN entities e ON e.id = t.subject_id WHERE t.object_id = ?'
      ).all(nodeId) as any[];

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
          if (row.next_id === toRow.id) { found = true; break; }
        }
      }
      if (found) break;
    }

    frontier = nextFrontier;
    if (frontier.length === 0) break;
  }

  if (!found) {
    return mcpText({ paths: [], sourceMemories: [], message: `No path found between "${args.from}" and "${args.to}" within ${maxDepth} hops.` });
  }

  // Reconstruct path
  const hops: { entity: string; predicate: string }[] = [];
  const memoryIds = new Set<number>();
  let current = toRow.id;

  while (current !== null) {
    const node = visited.get(current)!;
    hops.unshift({ entity: node.name, predicate: node.predicate });
    if (node.sourceMemoryId) memoryIds.add(node.sourceMemoryId);
    current = node.parentId!;
    if (current === null || node.parentId === null) break;
  }

  // Fetch source memories
  let sourceMemories: { id: number; title: string }[] = [];
  if (memoryIds.size > 0) {
    const ids = Array.from(memoryIds);
    const placeholders = ids.map(() => '?').join(',');
    sourceMemories = db.prepare(
      `SELECT id, title FROM memories WHERE id IN (${placeholders})`
    ).all(...ids) as any[];
  }

  return mcpText({ paths: [{ hops }], sourceMemories });
}
