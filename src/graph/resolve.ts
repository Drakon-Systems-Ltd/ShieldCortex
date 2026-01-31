import { getDatabase } from '../database/init.js';
import type { EntityType, ExtractionResult } from './extract.js';

export function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

export function resolveEntity(name: string, type: EntityType): number {
  const db = getDatabase();

  // 1. Exact match
  const exact = db.prepare('SELECT id FROM entities WHERE name = ? AND type = ?').get(name, type) as { id: number } | undefined;
  if (exact) return exact.id;

  // 2. Case-insensitive match
  const ciMatch = db.prepare('SELECT id FROM entities WHERE LOWER(name) = LOWER(?) AND type = ?').get(name, type) as { id: number } | undefined;
  if (ciMatch) return ciMatch.id;

  // 3. Alias match
  const aliasRows = db.prepare('SELECT id, aliases FROM entities WHERE type = ?').all(type) as { id: number; aliases: string | null }[];
  const nameLower = name.toLowerCase();
  for (const row of aliasRows) {
    if (!row.aliases) continue;
    const aliases: string[] = JSON.parse(row.aliases);
    if (aliases.some(a => a.toLowerCase() === nameLower)) {
      // Append input name as alias if not present
      if (!aliases.some(a => a.toLowerCase() === nameLower)) {
        // already matched, so it's present — skip
      }
      // Add the original casing if not already there
      if (!aliases.includes(name)) {
        aliases.push(name);
        db.prepare('UPDATE entities SET aliases = ? WHERE id = ?').run(JSON.stringify(aliases), row.id);
      }
      return row.id;
    }
  }

  // 4. Fuzzy match (names > 5 chars)
  if (name.length > 5) {
    const candidates = db.prepare('SELECT id, name, aliases FROM entities WHERE type = ? AND LENGTH(name) BETWEEN ? AND ?')
      .all(type, name.length - 2, name.length + 2) as { id: number; name: string; aliases: string | null }[];
    for (const cand of candidates) {
      if (levenshtein(name.toLowerCase(), cand.name.toLowerCase()) <= 2) {
        // Append input name as alias
        const aliases: string[] = cand.aliases ? JSON.parse(cand.aliases) : [];
        if (!aliases.includes(name)) {
          aliases.push(name);
          db.prepare('UPDATE entities SET aliases = ? WHERE id = ?').run(JSON.stringify(aliases), cand.id);
        }
        return cand.id;
      }
    }
  }

  // 5. No match — insert
  const result = db.prepare('INSERT INTO entities (name, type) VALUES (?, ?)').run(name, type);
  return Number(result.lastInsertRowid);
}

export function mergeEntities(keepId: number, removeId: number): void {
  const db = getDatabase();

  db.transaction(() => {
    // Reassign triples
    db.prepare('UPDATE OR IGNORE triples SET subject_id = ? WHERE subject_id = ?').run(keepId, removeId);
    db.prepare('UPDATE OR IGNORE triples SET object_id = ? WHERE object_id = ?').run(keepId, removeId);

    // Reassign memory_entities
    db.prepare('UPDATE OR IGNORE memory_entities SET entity_id = ? WHERE entity_id = ?').run(keepId, removeId);

    // Delete remaining references to removeId
    db.prepare('DELETE FROM triples WHERE subject_id = ? OR object_id = ?').run(removeId, removeId);
    db.prepare('DELETE FROM memory_entities WHERE entity_id = ?').run(removeId);

    // Merge aliases
    const keepRow = db.prepare('SELECT name, aliases, memory_count FROM entities WHERE id = ?').get(keepId) as { name: string; aliases: string | null; memory_count: number };
    const removeRow = db.prepare('SELECT name, aliases, memory_count FROM entities WHERE id = ?').get(removeId) as { name: string; aliases: string | null; memory_count: number };

    const keepAliases: string[] = keepRow.aliases ? JSON.parse(keepRow.aliases) : [];
    const removeAliases: string[] = removeRow.aliases ? JSON.parse(removeRow.aliases) : [];
    const allAliases = new Set([...keepAliases, ...removeAliases, removeRow.name]);
    allAliases.delete(keepRow.name); // don't include the kept entity's own name
    const mergedAliases = [...allAliases];

    // Update keepId
    db.prepare('UPDATE entities SET aliases = ?, memory_count = ? WHERE id = ?')
      .run(JSON.stringify(mergedAliases), keepRow.memory_count + removeRow.memory_count, keepId);

    // Delete removed entity
    db.prepare('DELETE FROM entities WHERE id = ?').run(removeId);
  })();
}

export function processExtractionResult(result: ExtractionResult, memoryId: number): void {
  const db = getDatabase();
  const nameToId = new Map<string, number>();

  // 1. Resolve all entities
  for (const entity of result.entities) {
    const entityId = resolveEntity(entity.name, entity.type);
    nameToId.set(entity.name, entityId);
  }

  // 2. Link entities to memory
  const insertMemEntity = db.prepare('INSERT OR IGNORE INTO memory_entities (memory_id, entity_id, role) VALUES (?, ?, ?)');
  for (const entity of result.entities) {
    const entityId = nameToId.get(entity.name)!;
    insertMemEntity.run(memoryId, entityId, 'mention');
  }

  // 3. Insert triples
  const insertTriple = db.prepare('INSERT OR IGNORE INTO triples (subject_id, predicate, object_id, source_memory_id) VALUES (?, ?, ?, ?)');
  for (const triple of result.triples) {
    const subjectId = nameToId.get(triple.subject);
    const objectId = nameToId.get(triple.object);
    if (subjectId !== undefined && objectId !== undefined) {
      insertTriple.run(subjectId, triple.predicate, objectId, memoryId);
    }
  }

  // 4. Increment memory_count for each unique entity
  const updateCount = db.prepare('UPDATE entities SET memory_count = memory_count + 1 WHERE id = ?');
  const uniqueIds = new Set(nameToId.values());
  for (const id of uniqueIds) {
    updateCount.run(id);
  }
}
