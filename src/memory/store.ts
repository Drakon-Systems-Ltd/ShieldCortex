/**
 * Memory Store
 *
 * Core CRUD operations for the memory database.
 * Handles storage, retrieval, and management of memories.
 */

import { getDatabase } from '../database/init.js';
import {
  Memory,
  MemoryInput,
  MemoryType,
  MemoryCategory,
  SearchOptions,
  SearchResult,
  MemoryConfig,
  DEFAULT_CONFIG,
} from './types.js';
import {
  calculateSalience,
  suggestCategory,
  extractTags,
  analyzeSalienceFactors,
} from './salience.js';
import {
  calculateDecayedScore,
  calculateReinforcementBoost,
  calculatePriority,
} from './decay.js';
import {
  emitMemoryCreated,
  emitMemoryAccessed,
  emitMemoryDeleted,
  emitMemoryUpdated,
} from '../api/events.js';

// Anti-bloat: Maximum content size per memory (10KB)
const MAX_CONTENT_SIZE = 10 * 1024;

/**
 * Truncate content if it exceeds max size
 */
function truncateContent(content: string): string {
  if (content.length > MAX_CONTENT_SIZE) {
    return content.slice(0, MAX_CONTENT_SIZE) + '\n\n[Content truncated - exceeded 10KB limit]';
  }
  return content;
}

/**
 * Escape FTS5 query to prevent syntax errors
 * FTS5 interprets "word-word" as "column:value" syntax
 * We quote individual terms to search them literally
 */
function escapeFts5Query(query: string): string {
  // Split on whitespace, quote each term, rejoin
  // This handles hyphenated words and special characters
  return query
    .split(/\s+/)
    .map(term => {
      // If term contains special FTS5 characters, quote it
      if (/[-:*^()]/.test(term) || term.includes('"')) {
        // Escape existing quotes and wrap in quotes
        return `"${term.replace(/"/g, '""')}"`;
      }
      return term;
    })
    .join(' ');
}

/**
 * Convert database row to Memory object
 */
function rowToMemory(row: Record<string, unknown>): Memory {
  return {
    id: row.id as number,
    type: row.type as MemoryType,
    category: row.category as MemoryCategory,
    title: row.title as string,
    content: row.content as string,
    project: row.project as string | undefined,
    tags: JSON.parse((row.tags as string) || '[]'),
    salience: row.salience as number,
    accessCount: row.access_count as number,
    lastAccessed: new Date(row.last_accessed as string),
    createdAt: new Date(row.created_at as string),
    decayedScore: row.decayed_score as number || row.salience as number,
    metadata: JSON.parse((row.metadata as string) || '{}'),
  };
}

/**
 * Add a new memory
 */
export function addMemory(
  input: MemoryInput,
  config: MemoryConfig = DEFAULT_CONFIG
): Memory {
  const db = getDatabase();

  // Calculate salience if not provided
  const salience = input.salience ?? calculateSalience(input);

  // Suggest category if not provided
  const category = input.category ?? suggestCategory(input);

  // Extract tags
  const tags = extractTags(input);

  // Determine type
  const type = input.type ?? (salience >= config.consolidationThreshold ? 'long_term' : 'short_term');

  const stmt = db.prepare(`
    INSERT INTO memories (type, category, title, content, project, tags, salience, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // Anti-bloat: Truncate content if too large
  const content = truncateContent(input.content);

  const result = stmt.run(
    type,
    category,
    input.title,
    content,
    input.project || null,
    JSON.stringify(tags),
    salience,
    JSON.stringify(input.metadata || {})
  );

  const memory = getMemoryById(result.lastInsertRowid as number)!;

  // Emit event for real-time dashboard
  emitMemoryCreated(memory);

  return memory;
}

/**
 * Get a memory by ID
 */
export function getMemoryById(id: number): Memory | null {
  const db = getDatabase();
  const row = db.prepare('SELECT * FROM memories WHERE id = ?').get(id) as Record<string, unknown> | undefined;
  if (!row) return null;
  return rowToMemory(row);
}

/**
 * Update a memory
 */
export function updateMemory(
  id: number,
  updates: Partial<MemoryInput>
): Memory | null {
  const db = getDatabase();
  const existing = getMemoryById(id);
  if (!existing) return null;

  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.title !== undefined) {
    fields.push('title = ?');
    values.push(updates.title);
  }
  if (updates.content !== undefined) {
    fields.push('content = ?');
    values.push(updates.content);
  }
  if (updates.type !== undefined) {
    fields.push('type = ?');
    values.push(updates.type);
  }
  if (updates.category !== undefined) {
    fields.push('category = ?');
    values.push(updates.category);
  }
  if (updates.project !== undefined) {
    fields.push('project = ?');
    values.push(updates.project);
  }
  if (updates.tags !== undefined) {
    fields.push('tags = ?');
    values.push(JSON.stringify(updates.tags));
  }
  if (updates.salience !== undefined) {
    fields.push('salience = ?');
    values.push(updates.salience);
  }
  if (updates.metadata !== undefined) {
    fields.push('metadata = ?');
    values.push(JSON.stringify(updates.metadata));
  }

  if (fields.length === 0) return existing;

  values.push(id);
  db.prepare(`UPDATE memories SET ${fields.join(', ')} WHERE id = ?`).run(...values);

  const updatedMemory = getMemoryById(id)!;

  // Emit event for real-time dashboard
  emitMemoryUpdated(updatedMemory);

  return updatedMemory;
}

/**
 * Delete a memory
 */
export function deleteMemory(id: number): boolean {
  const db = getDatabase();

  // Get memory before deletion for event
  const memory = getMemoryById(id);

  const result = db.prepare('DELETE FROM memories WHERE id = ?').run(id);

  // Emit event for real-time dashboard
  if (result.changes > 0 && memory) {
    emitMemoryDeleted(id, memory.title);
  }

  return result.changes > 0;
}

/**
 * Access a memory (updates access count and timestamp, returns reinforced memory)
 */
export function accessMemory(
  id: number,
  config: MemoryConfig = DEFAULT_CONFIG
): Memory | null {
  const db = getDatabase();
  const memory = getMemoryById(id);
  if (!memory) return null;

  // Calculate new salience with reinforcement
  const newSalience = calculateReinforcementBoost(memory, config);

  db.prepare(`
    UPDATE memories
    SET access_count = access_count + 1,
        last_accessed = CURRENT_TIMESTAMP,
        salience = ?
    WHERE id = ?
  `).run(newSalience, id);

  const updatedMemory = getMemoryById(id)!;

  // Emit event for real-time dashboard
  emitMemoryAccessed(updatedMemory, newSalience);

  return updatedMemory;
}

/**
 * Search memories using full-text search and filters
 */
export function searchMemories(
  options: SearchOptions,
  config: MemoryConfig = DEFAULT_CONFIG
): SearchResult[] {
  const db = getDatabase();
  const limit = options.limit || 20;

  let sql: string;
  const params: unknown[] = [];

  if (options.query && options.query.trim()) {
    // Use FTS search - escape query to prevent FTS5 syntax errors
    // FTS5 interprets "word-word" as "column:value", so we quote terms
    const escapedQuery = escapeFts5Query(options.query.trim());
    sql = `
      SELECT m.*, fts.rank
      FROM memories m
      JOIN memories_fts fts ON m.id = fts.rowid
      WHERE memories_fts MATCH ?
    `;
    params.push(escapedQuery);
  } else {
    // No query, just filter
    sql = `SELECT *, 0 as rank FROM memories m WHERE 1=1`;
  }

  // Add filters
  if (options.project) {
    sql += ' AND m.project = ?';
    params.push(options.project);
  }
  if (options.category) {
    sql += ' AND m.category = ?';
    params.push(options.category);
  }
  if (options.type) {
    sql += ' AND m.type = ?';
    params.push(options.type);
  }
  if (options.minSalience) {
    sql += ' AND m.salience >= ?';
    params.push(options.minSalience);
  }
  if (options.tags && options.tags.length > 0) {
    // Check if any tag matches
    const tagConditions = options.tags.map(() => "m.tags LIKE ?").join(' OR ');
    sql += ` AND (${tagConditions})`;
    options.tags.forEach(tag => params.push(`%"${tag}"%`));
  }

  sql += ' ORDER BY m.salience DESC, m.last_accessed DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(sql).all(...params) as Record<string, unknown>[];

  // Convert to SearchResult with computed scores
  const results: SearchResult[] = rows.map(row => {
    const memory = rowToMemory(row);
    const decayedScore = calculateDecayedScore(memory, config);
    memory.decayedScore = decayedScore;

    // Calculate relevance score combining FTS rank, salience, and recency
    const ftsScore = row.rank ? Math.abs(row.rank as number) / 100 : 0.5;
    const relevanceScore = (
      ftsScore * 0.4 +
      decayedScore * 0.4 +
      calculatePriority(memory) * 0.2
    );

    return { memory, relevanceScore };
  });

  // Sort by relevance and filter out too-decayed memories
  return results
    .filter(r => options.includeDecayed || r.memory.decayedScore >= config.salienceThreshold)
    .sort((a, b) => b.relevanceScore - a.relevanceScore);
}

/**
 * Get all memories for a project
 */
export function getProjectMemories(
  project: string,
  config: MemoryConfig = DEFAULT_CONFIG
): Memory[] {
  const db = getDatabase();
  const rows = db.prepare(`
    SELECT * FROM memories
    WHERE project = ?
    ORDER BY salience DESC, last_accessed DESC
  `).all(project) as Record<string, unknown>[];

  return rows.map(row => {
    const memory = rowToMemory(row);
    memory.decayedScore = calculateDecayedScore(memory, config);
    return memory;
  });
}

/**
 * Get recent memories
 */
export function getRecentMemories(
  limit: number = 10,
  project?: string
): Memory[] {
  const db = getDatabase();
  let sql = 'SELECT * FROM memories';
  const params: unknown[] = [];

  if (project) {
    sql += ' WHERE project = ?';
    params.push(project);
  }

  sql += ' ORDER BY last_accessed DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(sql).all(...params) as Record<string, unknown>[];
  return rows.map(rowToMemory);
}

/**
 * Get memories by type
 */
export function getMemoriesByType(
  type: MemoryType,
  limit: number = 50
): Memory[] {
  const db = getDatabase();
  const rows = db.prepare(`
    SELECT * FROM memories
    WHERE type = ?
    ORDER BY salience DESC, last_accessed DESC
    LIMIT ?
  `).all(type, limit) as Record<string, unknown>[];

  return rows.map(rowToMemory);
}

/**
 * Get high-priority memories (for context injection)
 */
export function getHighPriorityMemories(
  limit: number = 10,
  project?: string
): Memory[] {
  const db = getDatabase();
  let sql = `
    SELECT * FROM memories
    WHERE salience >= 0.6
  `;
  const params: unknown[] = [];

  if (project) {
    sql += ' AND project = ?';
    params.push(project);
  }

  sql += ' ORDER BY salience DESC, last_accessed DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(sql).all(...params) as Record<string, unknown>[];
  return rows.map(rowToMemory);
}

/**
 * Promote a memory from short-term to long-term
 */
export function promoteMemory(id: number): Memory | null {
  const db = getDatabase();
  db.prepare(`
    UPDATE memories
    SET type = 'long_term'
    WHERE id = ? AND type = 'short_term'
  `).run(id);

  return getMemoryById(id);
}

/**
 * Bulk delete decayed memories
 */
export function cleanupDecayedMemories(
  config: MemoryConfig = DEFAULT_CONFIG
): number {
  const db = getDatabase();

  // Get all short-term memories and check decay
  const shortTerm = getMemoriesByType('short_term', 1000);
  const toDelete: number[] = [];

  for (const memory of shortTerm) {
    const decayedScore = calculateDecayedScore(memory, config);
    if (decayedScore < config.salienceThreshold) {
      toDelete.push(memory.id);
    }
  }

  if (toDelete.length > 0) {
    const placeholders = toDelete.map(() => '?').join(',');
    db.prepare(`DELETE FROM memories WHERE id IN (${placeholders})`).run(...toDelete);
  }

  return toDelete.length;
}

/**
 * Get memory statistics
 */
export function getMemoryStats(project?: string): {
  total: number;
  shortTerm: number;
  longTerm: number;
  episodic: number;
  byCategory: Record<string, number>;
  averageSalience: number;
} {
  const db = getDatabase();

  let whereClause = '';
  const params: unknown[] = [];
  if (project) {
    whereClause = 'WHERE project = ?';
    params.push(project);
  }

  const total = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause}`).get(...params) as { count: number }).count;

  const shortTerm = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause} ${whereClause ? 'AND' : 'WHERE'} type = 'short_term'`).get(...params) as { count: number }).count;

  const longTerm = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause} ${whereClause ? 'AND' : 'WHERE'} type = 'long_term'`).get(...params) as { count: number }).count;

  const episodic = (db.prepare(`SELECT COUNT(*) as count FROM memories ${whereClause} ${whereClause ? 'AND' : 'WHERE'} type = 'episodic'`).get(...params) as { count: number }).count;

  const avgResult = db.prepare(`SELECT AVG(salience) as avg FROM memories ${whereClause}`).get(...params) as { avg: number | null };
  const averageSalience = avgResult.avg || 0;

  // Get counts by category
  const categoryRows = db.prepare(`
    SELECT category, COUNT(*) as count
    FROM memories ${whereClause}
    GROUP BY category
  `).all(...params) as { category: string; count: number }[];

  const byCategory: Record<string, number> = {};
  for (const row of categoryRows) {
    byCategory[row.category] = row.count;
  }

  return {
    total,
    shortTerm,
    longTerm,
    episodic,
    byCategory,
    averageSalience,
  };
}
