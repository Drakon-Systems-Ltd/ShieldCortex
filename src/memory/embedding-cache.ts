/**
 * Embedding Cache
 *
 * Stores pre-computed embeddings in SQLite to avoid re-embedding on every recall.
 * Self-migrating: creates the table on first use.
 */

import { getDatabase, isDatabaseInitialized } from '../database/init.js';
import { embedText } from './embedding.js';

const MODEL_VERSION = 'all-MiniLM-L6-v2';

let tableCreated = false;

/**
 * Ensure the memory_embeddings table exists (self-migrating).
 */
function ensureTable(): void {
  if (tableCreated) return;
  if (!isDatabaseInitialized()) return;

  try {
    const db = getDatabase();
    db.exec(`
      CREATE TABLE IF NOT EXISTS memory_embeddings (
        memory_id INTEGER PRIMARY KEY,
        embedding BLOB NOT NULL,
        model_version TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    tableCreated = true;
  } catch (e) {
    console.warn('[shieldcortex] Failed to create memory_embeddings table:', (e as Error).message);
  }
}

/**
 * Get a cached embedding for a memory ID.
 * Returns null if not cached or DB unavailable.
 */
export function getCachedEmbedding(memoryId: number): Float32Array | null {
  try {
    ensureTable();
    if (!isDatabaseInitialized()) return null;

    const db = getDatabase();
    const row = db.prepare(
      'SELECT embedding FROM memory_embeddings WHERE memory_id = ? AND model_version = ?',
    ).get(memoryId, MODEL_VERSION) as { embedding: Buffer } | undefined;

    if (!row) return null;

    const buf = row.embedding;
    return new Float32Array(buf.buffer, buf.byteOffset, buf.byteLength / 4);
  } catch (e) {
    console.warn('[shieldcortex] getCachedEmbedding error:', (e as Error).message);
    return null;
  }
}

/**
 * Store a computed embedding in the cache.
 */
export function setCachedEmbedding(memoryId: number, embedding: Float32Array): void {
  try {
    ensureTable();
    if (!isDatabaseInitialized()) return;

    const db = getDatabase();
    const buffer = Buffer.from(embedding.buffer, embedding.byteOffset, embedding.byteLength);

    db.prepare(`
      INSERT OR REPLACE INTO memory_embeddings (memory_id, embedding, model_version, created_at)
      VALUES (?, ?, ?, datetime('now'))
    `).run(memoryId, buffer, MODEL_VERSION);
  } catch (e) {
    console.warn('[shieldcortex] setCachedEmbedding error:', (e as Error).message);
  }
}

/**
 * Get embedding from cache, or compute + store if missing.
 * Returns null if both cache and computation fail.
 */
export async function getOrComputeEmbedding(
  memoryId: number,
  text: string,
): Promise<Float32Array | null> {
  // Try cache first
  const cached = getCachedEmbedding(memoryId);
  if (cached) return cached;

  // Compute embedding
  const embedding = await embedText(text);
  if (!embedding) return null;

  // Store in cache (best-effort)
  setCachedEmbedding(memoryId, embedding);

  return embedding;
}
