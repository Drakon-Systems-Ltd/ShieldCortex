import { randomUUID } from 'crypto';

/**
 * Insert an auto-extracted memory into the SC database.
 *
 * Single source of truth for hook-side memory writes. Both the pre-compact
 * and session-end hooks call this — keeping them in sync prevents the
 * "one hook works, the other silently fails" bug class (e.g. v4.12.4
 * post-fix where pre-compact and session-end would have drifted).
 *
 * Schema invariant: `memories.uuid` is `TEXT NOT NULL UNIQUE` with no
 * default. Every write path MUST supply a UUID.
 *
 * @param {import('better-sqlite3').Database} db - Open DB handle
 * @param {{ title: string, content: string, category: string, salience: number, tags: string[] }} memory
 * @param {string|null} [project] - Optional project scope
 */
export function saveAutoExtractedMemory(db, memory, project) {
  const timestamp = new Date().toISOString();
  const stmt = db.prepare(`
    INSERT INTO memories (uuid, title, content, type, category, salience, tags, project, created_at, last_accessed)
    VALUES (?, ?, ?, 'short_term', ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    randomUUID(),
    memory.title,
    memory.content,
    memory.category,
    memory.salience,
    JSON.stringify(memory.tags),
    project || null,
    timestamp,
    timestamp,
  );
}
