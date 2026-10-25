import type Database from 'better-sqlite3';
import type { ToolHashStore } from './mcp-tools-scanner.js';

/**
 * SQLite-backed hash store over the `mcp_tool_hashes` table. Persists the
 * per-(server,tool) content hash between scans so drift survives process exit.
 */
export class SqliteToolHashStore implements ToolHashStore {
  private readonly getStmt;
  private readonly upsertStmt;

  constructor(private readonly db: Database.Database) {
    this.getStmt = db.prepare(
      'SELECT content_hash FROM mcp_tool_hashes WHERE server_name = ? AND tool_name = ?',
    );
    // ON CONFLICT keeps first_seen, refreshes last_seen always, and bumps
    // last_changed only when the hash actually changed.
    this.upsertStmt = db.prepare(`
      INSERT INTO mcp_tool_hashes (server_name, tool_name, content_hash, first_seen, last_seen, last_changed)
      VALUES (@server, @tool, @hash, @now, @now, CASE WHEN @changed = 1 THEN @now ELSE NULL END)
      ON CONFLICT(server_name, tool_name) DO UPDATE SET
        content_hash = @hash,
        last_seen = @now,
        last_changed = CASE WHEN @changed = 1 THEN @now ELSE last_changed END
    `);
  }

  get(server: string, tool: string): string | undefined {
    const row = this.getStmt.get(server, tool) as { content_hash: string } | undefined;
    return row?.content_hash;
  }

  set(server: string, tool: string, hash: string, changed: boolean): void {
    this.upsertStmt.run({ server, tool, hash, changed: changed ? 1 : 0, now: new Date().toISOString() });
  }
}

/** Separator between source identity and server name in a scoped baseline key. */
const SCOPE_SEP = '\u0000';

/** Baseline key for a server as defined in one config source (#925). */
export function scopedServerKey(sourcePath: string, serverName: string): string {
  return `src${SCOPE_SEP}${sourcePath}${SCOPE_SEP}${serverName}`;
}

/**
 * View of a hash store whose baselines belong to ONE config source. The same
 * server name defined in a project config and a global config therefore has two
 * independent baselines: a repo-local server cannot poison, or false-alert
 * against, the global one.
 */
export function scopeHashStore(store: ToolHashStore, sourcePath: string): ToolHashStore {
  return {
    get: (server, tool) => store.get(scopedServerKey(sourcePath, server), tool),
    set: (server, tool, hash, changed) => store.set(scopedServerKey(sourcePath, server), tool, hash, changed),
  };
}

/**
 * One-off migration of pre-scoping rows, which are keyed by bare server name.
 * Each legacy hash is seeded into EVERY source that currently defines that
 * server name, so each source compares against it on its first scan and alerts
 * on a mismatch: no silent fresh baseline, even when two sources collide.
 * A fresh baseline only happens where there is no legacy row at all.
 * Legacy rows for names no source defines are left untouched until one does.
 * Idempotent: seeded rows are never overwritten and the legacy row is removed
 * only once it has been seeded somewhere.
 */
export function migrateLegacyToolHashes(
  db: Database.Database,
  definers: ReadonlyArray<{ name: string; sourcePath: string }>,
): number {
  const sourcesByName = new Map<string, Set<string>>();
  for (const d of definers) {
    const set = sourcesByName.get(d.name) ?? new Set<string>();
    set.add(d.sourcePath);
    sourcesByName.set(d.name, set);
  }
  if (sourcesByName.size === 0) return 0;

  const legacy = db.prepare(
    `SELECT server_name, tool_name, content_hash, first_seen, last_seen, last_changed
       FROM mcp_tool_hashes WHERE server_name NOT LIKE 'src' || char(0) || '%'`,
  ).all() as Array<{ server_name: string; tool_name: string; content_hash: string; first_seen: string | null; last_seen: string | null; last_changed: string | null }>;
  const seed = db.prepare(
    `INSERT OR IGNORE INTO mcp_tool_hashes (server_name, tool_name, content_hash, first_seen, last_seen, last_changed)
     VALUES (?, ?, ?, ?, ?, ?)`,
  );
  const drop = db.prepare('DELETE FROM mcp_tool_hashes WHERE server_name = ? AND tool_name = ?');

  let migrated = 0;
  db.transaction(() => {
    for (const row of legacy) {
      const sources = sourcesByName.get(row.server_name);
      if (!sources) continue;
      for (const sourcePath of sources) {
        seed.run(scopedServerKey(sourcePath, row.server_name), row.tool_name, row.content_hash, row.first_seen, row.last_seen, row.last_changed);
      }
      drop.run(row.server_name, row.tool_name);
      migrated++;
    }
  })();
  return migrated;
}
