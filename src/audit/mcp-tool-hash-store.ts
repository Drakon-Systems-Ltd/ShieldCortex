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
