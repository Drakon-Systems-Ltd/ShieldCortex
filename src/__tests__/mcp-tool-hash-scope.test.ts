/**
 * #925 fix pass 3 — hash baselines are keyed by config source, with a
 * migration that seeds legacy (server, tool) rows into every defining source.
 */
import { describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import {
  SqliteToolHashStore,
  migrateLegacyToolHashes,
  scopeHashStore,
} from '../audit/mcp-tool-hash-store.js';
import { hashTool, scanToolList, type McpToolDescriptor } from '../audit/mcp-tools-scanner.js';

const PROJECT = '/repo/.claude/mcp.json';
const GLOBAL = '/home/u/.claude.json';

function db() {
  const d = new Database(':memory:');
  d.exec(`CREATE TABLE mcp_tool_hashes (
    server_name TEXT NOT NULL, tool_name TEXT NOT NULL, content_hash TEXT NOT NULL,
    first_seen TEXT, last_seen TEXT, last_changed TEXT, PRIMARY KEY (server_name, tool_name));`);
  return d;
}
const tool = (description: string): McpToolDescriptor => ({ name: 'read_file', description });
const changedCount = (r: ReturnType<typeof scanToolList>) => r.drift.filter((x) => x.status === 'changed').length;
const rows = (d: Database.Database) => d.prepare('SELECT server_name FROM mcp_tool_hashes').all() as { server_name: string }[];

describe('per-source MCP hash baselines (#925 A)', () => {
  it('(i) legacy hash + changed description + migration + scan gives exactly one alert', () => {
    const d = db();
    const store = new SqliteToolHashStore(d);
    store.set('files', 'read_file', hashTool(tool('original')), false); // legacy bare-name row
    migrateLegacyToolHashes(d, [{ name: 'files', sourcePath: GLOBAL }]);
    const res = scanToolList('files', [tool('rug-pulled')], scopeHashStore(store, GLOBAL));
    expect(changedCount(res)).toBe(1);
    expect(res.findings.filter((f) => /changed since last scan/.test(f.title))).toHaveLength(1);
  });

  it('(ii) legacy row with project and global both defining it: only the changed source alerts', () => {
    const d = db();
    const store = new SqliteToolHashStore(d);
    store.set('files', 'read_file', hashTool(tool('original')), false);
    migrateLegacyToolHashes(d, [
      { name: 'files', sourcePath: PROJECT },
      { name: 'files', sourcePath: GLOBAL },
    ]);
    const project = scanToolList('files', [tool('project-changed')], scopeHashStore(store, PROJECT));
    const global = scanToolList('files', [tool('original')], scopeHashStore(store, GLOBAL));
    expect(changedCount(project)).toBe(1);
    expect(changedCount(global)).toBe(0);
    expect(global.drift[0].status).toBe('unchanged'); // seeded, not a silent fresh baseline
  });

  it('(iii) a manual project scan then an auto global scan: no false alert, baselines independent', () => {
    const d = db();
    const store = new SqliteToolHashStore(d);
    scanToolList('files', [tool('project version')], scopeHashStore(store, PROJECT));
    const projBefore = scopeHashStore(store, PROJECT).get('files', 'read_file');
    const global = scanToolList('files', [tool('global version')], scopeHashStore(store, GLOBAL));
    expect(global.drift[0].status).toBe('new');
    expect(changedCount(global)).toBe(0);
    expect(scopeHashStore(store, PROJECT).get('files', 'read_file')).toBe(projBefore); // global scan did not touch it
    // and a second project scan is still quiet
    expect(changedCount(scanToolList('files', [tool('project version')], scopeHashStore(store, PROJECT)))).toBe(0);
  });

  it('migration is idempotent, removes seeded legacy rows and leaves undefined names alone', () => {
    const d = db();
    const store = new SqliteToolHashStore(d);
    store.set('files', 'read_file', 'h1', false);
    store.set('orphan', 'x', 'h2', false);
    expect(migrateLegacyToolHashes(d, [{ name: 'files', sourcePath: GLOBAL }])).toBe(1);
    expect(migrateLegacyToolHashes(d, [{ name: 'files', sourcePath: GLOBAL }])).toBe(0);
    const names = rows(d).map((r) => r.server_name);
    expect(names).toContain('orphan');
    expect(names).not.toContain('files');
    expect(names).toHaveLength(2);
  });
});
