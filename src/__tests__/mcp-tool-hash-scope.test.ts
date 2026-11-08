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

describe('legacy server names that collide with the scoped-key prefix (#925 fix4)', () => {
  it('legacy rows for servers named src and SRC both migrate and alert on change, with no case folding', () => {
    const d = db();
    const store = new SqliteToolHashStore(d);
    store.set('src', 'read_file', hashTool(tool('orig-lower')), false);
    store.set('SRC', 'read_file', hashTool(tool('orig-upper')), false);
    expect(migrateLegacyToolHashes(d, [
      { name: 'src', sourcePath: GLOBAL },
      { name: 'SRC', sourcePath: GLOBAL },
    ])).toBe(2);
    const lower = scanToolList('src', [tool('rug-pulled')], scopeHashStore(store, GLOBAL));
    const upper = scanToolList('SRC', [tool('rug-pulled')], scopeHashStore(store, GLOBAL));
    expect(changedCount(lower)).toBe(1);
    expect(changedCount(upper)).toBe(1);
    // no case folding: each baseline is its own
    const d2 = db();
    const s2 = new SqliteToolHashStore(d2);
    s2.set('src', 'read_file', hashTool(tool('A')), false);
    s2.set('SRC', 'read_file', hashTool(tool('B')), false);
    migrateLegacyToolHashes(d2, [{ name: 'src', sourcePath: GLOBAL }, { name: 'SRC', sourcePath: GLOBAL }]);
    expect(scopeHashStore(s2, GLOBAL).get('src', 'read_file')).toBe(hashTool(tool('A')));
    expect(scopeHashStore(s2, GLOBAL).get('SRC', 'read_file')).toBe(hashTool(tool('B')));
  });

  it('already-scoped rows are not re-migrated as legacy', () => {
    const d = db();
    const store = new SqliteToolHashStore(d);
    scopeHashStore(store, GLOBAL).set('files', 'read_file', 'h', false);
    expect(migrateLegacyToolHashes(d, [{ name: 'files', sourcePath: GLOBAL }])).toBe(0);
    expect(rows(d)).toHaveLength(1);
  });
});
