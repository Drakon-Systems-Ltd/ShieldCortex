import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, expect, it } from '@jest/globals';

const HOOK = fileURLToPath(new URL('../../scripts/pre-compact-hook.mjs', import.meta.url));
const SCHEMA = new URL('../database/schema.sql', import.meta.url);

let home: string;
let configDir: string;
let dbPath: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-1170-home-'));
  configDir = join(home, '.shieldcortex');
  dbPath = join(configDir, 'memories.db');
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

function runHook(conversation: string) {
  const result = spawnSync(process.execPath, [HOOK], {
    cwd: home,
    env: {
      HOME: home,
      USERPROFILE: home,
      TMPDIR: home,
      SHIELDCORTEX_CONFIG_DIR: configDir,
      SHIELDCORTEX_AUDIT_DIR: join(configDir, 'audit'),
      SHIELDCORTEX_SKIP_EMBEDDINGS: '1',
    },
    input: JSON.stringify({ trigger: 'manual', conversation }),
    encoding: 'utf8',
    timeout: 5_000,
  });
  expect(result.error).toBeUndefined();
  expect(result.status).toBe(0);
  return result;
}

it.each([
  {
    name: 'the database is missing',
    dbIsDirectory: false,
    diagnostic: '[pre-compact] Memory database not found, skipping auto-extraction',
  },
  {
    name: 'the database cannot be opened',
    dbIsDirectory: true,
    diagnostic: '[pre-compact] Error: unable to open database file',
  },
])('keeps the zero-capture reminder silent and exits successfully when $name', ({ dbIsDirectory, diagnostic }) => {
  if (dbIsDirectory) {
    // A directory passes the existence check but SQLite cannot open it as a database.
    mkdirSync(dbPath, { recursive: true });
  }
  const result = runHook('Nothing to capture.');
  expect(result.stdout).toBe('');
  expect(result.stderr.trim()).toBe(diagnostic);
});

it('prints the existing reminder when one memory is actually saved', () => {
  mkdirSync(configDir, { mode: 0o700 });
  const db = new Database(dbPath);
  try {
    db.exec(readFileSync(SCHEMA, 'utf8'));
    const content = 'The bakery opens at seven on weekdays, which gives the breakfast volunteers enough time to collect the Friday order.';
    const result = runHook(`Turns out ${content}`);
    expect(result.stdout).toBe('\n🧠 AUTO-MEMORY: 1 item(s) saved before compaction.\n');
    // The hook can report a candidate even when the writer declines it.
    expect(db.prepare('SELECT content, source FROM memories').all()).toEqual([
      { content, source: 'hook:pre-compact-hook' },
    ]);
  } finally {
    db.close();
  }
});
