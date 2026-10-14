/**
 * #756 review: `shieldcortex maintain` must apply the same safe-runtime gate as
 * `initDatabase()` before it opens the DEFAULT database. These tests drive the
 * built CLI in a child process with a disposable HOME, because the gate and the
 * default path are resolved from the real process environment (Jest gives each
 * test file its own copy of process.env, so os.homedir() ignores HOME edits).
 * The entry is a one-line shim placed where resolveRuntimeInfo() classifies it
 * (npx cache or project checkout); it imports this repo's built dist/index.js.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, initDatabase } from '../../database/init.js';

let root: string;
let home: string;
let dbPath: string;
const sha = (file: string): string => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const distEntry = pathToFileURL(path.resolve('dist/index.js')).href;

function seed(): void {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = initDatabase(dbPath);
  db.prepare("INSERT INTO memories (uuid, title, content, type, category, salience, tags, created_at, last_accessed, embedding) VALUES (?, 'Title', 'Content', 'long_term', 'note', 0.5, '[]', datetime('now'), datetime('now'), NULL)").run('gate-fixture');
  db.exec('CREATE TABLE fixture_space (payload TEXT)');
  const bulk = db.prepare('INSERT INTO fixture_space VALUES (?)');
  for (let i = 0; i < 400; i++) bulk.run(`${i}-${'x'.repeat(2000)}`);
  db.exec('DELETE FROM fixture_space');
  db.pragma('journal_mode = DELETE');
  closeDatabase();
  for (const suffix of ['.lock', '-wal', '-shm']) fs.rmSync(dbPath + suffix, { force: true });
  const read = new Database(dbPath, { readonly: true });
  expect((read.pragma('freelist_count', { simple: true }) as number) / (read.pragma('page_count', { simple: true }) as number)).toBeGreaterThanOrEqual(0.2);
  read.close();
}

function vector(): Buffer | null {
  const read = new Database(dbPath, { readonly: true });
  try { return (read.prepare('SELECT embedding FROM memories WHERE uuid = ?').get('gate-fixture') as { embedding: Buffer | null }).embedding; }
  finally { read.close(); }
}

function assertUntouched(before: string): void {
  expect(sha(dbPath)).toBe(before);
  for (const suffix of ['.lock', '-wal', '-shm', '-journal']) expect(fs.existsSync(dbPath + suffix)).toBe(false);
  expect(vector()).toBeNull();
}

/** Write a shim entry under `<root>/<dir>` that runs the built CLI. */
function shim(dir: string): string {
  const pkgDir = path.join(root, dir);
  const entry = path.join(pkgDir, 'dist', 'index.js');
  fs.mkdirSync(path.dirname(entry), { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), '{"type":"module"}');
  fs.writeFileSync(entry, `import ${JSON.stringify(distEntry)};\n`);
  return entry;
}

function runCli(entry: string, args: string[], extraEnv: Record<string, string> = {}) {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, '.config'), ...extraEnv };
  delete env.CLAUDE_MEMORY_DB;
  if (!('SHIELDCORTEX_ALLOW_UNSAFE_RUNTIME' in extraEnv)) delete env.SHIELDCORTEX_ALLOW_UNSAFE_RUNTIME;
  Object.assign(env, extraEnv);
  const child = spawnSync(process.execPath, [entry, 'maintain', ...args], { env, encoding: 'utf8', timeout: 60_000 });
  return { ...child, describe: `status: ${child.status}\nstdout: ${child.stdout}\nstderr: ${child.stderr}\nerror: ${child.error}` };
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-maintain-gate-'));
  home = path.join(root, 'home');
  fs.mkdirSync(home);
  dbPath = path.join(home, '.shieldcortex', 'memories.db');
});

afterEach(() => {
  try { closeDatabase(); } catch { /* closed */ }
  fs.rmSync(root, { recursive: true, force: true });
});

const RUNTIMES = [
  ['npx cache', '.npm/_npx/t/node_modules/shieldcortex'],
  // src/index.ts only runs main() when argv[1] ends in /shieldcortex/dist/index.js.
  ['project checkout', 'ShieldCortex/shieldcortex'],
] as const;

describe('maintain default database runtime gate (#756)', () => {
  for (const [label, dir] of RUNTIMES) {
    for (const args of [['--json'], ['--dry-run', '--json']]) {
      it(`refuses an existing within-cap DB from a ${label} (${args.join(' ')})`, () => {
        seed();
        const before = sha(dbPath);
        const child = runCli(shim(dir), args);
        if (child.status !== 1 || !/Refusing to open/.test(child.stderr)) throw new Error(child.describe);
        assertUntouched(before);
      });
    }

    it(`refuses to create a fresh default DB from a ${label}`, () => {
      const child = runCli(shim(dir), ['--json']);
      if (child.status !== 1 || !/Refusing to open/.test(child.stderr)) throw new Error(child.describe);
      expect(fs.existsSync(dbPath)).toBe(false);
    });
  }

  it('does not treat an ambient CLAUDE_MEMORY_DB pointing at the default as explicit', () => {
    seed();
    const before = sha(dbPath);
    const child = runCli(shim(RUNTIMES[0][1]), ['--json'], { CLAUDE_MEMORY_DB: dbPath });
    if (child.status !== 1 || !/Refusing to open/.test(child.stderr)) throw new Error(child.describe);
    assertUntouched(before);
  });

  it('positive control: the explicit unsafe-runtime override lets the same run proceed', () => {
    seed();
    const before = sha(dbPath);
    const child = runCli(shim(RUNTIMES[0][1]), ['--json'], { SHIELDCORTEX_ALLOW_UNSAFE_RUNTIME: '1' });
    let report: { steps: Record<string, { status: string; reason: string }> };
    try { report = JSON.parse(child.stdout.trim().split('\n').pop() ?? ''); }
    catch { throw new Error(child.describe); }
    if (report.steps.vacuum.status !== 'ran') throw new Error(child.describe);
    expect(sha(dbPath)).not.toBe(before);
  });
});
