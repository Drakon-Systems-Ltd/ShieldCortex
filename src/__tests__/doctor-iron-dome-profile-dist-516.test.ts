/**
 * #516 review — a malformed persisted Iron Dome config must not reach any
 * doctor output. V8's JSON.parse error quotes the input back, so driving the
 * BUILT CLI is the honest proof: it covers the human report, `--verbose`,
 * `--json`, and anything a check writes to stdout or stderr along the way.
 */
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = join(repoRoot, 'dist', 'index.js');
const MARKER = 'SC516LEAK';
const MALFORMED = `{"killPhrase": ${MARKER}}`;
const ROW = 'could not read Iron Dome profile — stored config unreadable';

let home: string;

beforeAll(() => {
  requireFreshBuiltArtefacts({
    repoRoot,
    sources: [join(repoRoot, 'src', 'cli', 'doctor.ts'), join(repoRoot, 'src', 'defence', 'iron-dome', 'index.ts')],
    artefacts: [DIST_ENTRY, join(repoRoot, 'dist', 'cli', 'doctor.js')],
  });
  home = mkdtempSync(join(tmpdir(), 'sc-516-dist-home-'));
  const configDir = join(home, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  const db = new Database(join(configDir, 'memories.db'));
  db.exec('CREATE TABLE iron_dome_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT)');
  db.prepare('INSERT INTO iron_dome_config (key, value, updated_at) VALUES (?, ?, ?)').run('config', MALFORMED, '2020-01-01 00:00:00');
  db.close();
});

afterAll(() => {
  if (home) rmSync(home, { recursive: true, force: true });
});

function doctor(args: string[]): string {
  const run = spawnSync(process.execPath, [DIST_ENTRY, 'doctor', ...args], {
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
      COLUMNS: '200',
      NO_COLOR: '1',
    },
    encoding: 'utf8',
    timeout: 120_000,
  });
  return `${run.stdout ?? ''}\n${run.stderr ?? ''}`;
}

describe('doctor never echoes a malformed Iron Dome config (#516)', () => {
  it.each([
    ['human', []],
    ['verbose', ['--verbose']],
    ['json', ['--json']],
  ])('%s output', (_name, args) => {
    const output = doctor(args as string[]);
    expect(output).toContain(ROW);
    expect(output).not.toContain(MARKER);
    expect(output).not.toContain('is not valid JSON');
  }, 150_000);

  it('json carries the fixed row verbatim', () => {
    const stdout = doctor(['--json']);
    const body = JSON.parse(stdout.slice(stdout.indexOf('{'), stdout.lastIndexOf('}') + 1));
    const row = body.results.find((r: { label: string }) => r.label === 'Iron Dome profile');
    expect(row).toEqual({ label: 'Iron Dome profile', status: 'info', message: ROW });
  }, 150_000);
});
