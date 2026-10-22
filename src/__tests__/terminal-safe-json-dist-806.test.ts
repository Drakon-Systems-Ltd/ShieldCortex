/**
 * #806 — the BUILT CLI's `audit --json` goes through `stringifyJsonTerminalSafe`
 * (inside `formatJsonReport`).
 *
 * `audit` reads the real home directory and cwd (os.homedir(), which a
 * Jest-side HOME override does not reach), so it is driven as a child process
 * of `dist/index.js` with HOME and cwd pinned to temp fixtures, the same way
 * the #798 `audit --sarif` cases are. The `.env` file's directory name carries
 * the probe code points and reaches the report as the finding's file path.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = path.join(repoRoot, 'dist', 'index.js');

// U+009B (8-bit CSI), U+202E (RLO), U+2028 (LINE SEPARATOR), U+200B (ZWSP).
const CODES = [0x9b, 0x202e, 0x2028, 0x200b];
const UNSAFE = String.fromCharCode(...CODES);
const ESCAPES = CODES.map((c) => `\\u${c.toString(16).padStart(4, '0')}`);

function literalUnsafe(raw: string): string[] {
  return [...raw].filter((ch) => {
    const cp = ch.codePointAt(0)!;
    return (cp >= 0x80 && cp <= 0x9f) || cp === 0x61c || (cp >= 0x200b && cp <= 0x200f)
      || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064)
      || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff;
  }).map((ch) => `U+${ch.codePointAt(0)!.toString(16).padStart(4, '0')}`);
}

const roots: string[] = [];

beforeAll(() => {
  requireFreshBuiltArtefacts({
    repoRoot,
    sources: [
      path.join(repoRoot, 'src', 'cli', 'term-ui.ts'),
      path.join(repoRoot, 'src', 'cli', 'audit.ts'),
      path.join(repoRoot, 'src', 'audit', 'report-formatter.ts'),
      path.join(repoRoot, 'src', 'index.ts'),
    ],
    artefacts: [
      DIST_ENTRY,
      path.join(repoRoot, 'dist', 'cli', 'term-ui.js'),
      path.join(repoRoot, 'dist', 'cli', 'audit.js'),
      path.join(repoRoot, 'dist', 'audit', 'report-formatter.js'),
    ],
  });
});

afterEach(() => {
  for (const r of roots.splice(0)) fs.rmSync(r, { recursive: true, force: true });
});

/** A temp home and a cwd holding `apps/svc<tag>/.env` with a live-looking key. */
function auditFixture(tag: string): { home: string; cwd: string } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-806-dist-')));
  roots.push(root);
  const home = path.join(root, 'home');
  const cwd = path.join(root, 'cwd');
  fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
  const envDir = path.join(cwd, 'apps', `svc${tag}`);
  fs.mkdirSync(envDir, { recursive: true });
  fs.writeFileSync(path.join(envDir, '.env'), 'OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH\n');
  return { home, cwd };
}

function auditJson({ home, cwd }: { home: string; cwd: string }): string {
  const run = spawnSync(process.execPath, [DIST_ENTRY, 'audit', '--json'], {
    cwd,
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      SHIELDCORTEX_CONFIG_DIR: path.join(home, '.shieldcortex'),
      CLAUDE_MEMORY_DB: path.join(home, '.shieldcortex', 'memories.db'),
      SHIELDCORTEX_SKIP_EMBEDDINGS: '1',
      NO_COLOR: '1',
      COLUMNS: '200',
    },
    encoding: 'utf8',
    timeout: 120_000,
  });
  return run.stdout ?? '';
}

function findingPaths(stdout: string): string[] {
  const body = JSON.parse(stdout) as { findings: Array<{ filePath?: string }> };
  return body.findings.map((f) => f.filePath ?? '');
}

describe('built CLI audit --json on stdout is terminal-safe (#806)', () => {
  it('escapes the finding file path and round-trips it', () => {
    const stdout = auditJson(auditFixture(UNSAFE));
    expect(literalUnsafe(stdout)).toEqual([]);
    for (const esc of ESCAPES) expect(stdout).toContain(esc);
    expect(findingPaths(stdout).some((p) => p.includes(path.join('apps', `svc${UNSAFE}`, '.env')))).toBe(true);
  }, 150_000);

  it('with a clean location is byte-identical to plain JSON.stringify', () => {
    const stdout = auditJson(auditFixture('-plain'));
    expect(findingPaths(stdout).some((p) => p.includes(path.join('apps', 'svc-plain', '.env')))).toBe(true);
    expect(literalUnsafe(stdout)).toEqual([]);
    expect(stdout).toBe(`${JSON.stringify(JSON.parse(stdout), null, 2)}\n`);
  }, 150_000);
});
