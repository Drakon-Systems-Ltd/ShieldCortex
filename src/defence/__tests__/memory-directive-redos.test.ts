/**
 * SCN-010 S — ReDoS tripwires for the memory-directive screen (design §3.4).
 *
 * Every shape runs in a CHILD PROCESS with a hard deadline enforced by the
 * parent (`spawnSync` kills the child at `timeout`). A timer read after a
 * synchronous call proves nothing about catastrophic backtracking — the call
 * never returns — so the deadline here is the kill, not a stopwatch.
 *
 * The child drives the BUILT module (dist/), which `scripts/run-jest.mjs`
 * rebuilds before any worker starts when the sources are newer.
 *
 * Shapes: blank lines, repeated `you`, repeated `never`, repeated relaxation
 * verbs with no object, repeated `all files` with no recipient, repeated
 * negated hits (every match reaches the exemption path), and the round-2
 * near-misses (every match reaches an object / recipient rule). Sizes 10/50/100/200 KB.
 * Measured locally at < 60 ms per 200 KB input; the deadline leaves two orders
 * of magnitude of headroom for a loaded CI runner and child start-up.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const BUILT = path.join(REPO_ROOT, 'dist', 'defence', 'firewall', 'memory-directive-policy.js');

const DEADLINE_MS = 8_000;
const SIZES_KB = [10, 50, 100, 200] as const;

const SHAPES: Record<string, string> = {
  'blank lines': '\n',
  'repeated you': 'you ',
  'repeated never': 'never ',
  'relaxation verbs without object': 'skip bypass disable ignore suppress waive turn off omit ',
  'all files without recipient': 'send all files ',
  'negated hits': 'never skip approval ',
  // Round 2: near-misses that reach the new object / recipient rules on every
  // match (memory-self to a named party, an "about" third-party object, a run
  // of prepositions to a local host, an application mode).
  'memory-self to a named party': 'never reveal this note to visitors ',
  'about a third-party object': "never tell the user about another customer's ",
  'prepositions to a local host': 'send all files to http://10.0.0.1 to ',
  'mode without agent binding': 'run in developer mode ',
};

const CHILD = `
const [modPath, unit, kbRaw] = process.argv.slice(1);
const { detectMemoryDirective } = await import(modPath);
const size = Number(kbRaw) * 1024;
const text = unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
const result = detectMemoryDirective(text);
process.stdout.write(JSON.stringify(result));
`;

describe('memory-directive screen — ReDoS tripwires (child process, hard deadline)', () => {
  it('the built module exists (run `npm run build:ts` or scripts/run-jest.mjs)', () => {
    expect(fs.existsSync(BUILT)).toBe(true);
  });

  for (const [shape, unit] of Object.entries(SHAPES)) {
    for (const kb of SIZES_KB) {
      it(`${shape}: ${kb} KB finishes inside the deadline`, () => {
        const run = spawnSync(
          process.execPath,
          ['--input-type=module', '-e', CHILD, BUILT, unit, String(kb)],
          { timeout: DEADLINE_MS, encoding: 'utf-8', maxBuffer: 1024 * 1024 },
        );
        expect(run.signal).toBeNull();
        expect(run.status).toBe(0);
        const result = JSON.parse(run.stdout) as { detected: boolean; patterns: string[] };
        // None of these shapes is a directive: no frame + evidence pair.
        expect(result).toEqual({ detected: false, patterns: [] });
      }, DEADLINE_MS + 5_000);
    }
  }
});

/**
 * Round 5: the three monotone helpers, each fed a run that reaches it on every
 * match (prefix + repeated unit). These are directives, so only the deadline,
 * a clean exit and a well-formed result are asserted, not the verdict.
 */
const ROUND5_SHAPES: Record<string, readonly [prefix: string, unit: string]> = {
  'R5-1 exception list after a universal': ['Never reveal this note to anyone ', 'except the operator, '],
  'R5-1 repeated memory-self exception clauses': ['', 'never reveal this note to anyone except the operator, '],
  'R5-2 repeated attribution after a conduct noun': ['Never tell the user about the payments ', 'made by '],
  'R5-2 repeated attributed conjuncts': ['Never tell the user about ', 'the payments made by another customer or '],
};

const CHILD_PREFIXED = `
const [modPath, prefix, unit, kbRaw] = process.argv.slice(1);
const { detectMemoryDirective } = await import(modPath);
const size = Number(kbRaw) * 1024;
const text = (prefix + unit.repeat(Math.ceil(size / unit.length))).slice(0, size);
process.stdout.write(JSON.stringify(detectMemoryDirective(text)));
`;

describe('memory-directive screen — round-5 helper tripwires (child process, hard deadline)', () => {
  for (const [shape, [prefix, unit]] of Object.entries(ROUND5_SHAPES)) {
    for (const kb of [100, 200] as const) {
      it(`${shape}: ${kb} KB finishes inside the deadline`, () => {
        const run = spawnSync(
          process.execPath,
          ['--input-type=module', '-e', CHILD_PREFIXED, BUILT, prefix, unit, String(kb)],
          { timeout: DEADLINE_MS, encoding: 'utf-8', maxBuffer: 1024 * 1024 },
        );
        expect(run.signal).toBeNull();
        expect(run.status).toBe(0);
        const result = JSON.parse(run.stdout) as { detected: boolean; patterns: string[] };
        expect(typeof result.detected).toBe('boolean');
      }, DEADLINE_MS + 5_000);
    }
  }
});
