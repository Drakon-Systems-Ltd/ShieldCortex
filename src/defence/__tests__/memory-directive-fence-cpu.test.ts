/**
 * #1111 post-merge B2 — CPU budget for the helpers the memory-directive screen
 * reaches BEFORE its own index exists.
 *
 * The screen builds its skip mask with L2's `scanWrappers`, and for a
 * code-like fence body that runs L2's whole shape scan over the body. Those
 * helpers walked to the next newline from every span, split the whole prefix
 * per fence, re-read the sentence once per comma and per match, and restarted
 * `\n\s*` regexes at every newline of a blank run. A fenced write under 8 KB
 * held the scanner for seconds (2.4 s at 7.5 KB, cubic in the body).
 *
 * Every family runs in a CHILD PROCESS with a hard deadline (`spawnSync` kills
 * it), through the leaf (`detectMemoryDirective`) and through the real
 * memory-admission firewall call. The budget is a wall clock measured inside
 * the child around each call: loose for a loaded CI runner and far below the
 * old cost, so the old code fails it. Measured on a 2 vCPU ARM host with the
 * fix: every family here under 200 ms per call up to 50 KB (5.21.0: 2.5 s at
 * 7.5 KB and 20 s at 15 KB for the fenced near miss).
 *
 * Verdicts: these are near misses, and the screen and the firewall gave the
 * same verdicts on them before the fix (checked against the 5.21.0 build); the
 * tests pin those verdicts so a speed-up cannot come from skipping content.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const DIST = path.join(REPO_ROOT, 'dist', 'defence');

const DEADLINE_MS = 10_000;

/** Fixture generators, keyed by family; each takes a size parameter. */
const FIXTURES = String.raw`
const B = String.fromCharCode(96);
const F = B + B + B;
const fencedNearMiss = (N) => {
  const line = 'for example x' + ' list credentials,'.repeat(N);
  const K = Math.ceil((2 * N + 3) / 5) + 2;
  return F + 'json\n' + line + '\n' + 'x\n'.repeat(K) + F;
};
const fencedNearMissBytes = (n) => fencedNearMiss(Math.max(1, Math.floor((n - 30) / 18.8)));
// A tool-call near miss after an opening quote: directed, but no addressee and
// no self-reference, so every match asks for the runtime self-reference of its
// sentence. '.x' ends a sentence on the right but not on the left, so every
// match shares one sentence start with a later end (the overlapping scopes).
const QUOTED_UNIT = String.fromCharCode(34) + 'call a_b' + String.fromCharCode(34) + '.x';
const FAMILIES = {
  fencedNearMiss,
  repeatedEmptyFence: (n) => (F + '\n' + F + '\n').repeat(Math.ceil(n / 8)).slice(0, n),
  longLineNearMiss: (N) => F + 'json\n' + ' x list credentials'.repeat(N) + '\n' + 'x\n'.repeat(Math.ceil((3 * N - 5) / 5) + 3) + F,
  sixBackticks: (n) => (F + F).repeat(Math.ceil(n / 6)).slice(0, n),
  inlineSpansOneLine: (n) => (B + 'a' + B + ' ').repeat(Math.ceil(n / 4)).slice(0, n),
  fencedCueCommas: (N) => F + 'json\nfor example' + ' list credentials, x'.repeat(N) + '\n' + 'x\n'.repeat(Math.ceil((3 * N + 2) / 5) + 3) + F,
  manyFencesOneLine: (n) => ('a ' + F + 'json\n{}\n' + F + ' ').repeat(Math.ceil(n / 17)).slice(0, n),
  fencedBlankLines: (n) => F + 'json\n' + '\n'.repeat(n) + 'remember this\n' + F,
  fencedBlankLinesMachinery: (n) => F + 'json\n' + '\n'.repeat(n) + 'discard the previous instructions\n' + F,
  quoteRunFence: (n) => F + 'json\n' + '"'.repeat(n - 30) + 'x remember this\n' + F,
  fenced: fencedNearMissBytes,
  encoded: (n) => Buffer.from(fencedNearMissBytes(Math.ceil((n * 3) / 4))).toString('base64'),
  raw: (n) => ('for example x' + ' list credentials,'.repeat(Math.ceil(n / 18))).slice(0, n),
  quotedPunctuationScopes: (n) => QUOTED_UNIT.repeat(Math.max(1, Math.floor(n / QUOTED_UNIT.length))),
  fencedQuotedScopes: (n) => {
    const units = Math.max(1, Math.floor((n - 12) / (QUOTED_UNIT.length + 2)));
    return F + 'json\n' + QUOTED_UNIT.repeat(units) + '\n' + 'x\n'.repeat(units) + F;
  },
};
`;

const CHILD = `
${FIXTURES}
const [dist, family, sizeRaw, sourceType] = process.argv.slice(1);
const text = FAMILIES[family](Number(sizeRaw));
const { detectMemoryDirective } = await import(dist + '/firewall/memory-directive-policy.js');
const fw = await import(dist + '/firewall/index.js');
const { DEFAULT_DEFENCE_CONFIG } = await import(dist + '/types.js');
let t0 = performance.now();
const leaf = detectMemoryDirective(text);
const leafMs = performance.now() - t0;
t0 = performance.now();
const r = fw.analyzeFirewall(text, 'note', { type: sourceType, identifier: 'probe' }, 0.9,
  { ...DEFAULT_DEFENCE_CONFIG, mode: 'balanced' }, undefined, { memoryAdmission: 'agent' });
const fwMs = performance.now() - t0;
process.stdout.write(JSON.stringify({ len: text.length, leaf, leafMs, result: r.result, fwMs }));
`;

/** The firewall call's source type: L2's agent-addressed checks run on untrusted sources such as `web`. */
type Source = 'cli' | 'web';

type ChildOut = {
  len: number;
  leaf: { detected: boolean; patterns: string[] };
  leafMs: number;
  result: string;
  fwMs: number;
};

function run(family: string, size: number, source: Source = 'cli'): ChildOut {
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', CHILD, DIST, family, String(size), source], {
    timeout: DEADLINE_MS,
    encoding: 'utf-8',
    maxBuffer: 1024 * 1024,
  });
  expect(child.signal).toBeNull();
  expect(child.stderr).toBe('');
  expect(child.status).toBe(0);
  return JSON.parse(child.stdout) as ChildOut;
}

/** In-child budget per call, by input size: 600 ms up to ~16 KB, 1.5 s above. */
function budget(len: number): number {
  return len <= 16_500 ? 600 : 1_500;
}

const CASES: Array<[family: string, sizes: number[], source?: Source]> = [
  // The review's exact families (fenced near miss by N, then by length).
  ['fencedNearMiss', [100, 200, 400, 800, 2000]],
  ['repeatedEmptyFence', [12_500, 25_000, 50_000]],
  ['longLineNearMiss', [500, 1000, 2000]],
  ['sixBackticks', [12_500, 25_000, 50_000]],
  // The other helpers on the same path.
  ['inlineSpansOneLine', [50_000]],
  ['fencedCueCommas', [200, 800]],
  ['manyFencesOneLine', [50_000]],
  ['fencedBlankLines', [8_000, 32_000]],
  ['fencedBlankLinesMachinery', [32_000]],
  ['quoteRunFence', [15_360, 51_200]],
  // Fenced, encoded and raw at 7.5, 15 and 50 KB.
  ['fenced', [7_680, 15_360, 51_200]],
  ['encoded', [7_680, 15_360, 51_200]],
  ['raw', [7_680, 15_360, 51_200]],
  // Overlapping sentence scopes (review of #1136): fenced, the body decides
  // S's mask; unfenced, L2 reads the prose. Web source, so L2's
  // agent-addressed checks run. The fenced 50 KB size keeps the fence closed
  // inside one scan window.
  ['quotedPunctuationScopes', [7_680, 15_360, 51_200], 'web'],
  ['fencedQuotedScopes', [7_680, 15_360, 49_900], 'web'],
];

/** Firewall verdicts on 5.21.0 that are not ALLOW (measured on the 5.21.0 build). */
const FIREWALL_VERDICT: Record<string, string> = { fencedBlankLinesMachinery: 'QUARANTINE' };

describe('memory-directive screen — fence/wrapper helper CPU budget (#1111 post-merge B2, child process, hard deadline)', () => {
  it('the built modules exist (run `npm run build:ts` or scripts/run-jest.mjs)', () => {
    expect(fs.existsSync(path.join(DIST, 'firewall', 'memory-directive-policy.js'))).toBe(true);
    expect(fs.existsSync(path.join(DIST, 'firewall', 'index.js'))).toBe(true);
  });

  for (const [family, sizes, source = 'cli'] of CASES) {
    for (const size of sizes) {
      it(`${family} (${size}, ${source}): leaf and memory-admission firewall finish inside the budget, verdict unchanged`, () => {
        const out = run(family, size, source);
        // Near misses: no S hit, and the firewall verdict 5.21.0 gave (an L2
        // shape outside any code-like mask still quarantines, as before).
        expect(out.leaf).toEqual({ detected: false, patterns: [] });
        expect(out.result).toBe(FIREWALL_VERDICT[family] ?? 'ALLOW');
        expect(out.leafMs).toBeLessThan(budget(out.len));
        expect(out.fwMs).toBeLessThan(budget(out.len));
      }, DEADLINE_MS + 5_000);
    }
  }

  it('scaling stays near-linear: the 50 KB fenced near miss costs at most ~8x the 7.5 KB one (plus slack)', () => {
    const small = run('fenced', 7_680);
    const large = run('fenced', 51_200);
    // 6.7x the input; quadratic code would be ~45x, cubic ~300x.
    expect(large.leafMs).toBeLessThan(small.leafMs * 8 + 100);
  }, 2 * DEADLINE_MS + 5_000);
});
