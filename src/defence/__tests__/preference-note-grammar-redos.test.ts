/**
 * SCN-010 part C — ReDoS tripwires for the closed preference grammar G
 * (design scn-010c §6).
 *
 * Every shape runs in a CHILD PROCESS with a hard deadline enforced by the
 * parent (`spawnSync` kills the child at `timeout`): a synchronous call that
 * backtracks catastrophically never returns, so a stopwatch in this process
 * would prove nothing. Inside the child the call itself is timed and must
 * finish under 1 s at 200 KB, for `isClosedPreferenceNote` and for
 * `detectInstructions` (which now asks the grammar first).
 *
 * The child drives the BUILT modules (dist/), which `scripts/run-jest.mjs`
 * rebuilds before any worker starts when the sources are newer.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const GRAMMAR = path.join(REPO_ROOT, 'dist', 'defence', 'firewall', 'preference-note-grammar.js');
const DETECTOR = path.join(REPO_ROOT, 'dist', 'defence', 'firewall', 'instruction-detector.js');

const DEADLINE_MS = 8_000;
const BUDGET_MS = 1_000;
const SIZE = 200 * 1024;

/** [prefix, repeated unit, suffix]: the run is cut to 200 KB before the suffix. */
const SHAPES: Record<string, readonly [string, string, string]> = {
  'repeated frame words': ['', 'from now on always ', ''],
  'repeated spaces': ['', ' ', ''],
  'repeated commas': ['', ',', ''],
  'repeated T2 frame': ['', 'when the user asks for a summary, ', ''],
  'repeated T1 sentence without a full stop': ['', 'From now on, always use British English in replies ', ''],
  'repeated T2 sentence with a full stop': ['', 'When the user asks for a summary, keep it short. ', ''],
  'spaces around a G sentence (trimmed, then parsed)': ['', ' ', 'From now on, always use British English in replies.'],
  'repeated full stops': ['', '.', ''],
  'repeated digits after a keep frame': ['When the user asks for a list, keep it to ', '9', ''],
};

const CHILD = `
const [grammarPath, detectorPath, prefix, unit, suffix, sizeRaw] = process.argv.slice(1);
const { isClosedPreferenceNote } = await import(grammarPath);
const { detectInstructions } = await import(detectorPath);
const size = Number(sizeRaw);
const run = (prefix + unit.repeat(Math.ceil(size / unit.length))).slice(0, size);
const text = suffix ? run + suffix + run : run;
let t = performance.now();
const parsed = isClosedPreferenceNote(text);
const grammarMs = performance.now() - t;
t = performance.now();
const detected = detectInstructions(text);
const detectorMs = performance.now() - t;
process.stdout.write(JSON.stringify({ parsed, grammarMs, detectorMs, patterns: detected.patterns }));
`;

describe('preference grammar — ReDoS tripwires (child process, hard deadline)', () => {
  it('the built modules exist (run `npm run build:ts` or scripts/run-jest.mjs)', () => {
    expect(fs.existsSync(GRAMMAR)).toBe(true);
    expect(fs.existsSync(DETECTOR)).toBe(true);
  });

  for (const [shape, [prefix, unit, suffix]] of Object.entries(SHAPES)) {
    it(`${shape}: 200 KB under ${BUDGET_MS} ms for the grammar and for detectInstructions`, () => {
      const run = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', CHILD, GRAMMAR, DETECTOR, prefix, unit, suffix, String(SIZE)],
        { timeout: DEADLINE_MS, encoding: 'utf-8', maxBuffer: 1024 * 1024 },
      );
      expect(run.signal).toBeNull();
      expect(run.status).toBe(0);
      const result = JSON.parse(run.stdout) as { parsed: boolean; grammarMs: number; detectorMs: number };
      expect(result.grammarMs).toBeLessThan(BUDGET_MS);
      expect(result.detectorMs).toBeLessThan(BUDGET_MS);
      // Only the whitespace-wrapped single sentence is a note; every run is not.
      expect(result.parsed).toBe(shape.startsWith('spaces around'));
    }, DEADLINE_MS + 5_000);
  }
});
