/**
 * #509 r7 (PR #610 review, CASE-Drakon 2026-10-04) — the two self-protection
 * rows added to the three OUTAGE fallbacks (the Claude Code hook's table, the
 * OpenClaw interceptor's table, the Hermes `_FALLBACK_SELF_PROTECTION` list)
 * backtracked quadratically on long non-matching input: 100 KiB of newlines
 * took 20–35 s per row in Node and minutes in CPython, because `\n` is both a
 * separator the row anchors on and a character the gap after it consumed.
 *
 * Every gap between an anchor and the required literal is now bounded. This
 * suite holds each row under 50 ms on 100 KiB of padding, in the shapes that
 * were pathological, on all three surfaces — and checks the bounded rows
 * still fire on the commands they exist for. Reverting the bound makes the
 * newline shapes take tens of seconds here, so the budget fails loudly.
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const hookSrc = fs.readFileSync(path.join(repoRoot, 'scripts', 'pre-tool-hook.mjs'), 'utf-8');
const pluginSrc = fs.readFileSync(path.join(repoRoot, 'plugins', 'openclaw', 'interceptor.ts'), 'utf-8');

const PAD = 100 * 1024;
const BUDGET_MS = 50;
// Assembled at runtime (#444 convention) so the guard scanning this file's own
// write does not gate the test.
const SC = '~/.' + 'shieldcortex';
const RM = 'r' + 'm';

/** The two #509 r6 S2 rows of a FALLBACK_DANGEROUS_PATTERNS table, compiled
 *  from the same text the parity suite compares. */
function selfProtectionRows(src: string): Record<'r5-verb' | 'r6-cd', RegExp> {
  const start = src.indexOf('const FALLBACK_DANGEROUS_PATTERNS');
  const end = src.indexOf('\n];', start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const rows = src.slice(start, end).split('\n').map((l) => l.trim())
    .filter((l) => l.startsWith('{ re:') && l.includes('shieldcortex') && l.includes('(?:mv|cp|rm|rmdir|rsync|ln|install)'));
  expect(rows).toHaveLength(2);
  const out: Partial<Record<'r5-verb' | 'r6-cd', RegExp>> = {};
  for (const row of rows) {
    const m = row.match(/^\{ re: \/(.*)\/([a-z]*), signal: '/);
    expect(m).not.toBeNull();
    out[row.includes('(?:cd|pushd)') ? 'r6-cd' : 'r5-verb'] = new RegExp(m![1], m![2]);
  }
  expect(Object.keys(out).sort()).toEqual(['r5-verb', 'r6-cd']);
  return out as Record<'r5-verb' | 'r6-cd', RegExp>;
}

const shapes: Record<string, string> = {
  newlines: '\n'.repeat(PAD),
  'cd+newlines': `cd ${SC}\n` + '\n'.repeat(PAD),
  'newlines+assignments': '\n'.repeat(PAD / 2) + 'A=b '.repeat(PAD / 8),
  'paren-verb-spam': '(mv '.repeat(PAD / 4),
  'cd+paren-verb-spam': `cd ${SC}\n` + '(mv '.repeat(PAD / 4),
  words: 'a '.repeat(PAD / 2),
  'verb+words': 'mv ' + 'a '.repeat(PAD / 2),
  'cd+words': `cd ${SC}; ` + 'a '.repeat(PAD / 2),
  spaces: ' '.repeat(PAD),
  semicolons: ';'.repeat(PAD),
};

/** Min-of-3 wall time in ms; the min discards GC and scheduler noise. */
function best(fn: () => unknown): { ms: number; result: unknown } {
  let ms = Infinity;
  let result: unknown;
  for (let i = 0; i < 3; i++) {
    const t0 = performance.now();
    result = fn();
    ms = Math.min(ms, performance.now() - t0);
  }
  return { ms: Math.round(ms * 100) / 100, result };
}

describe('#509 r7 — the hook and interceptor outage rows are bounded', () => {
  for (const [surface, src] of [['hook', hookSrc], ['interceptor', pluginSrc]] as const) {
    it(`${surface}: both rows finish 100 KiB of padding under ${BUDGET_MS} ms, every shape`, () => {
      const rows = selfProtectionRows(src);
      const report: Array<{ shape: string; row: string; ms: number; hit: unknown }> = [];
      for (const [shape, text] of Object.entries(shapes)) {
        for (const [row, re] of Object.entries(rows)) {
          const { ms, result } = best(() => re.test(text));
          report.push({ shape, row, ms, hit: result });
        }
      }
      expect(report.map((r) => ({ ...r, hit: r.hit, under: r.ms < BUDGET_MS })))
        .toEqual(report.map((r) => ({ ...r, hit: false, under: true })));
    });
  }

  it('the bounded rows still fire on the shapes they exist for (both surfaces)', () => {
    const positives = [
      `mv ${SC} /tmp/x`,
      `sudo mv "$HOME/.shieldcortex/" /tmp/x`,
      `cp -r /tmp/forged/. ${SC}/`,
      // A blank-padded line after a separator: the `\n` is the anchor and the
      // blanks after it are the (newline-free) gap.
      `true\n\n    mv ${SC} /tmp/x`,
      `cd ${SC}; printf x > approvals/y`,
      `cd ${SC} && echo {} > config.json`,
      `cd ${SC}; mv * /tmp/x`,
      `cd ${SC}\n\n   ${RM} -rf ./*`,
    ];
    const negatives = ['ls -la', `echo "${RM} ${SC}"`, 'cd /tmp/build && mv ./* /tmp/out', `npm install --prefix ${SC}/`];
    for (const [surface, src] of [['hook', hookSrc], ['interceptor', pluginSrc]] as const) {
      const rows = Object.values(selfProtectionRows(src));
      const fires = (c: string) => rows.some((re) => re.test(c));
      expect(positives.map((c) => ({ surface, c, fires: fires(c) }))).toEqual(positives.map((c) => ({ surface, c, fires: true })));
      expect(negatives.map((c) => ({ surface, c, fires: fires(c) }))).toEqual(negatives.map((c) => ({ surface, c, fires: false })));
    }
  });
});

// Why there is no whole-call clock on the hook or the interceptor: every
// outage fallback caps its exec surface at 4 KiB (`fallbackExecSurface`), and
// four OLDER rows of the same tables (file-delete, modify-scheduler, both
// registry-code-exec) share the `(?:^|[;&|(\n]|\$\()\s*` anchor idiom, so a
// whole-table call on newline padding costs ~240 ms with or without this fix
// and cannot tell the bound from its revert. The rows above are compiled from
// the shipped text (the parity suite holds hook and interceptor text equal and
// drives the real fallbacks over a shared table); Hermes below runs the real
// compiled objects. The sibling rows are a follow-up, not this fix.
describe('#509 r7 — the Hermes bound is what actually runs', () => {
  it('Hermes: the same measurement, through the plugin\'s own test helper, under the budget', () => {
    const testsDir = path.join(repoRoot, 'plugins', 'hermes', 'shieldcortex', 'tests');
    const run = spawnSync('python3', ['-c',
      'import json, sys; sys.path.insert(0, sys.argv[1]); import test_fallback_regex_bounds as t; print(json.dumps(t.measure()))',
      testsDir,
    ], { encoding: 'utf8', timeout: 120_000 });
    expect({ status: run.status, stderr: run.status === 0 ? '' : run.stderr }).toEqual({ status: 0, stderr: '' });
    const result = JSON.parse(run.stdout.trim().split('\n').pop() as string) as Record<string, Record<string, [number, boolean]>>;
    expect(Object.keys(result).sort()).toEqual(Object.keys(shapes).sort());
    const rows = Object.entries(result).flatMap(([shape, t]) => (['r5-verb', 'r6-cd'] as const).map((row) => ({ shape, row, ms: t[row][0], hit: t[row][1] })));
    expect(rows.map((r) => ({ ...r, under: r.ms < BUDGET_MS }))).toEqual(rows.map((r) => ({ ...r, hit: false, under: true })));
  });
});
