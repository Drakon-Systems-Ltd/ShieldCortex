/**
 * #509 r7/r8 (PR #610 review) — the two self-protection rows added to the three
 * OUTAGE fallbacks (the Claude Code hook's table, the OpenClaw interceptor's
 * table, the Hermes `_FALLBACK_SELF_PROTECTION` list).
 *
 * r7: they backtracked quadratically on long non-matching input, because `\n`
 * is both a separator the row anchors on and a character the gap after it
 * consumed. Fixed by excluding `\n` from the blank run and stopping the
 * argument gap at `(`.
 *
 * r8 (Tars + Case, 2026-10-05): r7 also put `{0,512}` / `{0,4096}` length
 * bounds on the gaps. The 512 bound let padding INSIDE the 4096-character scan
 * cap hide a real match; the 4096 bound is a no-op behind that cap. Both are
 * gone. So this suite now holds two things, on all three surfaces and through
 * the capped entry point production calls (`fallbackSelfProtectionMatch`;
 * Hermes `fallback_surface` -> `fallback_self_protection_match`):
 *
 *   1. LONG POSITIVES — a padded command inside the cap is still detected.
 *      Re-adding a numeric bound on either gap fails these.
 *   2. TIMING AT THE CAP — pathological padding, cut to the cap by the entry
 *      point itself, stays inside a budget.
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

const CAP = 4096;
const PAD = 100 * 1024;
// Measured at the cap (min-of-3, arm64): every shape is under 1 ms except the
// backtick-anchor run (~8 ms) and the repeated `cd` (~3 ms), which are still
// quadratic in the capped length. The r7 newline regression costs 45-90 ms at
// the cap in Node, so this budget sits between the two; Hermes (where the same
// regression costs over a second) and the shipped-text check are the wider nets.
const BUDGET_MS = 40;
// Assembled at runtime (#444 convention) so the guard scanning this file's own
// write does not gate the test.
const SC = '~/.' + 'shieldcortex';
const RM = 'r' + 'm';

type Match = (args: Record<string, unknown>, toolName?: string) => string | null;

/** The hook is a script, not a module: its outage-fallback section is pure
 *  (tables and functions, no I/O), so the SHIPPED text of that section is
 *  evaluated and its real `fallbackSelfProtectionMatch` returned. */
function hookEntry(): { match: Match; cap: number } {
  const start = hookSrc.indexOf('const FALLBACK_DANGEROUS_PATTERNS');
  const end = hookSrc.indexOf('// ==================== AUDIT (local JSONL)');
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const api = new Function(`${hookSrc.slice(start, end)}\nreturn { match: fallbackSelfProtectionMatch, cap: FALLBACK_SCAN_CAP };`)();
  return api as { match: Match; cap: number };
}

async function entries(): Promise<Array<[string, Match]>> {
  const hook = hookEntry();
  expect(hook.cap).toBe(CAP);
  expect(pluginSrc).toMatch(/const FALLBACK_SCAN_CAP = 4096;/);
  const { fallbackSelfProtectionMatch } = await import('../../plugins/openclaw/interceptor.js');
  return [['hook', hook.match], ['interceptor', fallbackSelfProtectionMatch as Match]];
}

/** `head` + filler + `tail`, exactly `len` characters. */
function padTo(head: string, tail: string, len: number): string {
  const room = len - head.length - tail.length;
  return head + 'a '.repeat(room >> 1) + ' '.repeat(room & 1) + tail;
}

/** Padded commands that ARE guard-state access, all inside the cap. The first
 *  two are the review's reproductions (772 and 622 characters); a `{0,512}`
 *  argument bound drops every `verb` row here. */
const longPositives: Array<[string, string]> = [
  ['verb, 30 repeated flags (772)', 'mv ' + '--strip-trailing-slashes '.repeat(30) + '.shieldcortex moved'],
  ['verb, 300 padding tokens (622)', `${RM} -rf ` + 'a '.repeat(300) + SC],
  ['verb, target ends just under the cap (4090)', padTo('mv ', `${SC} /tmp/x`, CAP - 6)],
  ['verb, target ends exactly at the cap (4096)', padTo('mv ', SC, CAP)],
  ['cd, relative state write 3.6k later (3638)', `cd ${SC} && ` + 'echo hi; '.repeat(400) + `${RM} -rf approvals`],
  ['cd, state name ends exactly at the cap (4096)', padTo(`cd ${SC}; `, ' approvals', CAP)],
  ['cd, padded verb + glob just under the cap (4090)', padTo(`cd ${SC}; mv `, '* /tmp/x', CAP - 6)],
];
const shortTwins = [
  'mv .shieldcortex moved',
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
const negatives = [
  'ls -la', 'cat notes.txt', `echo "${RM} ${SC}"`, 'cd /tmp/build && mv ./* /tmp/out',
  `npm install --prefix ${SC}/`, 'mv a b && cd .shieldcortex-docs',
  // Padding alone is not a match, at any length inside the cap.
  'mv ' + '--strip-trailing-slashes '.repeat(30) + 'notes moved',
  padTo('mv ', 'notes.txt', CAP),
];

/** Padding shapes, 100 KiB each — the entry point cuts them to the cap. */
const shapes: Record<string, string> = {
  newlines: '\n'.repeat(PAD),
  'cd+newlines': `cd ${SC}\n` + '\n'.repeat(PAD),
  'newlines+assignments': '\n'.repeat(CAP / 2) + 'A=b '.repeat(PAD / 8),
  'paren-verb-spam': '(mv '.repeat(PAD / 4),
  'cd+paren-verb-spam': `cd ${SC}\n` + '(mv '.repeat(PAD / 4),
  'backtick-verb-spam': '`mv '.repeat(PAD / 4),
  'semicolon-verb-spam': '; mv '.repeat(PAD / 5),
  'cd-spam': `cd ${SC} `.repeat(PAD / 16),
  words: 'a '.repeat(PAD / 2),
  'verb+words': 'mv ' + 'a '.repeat(PAD / 2),
  'cd+words': `cd ${SC}; ` + 'a '.repeat(PAD / 2),
  spaces: ' '.repeat(PAD),
  semicolons: ';'.repeat(PAD),
};

/** Min-of-3 wall time in ms; the min discards GC and scheduler noise. */
function best<T>(fn: () => T): { ms: number; result: T } {
  let ms = Infinity;
  let result!: T;
  for (let i = 0; i < 3; i++) {
    const t0 = performance.now();
    result = fn();
    ms = Math.min(ms, performance.now() - t0);
  }
  return { ms: Math.round(ms * 100) / 100, result };
}

describe('#509 r8 — padding inside the scan cap never hides a self-protection match (hook, interceptor)', () => {
  it('the long positives are the lengths they claim, all inside the cap', () => {
    expect(longPositives.map(([, c]) => c.length)).toEqual([772, 622, 4090, 4096, 3638, 4096, 4090]);
  });

  it('every long positive and every short twin is on the floor, through the capped entry point', async () => {
    for (const [surface, match] of await entries()) {
      const got = [...longPositives.map(([, c]) => c), ...shortTwins].map((c) => ({ surface, len: c.length, head: c.slice(0, 40), signal: match({ command: c }, 'Bash') }));
      expect(got).toEqual(got.map((g) => ({ ...g, signal: 'touch-approval-store' })));
    }
  });

  it('padding alone, and the benign look-alikes, stay off the floor', async () => {
    for (const [surface, match] of await entries()) {
      const got = negatives.map((c) => ({ surface, len: c.length, head: c.slice(0, 40), signal: match({ command: c }, 'Bash') }));
      expect(got).toEqual(got.map((g) => ({ ...g, signal: null })));
    }
  });

  it('a target that starts past the cap is not seen — the cap, not a gap bound, is the limit', async () => {
    for (const [, match] of await entries()) {
      expect(match({ command: padTo('mv ', SC, CAP + SC.length + 2) }, 'Bash')).toBeNull();
    }
  });

  it('neither gap carries a length bound, in the shipped text of both tables or in Hermes', () => {
    const hermesSrc = fs.readFileSync(path.join(repoRoot, 'plugins', 'hermes', 'shieldcortex', 'sc_client.py'), 'utf-8');
    for (const [surface, src] of [['hook', hookSrc], ['interceptor', pluginSrc], ['hermes', hermesSrc]] as const) {
      const rows = src.split('\n').filter((l) => l.includes('(?:mv|cp|rm|rmdir|rsync|ln|install)') && !l.trim().startsWith('//') && !l.trim().startsWith('#'));
      expect({ surface, rows: rows.length >= 2 }).toEqual({ surface, rows: true });
      for (const row of rows) {
        expect({ surface, bounded: /\{\d+,\d*\}/.test(row) }).toEqual({ surface, bounded: false });
        // The two r7 edits that fix the cost are still there.
        expect({ surface, blankRun: row.includes('[^\\S\\n]*'), parenStop: row.includes('[^;&|\\n(]*?') }).toEqual({ surface, blankRun: true, parenStop: true });
      }
    }
  });
});

describe('#509 r8 — the capped entry point stays inside its budget on pathological padding', () => {
  it(`hook and interceptor: every shape under ${BUDGET_MS} ms, no match`, async () => {
    for (const [surface, match] of await entries()) {
      const report = Object.entries(shapes).map(([shape, text]) => {
        const { ms, result } = best(() => match({ command: text }, 'Bash'));
        return { surface, shape, ms, signal: result };
      });
      expect(report.map((r) => ({ ...r, under: r.ms < BUDGET_MS }))).toEqual(report.map((r) => ({ ...r, signal: null, under: true })));
    }
  });
});

describe('#509 r8 — Hermes: the same two properties, through fallback_surface -> fallback_self_protection_match', () => {
  it('long positives match, negatives do not, and every shape is inside the Hermes budget', () => {
    const testsDir = path.join(repoRoot, 'plugins', 'hermes', 'shieldcortex', 'tests');
    const run = spawnSync('python3', ['-c',
      'import json, sys; sys.path.insert(0, sys.argv[1]); import test_fallback_regex_bounds as t; print(json.dumps(t.report()))',
      testsDir,
    ], { encoding: 'utf8', timeout: 120_000 });
    expect({ status: run.status, stderr: run.status === 0 ? '' : run.stderr }).toEqual({ status: 0, stderr: '' });
    const result = JSON.parse(run.stdout.trim().split('\n').pop() as string) as {
      budget_ms: number;
      positives: Array<[string, number, boolean]>;
      negatives: Array<[string, number, boolean]>;
      timings: Record<string, [number, boolean]>;
    };
    // The same commands, by length, as the JS surfaces above.
    expect(result.positives.slice(0, longPositives.length).map(([, len]) => len)).toEqual(longPositives.map(([, c]) => c.length));
    expect(result.positives.map(([name, len, hit]) => ({ name, len, hit }))).toEqual(result.positives.map(([name, len]) => ({ name, len, hit: true })));
    expect(result.negatives.map(([name, len, hit]) => ({ name, len, hit }))).toEqual(result.negatives.map(([name, len]) => ({ name, len, hit: false })));
    expect(Object.keys(result.timings).sort()).toEqual(Object.keys(shapes).sort());
    const rows = Object.entries(result.timings).map(([shape, [ms, hit]]) => ({ shape, ms, hit }));
    expect(rows.map((r) => ({ ...r, under: r.ms < result.budget_ms }))).toEqual(rows.map((r) => ({ ...r, hit: false, under: true })));
  });
});
