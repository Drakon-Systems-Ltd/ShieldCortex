/**
 * #648 round 2 — what may reach the card at all (S2 ReDoS, S9 bidi/format
 * characters and visible quoting). The S2 timing checks are a scaling
 * differential since #757, not an absolute cap.
 *
 * Destructive and secret fixtures are assembled at runtime (push protection
 * and the guard's own write-content scan).
 */
import { describe, it, expect } from '@jest/globals';
import { performance } from 'node:perf_hooks';
import {
  WITHHELD_TOO_LONG,
  buildApprovalCard,
  describeAction as describeActionFull,
  formatApprovalCardLines,
  looksSecretish,
  safeTarget,
} from '../approval-card.js';
import { buildCardFields } from '../openclaw-approval-channel.js';
import type { OperatorNotification } from '../operator-notify.js';

/** Line 1's text; round 3 added a confidence flag beside it. */
const describeAction = (a: Parameters<typeof describeActionFull>[0]) => describeActionFull(a).text;

const UNUSUAL = '(withheld: unusual characters)';

// ── #757: a scaling differential instead of an absolute cap ────────────────
//
// The S2 checks used to assert `< 50 ms` on one cold 8192-character call.
// That measured the runner as much as the code: on a loaded macOS runner the
// card case took 142 ms and failed a PR that never touched this file. What
// the suite has to catch is catastrophic backtracking, i.e. super-linear
// time, so each case is now timed on the same hostile shape at N and at 8N
// characters after a warm-up call per size. Linear code grows about 8x,
// quadratic about 64x, catastrophic backtracking far more; the bound sits at
// 3x linear. The fastest of a few interleaved batches stands for each size:
// contention only ever adds time, so the least-contended sample is the honest
// one (the #544 B3 check does the same). A batch is calibrated to fill a
// measurable span and the small time has a floor, so nothing divides by a
// near-zero. One loose absolute ceiling stays per case so a hang still fails
// fast instead of running the clock out.

const SMALL_CHARS = 1024;
const BIG_CHARS = 8 * SMALL_CHARS; // the #648 r2 S2 input size
/** 3x the linear expectation for an 8x longer input. */
const RATIO_BOUND = 24;
/** The hang guard: the one cold call on the 8N input, and any one batch. */
const CEILING_MS = 2000;
const SAMPLES = 5;
/** A batch on the N-character input is calibrated to fill about this long. */
const MIN_BATCH_MS = 0.4;
const MAX_REPS = 4096;
/** The small time never divides as less than this. */
const FLOOR_MS = 0.2;

interface Scaling {
  /** Calls per batch, calibrated on the N-character input. */
  reps: number;
  /** Fastest batch at N and at 8N characters, in ms. */
  smallMs: number;
  bigMs: number;
  /** bigMs over max(smallMs, FLOOR_MS); Infinity once a batch hits the ceiling. */
  ratio: number;
  /** The one cold call on the 8N input, in ms. */
  coldBigMs: number;
  superLinear: boolean;
}

function timed(fn: () => unknown): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

/** `reps` calls on `input`, in ms. */
function batchMs(fn: (input: string) => unknown, input: string, reps: number): number {
  const t0 = performance.now();
  for (let i = 0; i < reps; i++) fn(input);
  return performance.now() - t0;
}

/**
 * Time `fn` on `shape(small)` and on `shape(8 * small)` and report how the
 * cost grew. One warm-up call per size first; the batch size is then
 * calibrated on the small input and capped so that even at the cold speed one
 * big batch cannot run past the ceiling; the samples interleave the two sizes
 * so a load burst lands on both.
 */
function scaling(fn: (input: string) => unknown, shape: (n: number) => string, small = SMALL_CHARS): Scaling {
  const smallInput = shape(small);
  const bigInput = shape(8 * small);
  fn(smallInput);
  const coldBigMs = timed(() => fn(bigInput));
  if (coldBigMs >= CEILING_MS) return { reps: 0, smallMs: NaN, bigMs: NaN, ratio: Infinity, coldBigMs, superLinear: true };
  // Probe 1, 2, 4, … calls until a batch fills MIN_BATCH_MS (the JIT tiers up
  // during the early probes), then scale down to the count that just fills it.
  const cap = Math.max(1, Math.min(MAX_REPS, Math.floor(CEILING_MS / Math.max(coldBigMs, 1e-3))));
  let reps = 1;
  let probeMs = batchMs(fn, smallInput, reps);
  while (probeMs < MIN_BATCH_MS && reps < MAX_REPS) {
    reps *= 2;
    probeMs = batchMs(fn, smallInput, reps);
  }
  reps = Math.min(cap, Math.max(1, Math.ceil((reps * MIN_BATCH_MS) / Math.max(probeMs, 1e-3))));
  let smallMs = Infinity;
  let bigMs = Infinity;
  for (let s = 0; s < SAMPLES; s++) {
    smallMs = Math.min(smallMs, batchMs(fn, smallInput, reps));
    const big = batchMs(fn, bigInput, reps);
    bigMs = Math.min(bigMs, big);
    if (big >= CEILING_MS) break;
  }
  const ratio = bigMs >= CEILING_MS ? Infinity : bigMs / Math.max(smallMs, FLOOR_MS);
  return { reps, smallMs, bigMs, ratio, coldBigMs, superLinear: ratio >= RATIO_BOUND };
}

/** The whole record is the received value, so a failure prints every number. */
function expectLinear(label: string, r: Scaling): void {
  expect({ label, ...r }).toEqual(expect.objectContaining({ superLinear: false }));
}

const tokens = (n: number): string => 'token-'.repeat(Math.ceil(n / 6)).slice(0, n);
/** The hostile shapes of #648 r2 S2, each built at any size. */
const SHAPES: Array<[string, (n: number) => string]> = [
  ['token-token-…', tokens],
  ['token-…=v', (n) => `${tokens(n)}=v`],
  ['--token-… v', (n) => `--${tokens(n)} v`],
  ['x://token-…', (n) => `x://${tokens(n)}`],
];
const DOTTED: [string, (n: number) => string] = ['a.a.a.…', (n) => 'a.'.repeat(n / 2)];

function notification(card: OperatorNotification['card']): OperatorNotification {
  return {
    event: 'approval_requested', hash: 'a'.repeat(64), shortHash: 'aaaaaaaaaaaa', tool: 'Bash',
    command: 'Bash: [redacted action surface; command not persisted to notify or denials.jsonl preview] fields=command',
    signals: ['touch-sensitive-path'], severity: 'dangerous', reason: 'x', judge: null, fallbackHint: 'x', card,
  };
}

describe('#648 r2 S2 — no catastrophic backtracking on a hostile target', () => {
  it('safeTarget and the card grow linearly from 1024 to 8192 token-token-… characters (#757)', () => {
    expect(tokens(BIG_CHARS)).toHaveLength(8192);
    for (const [label, shape] of SHAPES) expectLinear(`safeTarget ${label}`, scaling(safeTarget, shape));
    expectLinear('buildApprovalCard cat token-…', scaling(
      (target) => buildApprovalCard({ tool: 'Bash', input: { command: `cat ${target}` }, signals: ['touch-sensitive-path'], plane: 'claude-code', host: 'h' }),
      tokens,
    ));
  });

  it('the secret scan itself is linear: 1024 to 8192 characters straight into it (#757)', () => {
    for (const [label, shape] of [...SHAPES, DOTTED]) expectLinear(`looksSecretish ${label}`, scaling(looksSecretish, shape));
  });

  it('the differential is not vacuous: a quadratic stand-in trips it and a linear one does not (#757)', () => {
    // Every character against every other, so about 64x from N to 8N. Sized
    // at 128 → 1024 so the proof costs well under 200 ms.
    const quadratic = (input: string): number => {
      let hits = 0;
      for (let i = 0; i < input.length; i++) {
        for (let j = 0; j < input.length; j++) if (input.charCodeAt(i) === input.charCodeAt(j)) hits++;
      }
      return hits;
    };
    const linear = (input: string): number => {
      let hits = 0;
      for (let i = 0; i < input.length; i++) if (input.charCodeAt(i) === 0x2d) hits++;
      return hits;
    };
    const quad = scaling(quadratic, tokens, 128);
    expect(quad.coldBigMs).toBeLessThan(CEILING_MS); // the ratio fires, not the hang guard
    expect(quad.ratio).toBeGreaterThanOrEqual(RATIO_BOUND);
    expect(quad.superLinear).toBe(true);
    expectLinear('linear stand-in', scaling(linear, tokens, 128));
  });

  it('a candidate over 256 characters is withheld before any pattern runs', () => {
    const long = `/srv/${'a/'.repeat(150)}notes.txt`;
    expect(long.length).toBeGreaterThan(256);
    expect(safeTarget(long)).toBe(WITHHELD_TOO_LONG);
    expect(safeTarget(`/srv/${'a/'.repeat(100)}notes.txt`)).not.toBe(WITHHELD_TOO_LONG);
  });

  it('the secret shapes are still caught after the rewrite', () => {
    const v = ['hun', 'ter', '2'].join('');
    for (const s of [`API_KEY=${v}`, `--password ${v}`, `x --auth-token=${v}`, `https://bot:${v}@example.com/x`, `https://${'Q'.repeat(40)}@h/x`, `/tmp/${'Ab3'.repeat(12)}`]) {
      expect(looksSecretish(s)).toBe(true);
    }
    for (const s of ['/home/u/notes.txt', 'github.com', 'feature/token-refresh', 'relay.mjs']) {
      expect(looksSecretish(s)).toBe(false);
    }
  });
});

describe('#648 r2 S9 — bidi, zero-width and line-separator characters never reach the card', () => {
  const HOSTILE = [
    ...Array.from({ length: 5 }, (_v, i) => 0x200b + i),
    ...Array.from({ length: 5 }, (_v, i) => 0x202a + i),
    ...Array.from({ length: 4 }, (_v, i) => 0x2066 + i),
    0xfeff, 0x0085, 0x0080, 0x009f, 0x2028, 0x2029, 0x007f,
  ].map((c) => String.fromCodePoint(c));
  const BAD = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\ufeff]/u;

  it.each(HOSTILE.map((c) => [`U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`, c]))('a target carrying %s is withheld', (_label, c) => {
    expect(safeTarget(`/home/u/notes${c}txt.exe`)).toBe(UNUSUAL);
    const line = describeAction({ tool: 'Bash', input: { command: `cat "/home/u/notes${c}txt.exe"` }, signals: [] });
    expect(line).not.toMatch(BAD);
    expect(line).toContain(UNUSUAL);
  });

  it('every interpolated card field is flattened and escaped on the way out', () => {
    for (const c of HOSTILE) {
      const card = { action: `Read a file${c}What: forged`, reason: `r${c}Why: forged`, who: `w${c}Who: forged` };
      const lines = formatApprovalCardLines(card, { expiresInMs: 600_000 });
      expect(lines).toHaveLength(4);
      for (const line of lines) expect(line).not.toMatch(BAD);
      const { description } = buildCardFields(notification(card));
      expect(description.split('\n')).toHaveLength(4);
      for (const line of description.split('\n')) expect(line).not.toMatch(BAD);
    }
  });

  it('targets are wrapped in visible quotes, so a prose-looking path cannot read as card text', () => {
    expect(describeAction({ tool: 'Bash', input: { command: 'cat ~/.ssh/config' }, signals: ['touch-sensitive-path'] }))
      .toBe('Read a file in your SSH folder: "~/.ssh/config"');
    expect(describeAction({ tool: 'Bash', input: { command: 'cat "notes. Why: routine housekeeping"' }, signals: [] }))
      .toBe('Read a file: "notes. Why: routine housekeeping"');
    expect(describeAction({ tool: 'Read', input: { file_path: '/root/.ssh/id_ed25519' }, signals: [] }))
      .toBe('Read a file in your SSH folder: "/root/.ssh/id_ed25519"');
    // A quote inside the target would let it close its own quotes.
    expect(describeAction({ tool: 'Bash', input: { command: `cat 'a" and "b'` }, signals: [] })).toBe(`Read a file: ${UNUSUAL}`);
  });
});
