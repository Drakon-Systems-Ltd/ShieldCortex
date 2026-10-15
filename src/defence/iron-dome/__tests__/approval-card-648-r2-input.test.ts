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
// characters. Linear code grows about 8x, quadratic about 64x, catastrophic
// backtracking far more; the bound sits at 3x linear. The fastest of a few
// interleaved batches stands for each size: contention only ever adds time,
// so the least-contended sample is the honest one (the #544 B3 check does
// the same). A batch is calibrated to fill a measurable span on the small
// input, and that calibration is then checked against the batches actually
// measured: a one-call probe inflated by a scheduler pause would otherwise
// leave the batch at one call, under the resolution the ratio needs (round-2
// B1). A small time that stays unmeasurable after re-calibrating is reported
// inconclusive, which the assertion fails: no result passes on a floored
// denominator. One loose absolute ceiling stays per case so a hang still
// fails fast instead of running the clock out.

const SMALL_CHARS = 1024;
const BIG_CHARS = 8 * SMALL_CHARS; // the #648 r2 S2 input size
/** 3x the linear expectation for an 8x longer input. */
const RATIO_BOUND = 24;
/** The hang guard: the one cold call on the 8N input, and any one batch of either size. */
const CEILING_MS = 2000;
const SAMPLES = 5;
/** A batch on the N-character input is calibrated to fill about this long. */
const MIN_BATCH_MS = 0.4;
/** Room for a length-gated path: once inlined a call costs a few ns, so filling MIN_BATCH_MS takes ~100k calls. */
const MAX_REPS = 1 << 20;
/** The small time must reach this to be measurable; under it the result is inconclusive. */
const FLOOR_MS = 0.2;
/** How many times the batch may be re-sized from the measured small time. */
const MAX_RECALIBRATIONS = 3;

interface Scaling {
  /** Calls per batch, as finally calibrated on the N-character input. */
  reps: number;
  /** How many times the batch was re-sized after the sampled small time came in short. */
  recalibrations: number;
  /** Fastest batch at N and at 8N characters, in ms. */
  smallMs: number;
  bigMs: number;
  /** Whether any one batch, small or big, ran to the ceiling. */
  ceilingHit: boolean;
  /**
   * bigMs over smallMs; Infinity once the cold call or any batch hits the
   * ceiling. While inconclusive the denominator is floored at FLOOR_MS, so the
   * ratio is a lower bound on the true growth: it can still fail, never pass.
   */
  ratio: number;
  /** The one cold call on the 8N input, in ms. */
  coldBigMs: number;
  /** The small time never reached FLOOR_MS: too little resolution to call anything linear. */
  inconclusive: boolean;
  superLinear: boolean;
}

/** `reps` calls of `fn` on `input`, in ms. Injectable so a scripted clock can drive the classifier. */
type BatchClock = (fn: (input: string) => unknown, input: string, reps: number) => number;

const realBatchMs: BatchClock = (fn, input, reps) => {
  const t0 = performance.now();
  for (let i = 0; i < reps; i++) fn(input);
  return performance.now() - t0;
};

/**
 * Time `fn` on `shape(small)` and on `shape(8 * small)` and report how the
 * cost grew. One discarded warm-up call on the small input first; the first
 * call on the big input is the timed cold measurement the hang guard reads.
 * The batch size is then calibrated on the small input and capped so that
 * one big batch cannot run past the ceiling at the fastest big-call cost yet
 * seen (the cold call, later refined by the fastest sampled batch); the
 * samples interleave the two sizes so a load burst lands on both. If the
 * fastest small batch still comes in under MIN_BATCH_MS, the batch is re-sized
 * from that measured time and the samples are taken again, up to
 * MAX_RECALIBRATIONS times or until the cap binds.
 */
function scaling(
  fn: (input: string) => unknown,
  shape: (n: number) => string,
  small = SMALL_CHARS,
  clock: BatchClock = realBatchMs,
): Scaling {
  const smallInput = shape(small);
  const bigInput = shape(8 * small);
  fn(smallInput);
  const coldBigMs = clock(fn, bigInput, 1);
  if (coldBigMs >= CEILING_MS) {
    return { reps: 0, recalibrations: 0, smallMs: NaN, bigMs: NaN, ceilingHit: true, ratio: Infinity, coldBigMs, inconclusive: false, superLinear: true };
  }
  const capFor = (bigPerCallMs: number): number => Math.max(1, Math.min(MAX_REPS, Math.floor(CEILING_MS / Math.max(bigPerCallMs, 1e-3))));
  // Probe 1, 2, 4, … calls until a batch fills MIN_BATCH_MS (the JIT tiers up
  // during the early probes), then scale down to the count that just fills it.
  let cap = capFor(coldBigMs);
  let reps = 1;
  let probeMs = clock(fn, smallInput, reps);
  while (probeMs < MIN_BATCH_MS && reps < MAX_REPS) {
    reps *= 2;
    probeMs = clock(fn, smallInput, reps);
  }
  reps = Math.min(cap, Math.max(1, Math.ceil((reps * MIN_BATCH_MS) / Math.max(probeMs, 1e-3))));
  const sample = (): { smallMs: number; bigMs: number; ceilingHit: boolean } => {
    let smallMs = Infinity;
    let bigMs = Infinity;
    for (let s = 0; s < SAMPLES; s++) {
      const sm = clock(fn, smallInput, reps);
      smallMs = Math.min(smallMs, sm);
      if (sm >= CEILING_MS) return { smallMs, bigMs, ceilingHit: true };
      const big = clock(fn, bigInput, reps);
      bigMs = Math.min(bigMs, big);
      if (big >= CEILING_MS) return { smallMs, bigMs, ceilingHit: true };
    }
    return { smallMs, bigMs, ceilingHit: false };
  };
  // The probe is one reading and may carry a pause the samples never see; the
  // fastest sampled small batch is the authority on whether reps is enough.
  // The fastest sampled big batch likewise refines the cap the cold call set.
  let recalibrations = 0;
  let run = sample();
  while (!run.ceilingHit && run.smallMs < MIN_BATCH_MS && recalibrations < MAX_RECALIBRATIONS) {
    cap = Math.max(cap, capFor(run.bigMs / reps));
    if (reps >= cap) break;
    recalibrations++;
    // At least double: a JIT still tiering up makes each round's calls cheaper than the last round measured.
    reps = Math.min(cap, Math.max(2 * reps, Math.ceil((reps * MIN_BATCH_MS) / Math.max(run.smallMs, 1e-3))));
    run = sample();
  }
  const { smallMs, bigMs, ceilingHit } = run;
  const inconclusive = smallMs < FLOOR_MS;
  const ratio = ceilingHit ? Infinity : bigMs / Math.max(smallMs, FLOOR_MS);
  return { reps, recalibrations, smallMs, bigMs, ceilingHit, ratio, coldBigMs, inconclusive, superLinear: ratio >= RATIO_BOUND };
}

/** The whole record is the received value, so a failure prints every number. */
function expectLinear(label: string, r: Scaling): void {
  expect({ label, ...r }).toEqual(expect.objectContaining({ superLinear: false, inconclusive: false }));
}

/**
 * A scripted clock for driving `scaling` without real time; `fn` never runs.
 * Each size has a queue of fixed batch times consumed first, in call order
 * (the first big call is the cold one, the first small calls are the probes);
 * once a queue is empty a batch costs `perCall * reps` ms.
 */
function scriptedClock(smallPerCallMs: number, bigPerCallMs: number, first: { small?: number[]; big?: number[] } = {}): BatchClock {
  const queue = { small: [...(first.small ?? [])], big: [...(first.big ?? [])] };
  return (_fn, input, reps) => {
    const size = input.length > SMALL_CHARS ? 'big' : 'small';
    return queue[size].shift() ?? (size === 'big' ? bigPerCallMs : smallPerCallMs) * reps;
  };
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
    // The production assertion itself must reject it, not just the flag (r2 N1).
    expect(() => expectLinear('quadratic stand-in', quad)).toThrow();
    expectLinear('linear stand-in', scaling(linear, tokens, 128));
  });

  describe('the classifier, driven by a scripted clock (#757 r2)', () => {
    const noop = (): void => undefined;
    const drive = (clock: BatchClock): Scaling => scaling(noop, tokens, SMALL_CHARS, clock);

    it('B1: an inflated one-call probe followed by clean quadratic samples is rejected', () => {
      // 0.05 ms a call at N and 3.2 ms at 8N is 64x growth, but the probe
      // reads 0.8 ms (a pause), which ended calibration at one call; the
      // floored ratio 3.2 / 0.2 = 16 then passed.
      const r = drive(scriptedClock(0.05, 3.2, { small: [0.8] }));
      expect(r.coldBigMs).toBe(3.2);
      expect(r.recalibrations).toBeGreaterThanOrEqual(1);
      expect(r.reps).toBeGreaterThanOrEqual(8);
      expect(r.inconclusive).toBe(false);
      expect(r.ratio).toBeCloseTo(64, 6);
      expect(r.superLinear).toBe(true);
      expect(() => expectLinear('scripted quadratic, inflated probe', r)).toThrow();
    });

    it('a linear path passes', () => {
      const r = drive(scriptedClock(0.01, 0.08));
      expect(r).toEqual(expect.objectContaining({ ceilingHit: false, inconclusive: false, superLinear: false }));
      expect(r.smallMs).toBeGreaterThanOrEqual(MIN_BATCH_MS);
      expect(r.ratio).toBeCloseTo(8, 6);
      expectLinear('scripted linear', r);
    });

    it('N2: a later big batch at the ceiling is rejected even after an earlier fast one', () => {
      // Cold call, first sampled big batch, second sampled big batch.
      const r = drive(scriptedClock(0.01, 0.08, { big: [0.08, 3.2, CEILING_MS] }));
      expect(r).toEqual(expect.objectContaining({ ceilingHit: true, ratio: Infinity, superLinear: true }));
      expect(r.bigMs).toBe(3.2); // the fastest batch no longer hides the crossing
      expect(() => expectLinear('scripted late ceiling', r)).toThrow();
    });

    it('N2: a small batch at the ceiling is rejected too', () => {
      // The one-call probe fills MIN_BATCH_MS at once, so the next small call is the first sampled batch.
      const r = drive(scriptedClock(0.5, 4, { small: [0.5, CEILING_MS] }));
      expect(r).toEqual(expect.objectContaining({ reps: 1, ceilingHit: true, ratio: Infinity, superLinear: true }));
      expect(() => expectLinear('scripted small ceiling', r)).toThrow();
    });

    it('a path too fast to resolve even at the rep cap is inconclusive and fails, not linear', () => {
      // Half of FLOOR_MS at MAX_REPS: under the floor with nowhere left to grow.
      const tooFast = FLOOR_MS / 2 / MAX_REPS;
      const r = drive(scriptedClock(tooFast, 8 * tooFast));
      expect(r).toEqual(expect.objectContaining({ reps: MAX_REPS, inconclusive: true, superLinear: false }));
      expect(r.smallMs).toBeLessThan(FLOOR_MS);
      expect(() => expectLinear('scripted unresolvable', r)).toThrow();
    });
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
