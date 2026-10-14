/**
 * #500 — Action Guard must gate tool-call mutations to its own config and
 * lifecycle. When Guard is ON, an agent must not be able to switch it off,
 * downgrade it, uninstall it globally, or rewrite config.json via a tool.
 * Hook-file wiring (.claude/settings.json) and same-UID writes outside the
 * tool surface are NOT in this PR (see #501).
 *
 * Token-split literals so the live host scanner does not deny this file.
 */
import { evaluateToolCall } from '../tool-action-guard.js';

const cfg = { enabled: true, enforce: true } as any;
const SC = 'shield' + 'cortex';
const DISABLE = '--action-guard-' + 'disable';
const ADVISORY = '--action-guard-' + 'advisory';
const UNINST = 'un' + 'install';
const G = '-' + 'g';
const NPM = 'n' + 'pm';
const DEL = 'r' + 'm';
const FLAGS = '-' + 'rf';
const ROOT = ' /';
const PRIV = 's' + 'u' + 'd' + 'o';
const RMV = 'r' + 'm';
const YES = '--' + 'yes';

function bash(command: string) {
  return evaluateToolCall('Bash', { command }, cfg);
}

describe('#500 Action Guard self-protection', () => {
  it('gates signed CLI disable from a Bash tool call', () => {
    const v = bash(`${SC} config ${DISABLE}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  it('gates signed CLI advisory downgrade from a Bash tool call', () => {
    const v = bash(`${SC} config ${ADVISORY}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
    expect(v.decision).toBe('require_approval');
  });

  it('gates npx-prefixed disable', () => {
    const v = bash(`npx ${SC} config ${DISABLE}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('gates iron-dome deactivate', () => {
    const v = bash(`${SC} iron-dome deactivate`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('gates global uninstall of the package', () => {
    const v = bash(`${NPM} ${UNINST} ${G} ${SC}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('gates Write of ~/.shieldcortex/config.json', () => {
    const v = evaluateToolCall('Write', {
      file_path: '/home/ubuntu/.shieldcortex/config.json',
      content: '{"actionGuard":{"enabled":false}}',
    }, cfg);
    expect(v.signals ?? []).toContain('touch-guard-config');
    expect(v.severity).toBe('dangerous');
  });

  it('gates Edit of config.json', () => {
    const v = evaluateToolCall('Edit', {
      path: '/tmp/home/.shieldcortex/config.json',
      old_string: '"enabled": true',
      new_string: '"enabled": false',
    }, cfg);
    expect(v.signals ?? []).toContain('touch-guard-config');
    expect(v.severity).toBe('dangerous');
  });

  it('allows a pure echo of the disable flag (prose, not invocation)', () => {
    const v = bash(`echo blocked ${SC} config ${DISABLE}`);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
    expect(v.severity).not.toBe('dangerous');
  });

  it('still gates a catastrophic delete while Guard is on (control)', () => {
    const v = bash(`${DEL} ${FLAGS}${ROOT}`);
    expect(v.severity).toBe('catastrophic');
    expect(v.decision).toBe('block');
  });

  // GPT-6 r1: wrappers, absolute path, env assignment, node $(which), --location=global.
  it.each([
    ['absolute path', `/usr/bin/${SC} config ${DISABLE}`],
    ['env wrapper', `env ${SC} config ${DISABLE}`],
    ['env assignment prefix', `SHIELDCORTEX_CONFIG_DIR=/tmp/sc ${SC} config ${DISABLE}`],
    ['node $(which)', `node $(which ${SC}) config ${DISABLE}`],
    ['privilege wrapper', `${PRIV} ${SC} config ${DISABLE}`],
    ['npx auto-confirm', `npx ${YES} ${SC} config ${DISABLE}`],
    ['extra config flag before disable', `${SC} config --quiet ${DISABLE}`],
  ])('gates disable via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it.each([
    ['--location=global', `${NPM} ${UNINST} --location=global ${SC}`],
    ['--global long flag', `${NPM} ${UNINST} --global ${SC}`],
    ['npm short alias', `${NPM} ${RMV} ${G} ${SC}`],
    ['scoped realtime plugin', `${NPM} ${UNINST} ${G} @drakon-systems/${SC}-realtime`],
    ['yarn global remove', `yarn global remove ${SC}`],
  ])('gates global uninstall via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  it('does not gate global uninstall of an unrelated package with a shared prefix', () => {
    const v = bash(`${NPM} ${UNINST} ${G} ${SC}-helper`);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });

  it('does not gate a workspace-local uninstall', () => {
    const v = bash(`${NPM} ${UNINST} ${SC}`);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });

  // GPT-6 r2: shell quotes around the subcommand / flag reach npm as the same argv.
  it.each([
    ['quoted uninstall verb', `${NPM} "${UNINST}" ${G} ${SC}`],
    ['single-quoted uninstall verb', `${NPM} '${UNINST}' ${G} ${SC}`],
    ['quoted package', `${NPM} ${UNINST} ${G} "${SC}"`],
    ['quoted global flag', `${NPM} ${UNINST} "${G}" ${SC}`],
  ])('gates global uninstall via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });
  it.each([
    ['quoted disable flag', `${SC} config "${DISABLE}"`],
    ['quoted deactivate', `${SC} 'iron-dome' 'deactivate'`],
  ])('gates disable via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  // GPT-6 r3 P2: removal vocabulary as a query ARGUMENT is not an uninstall.
  it.each([
    ['npm ls with uninstall as an argument', `${NPM} ls ${G} ${SC} ${UNINST}`],
    ['npm view of the package', `${NPM} view ${SC} version`],
    ['npm ls -g of the package', `${NPM} ls ${G} ${SC}`],
    ['npm outdated -g', `${NPM} outdated ${G}`],
  ])('does not gate a read-only query: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });
  it('still gates when a flag precedes the verb', () => {
    const v = bash(`${NPM} ${G} ${UNINST} ${SC}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
  });

  // GPT-6 r3 P1 (cheap fold, disable flag only). Interior quotes in the
  // BINARY name (git-class) and general quote-normalization are #504.
  const IQ = String.fromCharCode(34);
  it.each([
    ['interior quote in disable', `${SC} config --action-guard-dis${IQ}able${IQ}`],
    ['backslash before able', `${SC} config --action-guard-dis\\able`],
  ])('gates disable via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });

  // GPT-6 r4: value-taking options before the verb; explicit --global=false.
  it.each([
    ['--loglevel silent before verb', `${NPM} --loglevel silent ${G} ${UNINST} ${SC}`],
    ['--prefix /opt before verb', `${NPM} --prefix /opt/n ${G} ${UNINST} ${SC}`],
    ['--global=true', `${NPM} ${UNINST} --global=true ${SC}`],
  ])('gates global uninstall via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });
  it.each([
    ['--global=false', `${NPM} ${UNINST} --global=false ${SC}`],
    ['--location=project', `${NPM} ${UNINST} --location=project ${SC}`],
  ])('does not gate an explicitly local uninstall: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });

  // r5 ReDoS tripwire: a (flag value?)* pre-verb group blew up to >60s on
  // this shape. Rule must stay linear on many flag/value pairs with no verb.
  it('stays fast on thousands of flag/value pairs before the package (ReDoS tripwire)', () => {
    const pairs = Array.from({ length: 4000 }, (_, i) => `--opt${i} val${i}`).join(' ');
    const t0 = Date.now();
    bash(`${NPM} ${pairs} ${G} ${SC}`);
    bash(`${NPM} ${'-a b '.repeat(10000)}${SC} ${G}`);
    expect(Date.now() - t0).toBeLessThan(500);
  });

  // GPT-6 r5 P1: later boolean wins in npm.
  it('gates when --global=false is overridden by a later --global=true', () => {
    const v = bash(`${NPM} ${UNINST} --global=false --global=true ${SC}`);
    expect(v.signals ?? []).toContain('disable-action-guard');
  });
  it('does not gate when --global=true is overridden by a later --global=false', () => {
    const v = bash(`${NPM} ${UNINST} --global=true --global=false ${SC}`);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });
  // GPT-6 r5 P2: repeated verb with a non-matching package must stay linear.
  it('stays fast on thousands of repeated verbs with a shared-prefix package (ReDoS tripwire 2)', () => {
    const t0 = Date.now();
    const v = bash(`${NPM} ${G} ` + (UNINST + ' ').repeat(4000) + `${SC}-helper`);
    expect(Date.now() - t0).toBeLessThan(300);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });

  // GPT-6 r6 P1: inline-shell -c was dropped because collectExecutableBodies
  // does not unwrap quoted programs. Recurse like the install disposer.
  it.each([
    ['bash -c double', `bash -c "${NPM} ${UNINST} ${G} ${SC}"`],
    ['sh -c single', `sh -c '${NPM} un ${G} ${SC}'`],
    ['eval wrapper', `eval "${NPM} ${UNINST} ${G} ${SC}"`],
    ['$PM fail-closed', `$PM ${UNINST} ${G} ${SC}`],
    ['npm uninstall -g -- pkg', `${NPM} ${UNINST} ${G} -- ${SC}`],
  ])('gates wrapped global uninstall via: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).toContain('disable-action-guard');
    expect(v.severity).toBe('dangerous');
  });
  it.each([
    ['eval as package query', `npm view ${SC} eval`],
    ['eval as local extra arg', `${NPM} ${UNINST} ${SC} eval`],
    ['echo of uninstall', `echo blocked ${NPM} ${UNINST} ${G} ${SC}`],
  ])('does not gate eval-as-vocabulary / echo: %s', (_label, command) => {
    const v = bash(command);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });
  // GPT-6 r6 P2: repeated pm / package tokens must stay linear now that
  // there is no DANGEROUS-table regex for uninstall.
  it.each([
    ['pkg-repeat', () => `${NPM} ls ` + (`${SC} `).repeat(4000) + 'x'],
    ['cli-repeat', () => `${SC} ` + (`${SC} `).repeat(4000) + 'status'],
  ])('stays fast on thousands of repeated %s tokens (ReDoS tripwire 3)', (_label, make) => {
    const t0 = Date.now();
    bash(make());
    expect(Date.now() - t0).toBeLessThan(300);
  });
  // pm-repeat is dominated by a PRE-EXISTING quadratic in the shell
  // tokeniser (`npm ` x 8000 = ~1.1s on main before #518, x4 per doubling).
  // Measure what THIS walk adds on top: the same input with and without a
  // guard package token. Absolute wall time on a shared CI runner is not a
  // property of this code.
  //
  // #759: each side used to be the fastest of two back-to-back calls, and one
  // slow call on the "with" side on a loaded macOS runner crossed the bound
  // (74.8 ms added against a 55.3 ms bound). The two sides are now sampled
  // interleaved as pairs (without_i, with_i), so a load burst lands on both
  // halves of a pair, and the verdict is the MEDIAN of the paired differences
  // with_i - without_i, pooled over every round sampled so far. One stalled
  // call cannot fail it, and one fast call cannot rescue it: the round-1 rule
  // judged min(with) - min(without), which let a single cheap with-call erase
  // quadratic work that every other call had paid (review B1). The bound
  // itself is unchanged: the walk may add a constant, max(ADDED_FLOOR_MS, half
  // the tokeniser time), where the tokeniser time is the least-contended
  // "without" call, since contention only ever adds time. A round that still
  // reads over the bound adds another round of pairs to the pool, up to
  // EXTRA_ROUNDS more, before the verdict. There is no absolute cap on either
  // side.
  const SAMPLES = 7;
  const EXTRA_ROUNDS = 2;
  const ALL_ROUNDS = 1 + EXTRA_ROUNDS;
  const ADDED_FLOOR_MS = 50;
  const ADDED_FRACTION = 0.5;
  /** Hang guard only: Jest's default 10 s could fail a slow runner on call count alone. */
  const TRIPWIRE_3B_TIMEOUT_MS = 60_000;

  interface AddedCost {
    /** Fastest observed "without" call, in ms: the honest tokeniser cost. */
    without: number;
    /** Median observed "with" call, in ms. */
    withPkg: number;
    /** Median of the paired differences with_i - without_i: what the guard package token adds. */
    added: number;
    /** max(ADDED_FLOOR_MS, without * ADDED_FRACTION). */
    bound: number;
    /** Rounds sampled before the verdict: 1 when the first round passed, at most ALL_ROUNDS. */
    rounds: number;
    /** Pairs pooled into the verdict: samples per round x rounds. */
    samples: number;
    /** The verdict, added < bound. The production case and the controls all read it from here. */
    withinBound: boolean;
  }

  const msOf = (fn: () => unknown): number => {
    const t0 = process.hrtime.bigint();
    fn();
    return Number(process.hrtime.bigint() - t0) / 1e6;
  };
  const median = (xs: readonly number[]): number => {
    const sorted = [...xs].sort((a, b) => a - b);
    const mid = sorted.length >> 1;
    return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  };

  /**
   * One discarded warm-up call per side, then `samplesPerRound` interleaved
   * pairs (without, with, without, with, ...). The verdict is the median of
   * the paired differences pooled over every round so far, against the bound
   * derived from the fastest "without" call. Returns as soon as the pooled
   * verdict passes; otherwise samples up to EXTRA_ROUNDS more rounds and
   * reports the final reading.
   */
  function addedCost(timeWithout: () => number, timeWith: () => number, samplesPerRound = SAMPLES): AddedCost {
    timeWithout();
    timeWith();
    const withouts: number[] = [];
    const withs: number[] = [];
    const diffs: number[] = [];
    for (let rounds = 1; ; rounds++) {
      for (let s = 0; s < samplesPerRound; s++) {
        const w0 = timeWithout();
        const w1 = timeWith();
        withouts.push(w0);
        withs.push(w1);
        diffs.push(w1 - w0);
      }
      const without = Math.min(...withouts);
      const added = median(diffs);
      const bound = Math.max(ADDED_FLOOR_MS, without * ADDED_FRACTION);
      const result: AddedCost = {
        without,
        withPkg: median(withs),
        added,
        bound,
        rounds,
        samples: diffs.length,
        withinBound: added < bound,
      };
      if (result.withinBound || rounds > EXTRA_ROUNDS) return result;
    }
  }

  const PM_REPEAT = `${NPM} ls ` + (`${NPM} `).repeat(2000);
  const timeBash = (cmd: string): number => msOf(() => bash(cmd));

  it('adds no more than a constant on top of the tokeniser for pm-repeat (ReDoS tripwire 3b)', () => {
    const r = addedCost(
      () => timeBash(PM_REPEAT + 'other-helper'),
      () => timeBash(PM_REPEAT + `${SC}-helper`),
    );
    expect(r).toMatchObject({ withinBound: true });
  }, TRIPWIRE_3B_TIMEOUT_MS);

  // Two controls run real CPU work on top of the real call through the same
  // addedCost. The positive control adds deliberately quadratic passes over
  // the input and must be rejected, so a no-op comparison fails here; the
  // negative control adds a linear pass and must pass at the default plan.
  // The quadratic workload is calibrated on the host first: round-1 CI showed
  // one fixed pass costing less than the bound on a fast macOS runner. So the
  // honest "without" side is measured, the bound derived from it, and the
  // number of passes doubled until one addition reads at least
  // CALIBRATION_MARGIN times that bound, or MAX_CALIBRATION_STEPS doublings
  // have been tried. k passes cost k * L^2, still quadratic in the input
  // length L. Every "with" call in the positive control then costs several
  // times the real call, so it samples CONTROL_SAMPLES pairs per round rather
  // than SAMPLES; it still runs every round, since always-paid quadratic work
  // is never rescued by re-sampling. (Intermittently paid work is the
  // synthetic intermittent control below.) Each control owns its sink.
  const CONTROL_SAMPLES = 3;
  const CALIBRATION_MARGIN = 3;
  const MAX_CALIBRATION_STEPS = 8;
  /** Discarded workload calls before calibration reads it, so the readings are of optimised code. */
  const CALIBRATION_WARMUPS = 3;
  // Both passes walk the input's char codes in a typed array rather than the
  // string: V8 serves charCodeAt on a concatenated (cons) string through an
  // indirection until a GC short-cuts it to the flat string, and bash() in
  // the with-call allocates enough to trigger that GC. Walking the string
  // read 1.7x slower in calibration than inside the helper, eating the margin.
  const codesOf = (s: string): Uint16Array => Uint16Array.from(s, (c) => c.charCodeAt(0));
  const quadraticPass = (codes: Uint16Array): number => {
    let hits = 0;
    for (let i = 0; i < codes.length; i++) {
      const c = codes[i];
      for (let j = 0; j < codes.length; j++) if (codes[j] === c) hits++;
    }
    return hits;
  };
  const quadraticPasses = (codes: Uint16Array, passes: number): number => {
    let hits = 0;
    for (let p = 0; p < passes; p++) hits += quadraticPass(codes);
    return hits;
  };
  const linearPass = (codes: Uint16Array): number => {
    let hits = 0;
    for (let i = 0; i < codes.length; i++) if (codes[i] === 32) hits++;
    return hits;
  };

  interface Calibration {
    /** Fastest of CONTROL_SAMPLES real "without" calls after a warm-up, in ms. */
    without: number;
    /** max(ADDED_FLOOR_MS, without * ADDED_FRACTION), as addedCost derives it. */
    bound: number;
    /** Quadratic passes per with-call: 1 doubled `steps` times. */
    passes: number;
    steps: number;
    /** Fastest of CONTROL_SAMPLES warm readings of `passes` passes, in ms: >= CALIBRATION_MARGIN * bound unless the cap was hit. */
    measured: number;
  }
  function calibrateQuadratic(codes: Uint16Array): Calibration {
    const timeWithout = () => timeBash(PM_REPEAT + 'other-helper');
    timeWithout();
    let without = Infinity;
    for (let s = 0; s < CONTROL_SAMPLES; s++) without = Math.min(without, timeWithout());
    const bound = Math.max(ADDED_FLOOR_MS, without * ADDED_FRACTION);
    // Warm the exact path the with-side will run, so the readings below are of
    // optimised code: a cold reading overstates the workload and would leave
    // the helper seeing less than CALIBRATION_MARGIN x bound.
    for (let w = 0; w < CALIBRATION_WARMUPS; w++) quadraticPasses(codes, 1);
    const timePasses = (passes: number): number => {
      let fastest = Infinity;
      for (let s = 0; s < CONTROL_SAMPLES; s++) fastest = Math.min(fastest, msOf(() => quadraticPasses(codes, passes)));
      return fastest;
    };
    let passes = 1;
    let steps = 0;
    let measured = timePasses(passes);
    while (measured < CALIBRATION_MARGIN * bound && steps < MAX_CALIBRATION_STEPS) {
      passes *= 2;
      steps++;
      measured = timePasses(passes);
    }
    return { without, bound, passes, steps, measured };
  }

  it('rejects a genuinely quadratic addition through the same differential (3b positive control, calibrated)', () => {
    const input = PM_REPEAT + `${SC}-helper`;
    const codes = codesOf(input);
    const calibration = calibrateQuadratic(codes);
    let sink = 0;
    const r = addedCost(
      () => timeBash(PM_REPEAT + 'other-helper'),
      () => msOf(() => { bash(input); sink += quadraticPasses(codes, calibration.passes); }),
      CONTROL_SAMPLES,
    );
    expect({ calibration, result: r }).toMatchObject({
      result: { withinBound: false, rounds: ALL_ROUNDS, samples: CONTROL_SAMPLES * ALL_ROUNDS },
    });
    expect(r.added).toBeGreaterThanOrEqual(r.bound);
    expect(sink).toBeGreaterThan(0);
  }, TRIPWIRE_3B_TIMEOUT_MS);

  it('passes a linear addition through the same differential (3b negative control)', () => {
    const input = PM_REPEAT + `${SC}-helper`;
    const codes = codesOf(input);
    let sink = 0;
    const r = addedCost(
      () => timeBash(PM_REPEAT + 'other-helper'),
      () => msOf(() => { bash(input); sink += linearPass(codes); }),
    );
    expect(r).toMatchObject({ withinBound: true });
    expect(sink).toBeGreaterThan(0);
  }, TRIPWIRE_3B_TIMEOUT_MS);

  // The verdict rule itself is pinned by synthetic traces through the same
  // addedCost: each callback returns the next fixed reading in ms, so these
  // controls are host-independent and run in microseconds. Reading 0 of a
  // trace is the discarded warm-up; the rest are consumed SAMPLES per round
  // for at most ALL_ROUNDS rounds, and a trace that runs out throws.
  const MAX_CALLS = 1 + SAMPLES * ALL_ROUNDS;
  const fixedMs = (readings: readonly number[]): (() => number) => {
    let next = 0;
    return () => {
      if (next >= readings.length) throw new Error(`fixed trace exhausted after ${readings.length} readings`);
      return readings[next++];
    };
  };
  const flat = (count: number, ms: number): number[] => Array.from({ length: count }, () => ms);
  const oneRound = (ms: (sample: number) => number): number[] => Array.from({ length: SAMPLES }, (_, s) => ms(s));
  /** Baseline either side pays; bound = max(ADDED_FLOOR_MS, BASE_MS * ADDED_FRACTION) = 100. */
  const BASE_MS = 200;
  const BASE_BOUND = 100;
  /** Quadratic work paid on the with side: four times the bound. */
  const QUAD_MS = 400;

  it('rejects intermittently paid quadratic work whose cheap calls land only in re-sample rounds (3b intermittent control)', () => {
    // Round 1 pays QUAD_MS on every with-call. Rounds 2 and 3 each have one
    // with-call that takes a fast path and costs only the baseline.
    const paid = oneRound(() => BASE_MS + QUAD_MS);
    const oneCheap = oneRound((s) => (s === 2 ? BASE_MS : BASE_MS + QUAD_MS));
    const r = addedCost(
      fixedMs(flat(MAX_CALLS, BASE_MS)),
      fixedMs([BASE_MS, ...paid, ...oneCheap, ...oneCheap]),
    );
    // The round-1 rule judged min(with) - min(without). After round 2 that was
    // BASE_MS - BASE_MS = 0 < 100, and this trace was ACCEPTED with rounds: 2.
    // The pooled median of the 21 paired differences is QUAD_MS: 19 pairs paid
    // it and 2 did not.
    expect(r).toMatchObject({
      withinBound: false,
      rounds: ALL_ROUNDS,
      samples: SAMPLES * ALL_ROUNDS,
      without: BASE_MS,
      bound: BASE_BOUND,
      added: QUAD_MS,
    });
  });

  it('tolerates one stalled call on either side on top of a small constant (3b one-noisy-sample control, the #759 shape)', () => {
    const SMALL_MS = 10;
    const STALL_MS = 500;
    const r = addedCost(
      fixedMs([BASE_MS, ...oneRound((s) => BASE_MS + (s === 5 ? STALL_MS : 0))]),
      fixedMs([BASE_MS, ...oneRound((s) => BASE_MS + SMALL_MS + (s === 3 ? STALL_MS : 0))]),
    );
    expect(r).toMatchObject({ withinBound: true, rounds: 1, samples: SAMPLES, added: SMALL_MS, bound: BASE_BOUND });
  });

  it.each<[string, number, number, Partial<AddedCost>]>([
    ['always-paid large cost is rejected in every round', BASE_MS, BASE_MS + QUAD_MS,
      { withinBound: false, rounds: ALL_ROUNDS, samples: SAMPLES * ALL_ROUNDS, added: QUAD_MS, bound: BASE_BOUND }],
    ['zero added cost passes in the first round', BASE_MS, BASE_MS,
      { withinBound: true, rounds: 1, samples: SAMPLES, added: 0, bound: BASE_BOUND }],
    ['a small linear added cost passes in the first round', BASE_MS, BASE_MS + 10,
      { withinBound: true, rounds: 1, added: 10, bound: BASE_BOUND }],
    ['added cost exactly at the bound is rejected (strict <)', BASE_MS, BASE_MS + BASE_BOUND,
      { withinBound: false, rounds: ALL_ROUNDS, added: BASE_BOUND, bound: BASE_BOUND }],
    ['the floor arm holds when half the tokeniser time is under ADDED_FLOOR_MS', 40, 40 + ADDED_FLOOR_MS - 1,
      { withinBound: true, rounds: 1, added: ADDED_FLOOR_MS - 1, bound: ADDED_FLOOR_MS }],
  ])('%s (3b constant-cost control)', (_label, withoutMs, withMs, expected) => {
    const r = addedCost(fixedMs(flat(MAX_CALLS, withoutMs)), fixedMs(flat(MAX_CALLS, withMs)));
    expect(r).toMatchObject(expected);
  });
});
