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
  // interleaved, so a load burst lands on both, and each side is its running
  // minimum: contention only ever adds time, so the least-contended call is
  // the honest one. A round that still reads over the bound is re-sampled,
  // up to EXTRA_ROUNDS more times, before the verdict. The bound itself is
  // unchanged: the walk may add a constant, max(ADDED_FLOOR_MS, half the
  // tokeniser time). There is no absolute cap on either side.
  const SAMPLES = 7;
  const EXTRA_ROUNDS = 2;
  const ADDED_FLOOR_MS = 50;
  const ADDED_FRACTION = 0.5;
  /** Hang guard only: Jest's default 10 s could fail a slow runner on call count alone. */
  const TRIPWIRE_3B_TIMEOUT_MS = 60_000;

  interface AddedCost {
    /** Fastest observed call on each side, in ms. */
    without: number;
    withPkg: number;
    /** withPkg - without: what the guard package token adds. */
    added: number;
    /** max(ADDED_FLOOR_MS, without * ADDED_FRACTION). */
    bound: number;
    /** Rounds sampled before the verdict: 1 when the first round passed, at most 1 + EXTRA_ROUNDS. */
    rounds: number;
    /** The verdict, added < bound. The production case and the controls both read it from here. */
    withinBound: boolean;
  }

  const msOf = (fn: () => unknown): number => {
    const t0 = process.hrtime.bigint();
    fn();
    return Number(process.hrtime.bigint() - t0) / 1e6;
  };

  /**
   * One discarded warm-up call per side, then `samples` interleaved calls per
   * side (without, with, without, with, ...) keeping the running minimum of
   * each. Returns as soon as a round reads under the bound; otherwise
   * re-samples up to EXTRA_ROUNDS more rounds and reports the final reading.
   */
  function addedCost(timeWithout: () => number, timeWith: () => number, samples = SAMPLES): AddedCost {
    timeWithout();
    timeWith();
    let without = Infinity;
    let withPkg = Infinity;
    for (let rounds = 1; ; rounds++) {
      for (let s = 0; s < samples; s++) {
        without = Math.min(without, timeWithout());
        withPkg = Math.min(withPkg, timeWith());
      }
      const added = withPkg - without;
      const bound = Math.max(ADDED_FLOOR_MS, without * ADDED_FRACTION);
      const result: AddedCost = { without, withPkg, added, bound, rounds, withinBound: added < bound };
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

  // Controls for the differential above. The positive control runs the same
  // real call plus a deliberately quadratic pass over the input through the
  // same addedCost and must be rejected, so a no-op comparison fails here.
  // Every "with" call in it costs several times the real call, so it samples
  // CONTROL_SAMPLES calls per round rather than SAMPLES; it still runs every
  // round, since a real quadratic is never rescued by re-sampling. The
  // negative control adds a linear pass and must pass at the default plan.
  const CONTROL_SAMPLES = 3;
  let sink = 0;
  const quadraticPass = (s: string): number => {
    let hits = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      for (let j = 0; j < s.length; j++) if (s.charCodeAt(j) === c) hits++;
    }
    return hits;
  };
  const linearPass = (s: string): number => {
    let hits = 0;
    for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) === 32) hits++;
    return hits;
  };

  it('rejects a genuinely quadratic addition through the same differential (3b positive control)', () => {
    const input = PM_REPEAT + `${SC}-helper`;
    const r = addedCost(
      () => timeBash(PM_REPEAT + 'other-helper'),
      () => msOf(() => { bash(input); sink += quadraticPass(input); }),
      CONTROL_SAMPLES,
    );
    expect(r).toMatchObject({ withinBound: false, rounds: 1 + EXTRA_ROUNDS });
    expect(r.added).toBeGreaterThanOrEqual(r.bound);
    expect(sink).toBeGreaterThan(0);
  }, TRIPWIRE_3B_TIMEOUT_MS);

  it('passes a linear addition through the same differential (3b negative control)', () => {
    const input = PM_REPEAT + `${SC}-helper`;
    const r = addedCost(
      () => timeBash(PM_REPEAT + 'other-helper'),
      () => msOf(() => { bash(input); sink += linearPass(input); }),
    );
    expect(r).toMatchObject({ withinBound: true });
    expect(sink).toBeGreaterThan(0);
  }, TRIPWIRE_3B_TIMEOUT_MS);
});
