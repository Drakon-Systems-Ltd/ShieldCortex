/**
 * ADR-002 measurement harness, Half B — proves the witness, corpus, containment,
 * canary and per-policy tally, WITHOUT a dist build. The witness is tested
 * against real state; the runner tally against a stub adapter; the containment
 * and effect-witness properties against real confined executions.
 *
 * The real in-process run against the BUILT evaluator is `run.mjs --execute`.
 *
 * Every finding in Tars's round-2 review has a test here that FAILS without the
 * fix:
 *   1. host mutation / containment  → canary + symlink-rejection tests
 *   2. goal witnesses / controls    → goal-witness, negative- and positive-control tests
 *   3. legit completion             → the `true`-substitution test
 *   (4,5,7 are Half A — see the replay test.)
 *   6. measurement kinds            → modelled/executed split test
 */
import { describe, it, expect } from '@jest/globals';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync, symlinkSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
// @ts-expect-error — plain ESM, no types
import { snapshot, diff, changed, fingerprint, confinedPath, assertConfined, observeGoal, observeDone, ContainmentError } from '../../scripts/guard-effect-fixtures/witness.mjs';
// @ts-expect-error — plain ESM, no types
import { CORPUS, ATTACKS, LEGIT, CONTROLS, validateFixture, PLANTED_KEY_MATERIAL } from '../../scripts/guard-effect-fixtures/corpus.mjs';
// @ts-expect-error — plain ESM, no types
import { tallyPolicies, sandboxExecutor, makeCanary, checkCanary, cleanupCanary } from '../../scripts/guard-effect-fixtures/run.mjs';
// @ts-expect-error — plain ESM, no types
import { stubEvaluatorAdapter } from '../../scripts/guard-effect-fixtures/adapter.mjs';

const realpath = (p: string) => execFileSync('realpath', [p], { encoding: 'utf8' }).trim();

describe('ADR-002 Half B — effect witness (filesystem)', () => {
  let root: string;
  beforeEach(() => {
    root = realpath(mkdtempSync(join(tmpdir(), 'sc-adr002-test-')));
    mkdirSync(join(root, 'witness'), { recursive: true });
    writeFileSync(join(root, 'witness', 'egress.log'), '');
    writeFileSync(join(root, 'protected.txt'), 'original\n');
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('detects an in-place content change', () => {
    const before = snapshot(root, ['protected.txt']);
    writeFileSync(join(root, 'protected.txt'), 'tampered\n');
    const after = snapshot(root, ['protected.txt']);
    expect(diff(before, after, ['protected.txt']).watchedMutated).toEqual(['protected.txt']);
  });

  it('changed() catches a delete-and-recreate with identical content via inode', () => {
    const a = fingerprint(join(root, 'protected.txt'));
    rmSync(join(root, 'protected.txt'));
    writeFileSync(join(root, 'protected.txt'), 'original\n');
    expect(changed(a, fingerprint(join(root, 'protected.txt')))).toBe(true);
  });
});

describe('ADR-002 Half B — containment (finding 1)', () => {
  let root: string;
  beforeEach(() => { root = realpath(mkdtempSync(join(tmpdir(), 'sc-adr002-cont-'))); });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('refuses a target lexically outside the sandbox', () => {
    expect(() => confinedPath(root, '/etc/passwd')).toThrow(ContainmentError);
    expect(() => assertConfined(root, '/etc/passwd')).toThrow(/escapes sandbox/);
  });

  it('refuses a path whose parent is a symlink OUT of the sandbox (no lstat bypass)', () => {
    // Plant a symlink inside the sandbox that points at the real /etc, then try
    // to read /etc/passwd "through" it. The old realpath-and-fall-back path
    // would have accepted the lexically-inside link target; confinedPath rejects.
    mkdirSync(join(root, 'sub'), { recursive: true });
    symlinkSync('/etc', join(root, 'sub', 'escape'));
    expect(() => confinedPath(root, 'sub/escape/passwd')).toThrow(ContainmentError);
  });

  it('allows a normal nested path that does not yet exist', () => {
    expect(confinedPath(root, 'a/b/c.txt')).toBe(join(root, 'a/b/c.txt'));
  });
});

describe('ADR-002 Half B — goal witnesses observe EFFECT, not invocation (finding 2)', () => {
  it('a version/list/read call does NOT achieve an egress or scheduler goal (negative control)', () => {
    // ctl-egress-secret-literal is a plain fetch with no body → nothing at sink.
    const ctl = CONTROLS.find((c: any) => c.id === 'ctl-egress-secret-literal')!;
    const paired = ATTACKS.find((a: any) => a.id === ctl.pairs)!;
    const obs = sandboxExecutor(ctl, { goalOverride: paired.goal });
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(false); // no bytes reached the sink
  });

  it('every read-only negative control scores 0 against its paired attack goal', () => {
    for (const ctl of CONTROLS) {
      const paired = ATTACKS.find((a: any) => a.id === ctl.pairs)!;
      const obs = sandboxExecutor(ctl, { goalOverride: paired.goal });
      expect({ id: ctl.id, achieved: obs.effectAchieved }).toEqual({ id: ctl.id, achieved: false });
    }
  });

  it('every executable attack achieves its goal with no gate (positive control) — the witness is proven', () => {
    for (const atk of ATTACKS.filter((a: any) => a.exec === 'sandbox')) {
      const obs = sandboxExecutor(atk);
      expect({ id: atk.id, achieved: obs.effectAchieved }).toEqual({ id: atk.id, achieved: true });
    }
  });

  it('egress goal is the secret BYTES at the sink, not curl having run', () => {
    const atk = ATTACKS.find((a: any) => a.id === 'egress-file-ref')!;
    const obs = sandboxExecutor(atk);
    expect(obs.effectAchieved).toBe(true);
    expect(obs.evidence).toMatch(/needle PRESENT/);
    // and the paired version-call control, sharing the same goal, does NOT.
    const ctl = CONTROLS.find((c: any) => c.id === 'ctl-egress-file-ref')!;
    expect(sandboxExecutor(ctl, { goalOverride: atk.goal }).effectAchieved).toBe(false);
  });
});

describe('ADR-002 Half B — legit completion is real work, not a green exit (finding 3)', () => {
  const four = ['legit-edit-inplace', 'legit-clean-build', 'legit-git-commit', 'legit-npx-build'];

  it('the four legit fixtures complete when actually run', () => {
    for (const id of four) {
      const fx = LEGIT.find((f: any) => f.id === id)!;
      expect({ id, completed: sandboxExecutor(fx).completed }).toEqual({ id, completed: true });
    }
  });

  it('substituting `true` for the command yields completed=0 for all four', () => {
    for (const id of four) {
      const fx = { ...LEGIT.find((f: any) => f.id === id)!, command: 'true' };
      expect({ id, completed: sandboxExecutor(fx).completed }).toEqual({ id, completed: false });
    }
  });
});

describe('ADR-002 Half B — outside-repo canary reproduces Tars\'s host-mutation attack (finding 1)', () => {
  it('a parent-env GIT_DIR pointing at a victim repo does NOT mutate it (env is built from scratch)', () => {
    const canary = makeCanary();
    const saved = process.env.GIT_DIR;
    try {
      // Tars's exact attack: GIT_DIR in the PARENT env, command = true.
      process.env.GIT_DIR = canary.gitDir ?? join(canary.dir, '.git');
      const obs = sandboxExecutor({
        id: 'canary-probe', kind: 'legit', klass: 'dev-work', exec: 'sandbox',
        command: 'true', done: { kind: 'stdout-contains', needle: '' },
      }, { canary });
      expect(obs.canaryOk).toBe(true);
      const after = checkCanary(canary);
      expect(after.ok).toBe(true);
      // The victim's user.email is unchanged (never became the sandbox identity).
      expect(readFileSync(canary.configPath, 'utf8')).toContain('before@example.invalid');
      expect(readFileSync(canary.configPath, 'utf8')).not.toContain('fx@example.invalid');
    } finally {
      if (saved === undefined) delete process.env.GIT_DIR; else process.env.GIT_DIR = saved;
      cleanupCanary(canary);
    }
  });

  it('an executed destructive fixture leaves the outside canary intact', () => {
    const canary = makeCanary();
    try {
      const atk = ATTACKS.find((a: any) => a.id === 'destruct-home')!;
      const obs = sandboxExecutor(atk, { canary });
      expect(obs.effectAchieved).toBe(true); // sandbox home wiped
      expect(obs.canaryOk).toBe(true);       // outside repo untouched
    } finally { cleanupCanary(canary); }
  });
});

describe('ADR-002 Half B — corpus integrity + validation', () => {
  it('every fixture is well-formed, ids unique, and passes static validation', () => {
    const ids = new Set<string>();
    for (const f of [...CORPUS, ...CONTROLS]) {
      expect(ids.has(f.id)).toBe(false);
      ids.add(f.id);
      expect(validateFixture(f)).toEqual([]);
    }
  });

  it('rejects an absolute path in a fixture command (containment by validation)', () => {
    expect(validateFixture({ id: 'x', kind: 'attack', exec: 'sandbox', command: 'cat /etc/shadow', goal: { kind: 'absent', path: 'home/x' } }))
      .toContain('absolute-path-in-command');
  });

  it('model-only fixtures are exactly the unconfinable absolute-root/device shapes', () => {
    const modelOnly = CORPUS.filter((f: any) => f.exec === 'model-only').map((f: any) => f.id).sort();
    expect(modelOnly).toEqual(['destruct-format', 'destruct-raw-write', 'destruct-root']);
  });

  it('has 14 executable attacks and one read-only control per executable attack', () => {
    const execAttacks = ATTACKS.filter((a: any) => a.exec === 'sandbox');
    expect(execAttacks.length).toBe(14);
    expect(CONTROLS.length).toBe(14);
    const paired = new Set(CONTROLS.map((c: any) => c.pairs));
    for (const a of execAttacks) expect(paired.has(a.id)).toBe(true);
  });
});

describe('ADR-002 Half B — per-policy tally keeps measurement kinds separate (finding 6)', () => {
  const verdicts = {
    'destruct-root': { decision: 'block', severity: 'catastrophic', signals: ['delete-root-or-home'] },
    'persist-bashrc-append': { decision: 'allow', severity: 'benign', signals: [] },
    'egress-file-ref': { decision: 'allow', severity: 'benign', signals: [] },
    'legit-read-guard-config': { decision: 'require_approval', severity: 'dangerous', signals: ['touch-guard-config'] },
  };
  const stub = stubEvaluatorAdapter(verdicts);
  const pick = Object.keys(verdicts);
  const rows = CORPUS.filter((f: any) => pick.includes(f.id)).map((fx: any) => ({
    fx, verdict: stub.evaluate(fx.command, fx.files, fx.id),
    // pretend both executable attacks achieved their goal under the no-guard run
    obs: fx.exec === 'sandbox' ? { effectAchieved: fx.kind === 'attack', completed: fx.kind === 'legit' && false, invalid: false } : null,
    witnessUnproven: false,
  }));

  it('reports executed-witness and modelled buckets separately, never summed', () => {
    const s = tallyPolicies(rows, { evaluatorId: 'stub', executed: true });
    const cur = s.policies.find((p: any) => p.id === 'current-tiers')!;
    // model-only root wipe lands ONLY in the modelled bucket
    expect(cur.modelled.attackTotal).toBe(1);
    expect(cur.executedWitness.attackTotal).toBe(s.counts.validExecutableAttacks);
    // the two are distinct objects; there is no blended attack rate field
    expect(Object.keys(cur)).toEqual(['id', 'label', 'executedWitness', 'modelled']);
  });

  it('a benign-classified executable attack is a MISS on every policy (effect achieved)', () => {
    const s = tallyPolicies(rows, { evaluatorId: 'stub', executed: true });
    for (const p of s.detail) {
      const f = p.fixtures.find((x: any) => x.id === 'egress-file-ref')!;
      expect(f.gated).toBe(false);
      expect(f.effectAchieved).toBe(true);
      expect(f.measurementKind).toBe('executed-witness');
    }
  });

  it('the model-only root wipe is gated by current tiers and the destruction floor', () => {
    const s = tallyPolicies(rows, { evaluatorId: 'stub', executed: true });
    const root = (pid: string) => s.detail.find((d: any) => d.id === pid)!.fixtures.find((f: any) => f.id === 'destruct-root')!;
    expect(root('current-tiers').gated).toBe(true);
    expect(root('destruction-floor').gated).toBe(true);
    expect(root('current-tiers').measurementKind).toBe('modelled');
  });
});
