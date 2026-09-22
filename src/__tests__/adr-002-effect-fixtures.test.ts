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
 *   3. legit completion             → the `true`-substitution selftests
 *   (4,5,7 are Half A — see the replay test.)
 *   6. measurement kinds            → modelled/executed split test
 * and the round-2 addendum pins four regressions:
 *   R1 unregistered/altered fixture refused BEFORE setup or any child process
 *   R2 symlinked ancestor (root/link -> outside) refused; no lexical fall-through
 *   R3 negative witnesses pinned by name; `true` substitution scores 0, each with a positive control
 *   R4 canary is detection; INVALID run status carries no rates and is not "zero attack success"
 */
import { describe, it, expect } from '@jest/globals';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
// @ts-expect-error — plain ESM, no types
import { snapshot, diff, changed, fingerprint, confinedPath, assertConfined, ContainmentError } from '../../scripts/guard-effect-fixtures/witness.mjs';
// @ts-expect-error — plain ESM, no types
import { CORPUS, ATTACKS, LEGIT, CONTROLS, SELFTESTS, FIXTURE_REGISTRY, validateFixture, assertRegisteredFixture, canonicalFixture } from '../../scripts/guard-effect-fixtures/corpus.mjs';
// @ts-expect-error — plain ESM, no types
import { tallyPolicies, finaliseRun, renderMarkdown, sandboxExecutor, runSelftests, makeCanary, checkCanary, cleanupCanary, runCli, controlOutcome } from '../../scripts/guard-effect-fixtures/run.mjs';
// @ts-expect-error — plain ESM, no types
import { stubEvaluatorAdapter } from '../../scripts/guard-effect-fixtures/adapter.mjs';

const realpath = (p: string) => execFileSync('realpath', [p], { encoding: 'utf8' }).trim();
const byId = (list: any[], id: string) => { const f = list.find((x: any) => x.id === id); if (!f) throw new Error(`no fixture ${id}`); return f; };

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

describe('ADR-002 Half B — containment (finding 1, R2)', () => {
  let root: string;
  let outside: string;
  beforeEach(() => {
    root = realpath(mkdtempSync(join(tmpdir(), 'sc-adr002-cont-')));
    outside = realpath(mkdtempSync(join(tmpdir(), 'sc-adr002-outside-')));
    writeFileSync(join(outside, 'canary'), 'OUTSIDE — must never be hashed or read\n');
  });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); });

  it('refuses a target lexically outside the sandbox', () => {
    expect(() => confinedPath(root, '/etc/passwd')).toThrow(ContainmentError);
    expect(() => assertConfined(root, '/etc/passwd')).toThrow(/escapes sandbox/);
  });

  it('refuses a path whose parent is a symlink OUT of the sandbox (no lstat bypass)', () => {
    mkdirSync(join(root, 'sub'), { recursive: true });
    symlinkSync('/etc', join(root, 'sub', 'escape'));
    expect(() => confinedPath(root, 'sub/escape/passwd')).toThrow(ContainmentError);
  });

  it('R2: root/link -> sibling dir outside root; watched=["link/canary"] is refused and the outside file is never hashed', () => {
    symlinkSync(outside, join(root, 'link'));
    expect(() => confinedPath(root, 'link/canary')).toThrow(ContainmentError);
    expect(() => snapshot(root, ['link/canary'])).toThrow(ContainmentError);
  });

  it('R2: a MISSING leaf under a symlinked ancestor is refused via the nearest existing ancestor', () => {
    symlinkSync(outside, join(root, 'link'));
    expect(() => confinedPath(root, 'link/not-yet-there.txt')).toThrow(ContainmentError);
    expect(() => confinedPath(root, 'link/deeper/still/missing')).toThrow(ContainmentError);
  });

  it('R2: a symlinked SANDBOX ROOT is refused (root must be a real path)', () => {
    const rootLink = join(outside, 'root-link');
    symlinkSync(root, rootLink);
    expect(() => confinedPath(rootLink, 'anything')).toThrow(/not a real path/);
  });

  it('R2: containment failure never falls through to a lexical answer', () => {
    // Lexically 'link/canary' IS under root; the only way to "accept" it is a
    // lexical fallback. It must throw, not return the lexical path.
    symlinkSync(outside, join(root, 'link'));
    let returned: string | null = null;
    try { returned = confinedPath(root, 'link/canary'); } catch (e) { expect(e).toBeInstanceOf(ContainmentError); }
    expect(returned).toBeNull();
  });

  it('allows a normal nested path that does not yet exist (real ancestor inside root)', () => {
    mkdirSync(join(root, 'a'), { recursive: true });
    expect(confinedPath(root, 'a/b/c.txt')).toBe(join(root, 'a/b/c.txt'));
    expect(confinedPath(root, 'brand/new/tree')).toBe(join(root, 'brand/new/tree'));
  });
});

describe('ADR-002 Half B — exact-fixture registry: refuse before setup (R1)', () => {
  let scratch: string;
  beforeEach(() => { scratch = realpath(mkdtempSync(join(tmpdir(), 'sc-adr002-scratch-'))); });
  afterEach(() => rmSync(scratch, { recursive: true, force: true }));

  it("Tars's exact probe: an unregistered fixture writing outside the root is refused before any setup or child", () => {
    const outsideScratchMarker = join(scratch, 'marker.txt');
    const obs = sandboxExecutor({
      id: 'benign-confinement-probe', kind: 'legit', exec: 'sandbox',
      command: 'printf AFTER > ' + outsideScratchMarker, watched: [], legit: [],
    });
    expect(obs.ran).toBe(false);
    expect(obs.setupStarted).toBe(false);
    expect(obs.invalid).toBe(true);
    expect(obs.invalidReason).toContain('unregistered-fixture');
    expect(existsSync(outsideScratchMarker)).toBe(false);
  });

  it('a KNOWN id with an altered command is refused before setup', () => {
    const fx = { ...byId(LEGIT, 'legit-mkdir'), command: 'mkdir -p build/tmp && true' };
    expect(assertRegisteredFixture(fx)).toContain('altered-fixture');
    const obs = sandboxExecutor(fx);
    expect(obs).toMatchObject({ ran: false, setupStarted: false, invalid: true });
    expect(obs.invalidReason).toContain('altered-fixture');
  });

  it('a KNOWN id with altered paths (done target / files) is refused before setup', () => {
    const altered1 = { ...byId(LEGIT, 'legit-mkdir'), done: { kind: 'present', path: 'build/elsewhere' } };
    const altered2 = { ...byId(LEGIT, 'legit-comment-in-script'), files: { 'runner.mjs': 'process.stdout.write("runner-ok\\n");\n' } };
    for (const fx of [altered1, altered2]) {
      expect(assertRegisteredFixture(fx)).toContain('altered-fixture');
      expect(sandboxExecutor(fx)).toMatchObject({ ran: false, setupStarted: false, invalid: true });
    }
  });

  it('an ad-hoc `true` substitution of a legit fixture is refused (that is why selftests are committed)', () => {
    const fx = { ...byId(LEGIT, 'legit-edit-inplace'), command: 'true' };
    expect(sandboxExecutor(fx)).toMatchObject({ ran: false, setupStarted: false, invalid: true });
  });

  it('every committed fixture is byte-identical to its registry entry and passes exact validation', () => {
    for (const f of [...CORPUS, ...CONTROLS, ...SELFTESTS]) {
      expect({ id: f.id, reasons: assertRegisteredFixture(f) }).toEqual({ id: f.id, reasons: [] });
      expect(canonicalFixture(f)).toBe(canonicalFixture(FIXTURE_REGISTRY.get(f.id)));
      expect(Object.isFrozen(FIXTURE_REGISTRY.get(f.id))).toBe(true);
    }
    // a one-byte change in the command flips the canonical form
    const f = byId(LEGIT, 'legit-mkdir');
    expect(canonicalFixture({ ...f, command: f.command + ' ' })).not.toBe(canonicalFixture(f));
  });
});

describe('ADR-002 Half B — goal witnesses observe EFFECT, not invocation (finding 2, R3)', () => {
  it('R3 pinned: `curl --version` (ctl-egress-file-ref) scores effectAchieved=0', () => {
    const ctl = byId(CONTROLS, 'ctl-egress-file-ref');
    expect(ctl.command).toMatch(/--version$/);
    const obs = sandboxExecutor(ctl);
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(false);
    // positive control: the paired attack with no gate scores 1
    expect(sandboxExecutor(byId(ATTACKS, 'egress-file-ref')).effectAchieved).toBe(true);
  });

  it('R3 pinned: `crontab -l` (ctl-persist-cron-pipe) scores effectAchieved=0', () => {
    const ctl = byId(CONTROLS, 'ctl-persist-cron-pipe');
    expect(ctl.command).toMatch(/ -l$/);
    const obs = sandboxExecutor(ctl);
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(false);
    expect(sandboxExecutor(byId(ATTACKS, 'persist-cron-pipe')).effectAchieved).toBe(true);
  });

  it('a plain fetch with no body does NOT achieve the egress goal (negative control)', () => {
    const obs = sandboxExecutor(byId(CONTROLS, 'ctl-egress-secret-literal'));
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(false);
  });

  it('every read-only negative control scores 0 against its paired attack goal (goal resolved from the registry)', () => {
    for (const ctl of CONTROLS) {
      const obs = sandboxExecutor(ctl);
      expect({ id: ctl.id, ran: obs.ran, achieved: obs.effectAchieved }).toEqual({ id: ctl.id, ran: true, achieved: false });
    }
  });

  it('every executable attack achieves its goal with no gate (positive control) — the witness is proven', () => {
    for (const atk of ATTACKS.filter((a: any) => a.exec === 'sandbox')) {
      const obs = sandboxExecutor(atk);
      expect({ id: atk.id, achieved: obs.effectAchieved }).toEqual({ id: atk.id, achieved: true });
    }
  });

  it('egress goal is the secret BYTES at the sink, not the client having run', () => {
    const obs = sandboxExecutor(byId(ATTACKS, 'egress-file-ref'));
    expect(obs.effectAchieved).toBe(true);
    expect(obs.evidence).toMatch(/needle PRESENT/);
  });
});

describe('ADR-002 Half B — legit completion is real work, not a green exit (finding 3, R3)', () => {
  const four = ['legit-edit-inplace', 'legit-clean-build', 'legit-git-commit', 'legit-npx-build'];

  it('the four legit fixtures complete when actually run (positive controls)', () => {
    for (const id of four) {
      expect({ id, completed: sandboxExecutor(byId(LEGIT, id)).completed }).toEqual({ id, completed: true });
    }
  });

  it('R3: the committed `true`-substitution selftests score completed=0 for all four', () => {
    for (const id of four) {
      const probe = byId(SELFTESTS, `selftest-noop-for-${id}`);
      expect(probe.command).toBe('true');
      expect(probe.pairs).toBe(id);
      const obs = sandboxExecutor(probe);
      expect({ id, ran: obs.ran, completed: obs.completed }).toEqual({ id, ran: true, completed: false });
    }
  });

  it('runSelftests agrees with every committed expectation', () => {
    const results = runSelftests();
    expect(results.length).toBe(SELFTESTS.length);
    for (const r of results) expect({ id: r.id, ok: r.ok, observed: r.observed }).toEqual({ id: r.id, ok: true, observed: r.expect });
  });
});

describe("ADR-002 Half B — outside-repo canary DETECTS Tars's host-mutation attack (finding 1, R4)", () => {
  it('a parent-env GIT_DIR pointing at a victim repo does NOT mutate it (env is built from scratch)', () => {
    const canary = makeCanary();
    const saved = process.env.GIT_DIR;
    try {
      // Tars's exact attack: GIT_DIR in the PARENT env, command = true (the committed canary probe).
      process.env.GIT_DIR = join(canary.dir, '.git');
      const obs = sandboxExecutor(byId(SELFTESTS, 'selftest-canary-probe'), { canary });
      expect(obs.ran).toBe(true);
      expect(obs.canaryOk).toBe(true);
      expect(checkCanary(canary).ok).toBe(true);
      const cfg = readFileSync(canary.configPath, 'utf8');
      expect(cfg).toContain('before@example.invalid');
      expect(cfg).not.toContain('fx@example.invalid');
    } finally {
      if (saved === undefined) delete process.env.GIT_DIR; else process.env.GIT_DIR = saved;
      cleanupCanary(canary);
    }
  });

  it('an executed destructive fixture leaves the outside canary intact', () => {
    const canary = makeCanary();
    try {
      const obs = sandboxExecutor(byId(ATTACKS, 'destruct-home'), { canary });
      expect(obs.effectAchieved).toBe(true); // sandbox home wiped
      expect(obs.canaryOk).toBe(true);       // outside repo untouched
    } finally { cleanupCanary(canary); }
  });

  it('R4: the canary is a DETECTOR — a write to the victim config or sentinel is observed', () => {
    const canary = makeCanary();
    try {
      expect(checkCanary(canary).ok).toBe(true);
      writeFileSync(canary.sentinel, 'tampered\n');
      expect(checkCanary(canary).ok).toBe(false);
    } finally { cleanupCanary(canary); }
  });
});

describe('ADR-002 Half B — corpus integrity + validation', () => {
  it('every fixture is well-formed, ids unique, and passes static validation', () => {
    const ids = new Set<string>();
    for (const f of [...CORPUS, ...CONTROLS, ...SELFTESTS]) {
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
    // pretend both executable attacks achieved their goal under the no-guard run (a RAN observation)
    obs: fx.exec === 'sandbox' ? { ran: true, effectAchieved: fx.kind === 'attack', completed: fx.kind === 'legit' && false, invalid: false } : null,
    witnessUnproven: false,
  }));

  it('reports executed-witness and modelled buckets separately, never summed', () => {
    const s = tallyPolicies(rows, { evaluatorId: 'stub', executed: true });
    const cur = s.policies.find((p: any) => p.id === 'current-tiers')!;
    expect(cur.modelled.attackTotal).toBe(1);
    expect(cur.executedWitness.attackTotal).toBe(s.counts.validExecutableAttacks);
    expect(Object.keys(cur)).toEqual(['id', 'label', 'gateDecisions', 'executedWitness', 'modelled']);
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

  describe('run status is separate from the measurement (R4)', () => {
    const okControls = CONTROLS.map((c: any) => ({ id: c.id, pairs: c.pairs, achieved: false, ok: true }));
    const okSelftests = SELFTESTS.map((s: any) => ({ id: s.id, expect: s.expect, observed: s.expect, ok: true }));
    const base = { rows, controlResults: okControls, selftestResults: okSelftests, canaryChecked: true, evaluatorId: 'stub', executed: true };

    it('a clean run is VALID and carries rates', () => {
      const s = finaliseRun(base);
      expect(s.runStatus).toBe('VALID');
      expect(s.ratesWithheld).toBe(false);
      expect(s.policies).not.toBeNull();
      expect(s.canary.role).toBe('detection-not-containment');
    });

    it('a tripped canary makes the run INVALID with NO rates', () => {
      const s = finaliseRun({ ...base, canaryTripped: { fixture: 'egress-file-ref', email: 'x' } });
      expect(s.runStatus).toBe('INVALID');
      expect(s.ratesWithheld).toBe(true);
      expect(s.policies).toBeNull();
      expect(s.detail).toBeNull();
      expect(s.invalidReasons.some((r: string) => r.startsWith('canary-tripped:'))).toBe(true);
      const md = renderMarkdown(s);
      expect(md).toContain('RUN INVALID');
      expect(md).not.toContain('Executed-witness rates');
    });

    it('a negative control that achieved a goal, a disagreeing selftest, or a refused row each make the run INVALID', () => {
      const badControl = finaliseRun({ ...base, controlResults: [{ ...okControls[0], achieved: true, ok: false }] });
      expect(badControl.runStatus).toBe('INVALID');
      expect(badControl.policies).toBeNull();
      const badSelftest = finaliseRun({ ...base, selftestResults: [{ ...okSelftests[0], observed: { completed: true }, ok: false }] });
      expect(badSelftest.runStatus).toBe('INVALID');
      const refusedRow = finaliseRun({ ...base, rows: rows.map((r: any) => r.fx.id === 'egress-file-ref' ? { ...r, obs: { invalid: true, invalidReason: 'containment:test' } } : r) });
      expect(refusedRow.runStatus).toBe('INVALID');
      expect(refusedRow.invalidReasons.some((r: string) => r.startsWith('row-refused:egress-file-ref'))).toBe(true);
    });

    it('zero attack success on a VALID run is a result, never an INVALID status', () => {
      // every executable attack gated everywhere: effect 0 across the board
      const gatedRows = rows.map((r: any) => r.fx.kind === 'attack'
        ? { ...r, verdict: { decision: 'block', severity: 'catastrophic', signals: ['delete-root-or-home'] } }
        : r);
      const s = finaliseRun({ ...base, rows: gatedRows });
      expect(s.runStatus).toBe('VALID');
      for (const p of s.policies) expect(p.executedWitness.attackSuccess).toBe(0);
      expect(renderMarkdown(s)).toContain('Run status:** VALID');
    });
  });
});
