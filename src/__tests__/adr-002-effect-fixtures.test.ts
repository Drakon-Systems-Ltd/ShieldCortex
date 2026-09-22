/**
 * ADR-002 measurement harness, Half B — proof the effect witness, corpus and
 * per-policy tally wire together, WITHOUT a dist build and WITHOUT executing any
 * shell. The witness is tested against real file mutations; the runner tally is
 * tested against a stub evaluator adapter with canned verdicts.
 *
 * The real, in-process run against the BUILT evaluator is `run.mjs --execute`;
 * it is deliberately not driven from Jest so the suite needs no build.
 */
import { describe, it, expect } from '@jest/globals';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// @ts-expect-error — plain ESM, no types
import { snapshot, diff, changed, fingerprint, assertConfined } from '../../scripts/guard-effect-fixtures/witness.mjs';
// @ts-expect-error — plain ESM, no types
import { CORPUS, ATTACKS, LEGIT } from '../../scripts/guard-effect-fixtures/corpus.mjs';
// @ts-expect-error — plain ESM, no types
import { tallyPolicies } from '../../scripts/guard-effect-fixtures/run.mjs';
// @ts-expect-error — plain ESM, no types
import { stubEvaluatorAdapter } from '../../scripts/guard-effect-fixtures/adapter.mjs';

describe('ADR-002 Half B — effect witness', () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sc-adr002-test-'));
    mkdirSync(join(root, 'witness'), { recursive: true });
    writeFileSync(join(root, 'witness', 'sink.log'), '');
    writeFileSync(join(root, 'protected.txt'), 'original\n');
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('detects an in-place content change', () => {
    const before = snapshot(root, ['protected.txt'], 'witness/sink.log');
    writeFileSync(join(root, 'protected.txt'), 'tampered\n');
    const after = snapshot(root, ['protected.txt'], 'witness/sink.log');
    const d = diff(before, after, ['protected.txt']);
    expect(d.effectAchieved).toBe(true);
    expect(d.watchedMutated).toEqual(['protected.txt']);
  });

  it('detects a delete', () => {
    const before = snapshot(root, ['protected.txt'], 'witness/sink.log');
    rmSync(join(root, 'protected.txt'));
    const after = snapshot(root, ['protected.txt'], 'witness/sink.log');
    expect(diff(before, after, ['protected.txt']).effectAchieved).toBe(true);
  });

  it('detects outbound bytes reaching the fake sink', () => {
    const before = snapshot(root, ['protected.txt'], 'witness/sink.log');
    appendFileSync(join(root, 'witness', 'sink.log'), 'SHIM curl ARGV: https://x/collect\n');
    const after = snapshot(root, ['protected.txt'], 'witness/sink.log');
    const d = diff(before, after, []);
    expect(d.sinkGrew).toBe(true);
    expect(d.effectAchieved).toBe(true);
  });

  it('reports no effect when nothing changed', () => {
    const before = snapshot(root, ['protected.txt'], 'witness/sink.log');
    const after = snapshot(root, ['protected.txt'], 'witness/sink.log');
    expect(diff(before, after, ['protected.txt']).effectAchieved).toBe(false);
  });

  it('changed() catches a delete-and-recreate with identical content via inode', () => {
    const a = fingerprint(join(root, 'protected.txt'));
    rmSync(join(root, 'protected.txt'));
    writeFileSync(join(root, 'protected.txt'), 'original\n'); // same bytes, new inode
    const b = fingerprint(join(root, 'protected.txt'));
    expect(changed(a, b)).toBe(true);
  });

  it('refuses a target outside the sandbox', () => {
    expect(() => assertConfined(root, '/etc/passwd')).toThrow(/escapes sandbox/);
  });
});

describe('ADR-002 Half B — corpus integrity', () => {
  it('every fixture is well-formed and ids are unique', () => {
    const ids = new Set<string>();
    for (const f of CORPUS) {
      expect(f.id).toBeTruthy();
      expect(['attack', 'legit']).toContain(f.kind);
      expect(['sandbox', 'model-only']).toContain(f.exec);
      expect(typeof f.command).toBe('string');
      expect(f.command.length).toBeGreaterThan(0);
      expect(ids.has(f.id)).toBe(false);
      ids.add(f.id);
    }
  });

  it('splits into attacks and legitimate work, both non-trivial', () => {
    expect(ATTACKS.length).toBeGreaterThanOrEqual(10);
    expect(LEGIT.length).toBeGreaterThanOrEqual(8);
    expect(ATTACKS.every((f: any) => f.kind === 'attack')).toBe(true);
    expect(LEGIT.every((f: any) => f.kind === 'legit')).toBe(true);
  });

  it('model-only fixtures are exactly the unconfinable absolute-root/device shapes', () => {
    const modelOnly = CORPUS.filter((f: any) => f.exec === 'model-only').map((f: any) => f.id).sort();
    expect(modelOnly).toEqual(['destruct-format', 'destruct-raw-write', 'destruct-root']);
    // and they are all attacks, never legit work
    expect(CORPUS.filter((f: any) => f.exec === 'model-only').every((f: any) => f.kind === 'attack')).toBe(true);
  });

  it('covers every attack class and every named evasion', () => {
    const classes = new Set(ATTACKS.map((f: any) => f.klass));
    expect([...classes].sort()).toEqual(['destruction', 'egress', 'persistence', 'security-config']);
    const evasions = new Set(CORPUS.map((f: any) => f.evasion).filter(Boolean));
    expect([...evasions].sort()).toEqual(['comment', 'heredoc', 'quoted', 'substitution']);
  });
});

describe('ADR-002 Half B — per-policy tally (stub adapter, modelled)', () => {
  // Canned verdicts: one attack the current tiers catch, one attack even the
  // current tiers miss (benign), and one legit call the tiers gate as an FP.
  const verdicts = {
    'destruct-root': { decision: 'block', severity: 'catastrophic', signals: ['delete-root-or-home'] },
    'persist-bashrc-append': { decision: 'allow', severity: 'benign', signals: [] },
    'legit-read-guard-config': { decision: 'require_approval', severity: 'dangerous', signals: ['touch-guard-config'] },
  };
  const stub = stubEvaluatorAdapter(verdicts);
  const pick = ['destruct-root', 'persist-bashrc-append', 'legit-read-guard-config'];
  const rows = CORPUS
    .filter((f: any) => pick.includes(f.id))
    .map((fx: any) => ({ fx, verdict: stub.evaluate(fx.command, fx.files, fx.id) }));

  it('a benign-classified attack is a MISS on every policy (attack succeeds)', () => {
    const s = tallyPolicies(rows, { execute: false, evaluatorId: 'stub' });
    for (const p of s.policies) {
      const bashrc = s.detail.find((d: any) => d.id === p.id)!
        .fixtures.find((f: any) => f.id === 'persist-bashrc-append')!;
      expect(bashrc.gated).toBe(false);
      expect(bashrc.effectAchieved).toBe(true);
    }
  });

  it('current tiers gate the root wipe; the destruction floor also does', () => {
    const s = tallyPolicies(rows, { execute: false, evaluatorId: 'stub' });
    const root = (pid: string) => s.detail.find((d: any) => d.id === pid)!.fixtures.find((f: any) => f.id === 'destruct-root')!;
    expect(root('current-tiers').gated).toBe(true);
    expect(root('destruction-floor').gated).toBe(true); // delete-root-or-home is on the floor
  });

  it('a read misclassified as touch-guard-config is a legit false positive on current tiers', () => {
    const s = tallyPolicies(rows, { execute: false, evaluatorId: 'stub' });
    const cur = s.policies.find((p: any) => p.id === 'current-tiers')!;
    expect(cur.legitFalsePositives).toBe(1);
    // the destruction floor does NOT gate a read (touch-guard-config not on it)
    const floor = s.policies.find((p: any) => p.id === 'destruction-floor')!;
    expect(floor.legitFalsePositives).toBe(0);
  });
});
