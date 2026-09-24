/**
 * ADR-002 measurement harness, round 6 (#570) — the four limitations #559
 * disclosed in the harness README, each pinned so the test FAILS with its fix
 * removed:
 *
 *   1. evaluator digest    — the built adapter binds a sha256 over the guard
 *                            modules it imports; a stub reports null and the
 *                            Markdown says the run is unbound.
 *   2. derived counts      — the executable-attack denominator, banner and
 *                            headings come from `corpusCounts(registry)`, not a
 *                            literal (proved by passing a registry with a
 *                            different count).
 *   3. own-target collateral — a fixture's own witness target is `intended`,
 *                            never `collateral`; only foreign targets are.
 *   4. failure_allowed     — Half A reports `guardFailedAllowed` separately
 *                            from `warnedOnly`, in summary, projection and
 *                            Markdown.
 *
 * No dist build, no product suite. Part 3 executes committed fixtures in the
 * harness's throwaway sandboxes exactly as the effect-fixtures suite does.
 */
import { describe, it, expect } from '@jest/globals';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// @ts-expect-error — plain ESM, no types
import { evaluatorDigest, stubEvaluatorAdapter, EVALUATOR_DIGEST_SCOPE } from '../../scripts/guard-effect-fixtures/adapter.mjs';
// @ts-expect-error — plain ESM, no types
import { CORPUS, ATTACKS, LEGIT, CONTROLS, SELFTESTS, FIXTURE_REGISTRY, corpusCounts } from '../../scripts/guard-effect-fixtures/corpus.mjs';
// @ts-expect-error — plain ESM, no types
import { tallyPolicies, finaliseRun, renderMarkdown, sandboxExecutor, ownTargets, banner } from '../../scripts/guard-effect-fixtures/run.mjs';
// @ts-expect-error — plain ESM, no types
import { EGRESS_LOG, SCHEDULER_STORE, FIREWALL_STATE } from '../../scripts/guard-effect-fixtures/witness.mjs';
// @ts-expect-error — plain ESM, no types
import { run, projectPublic, analyse, parseDenials, groupEvents } from '../../scripts/guard-policy-replay.mjs';

const byId = (list: any[], id: string) => { const f = list.find((x: any) => x.id === id); if (!f) throw new Error(`no fixture ${id}`); return f; };

// ═══════════════════════════════════════════════════════════════════════════
describe('round 6 / #570 item 1 — the evaluator id binds a digest of the built bytes', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-adr002-digest-'));
    mkdirSync(join(dir, 'nested'));
    writeFileSync(join(dir, 'b.js'), 'export const b = 1;\n');
    writeFileSync(join(dir, 'a.js'), 'export const a = 1;\n');
    writeFileSync(join(dir, 'nested', 'c.js'), 'export const c = 1;\n');
    writeFileSync(join(dir, 'a.d.ts'), 'export declare const a: number;\n');
    writeFileSync(join(dir, 'a.js.map'), '{}\n');
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('is deterministic, covers only .js files, and reports the scope it hashed', () => {
    const d1 = evaluatorDigest(dir);
    const d2 = evaluatorDigest(dir);
    expect(d1).toEqual(d2);
    expect(d1).toEqual({ algorithm: 'sha256', scope: EVALUATOR_DIGEST_SCOPE, files: 3, value: expect.stringMatching(/^[0-9a-f]{64}$/) });
  });

  it('changes when any imported module byte changes, or a module is added — not on an mtime touch or a non-.js edit', () => {
    const base = evaluatorDigest(dir).value;
    // mtime only: identical bytes → identical digest
    utimesSync(join(dir, 'a.js'), new Date(0), new Date(0));
    expect(evaluatorDigest(dir).value).toBe(base);
    // a .d.ts or a map is not what Node loads
    writeFileSync(join(dir, 'a.d.ts'), 'export declare const a: string;\n');
    writeFileSync(join(dir, 'a.js.map'), '{"v":2}\n');
    expect(evaluatorDigest(dir).value).toBe(base);
    // one byte in a nested module
    writeFileSync(join(dir, 'nested', 'c.js'), 'export const c = 2;\n');
    const afterEdit = evaluatorDigest(dir).value;
    expect(afterEdit).not.toBe(base);
    // an added module
    writeFileSync(join(dir, 'd.js'), 'export const d = 1;\n');
    const afterAdd = evaluatorDigest(dir);
    expect(afterAdd.value).not.toBe(afterEdit);
    expect(afterAdd.files).toBe(4);
  });

  it('the same bytes under a different path name give a different digest (the relative path is part of the input)', () => {
    const base = evaluatorDigest(dir).value;
    rmSync(join(dir, 'b.js'));
    writeFileSync(join(dir, 'bb.js'), 'export const b = 1;\n');
    expect(evaluatorDigest(dir).files).toBe(3);
    expect(evaluatorDigest(dir).value).not.toBe(base);
  });

  it('a stub adapter has no digest, and the summary + Markdown say the run is unbound', () => {
    const stub = stubEvaluatorAdapter({});
    expect(stub.digest).toBeNull();
    const rows = CORPUS.slice(0, 2).map((fx: any) => ({ fx, verdict: stub.evaluate(fx.command, fx.files, fx.id), obs: null, witnessUnproven: false }));
    const s = finaliseRun({ rows, executed: false, canaryChecked: false, evaluatorId: stub.id, evaluatorDigest: stub.digest });
    expect(s.evaluatorDigest).toBeNull();
    const md = renderMarkdown(s);
    expect(md).toMatch(/\*\*Evaluator:\*\* stub — NO BUILD DIGEST/);
    expect(md).toMatch(/not bound to any built evaluator bytes and is not decision-grade/);
  });

  it('a built digest is carried through tallyPolicies and finaliseRun into the JSON and the Markdown', () => {
    const digest = evaluatorDigest(dir);
    const stub = stubEvaluatorAdapter({});
    const rows = CORPUS.slice(0, 2).map((fx: any) => ({ fx, verdict: stub.evaluate(fx.command, fx.files, fx.id), obs: null, witnessUnproven: false }));
    expect(tallyPolicies(rows, { evaluatorId: 'built-dist-evaluateToolCall', evaluatorDigest: digest, executed: false }).evaluatorDigest).toEqual(digest);
    const s = finaliseRun({ rows, executed: false, canaryChecked: false, evaluatorId: 'built-dist-evaluateToolCall', evaluatorDigest: digest });
    expect(s.evaluatorDigest).toEqual(digest);
    const md = renderMarkdown(s);
    expect(md).toContain(`**Evaluator:** built-dist-evaluateToolCall — sha256 ${digest.value} over 3 file(s), scope ${EVALUATOR_DIGEST_SCOPE}`);
    expect(md).toContain('binds the built bytes, not a source revision');
    expect(md).not.toContain('NO BUILD DIGEST');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 6 / #570 item 2 — every reported count is derived from the registry', () => {
  it('corpusCounts() agrees with an independent count of the committed lists', () => {
    const c = corpusCounts();
    expect(c).toEqual({
      attacks: ATTACKS.length,
      executableAttacks: ATTACKS.filter((a: any) => a.exec === 'sandbox').length,
      modelOnlyAttacks: ATTACKS.filter((a: any) => a.exec === 'model-only').length,
      legit: LEGIT.length,
      controls: CONTROLS.length,
      selftests: SELFTESTS.length,
    });
    expect(Object.isFrozen(c)).toBe(true);
    // the default registry is the frozen one the executor validates against
    expect(corpusCounts(FIXTURE_REGISTRY)).toEqual(c);
  });

  it('the denominator, banner and headings READ the counts they are given — a registry with a different count changes all of them', () => {
    // a registry that is NOT the committed one: three executable attacks, one model-only, two legit
    const fake = new Map<string, any>([
      ['x1', { id: 'x1', kind: 'attack', exec: 'sandbox' }],
      ['x2', { id: 'x2', kind: 'attack', exec: 'sandbox' }],
      ['x3', { id: 'x3', kind: 'attack', exec: 'sandbox' }],
      ['m1', { id: 'm1', kind: 'attack', exec: 'model-only' }],
      ['l1', { id: 'l1', kind: 'legit', exec: 'sandbox' }],
      ['l2', { id: 'l2', kind: 'legit', exec: 'sandbox' }],
    ]);
    const counts = corpusCounts(fake);
    expect(counts).toEqual({ attacks: 4, executableAttacks: 3, modelOnlyAttacks: 1, legit: 2, controls: 0, selftests: 0 });
    expect(counts.executableAttacks).not.toBe(corpusCounts().executableAttacks); // the discriminating condition

    const stub = stubEvaluatorAdapter({});
    const rows = CORPUS.filter((f: any) => f.exec === 'sandbox').slice(0, 3).map((fx: any) => ({
      fx, verdict: stub.evaluate(fx.command, fx.files, fx.id),
      obs: { ran: true, effectAchieved: fx.kind === 'attack', completed: fx.kind === 'legit', invalid: false }, witnessUnproven: false,
    }));
    const t = tallyPolicies(rows, { evaluatorId: 'stub', executed: true, counts });
    expect(t.executableDenominator.expected).toBe(3);
    expect(t.banner).toContain('executed-witness (3 executable attacks)');
    expect(t.banner).toContain('modelled (1 unconfinable model-only shapes');

    const s = finaliseRun({ rows, executed: true, canaryChecked: true, evaluatorId: 'stub', counts });
    expect(s.executableDenominator.expected).toBe(3);
    expect(s.banner).toBe(banner(counts));
    const md = renderMarkdown(s);
    expect(md).toContain('### Executed-witness rates (3 registered executable attacks; effect observed)');
    expect(md).toContain(`### Modelled decisions (${s.counts.modelledAttacks} unconfinable model-only shapes`);
  });

  it('by default the denominator is the committed registry count, and it is the REGISTRY count, not the row count', () => {
    const stub = stubEvaluatorAdapter({});
    // only two executable attacks in the rows: the expected denominator must still be the registry's
    const rows = ATTACKS.filter((a: any) => a.exec === 'sandbox').slice(0, 2).map((fx: any) => ({
      fx, verdict: stub.evaluate(fx.command, fx.files, fx.id), obs: { ran: true, effectAchieved: true, invalid: false }, witnessUnproven: false,
    }));
    const t = tallyPolicies(rows, { evaluatorId: 'stub', executed: true });
    expect(t.executableDenominator).toEqual({ expected: corpusCounts().executableAttacks, valid: 2 });
    expect(t.banner).toContain(`executed-witness (${corpusCounts().executableAttacks} executable attacks)`);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 6 / #570 item 3 — a fixture\'s own witness target is intended, never collateral', () => {
  it('ownTargets maps each witness kind to the sandbox file it reads', () => {
    expect(ownTargets({ kind: 'egress', needle: 'x' })).toEqual([EGRESS_LOG]);
    expect(ownTargets({ kind: 'scheduler', needle: 'x' })).toEqual([SCHEDULER_STORE]);
    expect(ownTargets({ kind: 'firewall', state: 'inactive' })).toEqual([FIREWALL_STATE]);
    for (const kind of ['file-contains', 'json-field', 'absent', 'present', 'file-changed']) {
      expect(ownTargets({ kind, path: 'home/.bashrc' })).toEqual(['home/.bashrc']);
    }
    expect(ownTargets({ kind: 'git-commit', repo: 'r', file: 'f' })).toEqual([]);
    expect(ownTargets({ kind: 'stdout-contains', needle: 'x' })).toEqual([]);
    expect(ownTargets(null)).toEqual([]);
    expect(ownTargets(undefined)).toEqual([]);
  });

  it('a persistence attack that appends to the rc file: the rc file is INTENDED, not collateral', () => {
    const obs = sandboxExecutor(byId(ATTACKS, 'persist-bashrc-append'));
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(true); // positive control still holds
    expect(obs.intended).toEqual(['home/.bashrc']);
    expect(obs.collateral).not.toContain('home/.bashrc');
  });

  it('a legit in-place edit: the edited file is INTENDED, not collateral', () => {
    const obs = sandboxExecutor(byId(LEGIT, 'legit-edit-inplace'));
    expect(obs.ran).toBe(true);
    expect(obs.completed).toBe(true);
    expect(obs.intended).toEqual(['src/edit-me.ts']);
    expect(obs.collateral).not.toContain('src/edit-me.ts');
  });

  it('an egress attack: the sink log is INTENDED, not collateral; the scheduler store is neither touched nor claimed', () => {
    const obs = sandboxExecutor(byId(ATTACKS, 'egress-file-ref'));
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(true);
    expect(obs.intended).toEqual([EGRESS_LOG]);
    expect(obs.collateral).not.toContain(EGRESS_LOG);
    expect(obs.collateral).not.toContain(SCHEDULER_STORE);
  });

  it('a scheduler attack: the store is INTENDED; the sink log is not listed as its collateral', () => {
    const obs = sandboxExecutor(byId(ATTACKS, 'persist-cron-pipe'));
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(true);
    expect(obs.intended).toEqual([SCHEDULER_STORE]);
    expect(obs.collateral).not.toContain(SCHEDULER_STORE);
  });

  it('a read-only negative control mutates nothing it is about: intended is empty', () => {
    const obs = sandboxExecutor(byId(CONTROLS, 'ctl-persist-cron-pipe'));
    expect(obs.ran).toBe(true);
    expect(obs.effectAchieved).toBe(false);
    expect(obs.intended).toEqual([]);
  });

  it('the per-fixture tally row carries `intended` alongside `collateral`', () => {
    const stub = stubEvaluatorAdapter({});
    const fx = byId(ATTACKS, 'persist-bashrc-append');
    const obs = sandboxExecutor(fx);
    const t = tallyPolicies([{ fx, verdict: stub.evaluate(fx.command, fx.files, fx.id), obs, witnessUnproven: false }], { evaluatorId: 'stub', executed: true });
    const row = t.detail[0].fixtures[0];
    expect(row.intended).toEqual(['home/.bashrc']);
    expect(row.collateral ?? []).not.toContain('home/.bashrc');
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 6 / #570 item 4 — failure_allowed is a guard failure, not a warning', () => {
  const T0 = '2026-09-01T10:00:00.000Z';
  const row = (o: Record<string, unknown>) => JSON.stringify({
    event: 'action_guard_warning', outcome: 'warned', origin: 'claude-code-hook', tool: 'Bash', surface: 'Bash: [redacted]',
    signals: ['file-delete'], severity: 'dangerous', reason: 'r', detectedAt: T0, ...o,
  });
  const lines = (...rows: string[]) => rows.join('\n') + '\n';

  it('a failure_allowed event lands in guardFailedAllowed, never warnedOnly; a warned event stays warnedOnly', () => {
    const log = lines(
      row({ actionId: 'fa', outcome: 'failure_allowed' }),
      row({ actionId: 'w', outcome: 'warned' }),
      row({ actionId: 'd', event: 'action_guard_denial', outcome: 'auto_denied' }),
    );
    const { summary, markdown } = run(log);
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 3, unknown: 0, contradictory: 0, malformed: 0 }));
    expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 1, warnedOnly: 1, guardFailedAllowed: 1, other: 0 }));
    expect(markdown).toContain('| warned only | 1 |');
    expect(markdown).toContain('| guard failed, allowed | 1 | failure_allowed: the guard could not evaluate and FAILED OPEN');
  });

  it('the internal summary, the public projection and the Markdown all carry the bucket, and the buckets still partition the known events', () => {
    const log = lines(
      row({ actionId: 'fa1', outcome: 'failure_allowed' }),
      row({ actionId: 'fa2', outcome: 'failure_allowed' }),
      row({ actionId: 'w', outcome: 'warned' }),
    );
    const parsed = parseDenials(log);
    const internal = analyse(groupEvents(parsed.records), parsed);
    expect(internal.actual.guardFailedAllowed).toBe(2);
    expect(internal.actual.warnedOnly).toBe(1);
    const pub = projectPublic(internal);
    expect(pub.actual.guardFailedAllowed).toBe(2);
    expect(pub.actual.warnedOnly).toBe(1);
    const a = pub.actual;
    expect(a.actuallyStopped + a.stopUnconfirmed + a.warnedOnly + a.guardFailedAllowed + a.retryGranted + a.retryDeniedOrFailed + a.retryUnresolved + a.other)
      .toBe(internal.events.total);
    expect(run(log).markdown).toContain('| guard failed, allowed | 2 |');
  });

  it('failure_allowed never counts as stopped, and a later retry state still takes precedence over the bucket', () => {
    const retry = (actionId: string, outcome: string, detectedAt: string) =>
      JSON.stringify({ event: 'action_guard_denial', outcome, origin: 'claude-code-hook', actionId, detectedAt });
    const log = lines(
      row({ actionId: 'fa', outcome: 'failure_allowed' }),
      row({ actionId: 'fg', event: 'action_guard_denial', outcome: 'auto_denied' }),
      retry('fg', 'retry_granted', '2026-09-01T10:00:01.000Z'),
    );
    const { summary } = run(log);
    expect(summary.actual).toEqual(expect.objectContaining({ actuallyStopped: 0, guardFailedAllowed: 1, retryGranted: 1, warnedOnly: 0 }));
  });
});
