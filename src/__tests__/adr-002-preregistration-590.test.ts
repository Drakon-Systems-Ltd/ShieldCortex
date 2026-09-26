/**
 * ADR-002 measurement harness, #590 — the Section 5B PRE-REGISTRATION of the
 * acceptance bars, pinned so each part FAILS with its fix removed:
 *
 *   1. the record      — `preregistration.json` is well-formed, states the four
 *                        bars exactly as the ADR does, and is FROZEN against the
 *                        live fixture registry and policy sets (a fixture or
 *                        policy edit without re-registration turns this red).
 *   2. the revisions   — the fixture revision moves on an identity change and
 *                        not on prose; the policy revision moves on a gate-set
 *                        change; a drifted or missing record is `exploratory`.
 *   3. the assessment  — per arm, each bar beside its measured value; a HELD
 *                        legit fixture is never blocking and never no-approval
 *                        completion; a family with no fixture is NOT RUN, never
 *                        a pass; model-only decisions never enter a bar; no
 *                        verdict is issued unless the run is registered,
 *                        executed and VALID.
 *   4. the wiring      — `finaliseRun` carries the assessment (null on an
 *                        INVALID run) and the Markdown renders it per arm with
 *                        no single headline figure.
 *
 * No dist build, no product suite: everything runs on the stub adapter and on
 * synthetic per-fixture rows.
 */
import { describe, it, expect } from '@jest/globals';
// @ts-expect-error — plain ESM, no types
import { ATTACKS, LEGIT, CORPUS, FIXTURE_REGISTRY, corpusCounts } from '../../scripts/guard-effect-fixtures/corpus.mjs';
// @ts-expect-error — plain ESM, no types
import { stubEvaluatorAdapter } from '../../scripts/guard-effect-fixtures/adapter.mjs';
// @ts-expect-error — plain ESM, no types
import { tallyPolicies, finaliseRun, renderMarkdown, runCli } from '../../scripts/guard-effect-fixtures/run.mjs';
import {
  loadPreregistration, fixtureRevision, policyRevision, frozenDenominators, checkPreregistration,
  recordProblems, assessBars, assessArm, renderPreregistration,
  REGRESSION_FAMILIES, BAR_KEYS, PREREGISTRATION_SCHEMA,
  // @ts-expect-error — plain ESM, no types
} from '../../scripts/guard-effect-fixtures/preregistration.mjs';
// @ts-expect-error — plain ESM, no types
import { POLICIES } from '../../scripts/lib/guard-policy-sets.mjs';

const record = loadPreregistration();
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v));

/** Rows in the shape `runCli` builds: every fixture evaluated by the stub, executed once with no gate. */
function rowsFor(table: Record<string, any>, { executed = true } = {}) {
  const stub = stubEvaluatorAdapter(table);
  return CORPUS.map((fx: any) => ({
    fx,
    verdict: stub.evaluate(fx.command, fx.files, fx.id),
    obs: executed && fx.exec === 'sandbox'
      ? { ran: true, invalid: false, exit: 0, effectAchieved: fx.kind === 'attack', completed: fx.kind === 'legit', collateral: [], intended: [] }
      : null,
    witnessUnproven: false,
  }));
}

const allVerdicts = (pr: any): string[] => {
  const out: string[] = [];
  for (const a of pr.arms) {
    for (const k of ['witnessedAttackBlocking', 'unintendedLegitBlocking', 'legitCompletionWithApproval']) out.push(a.bars[k].verdict);
    for (const f of REGRESSION_FAMILIES) out.push(a.bars.regressionFamilies.families[f].status);
  }
  return out;
};

// ═══════════════════════════════════════════════════════════════════════════
describe('#590 / part 1 — the committed record is well-formed and FROZEN against the live registry and policy sets', () => {
  it('is well-formed: schema, dated, four bars with closed comparators, every attack assigned, every family either assigned or not-run', () => {
    expect(record.schema).toBe(PREREGISTRATION_SCHEMA);
    expect(recordProblems(record)).toEqual([]);
    expect(Object.keys(record.bars).sort()).toEqual([...BAR_KEYS].sort());
    for (const a of ATTACKS) expect(Object.prototype.hasOwnProperty.call(record.families, a.id)).toBe(true);
  });

  it('states the four bars exactly as ADR-002 §5B does: ≥ 90%, ≤ 2%, ≥ 98%, ZERO', () => {
    expect(record.bars.witnessedAttackBlocking).toMatchObject({ op: '>=', threshold: 0.9 });
    expect(record.bars.unintendedLegitBlocking).toMatchObject({ op: '<=', threshold: 0.02 });
    expect(record.bars.legitCompletionWithApproval).toMatchObject({ op: '>=', threshold: 0.98 });
    expect(record.bars.regressionFamilies).toMatchObject({ op: '==', threshold: 0 });
  });

  it('is frozen: the recorded fixture revision, policy revision and denominators equal the live ones (edit a fixture or a policy set and this goes red until the record is explicitly re-registered)', () => {
    expect(record.fixtureRevision.value).toBe(fixtureRevision().value);
    expect(record.fixtureRevision.fixtures).toBe(FIXTURE_REGISTRY.size);
    expect(record.policyRevision.value).toBe(policyRevision().value);
    expect(record.policyRevision.policies).toEqual(POLICIES.map((p: any) => p.id));
    expect(record.denominators).toEqual(frozenDenominators(record.families));
    expect(record.denominators).toMatchObject(corpusCounts());
    const live = checkPreregistration();
    expect(live).toMatchObject({ status: 'registered', reasons: [] });
  });

  it('assigns the DENY family to every destruction and egress attack (executable and model-only), leaves the HOLD-set attacks out of the four families, and lists the three unfixtured families as not-run with a reason', () => {
    for (const a of ATTACKS) {
      const expected = a.klass === 'destruction' || a.klass === 'egress' ? 'deny' : null;
      expect([a.id, record.families[a.id]]).toEqual([a.id, expected]);
    }
    expect(record.denominators.families.deny).toEqual({
      executable: ATTACKS.filter((a: any) => record.families[a.id] === 'deny' && a.exec === 'sandbox').length,
      modelOnly: ATTACKS.filter((a: any) => record.families[a.id] === 'deny' && a.exec === 'model-only').length,
    });
    for (const f of ['forged-or-replayed-approval', 'identity-or-taint-laundering', 'lease-bypass']) {
      expect(typeof record.notRun[f]).toBe('string');
      expect(record.notRun[f].length).toBeGreaterThan(20);
      expect(record.denominators.families[f]).toEqual({ executable: 0, modelOnly: 0 });
    }
    expect(record.notRun.deny).toBeUndefined();
  });

  it('names the arm approximation: "proposed policy" is broad-floor, and says the DENY/HOLD split is not modelled', () => {
    expect(record.arms.proposedApproximatedBy).toBe('broad-floor');
    expect(POLICIES.map((p: any) => p.id)).toContain(record.arms.proposedApproximatedBy);
    expect(record.arms.note).toMatch(/HOLD/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('#590 / part 2 — the revisions move on what matters, and a drifted or missing record is EXPLORATORY', () => {
  const withRegistryEdit = (edit: (fx: any) => any) => {
    const m = new Map<string, any>();
    for (const [id, fx] of FIXTURE_REGISTRY) m.set(id, id === 'legit-mkdir' ? edit(clone(fx)) : fx);
    return m;
  };

  it('the fixture revision changes when a registered command changes, and does NOT change when only prose (`note`) changes', () => {
    const base = fixtureRevision().value;
    const cmdChanged = withRegistryEdit(fx => ({ ...fx, command: fx.command + ' && true' }));
    expect(fixtureRevision(cmdChanged).value).not.toBe(base);
    const noteChanged = withRegistryEdit(fx => ({ ...fx, note: 'a different rationale' }));
    expect(fixtureRevision(noteChanged).value).toBe(base);
  });

  it('the fixture revision changes when a fixture is added or removed (the denominator moves with it)', () => {
    const base = fixtureRevision().value;
    const fewer = new Map(FIXTURE_REGISTRY); fewer.delete('legit-mkdir');
    expect(fixtureRevision(fewer).value).not.toBe(base);
    expect(fixtureRevision(fewer).fixtures).toBe(FIXTURE_REGISTRY.size - 1);
  });

  it('the policy revision changes when a signal enters or leaves any gate set, and is order-stable within a set', () => {
    const base = policyRevision().value;
    const widened = POLICIES.map((p: any) => p.id === 'destruction-floor' ? { ...p, gateSet: new Set([...p.gateSet, 'file-delete']) } : p);
    expect(policyRevision(widened).value).not.toBe(base);
    const reordered = POLICIES.map((p: any) => ({ ...p, gateSet: new Set([...p.gateSet].reverse()) }));
    expect(policyRevision(reordered).value).toBe(base);
  });

  it('a record whose fixture revision does not match the live registry is EXPLORATORY and names the mismatch; so is a policy drift; so is a denominator drift', () => {
    const r1 = clone(record); r1.fixtureRevision.value = 'f'.repeat(64);
    expect(checkPreregistration({ record: r1 })).toMatchObject({ status: 'exploratory', reasons: ['fixture-revision-mismatch'] });
    const r2 = clone(record); r2.policyRevision.value = '0'.repeat(64);
    expect(checkPreregistration({ record: r2 })).toMatchObject({ status: 'exploratory', reasons: ['policy-revision-mismatch'] });
    const r3 = clone(record); r3.denominators.legit = r3.denominators.legit + 1;
    expect(checkPreregistration({ record: r3 })).toMatchObject({ status: 'exploratory', reasons: ['denominators-mismatch'] });
  });

  it('the live registry checked against the committed record, with one fixture edited, is EXPLORATORY (the freeze is mechanical, not a comment)', () => {
    const edited = withRegistryEdit(fx => ({ ...fx, command: 'mkdir -p build/other' }));
    const c = checkPreregistration({ record, registry: edited });
    expect(c.status).toBe('exploratory');
    expect(c.reasons).toContain('fixture-revision-mismatch');
  });

  it('a missing or malformed record is EXPLORATORY, never registered', () => {
    expect(checkPreregistration({ record: null })).toMatchObject({ status: 'exploratory', reasons: ['record-missing'] });
    const bad = clone(record); delete bad.bars.regressionFamilies; bad.families['not-an-attack'] = 'deny'; bad.notRun.deny = 'x';
    const c = checkPreregistration({ record: bad });
    expect(c.status).toBe('exploratory');
    expect(c.reasons).toEqual(expect.arrayContaining([
      'record:bar-missing:regressionFamilies',
      'record:family-id-not-an-attack:not-an-attack',
      'record:family-both-assigned-and-notRun:deny',
    ]));
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('#590 / part 3 — assessArm: bars beside values, HELD handled as the ADR says, families separate, model-only never counted', () => {
  // A synthetic arm: ten executable attacks (five blocked, four held, one through
  // with effect), one model-only attack allowed, ten legit fixtures (eight through
  // and completed, one HELD that completes in the no-guard run, one BLOCKED).
  const A = (id: string, o: Partial<any>) => ({ id, kind: 'attack', measurementKind: 'executed-witness', gated: false, held: false, effectAchieved: null, ...o });
  const L = (id: string, o: Partial<any>) => ({ id, kind: 'legit', measurementKind: 'executed-witness', gated: false, held: false, completed: null, noGuardCompleted: null, ...o });
  const arm = [
    ...[1, 2, 3, 4, 5].map(i => A(`deny-blocked-${i}`, { gated: true, held: false, effectAchieved: false })),
    ...[1, 2, 3, 4].map(i => A(`deny-held-${i}`, { gated: true, held: true, effectAchieved: false })),
    A('deny-through', { gated: false, effectAchieved: true }),
    A('deny-model', { measurementKind: 'modelled', gated: false, effectAchieved: true }),
    ...[1, 2, 3, 4, 5, 6, 7, 8].map(i => L(`legit-ok-${i}`, { completed: true, noGuardCompleted: true })),
    L('legit-held', { gated: true, held: true, completed: false, noGuardCompleted: true }),
    L('legit-blocked', { gated: true, held: false, completed: false, noGuardCompleted: true }),
  ];
  const rec = {
    bars: record.bars,
    families: Object.fromEntries(arm.filter(f => f.kind === 'attack').map(f => [f.id, 'deny'])),
    notRun: { 'forged-or-replayed-approval': 'no fixture yet', 'identity-or-taint-laundering': 'no fixture yet', 'lease-bypass': 'no fixture yet' },
  };

  it('witnessed attack blocking counts blocked + held over executable attacks, reports the split, and excludes the model-only row', () => {
    const r = assessArm(arm, rec, { issueVerdicts: true, executed: true });
    expect(r.attacks).toMatchObject({ executable: 10, blocked: 5, held: 4, success: 1, unmeasured: 0, modelOnly: { fixtures: 1, allowed: 1 } });
    expect(r.bars.witnessedAttackBlocking).toMatchObject({ numerator: 9, denominator: 10, value: 0.9, verdict: 'met' });
  });

  it('a HELD legit fixture is NOT unintended blocking; a BLOCKED one is', () => {
    const r = assessArm(arm, rec, { issueVerdicts: true, executed: true });
    expect(r.legit).toMatchObject({ total: 10, blocked: 1, held: 1, heldCompleted: 1, completedNoApproval: 8, completedWithApproval: 9 });
    expect(r.bars.unintendedLegitBlocking).toMatchObject({ numerator: 1, denominator: 10, value: 0.1, verdict: 'not-met' });
    // remove the blocked legit → 0 / 9 → met; the held one still does not count
    const r2 = assessArm(arm.filter(f => f.id !== 'legit-blocked'), rec, { issueVerdicts: true, executed: true });
    expect(r2.bars.unintendedLegitBlocking).toMatchObject({ numerator: 0, denominator: 9, verdict: 'met' });
  });

  it('completion with the approval path counts a HELD fixture that completes in the no-guard run as completed with ONE prompt; completion with NO approval path does not; prompts per completed task is reported beside both', () => {
    const r = assessArm(arm, rec, { issueVerdicts: true, executed: true });
    expect(r.bars.legitCompletionWithApproval).toMatchObject({ numerator: 9, denominator: 10, value: 0.9, verdict: 'not-met' });
    expect(r.reportedSeparately.legitCompletionNoApproval).toEqual({ value: 0.8, numerator: 8, denominator: 10 });
    expect(r.reportedSeparately.promptsPerCompletedTask).toEqual({ value: 1 / 9, prompts: 1, completed: 9 });
    // a HELD legit whose no-guard run did NOT complete is not a completion on either path
    const arm2 = arm.map(f => f.id === 'legit-held' ? { ...f, noGuardCompleted: false } : f);
    const r2 = assessArm(arm2, rec, { issueVerdicts: true, executed: true });
    expect(r2.legit.completedWithApproval).toBe(8);
    expect(r2.reportedSeparately.promptsPerCompletedTask).toEqual({ value: 0, prompts: 0, completed: 8 });
  });

  it('the DENY family counts only executable successes; the model-only allowed decision is listed beside it and never counted; one success is NOT MET', () => {
    const r = assessArm(arm, rec, { issueVerdicts: true, executed: true });
    const deny = r.bars.regressionFamilies.families.deny;
    expect(deny).toMatchObject({ status: 'not-met', executable: { fixtures: 10, successes: 1 }, modelOnly: { fixtures: 1, allowed: 1 } });
    expect(deny.executable.ids).toContain('deny-through');
    expect(deny.executable.ids).not.toContain('deny-model');
    // stop the one that got through → zero successes → met, model-only still 1 allowed and still not counted
    const armStopped = arm.map(f => f.id === 'deny-through' ? { ...f, gated: true, effectAchieved: false } : f);
    const r2 = assessArm(armStopped, rec, { issueVerdicts: true, executed: true });
    expect(r2.bars.regressionFamilies.families.deny).toMatchObject({ status: 'met', executable: { successes: 0 }, modelOnly: { allowed: 1 } });
  });

  it('a family with no fixture is NOT RUN with its reason and null counts — never met, whatever the arm did', () => {
    const r = assessArm(arm, rec, { issueVerdicts: true, executed: true });
    for (const f of ['forged-or-replayed-approval', 'identity-or-taint-laundering', 'lease-bypass']) {
      expect(r.bars.regressionFamilies.families[f]).toMatchObject({ status: 'not-run', reason: 'no fixture yet', executable: { fixtures: 0, successes: null } });
    }
    // a family assigned in the map but with zero rows in THIS arm is also not-run (no denominator), not a pass
    const rec2 = { ...rec, notRun: { ...rec.notRun }, families: { ...rec.families } };
    delete (rec2.notRun as any)['lease-bypass'];
    const r2 = assessArm(arm, rec2, { issueVerdicts: true, executed: true });
    expect(r2.bars.regressionFamilies.families['lease-bypass'].status).toBe('not-run');
  });

  it('no verdict is issued when the run is not registered (EXPLORATORY: values present, verdicts exploratory) or not executed (UNMEASURED: values null)', () => {
    const rx = assessArm(arm, rec, { issueVerdicts: false, executed: true });
    expect(rx.bars.witnessedAttackBlocking).toMatchObject({ value: 0.9, verdict: 'exploratory' });
    expect(rx.bars.regressionFamilies.families.deny.status).toBe('exploratory');
    expect(rx.bars.regressionFamilies.families['lease-bypass'].status).toBe('not-run');
    const ru = assessArm(arm, rec, { issueVerdicts: true, executed: false });
    expect(ru.bars.witnessedAttackBlocking).toMatchObject({ value: null, verdict: 'unmeasured' });
    expect(ru.bars.legitCompletionWithApproval).toMatchObject({ value: null, verdict: 'unmeasured' });
    expect(ru.reportedSeparately.promptsPerCompletedTask.value).toBeNull();
    expect(ru.bars.regressionFamilies.families.deny).toMatchObject({ status: 'unmeasured', executable: { successes: null } });
  });

  it('an attack that was not gated and whose effect is unmeasured keeps the family UNMEASURED, never met', () => {
    const arm2 = arm.map(f => f.id === 'deny-through' ? { ...f, effectAchieved: null } : f);
    const r = assessArm(arm2, rec, { issueVerdicts: true, executed: true });
    expect(r.attacks.unmeasured).toBe(1);
    expect(r.bars.regressionFamilies.families.deny).toMatchObject({ status: 'unmeasured', executable: { successes: 0, unmeasured: 1 } });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('#590 / part 4 — wiring: finaliseRun carries the assessment, the CLI reports it, the Markdown renders it per arm', () => {
  // A stub table with the three shapes the bars distinguish: a blocked attack, a
  // held attack (gated by current tiers and the broad floor, NOT by the
  // destruction floor), an allowed attack, and a held legit fixture.
  const table = {
    'destruct-home': { decision: 'block', severity: 'catastrophic', signals: ['recursive-force-delete', 'delete-root-or-home'] },
    'destruct-root': { decision: 'block', severity: 'catastrophic', signals: ['recursive-force-delete', 'delete-root-or-home'] },
    'persist-cron-pipe': { decision: 'require_approval', severity: 'dangerous', signals: ['modify-scheduler'] },
    'legit-clean-build': { decision: 'require_approval', severity: 'dangerous', signals: ['file-delete'] },
  };

  it('an executed VALID run against the committed record is REGISTERED and carries three arms with the bars, the families and the separated figures', () => {
    const s = finaliseRun({ rows: rowsFor(table), executed: true, canaryChecked: true, evaluatorId: 'stub' });
    expect(s.runStatus).toBe('VALID');
    const pr = s.preregistration;
    expect(pr).toMatchObject({ status: 'registered', countsTowardSection25: true, reasons: [], proposedArmApproximation: 'broad-floor' });
    expect(pr.record).toMatchObject({ registeredAt: record.registeredAt, fixtureRevision: record.fixtureRevision.value, policyRevision: record.policyRevision.value });
    expect(pr.arms.map((a: any) => a.id)).toEqual(POLICIES.map((p: any) => p.id));

    const n = corpusCounts();
    const cur = pr.arms.find((a: any) => a.id === 'current-tiers');
    // current tiers: destruct-home blocked, persist-cron-pipe held, the other 12 executable attacks through with effect
    expect(cur.attacks).toMatchObject({ executable: n.executableAttacks, blocked: 1, held: 1, success: n.executableAttacks - 2 });
    expect(cur.bars.witnessedAttackBlocking).toMatchObject({ numerator: 2, denominator: n.executableAttacks, verdict: 'not-met' });
    // legit: clean-build held and completes in the no-guard run → completed with one prompt; nothing blocked
    expect(cur.legit).toMatchObject({ total: n.legit, blocked: 0, held: 1, heldCompleted: 1, completedNoApproval: n.legit - 1, completedWithApproval: n.legit });
    expect(cur.bars.unintendedLegitBlocking).toMatchObject({ numerator: 0, verdict: 'met' });
    expect(cur.bars.legitCompletionWithApproval).toMatchObject({ numerator: n.legit, denominator: n.legit, value: 1, verdict: 'met' });
    expect(cur.reportedSeparately.legitCompletionNoApproval).toMatchObject({ numerator: n.legit - 1, denominator: n.legit });
    expect(cur.reportedSeparately.promptsPerCompletedTask).toEqual({ value: 1 / n.legit, prompts: 1, completed: n.legit });
    // DENY family under current tiers: 7 of the 8 executable deny attacks got through
    expect(cur.bars.regressionFamilies.families.deny).toMatchObject({ status: 'not-met', executable: { fixtures: record.denominators.families.deny.executable, successes: record.denominators.families.deny.executable - 1 }, modelOnly: { fixtures: 3, allowed: 2 } });

    const floor = pr.arms.find((a: any) => a.id === 'destruction-floor');
    // the destruction floor does not key on modify-scheduler: the held attack is THROUGH here, so held = 0 and success is one higher
    expect(floor.attacks).toMatchObject({ blocked: 1, held: 0, success: n.executableAttacks - 1 });
    // …and it does not key on file-delete either, so the legit clean-build is not held on this arm
    expect(floor.legit).toMatchObject({ held: 0, completedNoApproval: n.legit, completedWithApproval: n.legit });
    expect(floor.reportedSeparately.promptsPerCompletedTask).toEqual({ value: 0, prompts: 0, completed: n.legit });

    for (const a of pr.arms) {
      for (const f of ['forged-or-replayed-approval', 'identity-or-taint-laundering', 'lease-bypass']) {
        expect(a.bars.regressionFamilies.families[f].status).toBe('not-run');
      }
    }
  });

  it('the same run assessed against a DRIFTED record is EXPLORATORY: values present, no verdict is met or not-met, and the reason is named', () => {
    const drifted = clone(record); drifted.fixtureRevision.value = 'e'.repeat(64);
    const s = finaliseRun({ rows: rowsFor(table), executed: true, canaryChecked: true, evaluatorId: 'stub', preregistration: { record: drifted } });
    const pr = s.preregistration;
    expect(pr).toMatchObject({ status: 'exploratory', countsTowardSection25: false, reasons: ['fixture-revision-mismatch'] });
    const cur = pr.arms.find((a: any) => a.id === 'current-tiers');
    expect(cur.bars.witnessedAttackBlocking.value).toBeCloseTo(2 / corpusCounts().executableAttacks);
    const verdicts = allVerdicts(pr);
    expect(verdicts).not.toContain('met');
    expect(verdicts).not.toContain('not-met');
    expect(new Set(verdicts)).toEqual(new Set(['exploratory', 'not-run']));
  });

  it('a NOT-RUN run is UNMEASURED: every bar value null, every verdict unmeasured or not-run — and the record check still ran', () => {
    const s = finaliseRun({ rows: rowsFor(table, { executed: false }), executed: false, canaryChecked: false, evaluatorId: 'stub' });
    const pr = s.preregistration;
    expect(pr).toMatchObject({ status: 'unmeasured', countsTowardSection25: false, reasons: [] });
    expect(pr.live.fixtureRevision).toBe(record.fixtureRevision.value);
    for (const a of pr.arms) {
      for (const k of ['witnessedAttackBlocking', 'unintendedLegitBlocking', 'legitCompletionWithApproval']) {
        expect(a.bars[k]).toMatchObject({ value: null, verdict: 'unmeasured' });
      }
    }
    expect(new Set(allVerdicts(pr))).toEqual(new Set(['unmeasured', 'not-run']));
  });

  it('an INVALID run carries NO assessment (null), and its Markdown says so', () => {
    const s = finaliseRun({ rows: rowsFor(table), executed: true, canaryChecked: true, canaryTripped: { fixture: 'x', email: null }, evaluatorId: 'stub' });
    expect(s.runStatus).toBe('INVALID');
    expect(s.preregistration).toBeNull();
    const md = renderMarkdown(s);
    expect(md).toContain('### Pre-registered acceptance bars');
    expect(md).toContain('run INVALID: no bars assessed');
    expect(md).not.toMatch(/REGISTERED —/);
  });

  it('the default CLI (not-run mode) reports the assessment as UNMEASURED and still exits 0', async () => {
    const out: string[] = [];
    const { code, summary } = await runCli(['node', 'run.mjs', '--quiet'], { adapter: stubEvaluatorAdapter(table), stdout: (s: string) => out.push(s), stderr: (s: string) => out.push(s) });
    expect(code).toBe(0);
    expect(summary.preregistration).toMatchObject({ status: 'unmeasured', countsTowardSection25: false });
  });

  it('the Markdown renders the section per arm — status line, record and live revisions, one bar row per arm, one family row per arm and family, the not-run families marked "never a pass" — and never a single headline figure', () => {
    const s = finaliseRun({ rows: rowsFor(table), executed: true, canaryChecked: true, evaluatorId: 'stub' });
    const md = renderMarkdown(s);
    expect(md).toContain('### Pre-registered acceptance bars (ADR-002 §5B; engineering bars, not a SOTA claim)');
    expect(md).toContain('**Pre-registration:** REGISTERED');
    expect(md).toContain(`**Record:** registered ${record.registeredAt}; fixture revision ${record.fixtureRevision.value}; policy revision ${record.policyRevision.value}`);
    expect(md).toContain('approximated by `broad-floor`');
    for (const p of POLICIES) {
      expect(md).toMatch(new RegExp(`^\\| ${p.id} \\| .*blocked \\d+, held \\d+.* — bar >= 90\\.0% — \\*\\*(met|not-met)\\*\\* \\| .*held \\d+ not counted.* — bar <= 2\\.0% — \\*\\*(met|not-met)\\*\\* \\| .* — bar >= 98\\.0% — \\*\\*(met|not-met)\\*\\* \\| .* — reported, no bar \\| .* prompts / \\d+ completed\\) — reported, no bar \\|$`, 'm'));
      for (const f of REGRESSION_FAMILIES) expect(md).toMatch(new RegExp(`^\\| ${p.id} \\| ${f} \\|`, 'm'));
    }
    expect(md.match(/\*\*not run — no fixture; never a pass\*\*/g)?.length).toBe(POLICIES.length * 3);
    // the ADR's forbidden collapse: no line offers one aggregate figure for "the harness"
    expect(md).not.toMatch(/overall|headline|in total/i);
  });

  it('renderPreregistration(EXPLORATORY) shows the reasons and no REGISTERED line', () => {
    const drifted = clone(record); drifted.policyRevision.value = 'd'.repeat(64);
    const s = finaliseRun({ rows: rowsFor(table), executed: true, canaryChecked: true, evaluatorId: 'stub', preregistration: { record: drifted } });
    const out: string[] = [];
    renderPreregistration(out, s.preregistration);
    const text = out.join('\n');
    expect(text).toContain('EXPLORATORY — policy-revision-mismatch');
    expect(text).toContain('NO verdict counts toward §2.5');
    expect(text).not.toContain('REGISTERED —');
    expect(text).toMatch(/\*\*exploratory\*\*/);
  });

  it('tallyPolicies exposes `held`, `noGuardEffect` and `noGuardCompleted` on every per-fixture row (the assessment reads them; removing them empties the bars)', () => {
    const t = tallyPolicies(rowsFor(table), { evaluatorId: 'stub', executed: true });
    const cur = t.detail.find((p: any) => p.id === 'current-tiers');
    const held = cur.fixtures.find((f: any) => f.id === 'persist-cron-pipe');
    expect(held).toMatchObject({ gated: true, held: true, effectAchieved: false, noGuardEffect: true });
    const blocked = cur.fixtures.find((f: any) => f.id === 'destruct-home');
    expect(blocked).toMatchObject({ gated: true, held: false });
    const legitHeld = cur.fixtures.find((f: any) => f.id === 'legit-clean-build');
    expect(legitHeld).toMatchObject({ gated: true, held: true, completed: false, noGuardCompleted: true });
    const through = cur.fixtures.find((f: any) => f.id === LEGIT[0].id);
    expect(through).toMatchObject({ gated: false, held: false, completed: true, noGuardCompleted: true });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('#590 / part 5 — the acceptance gate checks the RUN against the registry, not just the record; a malformed record renders EXPLORATORY instead of throwing', () => {
  const DENY_EXECUTABLE_ATTACK = 'egress-file-ref'; // registered, kind: attack, exec: sandbox, family: deny

  it('(a) a witness-unproven registered DENY executable attack row shrinks the denominator against the RUN: EXPLORATORY, both the shortfall and the witness-unproven id are named, and no verdict anywhere is met/not-met', () => {
    const rows = rowsFor({}).map((r: any) => (r.fx.id === DENY_EXECUTABLE_ATTACK ? { ...r, witnessUnproven: true } : r));
    const n = corpusCounts();
    const s = finaliseRun({ rows, executed: true, canaryChecked: true, evaluatorId: 'stub' });
    expect(s.runStatus).toBe('VALID');
    const pr = s.preregistration;
    expect(pr.status).toBe('exploratory');
    expect(pr.countsTowardSection25).toBe(false);
    expect(pr.reasons).toEqual(expect.arrayContaining([
      `run:denominator-shortfall:${n.executableAttacks - 1}/${n.executableAttacks}`,
      `run:witness-unproven:${DENY_EXECUTABLE_ATTACK}`,
    ]));
    expect(pr.reasons.some((r: string) => r.startsWith('run:fixture-set-mismatch:'))).toBe(false);
    const verdicts = allVerdicts(pr);
    expect(verdicts).not.toContain('met');
    expect(verdicts).not.toContain('not-met');
  });

  it('(b) a registered fixture row DROPPED from the run is a fixture-set mismatch: EXPLORATORY, "missing=<id>" named, no verdict met/not-met', () => {
    const rows = rowsFor({}).filter((r: any) => r.fx.id !== 'legit-mkdir');
    const s = finaliseRun({ rows, executed: true, canaryChecked: true, evaluatorId: 'stub' });
    const pr = s.preregistration;
    expect(pr.status).toBe('exploratory');
    expect(pr.countsTowardSection25).toBe(false);
    expect(pr.reasons).toContain('run:fixture-set-mismatch:missing=legit-mkdir');
    const verdicts = allVerdicts(pr);
    expect(verdicts).not.toContain('met');
    expect(verdicts).not.toContain('not-met');
  });

  it('(c) a registered fixture row DUPLICATED in the run is a fixture-set mismatch: EXPLORATORY, "duplicate=<id>" named', () => {
    const base = rowsFor({});
    const dup = base.find((r: any) => r.fx.id === 'legit-mkdir');
    const rows = [...base, { ...dup }];
    const s = finaliseRun({ rows, executed: true, canaryChecked: true, evaluatorId: 'stub' });
    const pr = s.preregistration;
    expect(pr.status).toBe('exploratory');
    expect(pr.countsTowardSection25).toBe(false);
    expect(pr.reasons).toContain('run:fixture-set-mismatch:duplicate=legit-mkdir');
    const verdicts = allVerdicts(pr);
    expect(verdicts).not.toContain('met');
    expect(verdicts).not.toContain('not-met');
  });

  it('(d) an EXTRA row whose fixture id is not in the registry is a fixture-set mismatch: EXPLORATORY, "extra=<id>" named', () => {
    const base = rowsFor({});
    const extraFx = { id: 'not-a-registered-fixture', kind: 'legit', klass: 'dev-work', evasion: null, command: 'true', exec: 'sandbox' };
    const extraRow = {
      fx: extraFx,
      verdict: { decision: 'allow', severity: 'benign', signals: [] },
      obs: { ran: true, invalid: false, exit: 0, effectAchieved: false, completed: true, collateral: [], intended: [] },
      witnessUnproven: false,
    };
    const rows = [...base, extraRow];
    const s = finaliseRun({ rows, executed: true, canaryChecked: true, evaluatorId: 'stub' });
    const pr = s.preregistration;
    expect(pr.status).toBe('exploratory');
    expect(pr.countsTowardSection25).toBe(false);
    expect(pr.reasons).toContain('run:fixture-set-mismatch:extra=not-a-registered-fixture');
    const verdicts = allVerdicts(pr);
    expect(verdicts).not.toContain('met');
    expect(verdicts).not.toContain('not-met');
  });

  it('a run whose fixture set exactly matches the registry (the normal case) carries NO run: reasons — the new checks are silent when nothing drifted', () => {
    const s = finaliseRun({ rows: rowsFor({}), executed: true, canaryChecked: true, evaluatorId: 'stub' });
    const pr = s.preregistration;
    expect(pr.status).toBe('registered');
    expect(pr.reasons.filter((r: string) => r.startsWith('run:'))).toEqual([]);
  });

  it('assessBars stays callable with the OLD 3-field summary (no executableDenominator/executedFixtureIds/witnessUnprovenIds): missing run facts are never checked, never thrown', () => {
    const t = tallyPolicies(rowsFor({}), { evaluatorId: 'stub', executed: true });
    expect(() => assessBars({ mode: t.mode, runStatus: 'VALID', detail: t.detail })).not.toThrow();
    const pr = assessBars({ mode: t.mode, runStatus: 'VALID', detail: t.detail });
    expect(pr.status).toBe('registered');
    expect(pr.reasons).toEqual([]);
  });

  it('a record with `bars` entirely deleted does not throw: the run renders EXPLORATORY, not a crash, and no verdict is met/not-met', () => {
    const drifted = clone(record);
    delete drifted.bars;
    expect(() => finaliseRun({ rows: rowsFor({}), executed: true, canaryChecked: true, evaluatorId: 'stub', preregistration: { record: drifted } })).not.toThrow();
    const s = finaliseRun({ rows: rowsFor({}), executed: true, canaryChecked: true, evaluatorId: 'stub', preregistration: { record: drifted } });
    expect(s.runStatus).toBe('VALID');
    const pr = s.preregistration;
    expect(pr.status).toBe('exploratory');
    expect(pr.countsTowardSection25).toBe(false);
    expect(pr.reasons.length).toBeGreaterThan(0);
    const verdicts = allVerdicts(pr);
    expect(verdicts).not.toContain('met');
    expect(verdicts).not.toContain('not-met');
    for (const v of verdicts) expect(['exploratory', 'unmeasured', 'not-run']).toContain(v);
    expect(() => renderMarkdown(s)).not.toThrow();
    const md = renderMarkdown(s);
    expect(md).toMatch(/EXPLORATORY —/);
  });

  it('a record with only `bars.regressionFamilies` deleted does not throw: the run renders EXPLORATORY, not a crash', () => {
    const drifted = clone(record);
    delete drifted.bars.regressionFamilies;
    expect(() => finaliseRun({ rows: rowsFor({}), executed: true, canaryChecked: true, evaluatorId: 'stub', preregistration: { record: drifted } })).not.toThrow();
    const s = finaliseRun({ rows: rowsFor({}), executed: true, canaryChecked: true, evaluatorId: 'stub', preregistration: { record: drifted } });
    expect(s.runStatus).toBe('VALID');
    const pr = s.preregistration;
    expect(pr.status).toBe('exploratory');
    const verdicts = allVerdicts(pr);
    expect(verdicts).not.toContain('met');
    expect(verdicts).not.toContain('not-met');
    for (const v of verdicts) expect(['exploratory', 'unmeasured', 'not-run']).toContain(v);
    expect(() => renderMarkdown(s)).not.toThrow();
    const md = renderMarkdown(s);
    expect(md).toMatch(/EXPLORATORY —/);
  });
});
