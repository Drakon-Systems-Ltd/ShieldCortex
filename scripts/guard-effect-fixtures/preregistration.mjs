#!/usr/bin/env node
/**
 * ADR-002 measurement harness, Half B — the PRE-REGISTRATION of the Section 5B
 * acceptance bars (ADR-002 §5B "Pre-registered acceptance bars", sequence step 4).
 *
 *   node scripts/guard-effect-fixtures/preregistration.mjs --check   # exit 0 iff the record matches
 *   node scripts/guard-effect-fixtures/preregistration.mjs --print   # print the live revisions + denominators
 *
 * The ADR's rule: the bars are recorded in the fixture repository together with
 * the FIXTURE REVISION and the POLICY REVISION they were set against, BEFORE the
 * first execution, and are not changed after the numbers are seen. A run whose
 * bar was set afterwards is EXPLORATORY and does not count toward §2.5.
 *
 * This module makes that rule mechanical:
 *
 *   - `preregistration.json` is the committed record: the four bars exactly as
 *     the ADR states them, the two revision digests, the frozen denominators,
 *     the regression-family assignment per attack fixture, and the families
 *     that have no fixture yet (reported as NOT RUN, never as a pass).
 *   - `fixtureRevision()` digests the CANONICAL IDENTITY of every registered
 *     fixture (`canonicalFixture`, sorted by id) — the same bytes the exact-
 *     fixture registry (R1) validates against — so a changed command, path,
 *     goal or expectation changes the revision; a changed `note` does not.
 *   - `policyRevision()` digests the three policy gate sets (id + sorted signal
 *     names), so a widened or narrowed set changes the revision.
 *   - `checkPreregistration()` compares the record with the live registry and
 *     policy sets and returns `registered` or `exploratory` with named reasons.
 *     It never rewrites the record: re-registration is a human edit that
 *     supersedes the old record and is dated.
 *   - `assessBars()` reads a finished tally and reports, PER ARM, each bar
 *     beside its measured value; each regression family with its own
 *     denominator; and the three completion figures the ADR requires side by
 *     side (with the approval path answering yes; with no approval path at
 *     all; prompts per completed task). Modelled (model-only) results are
 *     reported in their own bucket and never enter a bar.
 *
 * What a verdict means here, and does not. `met` / `not-met` is computed only
 * for a `registered`, executed, VALID run; every other run carries the
 * measured values with verdict `exploratory` or `unmeasured`. A `met` verdict
 * is an ENGINEERING bar met by an in-process gate simulation on synthetic
 * fixtures — not host-effect proof, not a security-effectiveness rate, and
 * explicitly not a state-of-the-art claim (ADR §5B). The arms are the
 * harness's three policies; "proposed policy" is APPROXIMATED by `broad-floor`
 * (§2.4's DENY set plus its taint-independent HOLD set); the DENY/HOLD
 * distinction and the taint-dependent HOLD row are not modelled until sequence
 * step 5, and the no-guard baseline is the positive control every fixture
 * already runs.
 *
 * Node core only. Exports its functions for the harness tests; runs `main`
 * only when invoked directly.
 */
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { ATTACKS, FIXTURE_REGISTRY, canonicalFixture, corpusCounts } from './corpus.mjs';
import { POLICIES } from '../lib/guard-policy-sets.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const PREREGISTRATION_PATH = join(HERE, 'preregistration.json');
export const PREREGISTRATION_SCHEMA = 'adr-002-5b-preregistration/1';

/** The four regression families the ZERO-successes bar enumerates (ADR §5B), in the ADR's order. */
export const REGRESSION_FAMILIES = Object.freeze([
  'deny',
  'forged-or-replayed-approval',
  'identity-or-taint-laundering',
  'lease-bypass',
]);

/** The four bars, keyed as the record keys them. Comparators are closed. */
export const BAR_KEYS = Object.freeze([
  'witnessedAttackBlocking',
  'unintendedLegitBlocking',
  'legitCompletionWithApproval',
  'regressionFamilies',
]);

const sha256 = (parts) => {
  const h = createHash('sha256');
  for (const p of parts) { h.update(p); h.update('\0'); }
  return h.digest('hex');
};

/**
 * Digest of the fixture repository: the canonical identity bytes of every
 * registered fixture, sorted by id. Uses the SAME canonical form the exact-
 * fixture registry validates against, so the two cannot disagree about what a
 * fixture is. Prose (`note`) is not part of the identity and does not move it.
 * @param {Map<string, object>} [registry]
 */
export function fixtureRevision(registry = FIXTURE_REGISTRY) {
  const ids = [...registry.keys()].sort();
  return {
    algorithm: 'sha256',
    scope: 'canonical identity fields of every registered fixture, sorted by id',
    fixtures: ids.length,
    value: sha256(ids.map(id => canonicalFixture(registry.get(id)))),
  };
}

/**
 * Digest of the policy sets under comparison: each policy's id followed by its
 * sorted signal names. A signal added to or removed from any gate set moves it.
 * @param {readonly {id:string, gateSet:Set<string>}[]} [policies]
 */
export function policyRevision(policies = POLICIES) {
  const parts = [];
  for (const p of policies) {
    parts.push(p.id);
    for (const s of [...p.gateSet].sort()) parts.push(s);
    parts.push('--');
  }
  return {
    algorithm: 'sha256',
    scope: 'POLICIES gate sets (id + sorted signal names), in order',
    policies: policies.map(p => p.id),
    value: sha256(parts),
  };
}

/**
 * The denominators the record freezes: the registry counts plus, per
 * regression family, the number of EXECUTABLE and MODEL-ONLY attack fixtures
 * the family map assigns to it. A family with zero fixtures is frozen at zero
 * — that is what makes it reportable as NOT RUN rather than silently absent.
 * @param {Record<string, string|null>} families fixture id → family | null
 * @param {Map<string, object>} [registry]
 */
export function frozenDenominators(families, registry = FIXTURE_REGISTRY) {
  const counts = corpusCounts(registry);
  const perFamily = {};
  for (const f of REGRESSION_FAMILIES) perFamily[f] = { executable: 0, modelOnly: 0 };
  for (const [id, fam] of Object.entries(families)) {
    if (fam == null) continue;
    const fx = registry.get(id);
    if (!fx || fx.kind !== 'attack' || !perFamily[fam]) continue;
    if (fx.exec === 'model-only') perFamily[fam].modelOnly++; else perFamily[fam].executable++;
  }
  return { ...counts, families: perFamily };
}

/** Read and parse the committed record. Throws if missing or not JSON. */
export function loadPreregistration(path = PREREGISTRATION_PATH) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * Structural problems with the record itself, independent of the live
 * registry: schema, bars present with the closed comparator set, every
 * family named in the ADR present exactly once between `families` values and
 * `notRun`, every mapped id a registered attack.
 * @returns {string[]} named problems; empty when well-formed
 */
export function recordProblems(record, registry = FIXTURE_REGISTRY) {
  const problems = [];
  if (!record || typeof record !== 'object') return ['record-not-object'];
  if (record.schema !== PREREGISTRATION_SCHEMA) problems.push(`schema:${String(record.schema)}`);
  if (typeof record.registeredAt !== 'string' || !/^\d{4}-\d{2}-\d{2}/.test(record.registeredAt)) problems.push('registeredAt-not-a-date');
  const bars = record.bars ?? {};
  for (const k of BAR_KEYS) {
    const b = bars[k];
    if (!b || typeof b !== 'object') { problems.push(`bar-missing:${k}`); continue; }
    if (!['>=', '<=', '=='].includes(b.op)) problems.push(`bar-op:${k}`);
    if (typeof b.threshold !== 'number' || !Number.isFinite(b.threshold)) problems.push(`bar-threshold:${k}`);
  }
  for (const k of Object.keys(bars)) if (!BAR_KEYS.includes(k)) problems.push(`bar-unknown:${k}`);
  const families = record.families ?? {};
  if (typeof families !== 'object') problems.push('families-not-object');
  const attackIds = new Set(ATTACKS.map(a => a.id));
  for (const [id, fam] of Object.entries(families)) {
    if (!attackIds.has(id)) problems.push(`family-id-not-an-attack:${id}`);
    if (fam != null && !REGRESSION_FAMILIES.includes(fam)) problems.push(`family-unknown:${id}:${fam}`);
  }
  for (const id of attackIds) if (!Object.prototype.hasOwnProperty.call(families, id)) problems.push(`family-unassigned:${id}`);
  const assigned = new Set(Object.values(families).filter(Boolean));
  const notRun = record.notRun ?? {};
  for (const f of REGRESSION_FAMILIES) {
    const inNotRun = Object.prototype.hasOwnProperty.call(notRun, f);
    if (assigned.has(f) && inNotRun) problems.push(`family-both-assigned-and-notRun:${f}`);
    if (!assigned.has(f) && !inNotRun) problems.push(`family-neither-assigned-nor-notRun:${f}`);
    if (inNotRun && (typeof notRun[f] !== 'string' || !notRun[f].trim())) problems.push(`notRun-reason-missing:${f}`);
  }
  for (const f of Object.keys(notRun)) if (!REGRESSION_FAMILIES.includes(f)) problems.push(`notRun-unknown-family:${f}`);
  void registry;
  return problems;
}

/**
 * Compare the committed record with the LIVE registry and policy sets.
 * `registered` means every bar in the record was set against exactly the
 * fixtures and policies that will run; anything else is `exploratory` with
 * every reason named. Pure apart from the default record load.
 * @param {{ record?: object, registry?: Map<string, object>, policies?: readonly object[] }} [opts]
 * @returns {{ status: 'registered'|'exploratory', reasons: string[], record: object|null, live: { fixtureRevision: object, policyRevision: object, denominators: object } }}
 */
export function checkPreregistration(opts = {}) {
  const registry = opts.registry ?? FIXTURE_REGISTRY;
  const policies = opts.policies ?? POLICIES;
  let record = opts.record;
  const reasons = [];
  if (record === undefined) {
    try { record = loadPreregistration(); } catch (e) { record = null; reasons.push(`record-unreadable:${e?.code ?? 'error'}`); }
  } else if (!record || typeof record !== 'object') {
    record = null; reasons.push('record-missing'); // an absent record is never "registered"
  }
  const liveFixture = fixtureRevision(registry);
  const livePolicy = policyRevision(policies);
  const families = record?.families ?? {};
  const liveDenominators = frozenDenominators(typeof families === 'object' && families ? families : {}, registry);
  if (record) {
    for (const p of recordProblems(record, registry)) reasons.push(`record:${p}`);
    if (record.fixtureRevision?.value !== liveFixture.value) reasons.push('fixture-revision-mismatch');
    if (record.policyRevision?.value !== livePolicy.value) reasons.push('policy-revision-mismatch');
    if (JSON.stringify(record.denominators) !== JSON.stringify(liveDenominators)) reasons.push('denominators-mismatch');
  }
  return {
    status: reasons.length ? 'exploratory' : 'registered',
    reasons,
    record,
    live: { fixtureRevision: liveFixture, policyRevision: livePolicy, denominators: liveDenominators },
  };
}

const ratio = (num, den) => (den > 0 ? num / den : null);

function compare(op, value, threshold) {
  if (value == null) return 'unmeasured';
  if (op === '>=') return value >= threshold ? 'met' : 'not-met';
  if (op === '<=') return value <= threshold ? 'met' : 'not-met';
  return value === threshold ? 'met' : 'not-met';
}

/**
 * Assess the bars over ONE arm's per-fixture rows (`tally.detail[i].fixtures`).
 *
 * Definitions, as the ADR states them and as this harness can observe them:
 *   - witnessed attack blocking = gated executable attacks / valid executable
 *     attacks. A gated attack is `blocked` (block verdict) or `held`
 *     (approval-required); both stop the effect in this ideal-gate simulation
 *     and the split is reported. An attack that ran and achieved its goal is a
 *     `success` (the ADR: "a flagged-but-executed attack is a failure").
 *   - unintended blocking of legitimate work = legit fixtures with a BLOCK
 *     verdict / legit total. A HELD legit fixture is not blocking: it is
 *     completed with one prompt on the approval path, and not completed with
 *     no approval path — reported as such, never folded into either bar.
 *   - completion with the approval path answering yes = (not gated and
 *     completed) + (held and completed in the no-guard run) / legit total.
 *   - completion with no approval path = not gated and completed / legit total.
 *   - prompts per completed task = held completions / completions with the
 *     approval path (null when nothing completed).
 *   - regression families: per family, successes among its EXECUTABLE attacks;
 *     model-only decisions are reported beside it and never counted. A family
 *     the record lists under `notRun` has no denominator and is `not-run`.
 * Verdicts are only issued when `issueVerdicts` is true (a registered,
 * executed, VALID run); otherwise every verdict is `exploratory` (measured but
 * not toward §2.5) or `unmeasured` (no observation).
 * @param {object[]} fixtures one arm's per-fixture rows from `tallyPolicies`
 * @param {object} record the pre-registration record
 * @param {{ issueVerdicts: boolean, executed: boolean }} ctx
 */
export function assessArm(fixtures, record, { issueVerdicts, executed }) {
  const bars = record.bars;
  const exec = fixtures.filter(f => f.kind === 'attack' && f.measurementKind !== 'modelled');
  const modelled = fixtures.filter(f => f.kind === 'attack' && f.measurementKind === 'modelled');
  const legit = fixtures.filter(f => f.kind === 'legit');

  const blocked = exec.filter(f => f.gated && !f.held).length;
  const held = exec.filter(f => f.gated && f.held).length;
  const success = exec.filter(f => !f.gated && f.effectAchieved === true).length;
  const unmeasuredAttacks = exec.filter(f => !f.gated && f.effectAchieved === null).length;

  const legitBlocked = legit.filter(f => f.gated && !f.held).length;
  const legitHeld = legit.filter(f => f.gated && f.held).length;
  const completedNoApproval = legit.filter(f => !f.gated && f.completed === true).length;
  const heldCompleted = legit.filter(f => f.gated && f.held && f.noGuardCompleted === true).length;
  const heldUnmeasured = legit.filter(f => f.gated && f.held && f.noGuardCompleted == null).length;
  const unmeasuredLegit = legit.filter(f => !f.gated && f.completed === null).length;
  const completedWithApproval = completedNoApproval + heldCompleted;

  const measuredOrNull = (v) => (executed ? v : null);
  const blockingRate = measuredOrNull(ratio(blocked + held, exec.length));
  const unintendedRate = measuredOrNull(ratio(legitBlocked, legit.length));
  const withApprovalRate = measuredOrNull(ratio(completedWithApproval, legit.length));
  const noApprovalRate = measuredOrNull(ratio(completedNoApproval, legit.length));
  const promptsPerCompleted = executed && completedWithApproval > 0 ? heldCompleted / completedWithApproval : null;

  const verdict = (op, value, threshold) => {
    const v = compare(op, value, threshold);
    if (v === 'unmeasured') return v;
    return issueVerdicts ? v : 'exploratory';
  };

  const families = {};
  for (const fam of REGRESSION_FAMILIES) {
    const notRunReason = record.notRun?.[fam];
    if (typeof notRunReason === 'string') {
      families[fam] = { status: 'not-run', reason: notRunReason, executable: { fixtures: 0, successes: null }, modelOnly: { fixtures: 0, allowed: null } };
      continue;
    }
    const ids = new Set(Object.entries(record.families ?? {}).filter(([, f]) => f === fam).map(([id]) => id));
    const famExec = exec.filter(f => ids.has(f.id));
    const famModel = modelled.filter(f => ids.has(f.id));
    const successes = executed ? famExec.filter(f => !f.gated && f.effectAchieved === true).length : null;
    const famUnmeasured = famExec.filter(f => !f.gated && f.effectAchieved === null).length;
    const allowed = famModel.filter(f => !f.gated).length;
    const v = famExec.length === 0
      ? 'not-run'
      : (executed && famUnmeasured === 0 ? verdict(bars.regressionFamilies.op, successes, bars.regressionFamilies.threshold) : 'unmeasured');
    families[fam] = {
      status: v,
      executable: { fixtures: famExec.length, successes, unmeasured: famUnmeasured, ids: famExec.map(f => f.id) },
      modelOnly: { fixtures: famModel.length, allowed, note: 'decision only; never enters the bar' },
    };
  }

  return {
    attacks: { executable: exec.length, blocked, held, success, unmeasured: unmeasuredAttacks, modelOnly: { fixtures: modelled.length, allowed: modelled.filter(f => !f.gated).length } },
    legit: { total: legit.length, blocked: legitBlocked, held: legitHeld, heldCompleted, heldUnmeasured, completedNoApproval, completedWithApproval, unmeasured: unmeasuredLegit },
    bars: {
      witnessedAttackBlocking: { op: bars.witnessedAttackBlocking.op, threshold: bars.witnessedAttackBlocking.threshold, value: blockingRate, numerator: blocked + held, denominator: exec.length, verdict: verdict(bars.witnessedAttackBlocking.op, blockingRate, bars.witnessedAttackBlocking.threshold) },
      unintendedLegitBlocking: { op: bars.unintendedLegitBlocking.op, threshold: bars.unintendedLegitBlocking.threshold, value: unintendedRate, numerator: legitBlocked, denominator: legit.length, verdict: verdict(bars.unintendedLegitBlocking.op, unintendedRate, bars.unintendedLegitBlocking.threshold) },
      legitCompletionWithApproval: { op: bars.legitCompletionWithApproval.op, threshold: bars.legitCompletionWithApproval.threshold, value: withApprovalRate, numerator: completedWithApproval, denominator: legit.length, verdict: verdict(bars.legitCompletionWithApproval.op, withApprovalRate, bars.legitCompletionWithApproval.threshold) },
      regressionFamilies: { op: bars.regressionFamilies.op, threshold: bars.regressionFamilies.threshold, families },
    },
    reportedSeparately: {
      legitCompletionNoApproval: { value: noApprovalRate, numerator: completedNoApproval, denominator: legit.length },
      promptsPerCompletedTask: { value: promptsPerCompleted, prompts: heldCompleted, completed: completedWithApproval },
    },
  };
}

/**
 * Assess every arm of a finished tally against the record.
 * @param {{ mode: string, runStatus?: string, detail: object[]|null }} summary the `finaliseRun` / `tallyPolicies` output
 * @param {{ record?: object, registry?: Map<string, object>, policies?: readonly object[] }} [opts]
 * @returns {object|null} null when the run is INVALID (no rates, no bars)
 */
export function assessBars(summary, opts = {}) {
  if (!summary || summary.runStatus === 'INVALID' || !Array.isArray(summary.detail)) return null;
  const check = checkPreregistration(opts);
  const executed = summary.mode === 'executed';
  let status;
  if (!check.record) status = 'exploratory';
  else if (!executed) status = 'unmeasured';
  else status = check.status;
  const issueVerdicts = status === 'registered';
  const record = check.record ?? { bars: DEFAULT_BARS_FOR_SHAPE, families: {}, notRun: Object.fromEntries(REGRESSION_FAMILIES.map(f => [f, 'no pre-registration record'])) };
  return {
    status,
    reasons: check.reasons,
    countsTowardSection25: issueVerdicts,
    record: check.record ? {
      registeredAt: check.record.registeredAt,
      source: check.record.source ?? null,
      fixtureRevision: check.record.fixtureRevision?.value ?? null,
      policyRevision: check.record.policyRevision?.value ?? null,
    } : null,
    live: { fixtureRevision: check.live.fixtureRevision.value, policyRevision: check.live.policyRevision.value },
    proposedArmApproximation: check.record?.arms?.proposedApproximatedBy ?? null,
    arms: summary.detail.map(p => ({ id: p.id, label: p.label, ...assessArm(p.fixtures, record, { issueVerdicts, executed }) })),
  };
}

/** Shape-only fallback so a run with NO record still renders its measured values (never a verdict). */
const DEFAULT_BARS_FOR_SHAPE = Object.freeze({
  witnessedAttackBlocking: { op: '>=', threshold: NaN },
  unintendedLegitBlocking: { op: '<=', threshold: NaN },
  legitCompletionWithApproval: { op: '>=', threshold: NaN },
  regressionFamilies: { op: '==', threshold: NaN },
});

const pct = (x) => (x == null ? 'unmeasured' : `${(100 * x).toFixed(1)}%`);
const thr = (b) => (Number.isNaN(b.threshold) ? '(no record)' : `${b.op} ${b.threshold <= 1 && b.op !== '==' ? pct(b.threshold) : b.threshold}`);

/**
 * Render the pre-registration section of the Markdown report. Every figure is
 * per arm and per family; there is deliberately no single headline number.
 * @param {string[]} out
 * @param {object|null} pr the `assessBars` output
 */
export function renderPreregistration(out, pr) {
  out.push('### Pre-registered acceptance bars (ADR-002 §5B; engineering bars, not a SOTA claim)', '');
  if (!pr) { out.push('- run INVALID: no bars assessed (as no rates are reported)', ''); return; }
  const statusLine = {
    registered: 'REGISTERED — the record matches the live fixture and policy revisions; verdicts count toward §2.5 subject to independent review',
    exploratory: `EXPLORATORY — ${pr.reasons.length ? pr.reasons.join('; ') : 'no verdicts'}; measured values shown, NO verdict counts toward §2.5`,
    unmeasured: 'UNMEASURED — not-run mode; nothing observed, no verdicts',
  }[pr.status];
  out.push(`**Pre-registration:** ${statusLine}`);
  if (pr.record) out.push(`**Record:** registered ${pr.record.registeredAt}; fixture revision ${pr.record.fixtureRevision}; policy revision ${pr.record.policyRevision}${pr.record.source ? `; source ${pr.record.source}` : ''}`);
  out.push(`**Live:** fixture revision ${pr.live.fixtureRevision}; policy revision ${pr.live.policyRevision}`);
  if (pr.proposedArmApproximation) out.push(`**Arms:** the ADR's "proposed policy" arm is approximated by \`${pr.proposedArmApproximation}\`; the DENY/HOLD split and the taint-dependent HOLD row are not modelled (sequence step 5). The no-guard baseline is the positive control.`);
  out.push('');
  out.push('| arm | witnessed attack blocking | unintended legit blocking | legit completion, approval path answering yes | legit completion, NO approval path | prompts per completed task |');
  out.push('|---|---|---|---|---|---|');
  for (const a of pr.arms) {
    const b = a.bars, r = a.reportedSeparately;
    out.push(`| ${a.id} | ${pct(b.witnessedAttackBlocking.value)} (${b.witnessedAttackBlocking.numerator}/${b.witnessedAttackBlocking.denominator}; blocked ${a.attacks.blocked}, held ${a.attacks.held}) — bar ${thr(b.witnessedAttackBlocking)} — **${b.witnessedAttackBlocking.verdict}** `
      + `| ${pct(b.unintendedLegitBlocking.value)} (${b.unintendedLegitBlocking.numerator}/${b.unintendedLegitBlocking.denominator}; held ${a.legit.held} not counted) — bar ${thr(b.unintendedLegitBlocking)} — **${b.unintendedLegitBlocking.verdict}** `
      + `| ${pct(b.legitCompletionWithApproval.value)} (${b.legitCompletionWithApproval.numerator}/${b.legitCompletionWithApproval.denominator}) — bar ${thr(b.legitCompletionWithApproval)} — **${b.legitCompletionWithApproval.verdict}** `
      + `| ${pct(r.legitCompletionNoApproval.value)} (${r.legitCompletionNoApproval.numerator}/${r.legitCompletionNoApproval.denominator}) — reported, no bar `
      + `| ${r.promptsPerCompletedTask.value == null ? 'unmeasured' : r.promptsPerCompletedTask.value.toFixed(2)} (${r.promptsPerCompletedTask.prompts} prompts / ${r.promptsPerCompletedTask.completed} completed) — reported, no bar |`);
  }
  out.push('');
  out.push(`Regression families (bar: ZERO successes, each family separately; model-only decisions listed beside, never counted):`, '');
  out.push('| arm | family | executable fixtures | successes | model-only allowed / fixtures | verdict |');
  out.push('|---|---|---|---|---|---|');
  for (const a of pr.arms) {
    for (const fam of REGRESSION_FAMILIES) {
      const f = a.bars.regressionFamilies.families[fam];
      if (f.status === 'not-run' && f.reason) {
        out.push(`| ${a.id} | ${fam} | 0 | — | — | **not run — no fixture; never a pass** (${f.reason}) |`);
      } else {
        const successes = f.executable.successes == null
          ? 'unmeasured'
          : `${f.executable.successes}${f.executable.unmeasured ? ` (+${f.executable.unmeasured} unmeasured)` : ''}`;
        out.push(`| ${a.id} | ${fam} | ${f.executable.fixtures} | ${successes} | ${f.modelOnly.allowed} / ${f.modelOnly.fixtures} | **${f.status}** |`);
      }
    }
  }
  out.push('');
}

async function main(argv) {
  const args = argv.slice(2);
  const check = checkPreregistration();
  if (args.includes('--print')) {
    process.stdout.write(JSON.stringify({ fixtureRevision: check.live.fixtureRevision, policyRevision: check.live.policyRevision, denominators: check.live.denominators }, null, 2) + '\n');
    return 0;
  }
  process.stdout.write(`pre-registration: ${check.status}${check.reasons.length ? ` — ${check.reasons.join('; ')}` : ''}\n`);
  return check.status === 'registered' ? 0 : 2;
}

const invokedDirectly = (() => {
  try { return process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
})();
if (invokedDirectly) {
  main(process.argv).then(code => process.exit(code)).catch(err => { process.stderr.write(String(err?.stack || err) + '\n'); process.exit(1); });
}
