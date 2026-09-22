/**
 * ADR-002 measurement harness — round-3 regressions (Tars's round-2 review of
 * #559 at 8ca166fe, re-verified against 91daceea and pinned here). Every test
 * FAILS without its fix.
 *
 *   1. CONTAINMENT / REGISTRY — Tars's four probes (1a unregistered fixture
 *      writing outside its sandbox; 1b known id with a changed command; 1c a
 *      command / target with parent traversal; 1d a model-only fixture handed
 *      to the executor) are refused BEFORE setup (`setupStarted=false`,
 *      `ran=false`), and the CLI exits non-zero when ANY invalid fixture is
 *      present — an invalid fixture fails the run, it never passes because
 *      `effectAchieved` happened to be false. A negative control that did not
 *      run is not a pass.
 *   2. FALSE EVIDENCE WITHOUT --execute — the default CLI is an explicit
 *      NOT-RUN mode: zero observations, null outcomes, null rates, no control
 *      claims, no "achieved" / "effect observed" text.
 *   3. PRIVACY / EXPORT — one projection feeds JSON and Markdown; a signal name
 *      is printed only by vocabulary MEMBERSHIP (cross-checked against the
 *      writer and guard source); metadata is enum-or-other.
 *   4. SCHEMA / ACCOUNTING — declared denial without signals is malformed;
 *      numeric status / array channel is malformed; whitespace deliveredVia is
 *      not a delivery; malformed / unknown / contradictory are three buckets.
 *
 * No dist build, no host log, no product code.
 */
import { describe, it, expect } from '@jest/globals';
import { mkdtempSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
// @ts-expect-error — plain ESM, no types
import { CORPUS, ATTACKS, LEGIT, CONTROLS, SELFTESTS, assertRegisteredFixture } from '../../scripts/guard-effect-fixtures/corpus.mjs';
// @ts-expect-error — plain ESM, no types
import { sandboxExecutor, runCli, controlOutcome, finaliseRun, tallyPolicies, renderMarkdown } from '../../scripts/guard-effect-fixtures/run.mjs';
// @ts-expect-error — plain ESM, no types
import { stubEvaluatorAdapter } from '../../scripts/guard-effect-fixtures/adapter.mjs';
// @ts-expect-error — plain ESM, no types
import { run, parseDenials, groupEvents, classifyRecord, bucketOf, projectPublic, analyse } from '../../scripts/guard-policy-replay.mjs';
// @ts-expect-error — plain ESM, no types
import { GUARD_SIGNAL_VOCABULARY, TOOL_ENUM, REDACTED_SIGNAL_LABEL, validateNotify, publicSignalName } from '../../scripts/lib/guard-log-schema.mjs';
// @ts-expect-error — plain ESM, no types
import { NEVER_LOGGED_SIGNALS } from '../../scripts/lib/guard-policy-sets.mjs';

const realpath = (p: string) => execFileSync('realpath', [p], { encoding: 'utf8' }).trim();
const byId = (list: any[], id: string) => { const f = list.find((x: any) => x.id === id); if (!f) throw new Error(`no fixture ${id}`); return f; };
// jest runs from the repo root (ESM: no __dirname); the source cross-check reads two tracked files from there.
const REPO = resolve(process.cwd());

/** A silent CLI harness: captures output, never touches process.exit. */
function cli(args: string[], deps: any = {}) {
  const out: string[] = [], err: string[] = [], files: Record<string, string> = {};
  return runCli(['node', 'run.mjs', ...args], {
    stdout: (s: string) => out.push(s), stderr: (s: string) => err.push(s), write: (p: string, t: string) => { files[p] = t; },
    ...deps,
  }).then((r: any) => ({ ...r, out: out.join(''), err: err.join(''), files }));
}

// ═══════════════════════════════════════════════════════════════════════════
describe('round 3 / finding 1 — containment + registry: refuse before setup, fail the run', () => {
  let scratch: string;
  beforeEach(() => { scratch = realpath(mkdtempSync(join(tmpdir(), 'sc-adr002-r3-'))); });
  afterEach(() => rmSync(scratch, { recursive: true, force: true }));

  it('1a: an unregistered fixture that writes OUTSIDE its sandbox is refused before setup and the marker is never written', () => {
    const marker = join(scratch, 'marker.txt');
    const fx = { id: 'benign-confinement-probe', kind: 'legit', exec: 'sandbox', command: 'printf AFTER > ' + marker, done: { kind: 'present', path: 'build' } };
    const obs = sandboxExecutor(fx);
    expect(obs).toMatchObject({ ran: false, setupStarted: false, invalid: true });
    expect(obs.invalidReason).toContain('unregistered-fixture');
    expect(existsSync(marker)).toBe(false);
  });

  it('1b: a KNOWN id with a changed command is refused before setup and nothing is written', () => {
    const marker = join(scratch, 'marker.txt');
    const fx = { ...byId(LEGIT, 'legit-mkdir'), command: 'mkdir -p build/tmp && printf X > ' + marker };
    const obs = sandboxExecutor(fx);
    expect(obs).toMatchObject({ ran: false, setupStarted: false, invalid: true });
    expect(obs.invalidReason).toContain('altered-fixture');
    expect(existsSync(marker)).toBe(false);
  });

  it('1c: parent traversal in a command, a done target or a files path is refused before setup', () => {
    const cmd = { ...byId(LEGIT, 'legit-write-file'), command: 'echo x > ../../traversal.txt' };
    const done = { ...byId(LEGIT, 'legit-mkdir'), done: { kind: 'present', path: '../outside' } };
    const files = { ...byId(LEGIT, 'legit-comment-in-script'), files: { '../runner.mjs': 'process.stdout.write("x")' } };
    for (const fx of [cmd, done, files]) {
      expect(assertRegisteredFixture(fx).length).toBeGreaterThan(0);
      expect(sandboxExecutor(fx)).toMatchObject({ ran: false, setupStarted: false, invalid: true });
    }
    // and an UNREGISTERED fixture carrying traversal is refused by membership, not by a shell deny-regex
    const unreg = { id: 'traversal-probe', kind: 'legit', exec: 'sandbox', command: 'cat ../../etc-like', done: { kind: 'present', path: 'build' } };
    const obs = sandboxExecutor(unreg);
    expect(obs).toMatchObject({ ran: false, setupStarted: false });
    expect(obs.invalidReason).toContain('unregistered-fixture');
  });

  it('1d: a model-only fixture is refused by the executor BEFORE setup, registered or not', () => {
    const registered = sandboxExecutor(byId(ATTACKS, 'destruct-root'));
    expect(registered).toMatchObject({ ran: false, setupStarted: false, invalid: true, invalidReason: 'not-executable' });
    const harmless = { id: 'harmless-model', kind: 'attack', exec: 'model-only', command: 'printf harmless-model' };
    const obs = sandboxExecutor(harmless);
    expect(obs).toMatchObject({ ran: false, setupStarted: false, invalid: true });
    expect(obs.invalidReason).toContain('unregistered-fixture');
  });

  it('a negative control that did NOT run is not a pass merely because effectAchieved is false', () => {
    const ctl = byId(CONTROLS, 'ctl-egress-file-ref');
    expect(controlOutcome(ctl, { ran: false, setupStarted: false, invalid: true, invalidReason: 'altered-fixture', effectAchieved: false }).ok).toBe(false);
    expect(controlOutcome(ctl, { ran: true, invalid: false, effectAchieved: false, evidence: 'x' }).ok).toBe(true);
    expect(controlOutcome(ctl, { ran: true, invalid: false, effectAchieved: true, evidence: 'x' }).ok).toBe(false);
    expect(controlOutcome(ctl, null).ok).toBe(false);
  });

  describe('the CLI fails the run when ANY invalid fixture is present (never evaluated, never executed)', () => {
    const stub = stubEvaluatorAdapter({});

    it('default mode: an unregistered fixture in the corpus → exit 3, INVALID, not in rows', async () => {
      const marker = join(scratch, 'marker.txt');
      const bad = { id: 'benign-confinement-probe', kind: 'legit', exec: 'sandbox', command: 'printf AFTER > ' + marker, done: { kind: 'present', path: 'build' } };
      const r = await cli([], { adapter: stub, fixtures: { corpus: [byId(LEGIT, 'legit-mkdir'), bad], controls: [], selftests: [] } });
      expect(r.code).toBe(3);
      expect(r.summary.runStatus).toBe('INVALID');
      expect(r.summary.invalidReasons).toContain('corpus-fixture-invalid:benign-confinement-probe');
      expect(r.summary.policies).toBeNull();
      expect(r.out).toContain('RUN INVALID');
      expect(existsSync(marker)).toBe(false);
    });

    it('--execute: an unregistered outside-writer is refused, the marker is absent, exit 3', async () => {
      const marker = join(scratch, 'marker.txt');
      const bad = { id: 'benign-confinement-probe', kind: 'legit', exec: 'sandbox', command: 'printf AFTER > ' + marker, done: { kind: 'present', path: 'build' } };
      const r = await cli(['--execute'], { adapter: stub, fixtures: { corpus: [byId(LEGIT, 'legit-mkdir'), bad], controls: [], selftests: [] } });
      expect(r.code).toBe(3);
      expect(r.summary.runStatus).toBe('INVALID');
      expect(existsSync(marker)).toBe(false);
      // the valid fixture DID run (the executor is fine); the invalid one never did
      expect(r.summary.observations.fixtures).toBe(1);
    });

    it('--execute: a harmless unregistered model-only fixture is invalid and never runs (exit 3)', async () => {
      const harmless = { id: 'harmless-model', kind: 'attack', exec: 'model-only', command: 'printf harmless-model' };
      const r = await cli(['--execute'], { adapter: stub, fixtures: { corpus: [harmless], controls: [], selftests: [] } });
      expect(r.code).toBe(3);
      expect(r.summary.invalidReasons).toContain('corpus-fixture-invalid:harmless-model');
      expect(r.summary.observations.fixtures).toBe(0);
    });

    it('a known id with an altered command in the corpus → exit 3 even though it would "achieve nothing"', async () => {
      const altered = { ...byId(LEGIT, 'legit-mkdir'), command: 'true' };
      const r = await cli([], { adapter: stub, fixtures: { corpus: [altered], controls: [], selftests: [] } });
      expect(r.code).toBe(3);
      expect(r.summary.invalidFixtures[0].reasons).toContain('altered-fixture');
    });

    it('the committed corpus is valid under the same up-front check (control: exit 0 in default mode)', async () => {
      const r = await cli([], { adapter: stub });
      expect(r.code).toBe(0);
      expect(r.summary.invalidFixtures).toEqual([]);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 3 / finding 2 — the default CLI is an explicit NOT-RUN mode with no evidence claims', () => {
  const stub = stubEvaluatorAdapter({
    'persist-bashrc-append': { decision: 'allow', severity: 'benign', signals: [] },
    'egress-file-ref': { decision: 'require_approval', severity: 'dangerous', signals: ['external-egress'] },
    'destruct-root': { decision: 'block', severity: 'catastrophic', signals: ['delete-root-or-home'] },
  });

  it('default run: exit 0, mode not-run, zero observations, null rates, no control claims, no "achieved"/"effect observed" text', async () => {
    const r = await cli(['--json', 'out.json', '--md', 'out.md'], { adapter: stub });
    expect(r.code).toBe(0);
    const s = r.summary;
    expect(s.mode).toBe('not-run');
    expect(s.observations).toEqual({ fixtures: 0, negativeControls: 0, selftests: 0 });
    expect(s.ratesWithheld).toBe(true);
    expect(s.canary.checked).toBe(false);
    expect(s.controls.negative).toBeNull();
    expect(s.controls.positive).toBeNull();
    expect(s.selftests).toBeNull();
    expect(s.executableDenominator).toBeNull();
    for (const p of s.policies) {
      expect(p.executedWitness.measured).toBe(false);
      expect(p.executedWitness.attackSuccessRate).toBeNull();
      expect(p.executedWitness.attackSuccess).toBeNull();
      expect(p.executedWitness.legitCompletionRate).toBeNull();
      expect(p.executedWitness.legitCompleted).toBeNull();
    }
    // every non-gated executable outcome is unmeasured (null), never assumed true
    for (const d of s.detail) for (const f of d.fixtures) {
      if (f.measurementKind === 'modelled') continue;
      expect(f.measurementKind).toBe('not-run');
      if (f.kind === 'attack' && !f.gated) expect(f.effectAchieved).toBeNull();
      if (f.kind === 'legit' && !f.gated) expect(f.completed).toBeNull();
    }
    for (const text of [r.out, r.files['out.md']]) {
      expect(text).not.toMatch(/achieved/i);
      expect(text).not.toMatch(/effect observed/i);
      expect(text).not.toMatch(/Executed-witness rates/);
    }
    expect(r.out).toContain('NOT EXECUTED');
    expect(r.err).toContain('NOT EXECUTED');
    const json = JSON.parse(r.files['out.json']);
    // no string VALUE in the JSON claims an observation (keys such as `effectAchieved` hold null)
    const values: string[] = [];
    const walk = (v: any) => { if (typeof v === 'string') values.push(v); else if (v && typeof v === 'object') Object.values(v).forEach(walk); };
    walk(json);
    expect(values.filter(v => /achieved|effect observed/i.test(v))).toEqual([]);
    expect(json.observations.fixtures).toBe(0);
    expect(json.policies.every((p: any) => p.executedWitness.attackSuccessRate === null && p.executedWitness.legitCompletionRate === null)).toBe(true);
  });

  it('tallyPolicies(executed:false) never derives an effect or completion from a missing observation', () => {
    const rows = CORPUS.map((fx: any) => ({ fx, verdict: stub.evaluate(fx.command, fx.files, fx.id), obs: null, witnessUnproven: false }));
    const s = tallyPolicies(rows, { evaluatorId: 'stub', executed: false });
    expect(s.mode).toBe('not-run');
    const cur = s.policies.find((p: any) => p.id === 'current-tiers');
    expect(cur.executedWitness.attackSuccess).toBeNull();
    expect(cur.executedWitness.attackUnmeasured + cur.executedWitness.attackGated).toBe(cur.executedWitness.attackTotal);
    // the modelled bucket is a DECISION and is still reported
    expect(cur.modelled.attackTotal).toBe(3);
    // and finaliseRun in not-run mode carries no positive-control claims
    const f = finaliseRun({ rows, executed: false, canaryChecked: false, evaluatorId: 'stub' });
    expect(f.controls.positive).toBeNull();
    expect(renderMarkdown(f)).not.toMatch(/achieved/i);
  });

  it('an executed row with ran=true IS measured (the fix does not mute real observations)', () => {
    const rows = CORPUS.filter((f: any) => f.id === 'persist-bashrc-append').map((fx: any) => ({
      fx, verdict: stub.evaluate(fx.command, fx.files, fx.id), obs: { ran: true, invalid: false, effectAchieved: true, exit: 0, evidence: 'needle PRESENT' }, witnessUnproven: false,
    }));
    const s = tallyPolicies(rows, { evaluatorId: 'stub', executed: true });
    const cur = s.policies.find((p: any) => p.id === 'current-tiers');
    expect(cur.executedWitness.measured).toBe(true);
    expect(cur.executedWitness.attackSuccess).toBe(1);
  });

  it('gated approval-required verdicts render as HELD, not as an observed block', async () => {
    const r = await cli([], { adapter: stub });
    expect(r.out).toMatch(/\| egress-file-ref \|.*\| require_approval \| yes \| HELD \|/);
    expect(r.out).toMatch(/\| destruct-root \|.*\| block \| yes \| blocked \|/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
const PRIVATE_SENTENCE = 'the operator lives at 12 Example Street and this sentence is private';
const PRIVATE_CHANNEL = 'private-channel-name-xyz';
const row = (o: Record<string, unknown>) => JSON.stringify({
  event: 'action_guard_denial', tool: 'Bash', severity: 'dangerous', outcome: 'auto_denied', origin: 'claude-code-hook',
  detectedAt: '2026-09-01T00:00:00.000Z', notify: { status: 'no_channel', deliveredVia: null }, ...o,
});

describe('round 3 / finding 3 — one safe export projection; vocabulary membership, not syntax', () => {
  const LOG = [
    row({ actionId: 'p1', signals: [PRIVATE_SENTENCE] }),
    row({ actionId: 'p2', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: PRIVATE_CHANNEL } }),
    row({ actionId: 'p3', signals: ['looks-conforming-but-unregistered'] }),
    row({ actionId: 'p4', signals: ['file-delete'], tool: 'MyPrivateToolName', severity: 'weird-severity', event: 'action_guard_denial' }),
    row({ actionId: 'p5', signals: ['file-delete'], outcome: 'some_other_outcome' }),
    row({ actionId: 'p6', signals: ['file-delete', 'external-egress'] }),
  ].join('\n') + '\n';

  it('a synthetic private sentence in a signal field appears in NEITHER the JSON nor the Markdown', () => {
    const { summary, markdown } = run(LOG);
    const json = JSON.stringify(summary);
    expect(json).not.toContain(PRIVATE_SENTENCE);
    expect(markdown).not.toContain(PRIVATE_SENTENCE);
    expect(json).not.toContain('12 Example Street');
    expect(markdown).not.toContain('12 Example Street');
  });

  it('a conforming-looking but unregistered signal name is NOT printed; it is counted under the redacted bucket and its event is unknown', () => {
    const { summary, markdown } = run(LOG);
    const json = JSON.stringify(summary);
    expect(json).not.toContain('looks-conforming-but-unregistered');
    expect(markdown).not.toContain('looks-conforming-but-unregistered');
    expect(summary.redactedSignals.occurrences).toBe(2); // p1 + p3
    expect(summary.redactedSignals.events).toBe(2);
    expect(summary.redactedSignals.label).toBe(REDACTED_SIGNAL_LABEL);
    expect(summary.evidence.unknownReasons['signal-outside-vocabulary']).toBe(2);
    expect(summary.perSignal.map((r: any) => r.signal).sort()).toEqual(['external-egress', 'file-delete']);
  });

  it('a private channel, tool, severity or outcome string never reaches either output; each maps to its enum or "other"', () => {
    const { summary, markdown } = run(LOG);
    const json = JSON.stringify(summary);
    for (const text of [json, markdown]) {
      expect(text).not.toContain(PRIVATE_CHANNEL);
      expect(text).not.toContain('MyPrivateToolName');
      expect(text).not.toContain('weird-severity');
      expect(text).not.toContain('some_other_outcome');
    }
    expect(summary.tools).toEqual(expect.objectContaining({ Bash: 5, other: 1 }));
    expect(summary.severity).toEqual(expect.objectContaining({ dangerous: 5, other: 1 }));
    expect(summary.delivery.finalStatus).toEqual(expect.objectContaining({ 'delivered via=other': 1 }));
    expect(summary.actual.finalEnforcementOutcome).toEqual(expect.objectContaining({ auto_denied: 5, none: 1 }));
  });

  it('publicSignalName is membership, not a regex: a lexically valid name outside the vocabulary is redacted', () => {
    expect(publicSignalName('file-delete')).toBe('file-delete');
    expect(publicSignalName('legit-name')).toBe(REDACTED_SIGNAL_LABEL);
    expect(publicSignalName('Injected Title; SELECT 1')).toBe(REDACTED_SIGNAL_LABEL);
    expect(publicSignalName(42)).toBe(REDACTED_SIGNAL_LABEL);
  });

  it('the JSON and Markdown consume the SAME projection: projectPublic(analyse(...)) is idempotent and is what run() returns', () => {
    const parsed = parseDenials(LOG);
    const internal = analyse(groupEvents(parsed.records), { malformed: parsed.malformed, rowCount: parsed.records.length + parsed.malformed.length, blankLines: parsed.blankLines });
    const once = projectPublic(internal);
    expect(projectPublic(once)).toEqual(once);
    expect(run(LOG).summary).toEqual(once);
  });

  it('the embedded signal vocabulary equals the writer\'s allowlist (+ its redaction marker), and every guard-source signal is either logged or listed never-logged', () => {
    const hook = readFileSync(join(REPO, 'scripts', 'pre-tool-hook.mjs'), 'utf8');
    const block = /const SAFE_SIGNALS = new Set\(\[([\s\S]*?)\]\);/.exec(hook);
    expect(block).not.toBeNull();
    const writerSet = new Set([...block![1].matchAll(/'([a-z0-9-]+)'/g)].map(m => m[1]));
    const vocab = new Set(GUARD_SIGNAL_VOCABULARY);
    expect([...vocab].filter(s => s !== 'redacted-signal').sort()).toEqual([...writerSet].sort());
    expect(vocab.has('redacted-signal')).toBe(true);

    const guard = readFileSync(join(REPO, 'src', 'defence', 'iron-dome', 'tool-action-guard.ts'), 'utf8');
    const emitted = new Set([...guard.matchAll(/signal: '([a-z0-9-]+)'/g)].map(m => m[1]));
    const unscannable = /UNSCANNABLE_SIGNALS = \[([^\]]*)\]/.exec(guard);
    for (const m of (unscannable ? unscannable[1] : '').matchAll(/'([a-z0-9-]+)'/g)) emitted.add(m[1]);
    expect(emitted.size).toBeGreaterThan(30);
    const never = new Set(NEVER_LOGGED_SIGNALS);
    const orphans = [...emitted].filter(s => !vocab.has(s) && !never.has(s));
    expect(orphans).toEqual([]);

    const tools = /const SAFE_TOOL_NAMES = new Set\(\[([\s\S]*?)\]\);/.exec(hook);
    const writerTools = new Set([...tools![1].matchAll(/'([A-Za-z]+)'/g)].map(m => m[1]));
    expect([...TOOL_ENUM].filter(t => t !== 'tool').sort()).toEqual([...writerTools].sort());
  });
});

// ═══════════════════════════════════════════════════════════════════════════
describe('round 3 / finding 4 — schema contracts and the three evidence buckets', () => {
  it('a DECLARED denial (event + outcome) with missing signals is MALFORMED, not "other"', () => {
    const log = JSON.stringify({ event: 'action_guard_denial', outcome: 'auto_denied', actionId: 'd1', tool: 'Bash' }) + '\n';
    const { malformed, records } = parseDenials(log);
    expect(malformed).toEqual([{ lineNo: 1, reason: 'missing-signals' }]);
    // round 4 (M1): the malformed JSON row is RETAINED as a record of its event, carrying no signals
    expect(records.map((x: any) => ({ kind: x.kind, reason: x.reason, signals: x.signals }))).toEqual([{ kind: 'malformed', reason: 'missing-signals', signals: [] }]);
    const { summary } = run(log);
    expect(summary.evidence.malformedRows).toBe(1);
    expect(summary.evidence.malformed).toBe(1);
    expect(summary.evidence.validKnown).toBe(0);
    expect(summary.actual.actuallyStopped).toBe(0);
  });

  it('a declared warning with missing signals is malformed too; a retry row without signals is a lifecycle record', () => {
    const w = JSON.stringify({ event: 'action_guard_warning', outcome: 'warned', actionId: 'w1' });
    const r = JSON.stringify({ event: 'action_guard_denial', outcome: 'retry_granted', actionId: 'w1' });
    const { malformed, records } = parseDenials(w + '\n' + r + '\n');
    expect(malformed.map((m: any) => m.reason)).toEqual(['missing-signals']);
    expect(records.map((x: any) => x.kind)).toEqual(['malformed', 'dnp_retry']);
    // and the event they share is MALFORMED, not known, not retry-only unknown
    const { summary } = run(w + '\n' + r + '\n');
    expect(summary.evidence).toEqual(expect.objectContaining({ validKnown: 0, malformed: 1, unknown: 0 }));
  });

  it('classifyRecord discriminates by the declared contract; a mismatched pair is CONTRADICTORY; unknown pairs are other', () => {
    expect(classifyRecord({ event: 'action_guard_denial', outcome: 'auto_denied' }).kind).toBe('denial');
    expect(classifyRecord({ event: 'action_guard_warning', outcome: 'warned' }).kind).toBe('warning');
    expect(classifyRecord({ event: 'action_guard_warning', outcome: 'failure_allowed' }).kind).toBe('warning');
    expect(classifyRecord({ event: 'action_guard_denial', outcome: 'warned' })).toEqual({ kind: 'contradictory', reason: 'event-outcome-mismatch' });
    expect(classifyRecord({ event: 'action_guard_warning', outcome: 'auto_denied' })).toEqual({ kind: 'contradictory', reason: 'event-outcome-mismatch' });
    expect(classifyRecord({ event: 'action_guard_denial', outcome: 'made_up' }).kind).toBe('other');
    expect(classifyRecord({ event: 'something_else', outcome: 'auto_denied' }).kind).toBe('other');
    // presence of a signals array is NOT what makes a denial
    expect(classifyRecord({ outcome: 'made_up', signals: ['file-delete'] }).kind).toBe('other');
  });

  it('a numeric notify status or an array channel is MALFORMED, never silently "none"', () => {
    const a = row({ actionId: 'n1', signals: ['file-delete'], notify: { status: 42, deliveredVia: null } });
    const b = row({ actionId: 'n2', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: ['a'] } });
    const c = row({ actionId: 'n3', signals: ['file-delete'], notify: 'delivered' });
    const { malformed, records } = parseDenials([a, b, c].join('\n') + '\n');
    expect(malformed.map((m: any) => m.reason)).toEqual(['notify-status-not-string', 'notify-channel-not-string', 'notify-not-object']);
    // retained as malformed records (round 4); their notify is NOT read — no delivery claim survives
    expect(records.map((x: any) => x.kind)).toEqual(['malformed', 'malformed', 'malformed']);
    expect(records.every((x: any) => x.notify.present === false && x.signals.length === 0)).toBe(true);
    expect(run([a, b, c].join('\n') + '\n').summary.delivery.anyValidatedDelivery).toBe(0);
    expect(validateNotify({ notify: { status: 42 } })).toEqual({ ok: false, reason: 'notify-status-not-string' });
  });

  it('deliveredVia of whitespace is NOT a validated delivery; delivered-without-channel is a CONTRADICTION', () => {
    const log = row({ actionId: 'ws', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: '   ' } }) + '\n';
    const { summary } = run(log);
    expect(summary.delivery.anyValidatedDelivery).toBe(0);
    expect(summary.delivery.claimedWithoutChannel).toBe(1);
    expect(summary.evidence.contradictory).toBe(1);
    expect(summary.evidence.contradictoryReasons).toEqual({ 'delivery-claimed-without-channel': 1 });
    expect(summary.known.total).toBe(0); // a contradictory event is not a known event
    expect(validateNotify({ notify: { status: 'delivered', deliveredVia: '   ' } })).toEqual({ ok: true, status: 'delivered', channel: null });
  });

  it('a validated delivery needs a delivery-claim status WITH a channel (enum or other), across any record of the event', () => {
    const log = [
      row({ actionId: 'ok', signals: ['file-delete'], notify: { status: 'delivered', deliveredVia: 'webhook' } }),
      row({ actionId: 'ok', signals: ['file-delete'], notify: { status: 'coalesced', deliveredVia: null }, detectedAt: '2026-09-01T00:00:01.000Z' }),
      row({ actionId: 'nochan', signals: ['file-delete'], notify: { status: 'no_channel', deliveredVia: 'webhook' } }), // channel without a claim ≠ delivery
    ].join('\n') + '\n';
    const { summary } = run(log);
    expect(summary.delivery.anyValidatedDelivery).toBe(1);
    expect(summary.delivery.coalescedEver).toBe(1);
    expect(summary.evidence.contradictory).toBe(0);
  });

  it('unknown / non-conforming signal rows are excluded from every known denominator', () => {
    const log = [
      row({ actionId: 'k1', signals: ['file-delete'] }),
      row({ actionId: 'u1', signals: ['not-in-vocabulary'] }),
      row({ actionId: 'u2', signals: ['file-delete', 'not-in-vocabulary'] }), // partial: still excluded
      row({ actionId: 'u3', signals: ['redacted-signal'] }),
      row({ actionId: 'u4', signals: [] }),
    ].join('\n') + '\n';
    const { summary } = run(log);
    expect(summary.known.total).toBe(1);
    expect(summary.evidence.unknown).toBe(4);
    expect(summary.evidence.unknownReasons).toEqual({ 'signal-outside-vocabulary': 2, 'redacted-only': 1, 'empty-signals': 1 });
    for (const p of summary.policies) expect(p.hypotheticalMatch + p.hypotheticalNoMatch).toBe(1);
    expect(summary.perSignal.reduce((n: number, r: any) => n + r.events, 0)).toBe(1);
  });

  it('malformed / unknown / contradictory / known are four separate buckets with counts, and they partition the events (round 4)', () => {
    const log = [
      row({ actionId: 'k1', signals: ['file-delete'] }),                                                   // known
      row({ actionId: 'u1', signals: ['redacted-signal'] }),                                               // unknown
      row({ actionId: 'c1', signals: ['file-delete'], event: 'action_guard_warning', outcome: 'auto_denied' }), // contradictory (pair)
      row({ actionId: 'c2', signals: ['file-delete'], outcome: 'auto_denied' }),                           // contradictory (conflict, with next)
      row({ actionId: 'c2', signals: ['file-delete'], outcome: 'denied_no_prompt_surface', detectedAt: '2026-09-01T00:00:01.000Z' }),
      'not json',                                                                                          // malformed
      JSON.stringify({ event: 'action_guard_denial', outcome: 'auto_denied', actionId: 'm2' }),           // malformed (missing signals)
    ].join('\n') + '\n';
    const { summary, markdown } = run(log);
    expect(summary.evidence).toEqual({
      validKnown: 1,
      unknown: 1, unknownReasons: { 'redacted-only': 1 },
      contradictory: 2, contradictoryReasons: { 'event-outcome-mismatch': 1, 'conflicting-enforcement-outcomes': 1 },
      // the malformed JSON row (m2) is an EVENT in the malformed bucket; the not-json line is row-level only
      malformed: 1, malformedEventReasons: { 'missing-signals': 1 },
      malformedRows: 2, malformedReasons: { 'not-json': 1, 'missing-signals': 1 },
    });
    expect(summary.events.total).toBe(5);
    expect(summary.evidence.validKnown + summary.evidence.unknown + summary.evidence.contradictory + summary.evidence.malformed).toBe(summary.events.total);
    expect(markdown).toContain('### Evidence buckets');
    expect(markdown).toMatch(/\| contradictory events \| 2 \|/);
    expect(markdown).toMatch(/\| malformed events \| 1 \|/);
    expect(markdown).toMatch(/\| malformed rows[^|]*\| 2 \|/);
    const events = groupEvents(parseDenials(log).records);
    expect(bucketOf(events.find((e: any) => e.key === 'aid:c2')!)).toEqual({ bucket: 'contradictory', reason: 'conflicting-enforcement-outcomes' });
  });
});
