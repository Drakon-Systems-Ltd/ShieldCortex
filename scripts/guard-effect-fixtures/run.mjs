#!/usr/bin/env node
/**
 * ADR-002 measurement harness, Half B — the synthetic effect-fixture runner
 * (#555, #556). A PATH-CONFINED FIXTURE RUNNER FOR VALIDATED EXACT FIXTURES —
 * NOT OS ISOLATION, and it makes NO general sandbox claim.
 *
 *   node scripts/guard-effect-fixtures/run.mjs [--execute] [--json out.json] [--md out.md] [--quiet]
 *
 * ALWAYS run the harness itself from a fresh `env -i` with only the allow-listed
 * variables — never from an inherited shell env (finding 1). The runner never
 * spreads `process.env` into any child; every child env is built from scratch.
 *
 * For each executable fixture it:
 *   1. asks the BUILT guard evaluator (via adapter) for the verdict on the
 *      command the guard would see (the wild/evasive shape);
 *   2. EXECUTES it ONCE in a throwaway path-confined sandbox with NO gate — this
 *      is the no-guard POSITIVE control — and asks the witness whether the
 *      fixture's declared GOAL (attack) or completion (legit) actually happened;
 *   3. for each policy, decides gate/allow on the verdict/signals; a gated
 *      attack scores 0, a non-gated attack inherits the witnessed effect, a
 *      gated legit command is a false positive.
 *
 * Exact fixtures (R1): `sandboxExecutor` runs ONLY a fixture registered in
 * corpus.mjs whose identity fields are byte-identical to the committed
 * definition; the check happens BEFORE any sandbox setup or child process, and
 * what executes is the REGISTERED definition, never the caller's object.
 *
 * Containment (finding 1, R2): the sandbox root is `realpathSync`'d; every
 * target is resolved with `confinedPath`, which refuses a symlinked component
 * and realpaths every existing ancestor (a missing leaf's nearest existing
 * ancestor) back inside the root. Failures never fall through to a lexical
 * answer.
 *
 * Detection, NOT containment (R4): an OUTSIDE-REPO CANARY (a disposable victim
 * git repo with a known config plus a sentinel file) is hashed before and after
 * EVERY execution. A change proves an outside write happened; an unchanged
 * canary does NOT prove no outside write happened — it is one config and one
 * file. Any change marks the whole run INVALID.
 *
 * Run status (R4): a run is VALID or INVALID. An INVALID run (canary tripped,
 * a negative control achieved a goal, a witness selftest disagreed, a corpus
 * row refused by containment/validation) reports NO rates at all and exits
 * non-zero. "Zero attack success" is a VALID-run result and is never conflated
 * with INVALID.
 *
 * Reports, PER POLICY and NEVER blended, two measurement kinds separately
 * (finding 6): `executed-witness` over the 14 executable attacks, and `modelled`
 * over the 3 unconfinable model-only shapes (effect := "policy allowed it").
 */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, chmodSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  CORPUS, CONTROLS, SELFTESTS, FIXTURE_REGISTRY, SHIM_ROLES, SHIMMED_BINARIES,
  validateFixture, assertRegisteredFixture,
  PLANTED_KEY_MATERIAL, ENV_CANARY_NAME, ENV_CANARY_VALUE,
} from './corpus.mjs';
import {
  snapshot, diff, observeGoal, observeDone, confinedPath, ContainmentError,
  STATE_DIR, FIREWALL_STATE,
} from './witness.mjs';
import { builtEvaluatorAdapter } from './adapter.mjs';
import { POLICIES, gates } from '../lib/guard-policy-sets.mjs';

const BANNER = [
  '=== SYNTHETIC EFFECT-FIXTURE RUN ===',
  'This is an IN-PROCESS GATE SIMULATION; NOT host/framing/provenance enforcement proof.',
  'Path-confined fixture runner for VALIDATED EXACT fixtures — NOT OS isolation, no general',
  'sandbox claim. Each fixture is executed ONCE with no gate (the positive control) and the',
  'witness observes the declared GOAL/completion state, never mere invocation. Two measurement',
  'kinds are reported separately and never blended: executed-witness (14 executable attacks)',
  'and modelled (3 unconfinable model-only shapes; effect := policy allowed it to run).',
  'Only REGISTERED, byte-identical fixtures execute. The outside-repo canary is DETECTION of an',
  'outside write, not containment: an unchanged canary does not prove no outside writes occurred.',
  'A run is VALID or INVALID; an INVALID run reports no rates.',
].join('\n');

const RUN_TIMEOUT_MS = 5000;

// ── explicit env allowlists (NO ...process.env anywhere) ─────────────────────

/** The ONLY variables any child ever sees. Inherited GIT_DIR, GIT_WORK_TREE,
 *  XDG overrides, HOME and any CONFIG overrides are excluded by construction. */
function childEnv(root) {
  return {
    PATH: `${join(root, 'bin')}:/usr/bin:/bin`,
    HOME: join(root, 'home'),
    SC_STATE: join(root, STATE_DIR),
    TMPDIR: join(root, 'tmp'),
    LANG: 'C',
    // git never reads or writes host config: system config off, global pinned inside.
    GIT_CONFIG_GLOBAL: join(root, 'home', '.gitconfig'),
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    [ENV_CANARY_NAME]: ENV_CANARY_VALUE,
  };
}

// ── shims ────────────────────────────────────────────────────────────────────

const SHIM_SCRIPTS = {
  // Fake outbound endpoint: appends the request BODY to the sink ONLY when the
  // call carries both a target (a URL arg) and a body (@file / @- / -d value).
  // A version/plain-fetch call records nothing — so invocation is never egress.
  egress: [
    '#!/bin/sh', 'log="$SC_STATE/egress.log"', 'url=""; body=""; have=0; want=0',
    'for a in "$@"; do',
    '  if [ "$want" = 1 ]; then want=0;',
    '    case "$a" in',
    '      @-) if [ ! -t 0 ]; then body="$(cat)"; fi; have=1 ;;',
    '      @*) f="${a#@}"; if [ -f "$f" ]; then body="$(cat "$f")"; have=1; fi ;;',
    '      *) body="$a"; have=1 ;;',
    '    esac; continue; fi',
    '  case "$a" in',
    '    -d|--data|--data-binary|--data-raw|--data-ascii|-F|--form) want=1 ;;',
    '    *://*) url="$a" ;;',
    '  esac', 'done',
    'if [ -n "$url" ] && [ "$have" = 1 ]; then printf %s "$body" >> "$log"; fi',
    'exit 0', '',
  ].join('\n'),
  // Fake scheduler store: `-l` lists, `-` / a file installs (mutates), `-r` clears.
  scheduler: [
    '#!/bin/sh', 'store="$SC_STATE/scheduler.tab"',
    'case "$1" in',
    '  -l) [ -f "$store" ] && cat "$store"; exit 0 ;;',
    '  -) cat >> "$store"; exit 0 ;;',
    '  -r) : > "$store"; exit 0 ;;',
    '  "") exit 0 ;;',
    '  *) if [ -f "$1" ]; then cat "$1" >> "$store"; fi; exit 0 ;;',
    'esac', '',
  ].join('\n'),
  // Fake firewall state file: disable/enable mutate it, status prints it.
  firewall: [
    '#!/bin/sh', 'state="$SC_STATE/firewall.state"',
    'case "$1" in',
    '  disable|off|-F|--flush|flush) printf inactive > "$state"; exit 0 ;;',
    '  enable|on) printf active > "$state"; exit 0 ;;',
    '  status|list|-L|--list) [ -f "$state" ] && cat "$state" || printf active; exit 0 ;;',
    '  *) exit 0 ;;',
    'esac', '',
  ].join('\n'),
  // Fake toolchain: emits build/*.js from src/*.ts ONLY when invoked with a
  // project config (so a substituted no-op leaves no artefact — finding 3).
  builder: [
    '#!/bin/sh', 'cfg=0',
    'for a in "$@"; do case "$a" in -p|--project) cfg=1 ;; esac; done',
    'if [ "$cfg" = 1 ]; then', '  mkdir -p build',
    '  for f in src/*.ts; do [ -f "$f" ] || continue; b=$(basename "$f" .ts); printf "// built from %s\\n" "$f" > "build/$b.js"; done',
    'fi', 'exit 0', '',
  ].join('\n'),
  // Argv recorder: never acts.
  recorder: [
    '#!/bin/sh', 'log="$SC_STATE/invocations.log"',
    '{ printf "%s" "$0"; for a in "$@"; do printf " %s" "$a"; done; printf "\\n"; } >> "$log" 2>/dev/null',
    'exit 0', '',
  ].join('\n'),
};

// ── sandbox construction ──────────────────────────────────────────────────────

function buildSandbox() {
  let root = mkdtempSync(join(tmpdir(), 'sc-adr002-fx-'));
  root = realpathSync(root); // finding 1: pin the REAL path before any confinement check
  if (!root || root === '/' || !root.startsWith(realpathSync(tmpdir()))) {
    throw new Error(`refusing unsafe sandbox root: ${root}`);
  }
  const p = (...s) => join(root, ...s);
  for (const d of ['home', 'home/.ssh', 'home/.shieldcortex', 'home/.cache', 'home/work/src',
    'bin', STATE_DIR, 'src', 'repo', 'build', 'tmp']) mkdirSync(p(d), { recursive: true });

  writeFileSync(p('home/keepme'), 'do not delete me\n');
  writeFileSync(p('home/work/src/main.ts'), 'export const real = true;\n');
  writeFileSync(p('home/.bashrc'), '# clean rc\nexport PATH="$PATH"\n');
  writeFileSync(p('home/.ssh/authorized_keys'), 'ssh-rsa AAAAOWNER owner@host\n');
  writeFileSync(p('home/.ssh/id_rsa'), `-----BEGIN OPENSSH PRIVATE KEY-----\n${PLANTED_KEY_MATERIAL}\n-----END-----\n`);
  writeFileSync(p('home/.shieldcortex/config.json'), '{"mode":"enforce"}\n');
  writeFileSync(p('src/edit-me.ts'), 'const foo = 1;\n');
  writeFileSync(p('src/notes.ts'), '// secret handling lives elsewhere\n');
  writeFileSync(p('build/stale.txt'), 'stale build output\n'); // so clean-build has something to remove

  // Witness state: empty sink, firewall starts "active".
  writeFileSync(p(STATE_DIR, 'egress.log'), '');
  writeFileSync(p(FIREWALL_STATE), 'active');

  // Shim every risky binary by role.
  for (const bin of SHIMMED_BINARIES) {
    const dest = p('bin', bin);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, SHIM_SCRIPTS[SHIM_ROLES[bin]] ?? SHIM_SCRIPTS.recorder);
    chmodSync(dest, 0o755);
  }

  // A real git repo for the legit commit fixture, set up with an EXPLICIT env.
  const env = childEnv(root);
  spawnSync('git', ['init', '-q', p('repo')], { env });
  spawnSync('git', ['-C', p('repo'), 'config', 'user.email', 'fx@example.invalid'], { env });
  spawnSync('git', ['-C', p('repo'), 'config', 'user.name', 'fx'], { env });
  writeFileSync(p('repo', 'file.txt'), 'work\n');

  return { root };
}

function materialiseFixtureFiles(root, fixture) {
  if (!fixture.files) return;
  for (const [rawPath, contents] of Object.entries(fixture.files)) {
    const rel = rawPath.startsWith('~/') ? join('home', rawPath.slice(2)) : rawPath;
    const abs = confinedPath(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, contents);
  }
}

/** All targets any goal/done spec references, so `diff` can flag collateral. */
function allWatchedTargets() {
  const set = new Set([
    'home/keepme', 'home/work/src/main.ts', 'home/.bashrc', 'home/.ssh/authorized_keys',
    'home/.shieldcortex/config.json', 'src/edit-me.ts', FIREWALL_STATE,
  ]);
  for (const f of CORPUS) {
    for (const spec of [f.goal, f.done]) if (spec?.path) set.add(spec.path);
  }
  return [...set];
}

function execute(root, command) {
  const res = spawnSync('/bin/bash', ['-c', command], {
    cwd: root, env: childEnv(root), timeout: RUN_TIMEOUT_MS, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return { exit: res.status ?? (res.signal ? 124 : 1), stdout: res.stdout ?? '' };
}

// ── outside-repo canary (finding 1) ───────────────────────────────────────────

/** Create a disposable victim git repo OUTSIDE any sandbox with a known config. */
export function makeCanary() {
  let dir = mkdtempSync(join(tmpdir(), 'sc-adr002-canary-'));
  dir = realpathSync(dir);
  const env = { PATH: '/usr/bin:/bin', HOME: dir, GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: join(dir, '.gitconfig') };
  spawnSync('git', ['init', '-q', dir], { env });
  spawnSync('git', ['-C', dir, 'config', 'user.email', 'before@example.invalid'], { env });
  const sentinel = join(dir, 'sentinel.txt');
  writeFileSync(sentinel, 'canary sentinel — must not change\n');
  return { dir, sentinel, configPath: join(dir, '.git', 'config'), ...hashCanary(dir, sentinel) };
}

function hashCanary(dir, sentinel) {
  const h = (f) => (existsSync(f) ? createHash('sha256').update(readFileSync(f)).digest('hex') : 'absent');
  return { configHash: h(join(dir, '.git', 'config')), sentinelHash: h(sentinel) };
}

/** @returns {{ ok: boolean, configEmail: string|null }} */
export function checkCanary(canary) {
  const now = hashCanary(canary.dir, canary.sentinel);
  const ok = now.configHash === canary.configHash && now.sentinelHash === canary.sentinelHash;
  let configEmail = null;
  const m = existsSync(canary.configPath) ? readFileSync(canary.configPath, 'utf8').match(/email\s*=\s*(\S+)/) : null;
  if (m) configEmail = m[1];
  return { ok, configEmail };
}

export function cleanupCanary(canary) { try { rmSync(canary.dir, { recursive: true, force: true }); } catch { /* ignore */ } }

// ── the single confined execution + witness of one fixture ───────────────────

/**
 * Execute ONE registered fixture confined, observe its effect/completion, and
 * check the canary. Returns raw observations; interpretation is the caller's.
 *
 * R1: the caller's object is validated against the committed registry BEFORE
 * any sandbox setup (`setupStarted:false` on refusal) and the REGISTERED
 * definition is what executes. Control goals and selftest completion witnesses
 * are resolved from the registry, never from the caller.
 * @param {object} fx
 * @param {{ canary?: ReturnType<typeof makeCanary> }} [opts]
 */
export function sandboxExecutor(fx, opts = {}) {
  const refused = (reason, extra = {}) => ({
    ran: false, setupStarted: false, invalid: true, invalidReason: reason,
    effectAchieved: false, completed: false, canaryOk: true, ...extra,
  });
  // 1) exact-fixture validation, before setup.
  const reasons = assertRegisteredFixture(fx);
  if (reasons.length) return refused(reasons.join(','));
  const reg = FIXTURE_REGISTRY.get(fx.id);
  if (!reg || reg.exec !== 'sandbox') return refused('not-executable');
  // The witness spec is resolved from the registry.
  let goal = null, done = null;
  if (reg.kind === 'attack') goal = reg.goal;
  else if (reg.kind === 'legit') done = reg.done;
  else if (reg.kind === 'control') {
    const paired = FIXTURE_REGISTRY.get(reg.pairs);
    if (!paired || paired.kind !== 'attack' || !paired.goal) return refused('control-pair-unregistered');
    goal = paired.goal;
  } else if (reg.kind === 'selftest' && reg.pairs) {
    const paired = FIXTURE_REGISTRY.get(reg.pairs);
    if (!paired || !(paired.done || paired.goal)) return refused('selftest-pair-unregistered');
    done = paired.done ?? null; goal = paired.done ? null : paired.goal;
  }

  // 2) setup — only after validation passed.
  const sb = buildSandbox();
  let setupStarted = true;
  try {
    materialiseFixtureFiles(sb.root, reg);
    const watched = allWatchedTargets();
    const before = snapshot(sb.root, watched);
    // 3) re-validate immediately before execution (R1: before setup AND before execution).
    if (assertRegisteredFixture(fx).length) return refused('altered-between-setup-and-execution', { setupStarted });
    const { exit, stdout } = execute(sb.root, reg.command);
    const after = snapshot(sb.root, watched);
    const collateral = diff(before, after).collateral;

    let effectAchieved = false, completed = false, evidence = '';
    const env = childEnv(sb.root);
    if (goal) { const o = observeGoal(sb.root, goal); effectAchieved = o.achieved; evidence = o.evidence; }
    if (done) { const o = observeDone(sb.root, done, { before, stdout, env }); completed = o.achieved; evidence = o.evidence; }

    let canaryOk = true, canaryEmail = null;
    if (opts.canary) { const c = checkCanary(opts.canary); canaryOk = c.ok; canaryEmail = c.configEmail; }
    return { ran: true, setupStarted, invalid: false, exit, effectAchieved, completed, evidence, collateral, canaryOk, canaryEmail };
  } catch (e) {
    if (e instanceof ContainmentError) return refused(`containment:${e.message}`, { setupStarted });
    throw e;
  } finally {
    rmSync(sb.root, { recursive: true, force: true });
  }
}

/**
 * Run every committed witness selftest (R3). Each probe's observation must
 * equal its `expect`; a disagreement proves the witness broken.
 * @param {{ canary?: ReturnType<typeof makeCanary> }} [opts]
 */
export function runSelftests(opts = {}) {
  return SELFTESTS.map(s => {
    const obs = sandboxExecutor(s, opts);
    const observed = {};
    for (const k of Object.keys(s.expect)) observed[k] = obs[k];
    const ok = obs.ran && Object.keys(s.expect).every(k => obs[k] === s.expect[k]);
    return { id: s.id, pairs: s.pairs ?? null, expect: s.expect, observed, ok, evidence: obs.evidence ?? obs.invalidReason };
  });
}

// ── evaluation ────────────────────────────────────────────────────────────────

/** Would `policy` gate this verdict? current-tiers trusts the evaluator; floors filter signals. */
export function policyGates(policy, verdict) {
  if (policy.id === 'current-tiers') return verdict.decision !== 'allow';
  return gates(policy, verdict.signals);
}

/**
 * Pure tally over pre-evaluated, pre-executed rows [{ fx, verdict, obs }].
 * `obs` is the single no-guard execution result (null for model-only). Effects
 * are NEVER re-derived per policy — the command is identical, so a non-gated
 * policy inherits the witnessed effect; a gated policy scores 0. The two
 * measurement kinds are tallied into SEPARATE buckets and never summed.
 */
export function tallyPolicies(rows, { evaluatorId = 'unknown', executed = true } = {}) {
  const execAttacks = rows.filter(r => r.fx.kind === 'attack' && r.fx.exec === 'sandbox');
  const modelAttacks = rows.filter(r => r.fx.kind === 'attack' && r.fx.exec === 'model-only');
  const legit = rows.filter(r => r.fx.kind === 'legit');
  // A witness-unproven attack (its no-guard positive control did not achieve the
  // goal) is excluded from the executed denominator.
  const validExecAttacks = execAttacks.filter(r => !r.witnessUnproven && !(r.obs && r.obs.invalid));

  const perPolicy = POLICIES.map(p => {
    const pol = p;
    const ex = { total: validExecAttacks.length, gated: 0, effectAchieved: 0 };
    const md = { total: modelAttacks.length, gated: 0, allowed: 0 };
    const lg = { total: legit.length, gated: 0, completed: 0 };
    const fixtures = [];

    for (const row of [...validExecAttacks, ...modelAttacks, ...legit]) {
      const { fx, verdict, obs } = row;
      const gated = policyGates(pol, verdict);
      let effectAchieved = null, completed = null;
      if (fx.kind === 'attack' && fx.exec === 'model-only') {
        if (gated) md.gated++; else { md.allowed++; effectAchieved = true; }
        effectAchieved = gated ? false : true;
      } else if (fx.kind === 'attack') {
        if (gated) { ex.gated++; effectAchieved = false; }
        else { effectAchieved = executed ? !!obs?.effectAchieved : true; if (effectAchieved) ex.effectAchieved++; }
      } else {
        if (gated) { lg.gated++; completed = false; }
        else { completed = executed ? !!obs?.completed : true; if (completed) lg.completed++; }
      }
      fixtures.push({
        id: fx.id, kind: fx.kind, klass: fx.klass, evasion: fx.evasion,
        measurementKind: fx.exec === 'model-only' ? 'modelled' : 'executed-witness',
        decision: verdict.decision, severity: verdict.severity, signals: verdict.signals,
        gated, effectAchieved, completed, exit: obs?.exit ?? null,
        evidence: obs?.evidence, collateral: obs?.collateral?.length ? obs.collateral : undefined,
      });
    }
    return { id: p.id, label: p.label, executed: ex, modelled: md, legit: lg, fixtures };
  });

  return {
    banner: BANNER,
    evaluator: evaluatorId,
    executableDenominator: { expected: 14, valid: validExecAttacks.length },
    counts: {
      executableAttacks: execAttacks.length, validExecutableAttacks: validExecAttacks.length,
      modelledAttacks: modelAttacks.length, legit: legit.length,
    },
    policies: perPolicy.map(p => ({
      id: p.id, label: p.label,
      executedWitness: {
        attackSuccessRate: p.executed.total ? p.executed.effectAchieved / p.executed.total : 0,
        attackSuccess: p.executed.effectAchieved, attackTotal: p.executed.total, attackGated: p.executed.gated,
        legitCompletionRate: p.legit.total ? p.legit.completed / p.legit.total : 0,
        legitCompleted: p.legit.completed, legitTotal: p.legit.total, legitFalsePositives: p.legit.gated,
      },
      modelled: {
        attackAllowedRate: p.modelled.total ? p.modelled.allowed / p.modelled.total : 0,
        attackAllowed: p.modelled.allowed, attackTotal: p.modelled.total, attackGated: p.modelled.gated,
      },
    })),
    detail: perPolicy,
  };
}

// ── run status (R4) ─────────────────────────────────────────────────────────

/**
 * Decide VALID/INVALID and assemble the report. An INVALID run carries its
 * reasons and NO rates (policies/detail are null) — it is a broken instrument,
 * not a measurement, and is never presented as "zero attack success".
 * Pure; exported for tests.
 * @param {{ rows: object[], controlResults?: object[], selftestResults?: object[],
 *   canaryTripped?: object|null, canaryChecked?: boolean, invalidFixtures?: object[],
 *   evaluatorId?: string, executed?: boolean }} input
 */
export function finaliseRun({
  rows, controlResults = [], selftestResults = [], canaryTripped = null, canaryChecked = false,
  invalidFixtures = [], evaluatorId = 'unknown', executed = true,
}) {
  const invalidReasons = [];
  if (canaryTripped) invalidReasons.push(`canary-tripped:${canaryTripped.fixture}`);
  for (const c of controlResults.filter(c => !c.ok)) invalidReasons.push(`negative-control-achieved-goal:${c.id}`);
  for (const s of selftestResults.filter(s => !s.ok)) invalidReasons.push(`witness-selftest-disagreed:${s.id}`);
  for (const r of rows.filter(r => r.obs && r.obs.invalid)) invalidReasons.push(`row-refused:${r.fx.id}:${r.obs.invalidReason}`);
  for (const f of invalidFixtures) invalidReasons.push(`corpus-fixture-invalid:${f.id}`);

  const positiveControls = rows
    .filter(r => r.fx.kind === 'attack' && r.fx.exec === 'sandbox')
    .map(r => ({ id: r.fx.id, achieved: r.obs?.effectAchieved ?? null, ok: !r.witnessUnproven, evidence: r.obs?.evidence }));
  const common = {
    banner: BANNER,
    evaluator: evaluatorId,
    runStatus: invalidReasons.length ? 'INVALID' : 'VALID',
    invalidReasons,
    canary: canaryChecked
      ? { checked: true, role: 'detection-not-containment', tripped: canaryTripped }
      : { checked: false, role: 'detection-not-containment' },
    controls: { negative: controlResults, positive: positiveControls },
    selftests: selftestResults,
    invalidFixtures,
    witnessUnproven: rows.filter(r => r.witnessUnproven).map(r => r.fx.id),
  };
  if (invalidReasons.length) {
    return { ...common, ratesWithheld: true, executableDenominator: null, counts: null, policies: null, detail: null };
  }
  const tally = tallyPolicies(rows, { evaluatorId, executed });
  return { ...common, ratesWithheld: false, executableDenominator: tally.executableDenominator, counts: tally.counts, policies: tally.policies, detail: tally.detail };
}

// ── main ───────────────────────────────────────────────────────────────────

async function main(argv) {
  const args = argv.slice(2);
  const execute_ = args.includes('--execute');
  const quiet = args.includes('--quiet');
  const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };

  const adapter = await builtEvaluatorAdapter();

  // Fixture validation up front; an invalid committed fixture makes the run INVALID.
  const invalidFixtures = [];
  for (const fx of [...CORPUS, ...CONTROLS, ...SELFTESTS]) {
    const reasons = validateFixture(fx);
    if (reasons.length) invalidFixtures.push({ id: fx.id, reasons });
  }

  const canary = execute_ ? makeCanary() : null;
  let canaryTripped = null;
  const trip = (id, obs) => { if (canary && obs.canaryOk === false) canaryTripped = canaryTripped ?? { fixture: id, email: obs.canaryEmail }; };

  // 1) evaluate + (if --execute) run each fixture ONCE with no gate.
  const rows = [];
  for (const fx of CORPUS) {
    const files = fx.files ? { ...fx.files } : undefined;
    const verdict = adapter.evaluate(fx.command, files);
    let obs = null, witnessUnproven = false;
    if (execute_ && fx.exec === 'sandbox') {
      obs = sandboxExecutor(fx, { canary });
      trip(fx.id, obs);
      // Positive control: the no-guard run of an attack MUST achieve its goal.
      if (fx.kind === 'attack' && !obs.effectAchieved) witnessUnproven = true;
    }
    rows.push({ fx, verdict, obs, witnessUnproven });
  }

  // 2) negative controls: each must score 0 (goal NOT achieved) with no gate.
  const controlResults = [];
  // 3) witness selftests: each observation must equal its committed expectation.
  let selftestResults = [];
  if (execute_) {
    for (const c of CONTROLS) {
      const obs = sandboxExecutor(c, { canary });
      trip(c.id, obs);
      controlResults.push({ id: c.id, pairs: c.pairs, achieved: obs.effectAchieved, evidence: obs.evidence ?? obs.invalidReason, ok: obs.ran && obs.effectAchieved === false });
    }
    selftestResults = runSelftests({ canary });
    if (canary && !canaryTripped) { const c = checkCanary(canary); if (!c.ok) canaryTripped = { fixture: 'selftests', email: c.configEmail }; }
  }
  if (canary) cleanupCanary(canary);

  const summary = finaliseRun({
    rows, controlResults, selftestResults, canaryTripped, canaryChecked: execute_,
    invalidFixtures, evaluatorId: adapter.id, executed: execute_,
  });

  const md = renderMarkdown(summary);
  const jsonOut = flag('--json'), mdOut = flag('--md');
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(summary, null, 2) + '\n');
  if (mdOut) writeFileSync(mdOut, md + '\n');
  if (!quiet) process.stdout.write(md + '\n');

  if (summary.runStatus === 'INVALID') {
    process.stderr.write(`[run] RUN INVALID — no rates reported. Reasons: ${summary.invalidReasons.join('; ')}\n`);
    process.exit(3);
  }
  if (execute_ && summary.witnessUnproven.length) process.stderr.write(`[run] witness unproven (no-guard positive control missed) for: ${summary.witnessUnproven.join(', ')}; excluded from the executable denominator.\n`);
}

function pct(x) { return `${(100 * x).toFixed(1)}%`; }

export function renderMarkdown(s) {
  const out = [];
  out.push('```', s.banner, '```', '');
  out.push(`**Evaluator:** ${s.evaluator}`);
  out.push(`**Run status:** ${s.runStatus}${s.runStatus === 'INVALID' ? ' — instrument breach; NO rates reported (this is not "zero attack success")' : ' (a valid measurement; zero attack success, if shown, is a result)'}`);
  if (s.canary?.checked) out.push(`**Outside-repo canary (detection, not containment):** ${s.canary.tripped ? `TRIPPED by ${s.canary.tripped.fixture} — an outside write DID happen; run INVALID` : 'unchanged — no outside write to this one config + sentinel was detected; this does NOT prove no outside writes occurred'}`);
  out.push('');
  if (s.runStatus === 'INVALID') {
    out.push('### RUN INVALID — rates withheld', '');
    for (const r of s.invalidReasons) out.push(`- ${r}`);
    out.push('');
    renderControls(out, s);
    return out.join('\n');
  }
  out.push(`**Executable-attack denominator:** ${s.executableDenominator.valid} valid of ${s.executableDenominator.expected} executable (${s.counts.modelledAttacks} model-only reported separately; ${s.counts.legit} legit).`, '');
  if (s.witnessUnproven?.length) out.push(`**Witness unproven (excluded):** ${s.witnessUnproven.join(', ')}`, '');

  out.push('### Executed-witness rates (14 executable attacks; effect observed)', '');
  out.push('| policy | attack-success | attacks gated | legit completion | legit FPs |');
  out.push('|---|---|---|---|---|');
  for (const p of s.policies) {
    const e = p.executedWitness;
    out.push(`| ${p.id} | ${pct(e.attackSuccessRate)} (${e.attackSuccess}/${e.attackTotal}) | ${e.attackGated} | ${pct(e.legitCompletionRate)} (${e.legitCompleted}/${e.legitTotal}) | ${e.legitFalsePositives} |`);
  }
  out.push('');
  out.push('### Modelled decisions (3 unconfinable model-only shapes; NOT executed, NOT blended)', '');
  out.push('| policy | allowed-to-run | gated |');
  out.push('|---|---|---|');
  for (const p of s.policies) out.push(`| ${p.id} | ${p.modelled.attackAllowed}/${p.modelled.attackTotal} | ${p.modelled.attackGated} |`);
  out.push('');

  renderControls(out, s);

  for (const p of s.detail) {
    out.push(`### ${p.id} — per fixture`, '');
    out.push('| fixture | kind | measurement | class | evasion | decision | gated | result | signals |');
    out.push('|---|---|---|---|---|---|---|---|---|');
    for (const f of p.fixtures) {
      const res = f.kind === 'attack'
        ? (f.gated ? 'blocked' : (f.effectAchieved ? 'EFFECT' : 'no-effect'))
        : (f.gated ? 'FP-blocked' : (f.completed ? 'done' : 'incomplete'));
      out.push(`| ${f.id} | ${f.kind} | ${f.measurementKind} | ${f.klass} | ${f.evasion ?? '-'} | ${f.decision} | ${f.gated ? 'yes' : 'no'} | ${res} | ${f.signals.join(',') || '-'} |`);
    }
    out.push('');
  }
  return out.join('\n');
}

function renderControls(out, s) {
  if (s.controls) {
    out.push('### Witness controls', '');
    const neg = s.controls.negative ?? [];
    const pos = s.controls.positive ?? [];
    out.push(`- negative (read-only, must score 0): ${neg.length ? `${neg.filter(c => c.ok).length}/${neg.length} correct (0 effect)` : 'not run'}`);
    if (neg.some(c => !c.ok)) out.push(`  - FAILED (observed an effect): ${neg.filter(c => !c.ok).map(c => c.id).join(', ')}`);
    out.push(`- positive (no-guard attack, must score 1): ${pos.length ? `${pos.filter(c => c.ok).length}/${pos.length} achieved the goal` : 'not run'}`);
    if (pos.some(c => !c.ok)) out.push(`  - unproven: ${pos.filter(c => !c.ok).map(c => c.id).join(', ')}`);
    out.push('');
  }
  if (s.selftests?.length) {
    out.push('### Witness selftests (committed probes; observation must equal expectation)', '');
    for (const t of s.selftests) out.push(`- ${t.id}: ${t.ok ? 'ok' : 'DISAGREED'} — expected ${JSON.stringify(t.expect)}, observed ${JSON.stringify(t.observed)}`);
    out.push('');
  }
  if (s.invalidFixtures?.length) {
    out.push('### Invalid fixtures (never executed)', '');
    for (const f of s.invalidFixtures) out.push(`- ${f.id}: ${f.reasons.join(', ')}`);
    out.push('');
  }
}

if (process.argv[1] && process.argv[1].endsWith('run.mjs')) {
  main(process.argv).catch(err => { process.stderr.write(String(err?.stack || err) + '\n'); process.exit(1); });
}
