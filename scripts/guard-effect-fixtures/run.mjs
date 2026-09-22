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
 * Containment (finding 1): the sandbox root is `realpathSync`'d; every target is
 * resolved with `confinedPath`, which refuses a symlinked component. An OUTSIDE-
 * REPO CANARY (a disposable victim git repo with a known config) is hashed
 * before and after EVERY execution; any change marks the whole run INVALID and
 * exits non-zero.
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
  CORPUS, ATTACKS, LEGIT, CONTROLS, SHIM_ROLES, SHIMMED_BINARIES, validateFixture,
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
 * Execute ONE fixture confined, observe its effect/completion, and verify the
 * canary is untouched. Returns raw observations; interpretation is the caller's.
 * @param {object} fx
 * @param {{ canary?: ReturnType<typeof makeCanary>, goalOverride?: object }} [opts]
 */
export function sandboxExecutor(fx, opts = {}) {
  const invalid = validateFixture(fx);
  if (invalid.length) return { ran: false, invalid: true, invalidReason: invalid.join(','), effectAchieved: false, completed: false };
  const sb = buildSandbox();
  try {
    materialiseFixtureFiles(sb.root, fx);
    const watched = allWatchedTargets();
    const before = snapshot(sb.root, watched);
    const { exit, stdout } = execute(sb.root, fx.command);
    const after = snapshot(sb.root, watched);
    const collateral = diff(before, after).collateral;

    let effectAchieved = false, completed = false, evidence = '';
    const env = childEnv(sb.root);
    if (fx.kind === 'attack') {
      const o = observeGoal(sb.root, fx.goal); effectAchieved = o.achieved; evidence = o.evidence;
    } else if (fx.kind === 'legit') {
      const o = observeDone(sb.root, fx.done, { before, stdout, env }); completed = o.achieved; evidence = o.evidence;
    } else if (fx.kind === 'control') {
      // A negative control shares its paired attack's goal; it must NOT achieve it.
      const goal = opts.goalOverride ?? fx.goal;
      const o = observeGoal(sb.root, goal); effectAchieved = o.achieved; evidence = o.evidence;
    }

    let canaryOk = true, canaryEmail = null;
    if (opts.canary) { const c = checkCanary(opts.canary); canaryOk = c.ok; canaryEmail = c.configEmail; }
    return { ran: true, invalid: false, exit, effectAchieved, completed, evidence, collateral, canaryOk, canaryEmail };
  } catch (e) {
    if (e instanceof ContainmentError) return { ran: false, invalid: true, invalidReason: `containment:${e.message}`, effectAchieved: false, completed: false, canaryOk: true };
    throw e;
  } finally {
    rmSync(sb.root, { recursive: true, force: true });
  }
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

// ── main ───────────────────────────────────────────────────────────────────

async function main(argv) {
  const args = argv.slice(2);
  const execute_ = args.includes('--execute');
  const quiet = args.includes('--quiet');
  const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };

  const adapter = await builtEvaluatorAdapter();

  // Fixture validation up front; INVALID fixtures never run.
  const invalidFixtures = [];
  for (const fx of [...CORPUS, ...CONTROLS]) {
    const reasons = validateFixture(fx);
    if (reasons.length) invalidFixtures.push({ id: fx.id, reasons });
  }

  const canary = execute_ ? makeCanary() : null;
  let canaryTripped = null;

  // 1) evaluate + (if --execute) run each fixture ONCE with no gate.
  const rows = [];
  for (const fx of CORPUS) {
    const files = fx.files ? { ...fx.files } : undefined;
    const verdict = adapter.evaluate(fx.command, files);
    let obs = null, witnessUnproven = false;
    if (execute_ && fx.exec === 'sandbox') {
      obs = sandboxExecutor(fx, { canary });
      if (canary && obs.canaryOk === false) canaryTripped = { fixture: fx.id, email: obs.canaryEmail };
      // Positive control: the no-guard run of an attack MUST achieve its goal.
      if (fx.kind === 'attack' && !obs.effectAchieved) witnessUnproven = true;
    }
    rows.push({ fx, verdict, obs, witnessUnproven });
  }

  // 2) negative controls: each must score 0 (goal NOT achieved) with no gate.
  const controlResults = [];
  if (execute_) {
    const byId = Object.fromEntries(ATTACKS.map(a => [a.id, a]));
    for (const c of CONTROLS) {
      const paired = byId[c.pairs];
      const obs = sandboxExecutor(c, { canary, goalOverride: paired?.goal });
      if (canary && obs.canaryOk === false) canaryTripped = canaryTripped ?? { fixture: c.id, email: obs.canaryEmail };
      controlResults.push({ id: c.id, pairs: c.pairs, achieved: obs.effectAchieved, evidence: obs.evidence, ok: obs.effectAchieved === false });
    }
  }
  if (canary) cleanupCanary(canary);

  const summary = tallyPolicies(rows, { evaluatorId: adapter.id, executed: execute_ });
  const positiveControls = rows
    .filter(r => r.fx.kind === 'attack' && r.fx.exec === 'sandbox')
    .map(r => ({ id: r.fx.id, achieved: r.obs?.effectAchieved ?? null, ok: !r.witnessUnproven, evidence: r.obs?.evidence }));

  summary.controls = { negative: controlResults, positive: positiveControls };
  summary.invalidFixtures = invalidFixtures;
  summary.canary = execute_ ? { checked: true, tripped: canaryTripped } : { checked: false };
  summary.witnessUnproven = rows.filter(r => r.witnessUnproven).map(r => r.fx.id);

  const md = renderMarkdown(summary);
  const jsonOut = flag('--json'), mdOut = flag('--md');
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(summary, null, 2) + '\n');
  if (mdOut) writeFileSync(mdOut, md + '\n');
  if (!quiet) process.stdout.write(md + '\n');

  // Fail the run on any containment or witness-integrity breach (finding 1/2).
  const controlFail = controlResults.filter(c => !c.ok);
  if (canaryTripped) { process.stderr.write(`[run] CANARY TRIPPED by ${canaryTripped.fixture} (victim email now ${canaryTripped.email}); run INVALID.\n`); process.exit(3); }
  if (controlFail.length) { process.stderr.write(`[run] negative control(s) achieved a goal: ${controlFail.map(c => c.id).join(', ')}; run INVALID.\n`); process.exit(4); }
  if (execute_ && summary.witnessUnproven.length) process.stderr.write(`[run] witness unproven (no-guard positive control missed) for: ${summary.witnessUnproven.join(', ')}; excluded from the executable denominator.\n`);
}

function pct(x) { return `${(100 * x).toFixed(1)}%`; }

export function renderMarkdown(s) {
  const out = [];
  out.push('```', s.banner, '```', '');
  out.push(`**Evaluator:** ${s.evaluator}`);
  out.push(`**Executable-attack denominator:** ${s.executableDenominator.valid} valid of ${s.executableDenominator.expected} executable (${s.counts.modelledAttacks} model-only reported separately; ${s.counts.legit} legit).`, '');
  if (s.canary?.checked) out.push(`**Outside-repo canary:** ${s.canary.tripped ? `TRIPPED by ${s.canary.tripped.fixture} — run INVALID` : 'intact (no host git repo mutated)'}`, '');
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
  if (s.invalidFixtures?.length) {
    out.push('### Invalid fixtures (never executed)', '');
    for (const f of s.invalidFixtures) out.push(`- ${f.id}: ${f.reasons.join(', ')}`);
    out.push('');
  }

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

if (process.argv[1] && process.argv[1].endsWith('run.mjs')) {
  main(process.argv).catch(err => { process.stderr.write(String(err?.stack || err) + '\n'); process.exit(1); });
}
