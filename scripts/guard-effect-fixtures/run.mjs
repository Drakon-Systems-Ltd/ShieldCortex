#!/usr/bin/env node
/**
 * ADR-002 measurement harness, Half B — the synthetic effect-fixture runner
 * (#555, #556).
 *
 *   node scripts/guard-effect-fixtures/run.mjs [--execute] [--json out.json] [--md out.md] [--quiet]
 *
 * Answers ADR-002's validation question the right way round: not "did the guard
 * DETECT the shape" but "was the EFFECT achieved" — separately for attacks and
 * for legitimate work, under each policy.
 *
 * For each fixture it:
 *   1. asks the BUILT guard evaluator (via adapter) for the verdict on the
 *      command the guard would see (the wild/evasive shape);
 *   2. for each policy, decides gate/allow (current-tiers uses the evaluator's
 *      own decision; the two floors filter the emitted signals through their
 *      signal set — the ADR's "audit-only demotion");
 *   3. if a policy does NOT gate, EXECUTES the confined equivalent in a
 *      throwaway sandbox (unless --execute is omitted, or the fixture is
 *      model-only) and asks the witness whether an effect actually happened.
 *
 * Reports, PER POLICY and never summed:
 *   - attack-success rate      = attacks whose effect was achieved / all attacks
 *   - legitimate-work rate     = legit fixtures whose work completed / all legit
 *
 * SAFETY. Every executed command runs under `env -i` with HOME and cwd set to a
 * fresh mktemp sandbox and a shim bin first on PATH, so `~` resolves inside the
 * sandbox and network/scheduler/disk binaries hit a recorder. Fixtures marked
 * `model-only` (absolute-root wipe, block-device format/overwrite) are NEVER
 * executed — they cannot be confined — and their "effect achieved" is defined
 * as "the policy allowed the command to run". Without `--execute`, nothing is
 * run at all: effect is modelled the same way for every non-gated fixture, and
 * the report says so. This runner never touches the live host.
 */
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { CORPUS, ATTACKS, LEGIT, SHIMMED_BINARIES } from './corpus.mjs';
import { snapshot, diff, assertConfined } from './witness.mjs';
import { builtEvaluatorAdapter } from './adapter.mjs';
import { POLICIES, gates } from '../lib/guard-policy-sets.mjs';

const BANNER = [
  '=== SYNTHETIC EFFECT-FIXTURE RUN ===',
  'Fixtures are SYNTHETIC and confined to a throwaway sandbox (env -i, HOME+cwd remapped,',
  'shimmed network/scheduler/disk binaries). The guard evaluator is the BUILT dist artefact,',
  'called in-process. Two rates are reported per policy and never summed: attack-success',
  '(effect achieved despite the gate) and legitimate-work completion. model-only fixtures',
  '(absolute-root/block-device shapes) are never executed; their effect := "policy allowed it".',
].join('\n');

// ── sandbox construction ────────────────────────────────────────────────────

/** All protected/legit targets any fixture references, so the witness watches them all. */
function allWatchedTargets() {
  const set = new Set([
    'home/keepme', 'home/work/src/main.ts', 'home/.bashrc', 'home/.ssh/authorized_keys',
    'home/.shieldcortex/config.json',
  ]);
  for (const f of CORPUS) for (const w of f.watched ?? []) set.add(w);
  return [...set];
}

function buildSandbox() {
  const root = mkdtempSync(join(tmpdir(), 'sc-adr002-fx-'));
  if (!root || root === '/' || !root.startsWith(tmpdir())) throw new Error(`refusing unsafe sandbox root: ${root}`);
  const p = (...s) => join(root, ...s);
  for (const d of ['home', 'home/.ssh', 'home/.shieldcortex', 'home/.cache', 'home/work/src',
    'bin', 'witness', 'src', 'repo', 'build', 'tmp']) mkdirSync(p(d), { recursive: true });

  // Fake protected targets, each with recognisable content.
  writeFileSync(p('home/keepme'), 'do not delete me\n');
  writeFileSync(p('home/work/src/main.ts'), 'export const real = true;\n');
  writeFileSync(p('home/.bashrc'), '# clean rc\nexport PATH="$PATH"\n');
  writeFileSync(p('home/.ssh/authorized_keys'), 'ssh-rsa AAAAOWNER owner@host\n');
  writeFileSync(p('home/.ssh/id_rsa'), '-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYMATERIAL\n-----END-----\n');
  writeFileSync(p('home/.shieldcortex/config.json'), '{"mode":"enforce"}\n');
  // Legit dev-work source files. `notes.ts` mentions the search word so the
  // grep fixture matches and exits 0 — a real search of a real tree, not an
  // empty one that would exit non-zero and read as "incomplete".
  writeFileSync(p('src/edit-me.ts'), 'const foo = 1;\n');
  writeFileSync(p('src/notes.ts'), '// secret handling lives elsewhere\n');

  const sink = p('witness', 'sink.log');
  writeFileSync(sink, '');

  // Shim every risky binary: record argv + stdin to the sink, exit 0, never act.
  const shim = [
    '#!/bin/sh',
    'sink="${SC_SINK:-/dev/null}"',
    '{ printf "SHIM %s ARGV:" "$0"; for a in "$@"; do printf " %s" "$a"; done; printf "\\n"; ',
    '  if [ ! -t 0 ]; then cat; fi; } >> "$sink" 2>/dev/null',
    'exit 0',
    '',
  ].join('\n');
  for (const bin of SHIMMED_BINARIES) {
    const dest = p('bin', bin);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, shim);
    chmodSync(dest, 0o755);
  }
  // A real git repo for the legit commit fixture.
  const gitEnv = { ...process.env, HOME: p('home'), GIT_CONFIG_GLOBAL: p('home/.gitconfig'), GIT_CONFIG_SYSTEM: '/dev/null' };
  spawnSync('git', ['init', '-q', p('repo')], { env: gitEnv });
  spawnSync('git', ['-C', p('repo'), 'config', 'user.email', 'fx@example.invalid'], { env: gitEnv });
  spawnSync('git', ['-C', p('repo'), 'config', 'user.name', 'fx'], { env: gitEnv });
  writeFileSync(p('repo', 'file.txt'), 'work\n');

  return { root, sink };
}

/** Materialise a fixture's `files` map (with `~` remapped to the sandbox home) so cat/fold can read them. */
function materialiseFixtureFiles(root, fixture) {
  const out = {};
  if (!fixture.files) return out;
  for (const [rawPath, contents] of Object.entries(fixture.files)) {
    const abs = rawPath.startsWith('~/') ? join(root, 'home', rawPath.slice(2)) : join(root, rawPath);
    assertConfined(root, abs);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, contents);
    // The evaluator's resolveScriptSource is asked for the path AS WRITTEN in
    // the command (`~/payload.sh`, `runner.mjs`), so key the map by that.
    out[rawPath] = contents;
  }
  return out;
}

const RUN_TIMEOUT_MS = 5000;

/** Execute one fixture's command confined to the sandbox. Returns { exit, ran }. */
function executeConfined(root, sink, fixture) {
  const home = join(root, 'home');
  const env = {
    PATH: `${join(root, 'bin')}:/usr/bin:/bin`,
    HOME: home,
    SC_SINK: sink,
    TMPDIR: join(root, 'tmp'),
    LANG: 'C',
  };
  const res = spawnSync('/bin/bash', ['-c', fixture.command], {
    cwd: root, env, timeout: RUN_TIMEOUT_MS, encoding: 'utf8', stdio: ['ignore', 'ignore', 'ignore'],
  });
  return { exit: res.status ?? (res.signal ? 124 : 1), ran: true };
}

/**
 * Execute ONE exec:sandbox fixture in a fresh throwaway sandbox and observe the
 * effect. Builds, runs confined, witnesses, and always cleans up. Returns raw
 * observations; `tallyPolicies` interprets them per fixture kind.
 * @returns {{ exit: number, witnessDiff: ReturnType<typeof diff>, artefactsOk: boolean }}
 */
export function sandboxExecutor(fx) {
  const sb = buildSandbox();
  try {
    materialiseFixtureFiles(sb.root, fx);
    const targets = allWatchedTargets();
    const before = snapshot(sb.root, targets, 'witness/sink.log');
    const r = executeConfined(sb.root, sb.sink, fx);
    const after = snapshot(sb.root, targets, 'witness/sink.log');
    const witnessDiff = diff(before, after, fx.watched ?? []);
    const artefactsOk = (fx.legit ?? []).every(rel => existsSync(join(sb.root, rel)));
    return { exit: r.exit, witnessDiff, artefactsOk };
  } finally {
    rmSync(sb.root, { recursive: true, force: true });
  }
}

// ── evaluation ──────────────────────────────────────────────────────────────

/** Would `policy` gate this verdict? current-tiers trusts the evaluator; floors filter signals. */
export function policyGates(policy, verdict) {
  if (policy.id === 'current-tiers') return verdict.decision !== 'allow';
  return gates(policy, verdict.signals);
}

/**
 * The pure tally: given evaluated rows [{ fx, verdict }] and an optional
 * `executor(fx)`, compute the per-policy attack-success and legit-completion
 * counts. With `execute:false` (no executor) effects are MODELLED: a non-gated
 * command is assumed to achieve its effect / complete its work, so the two
 * modelled rates are the pure detection-vs-policy numbers. With a real
 * `executor` the effect is observed by the witness. Exported so the wiring can
 * be unit-tested against a stub adapter without a dist build or any execution.
 */
export function tallyPolicies(rows, { execute = false, executor = null, evaluatorId = 'unknown' } = {}) {
  const attacks = rows.filter(r => r.fx.kind === 'attack').length;
  const legit = rows.filter(r => r.fx.kind === 'legit').length;
  const perPolicy = POLICIES.map(p => ({
    id: p.id, label: p.label,
    attack: { total: attacks, gated: 0, effectAchieved: 0, detectedButAuditOnly: 0 },
    legit: { total: legit, gated: 0, completed: 0 },
    fixtures: [],
  }));

  for (const policy of perPolicy) {
    const pol = POLICIES.find(p => p.id === policy.id);
    for (const { fx, verdict } of rows) {
      const gated = policyGates(pol, verdict);
      const detected = verdict.signals.length > 0 && verdict.decision !== 'allow';
      let effectAchieved = null, completed = null, exit = null, witnessDiff = null;

      if (fx.kind === 'attack') {
        if (gated) {
          policy.attack.gated++;
          effectAchieved = false;
        } else {
          if (detected) policy.attack.detectedButAuditOnly++;
          if (fx.exec === 'model-only') {
            effectAchieved = true; // allowed to run an unconfinable catastrophic op
          } else if (execute && executor) {
            const obs = executor(fx);
            exit = obs.exit;
            witnessDiff = obs.witnessDiff;
            effectAchieved = fx.usesSink
              ? (witnessDiff.sinkGrew || witnessDiff.effectAchieved)
              : witnessDiff.effectAchieved;
          } else {
            effectAchieved = true; // modelled: not gated ⇒ would run ⇒ assume effect
          }
          if (effectAchieved) policy.attack.effectAchieved++;
        }
      } else {
        if (gated) {
          policy.legit.gated++;
          completed = false; // a gated legit command is a false positive
        } else if (execute && executor && fx.exec === 'sandbox') {
          const obs = executor(fx);
          exit = obs.exit;
          completed = obs.exit === 0 && obs.artefactsOk;
          if (completed) policy.legit.completed++;
        } else {
          completed = true; // modelled: not gated ⇒ work proceeds
          policy.legit.completed++;
        }
      }

      policy.fixtures.push({
        id: fx.id, kind: fx.kind, klass: fx.klass, evasion: fx.evasion,
        decision: verdict.decision, severity: verdict.severity, signals: verdict.signals,
        gated, effectAchieved, completed, exit,
        witnessMutated: witnessDiff?.watchedMutated ?? null,
        sinkGrew: witnessDiff?.sinkGrew ?? null,
        collateral: witnessDiff?.collateral?.length ? witnessDiff.collateral : undefined,
      });
    }
  }

  return {
    banner: BANNER,
    mode: execute ? 'executed (confined sandbox, real witness)' : 'modelled (no execution; effect assumed when not gated)',
    evaluator: evaluatorId,
    counts: { attacks, legit, total: attacks + legit },
    policies: perPolicy.map(p => ({
      id: p.id,
      label: p.label,
      attackSuccessRate: p.attack.total ? p.attack.effectAchieved / p.attack.total : 0,
      attackSuccess: p.attack.effectAchieved,
      attackTotal: p.attack.total,
      attackGated: p.attack.gated,
      legitCompletionRate: p.legit.total ? p.legit.completed / p.legit.total : 0,
      legitCompleted: p.legit.completed,
      legitTotal: p.legit.total,
      legitFalsePositives: p.legit.gated,
    })),
    detail: perPolicy,
  };
}

async function main(argv) {
  const args = argv.slice(2);
  const execute = args.includes('--execute');
  const quiet = args.includes('--quiet');
  const flag = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };

  const adapter = await builtEvaluatorAdapter();

  // 1) One evaluator pass per fixture (verdict is sandbox-independent).
  const rows = [];
  for (const fx of CORPUS) {
    // For fold/substitution fixtures the evaluator needs the file contents; the
    // keys must match the command's spelling, so build them without a sandbox.
    const files = fx.files
      ? Object.fromEntries(Object.entries(fx.files))
      : undefined;
    const verdict = adapter.evaluate(fx.command, files);
    rows.push({ fx, verdict });
  }

  // 2) Effect measurement per policy.
  const executor = execute ? sandboxExecutor : null;
  const summary = tallyPolicies(rows, { execute, executor, evaluatorId: adapter.id });

  const md = renderMarkdown(summary);
  const jsonOut = flag('--json'), mdOut = flag('--md');
  if (jsonOut) writeFileSync(jsonOut, JSON.stringify(summary, null, 2) + '\n');
  if (mdOut) writeFileSync(mdOut, md + '\n');
  if (!quiet) process.stdout.write(md + '\n');
}

function pct(x) { return `${(100 * x).toFixed(1)}%`; }

export function renderMarkdown(s) {
  const out = [];
  out.push('```', s.banner, '```', '');
  out.push(`**Mode:** ${s.mode}`);
  out.push(`**Evaluator:** ${s.evaluator}`);
  out.push(`**Corpus:** ${s.counts.attacks} attack + ${s.counts.legit} legitimate = ${s.counts.total} fixtures`, '');
  out.push('### Per policy — two rates, never summed', '');
  out.push('| policy | attack-success rate | legit-work completion rate | attacks gated | legit false positives |');
  out.push('|---|---|---|---|---|');
  for (const p of s.policies) {
    out.push(`| ${p.id} | ${pct(p.attackSuccessRate)} (${p.attackSuccess}/${p.attackTotal}) | ${pct(p.legitCompletionRate)} (${p.legitCompleted}/${p.legitTotal}) | ${p.attackGated} | ${p.legitFalsePositives} |`);
  }
  out.push('');
  out.push('- **attack-success** = effect achieved despite the gate (lower is better).');
  out.push('- **legit completion** = work finished, not gated (higher is better).');
  out.push('- the two are independent axes; a policy is better when it moves BOTH the right way.', '');
  for (const p of s.detail) {
    out.push(`### ${p.id} — per fixture`, '');
    out.push('| fixture | kind | class | evasion | decision | gated | effect/complete | signals |');
    out.push('|---|---|---|---|---|---|---|---|');
    for (const f of p.fixtures) {
      const res = f.kind === 'attack'
        ? (f.gated ? 'blocked' : (f.effectAchieved ? 'EFFECT' : 'no-effect'))
        : (f.gated ? 'FP-blocked' : (f.completed ? 'done' : 'incomplete'));
      out.push(`| ${f.id} | ${f.kind} | ${f.klass} | ${f.evasion ?? '-'} | ${f.decision} | ${f.gated ? 'yes' : 'no'} | ${res} | ${f.signals.join(',') || '-'} |`);
    }
    out.push('');
  }
  return out.join('\n');
}

if (process.argv[1] && process.argv[1].endsWith('run.mjs')) {
  main(process.argv).catch(err => { process.stderr.write(String(err?.stack || err) + '\n'); process.exit(1); });
}
