import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import {
  type ReconcileInput,
  gatherReconcileInput,
  reconcilePluginState,
  planReconcileActions,
  canonicalProjectDirFromIndex,
  REALTIME_PLUGIN_ID,
  type ReconcileVerdict,
  type ReconcileStep,
} from '../integrations/openclaw-plugin-index.js';
import { runPluginSelfCheck, type SelfCheckRunResult } from './openclaw-selfcheck.js';
import { waitForGatewayReady } from './gateway-readiness.js';
import { summariseRepair, renderRepairHeadline } from './repair-verdict.js';
import { resolveRepairConsent } from './repair-consent.js';
import { summariseCommandOutput } from '../integrations/child-output.js';

/**
 * The #74 metadata reconciler orchestrator.
 *
 * gather (three layers off disk) → classify → plan → execute the plan behind
 * the gateway-safety guards → honest-state self-check. Lives in its own module
 * (not setup/openclaw.ts, which trips Jest's ESM loader) so the full flow is
 * runtime-testable with injected executors — nothing ever touches a live
 * gateway in tests or under the frozen-toggle freeze.
 *
 * It fixes the three aiquant remediation failures:
 *   1. "source not found" — OpenClaw-tracked plugins are refreshed with
 *      `openclaw plugins update`, which the SC install path never called.
 *   2. "registered but inactive" — every remediation ends with a gateway reload
 *      + a two-proof self-check; success is never reported without it.
 *   3. "regressed to 4.25.4" — a regressed build is reinstalled PINNED to the
 *      expected version, never a floating spec.
 */

const PACKAGE_NAME = '@drakon-systems/shieldcortex-realtime';

export interface StepResult {
  kind: ReconcileStep['kind'];
  ok: boolean;
  detail: string;
}

/** #156 — one extra detect→remediate pass when the first did not converge. */
export const MAX_RECONCILE_PASSES = 2;

export interface ReconcileExecResult {
  /** The state BEFORE remediation — what the plan was computed from. */
  verdict: ReconcileVerdict;
  /**
   * The state re-read AFTER remediation (#145). The closing report must be
   * shaped by this, never by `verdict`: echoing the pre-remediation snapshot
   * produced "FAILED: version-regressed (4.47.16 running)" seconds after a
   * successful upgrade to 4.47.19 — a false red that sends operators to
   * re-remediate a healthy box. Absent on dry-runs (nothing changed).
   */
  postVerdict?: ReconcileVerdict;
  plan: ReconcileStep[];
  applied: boolean;
  stepResults: StepResult[];
  selfCheck?: SelfCheckRunResult;
  ok: boolean;
  messages: string[];
  /** How many detect→remediate passes ran (#156). */
  passes?: number;
}

export interface ReconcileOptions {
  home?: string;
  expectedVersion: string;
  pluginId?: string;
  /**
   * Whether to actually execute the remediation plan. When omitted it defaults
   * to false unless the operator consents (`SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1`)
   * and we are not under a Jest worker — so tests and headless runs dry-run.
   */
  apply?: boolean;
  /** Injectable openclaw executor (defaults to a guarded spawnSync). */
  runCommand?: (argv: string[]) => { status: number; output: string };
  /** Injectable gateway reload (defaults to the guarded restartOpenClawGateway). */
  reloadGateway?: () => Promise<{ restarted: boolean; detail?: string }>;
  /** Injectable self-check (defaults to runPluginSelfCheck). */
  selfCheck?: (home: string, pluginId: string) => Promise<SelfCheckRunResult>;
  /** Injectable duplicate-dir pruner (defaults to rm -rf of the project dir). */
  pruneDir?: (home: string, dirName: string) => void;
  /**
   * Injectable registration writer for the `restore-registration` step.
   * Defaults to `verifyPluginRegistration`, which merge-preserves every other
   * key in openclaw.json and re-reads to prove the write landed. Imported
   * lazily for the same reason `reloadGateway` is: setup/openclaw.ts trips
   * Jest's ESM loader if this module imports it eagerly.
   */
  restoreRegistration?: (home: string, pluginId: string) => { ok: boolean; detail: string };
  /**
   * Injectable readiness wait (#156). Defaults to polling OpenClaw's own
   * boot-lifecycle table for a process that started AFTER the restart. Tests
   * inject, so nothing ever sleeps on a live gateway.
   */
  waitForGateway?: (opts: { startedAfterMs: number }) => Promise<{ ready: boolean; reason?: string; waitedMs: number }>;
  /**
   * Injectable state reader, used for the pre-remediation read AND the #145
   * post-remediation re-read (defaults to gather + reconcile against the
   * host). One seam for both so a test cannot accidentally pin only the pre
   * path and leave the re-read unproven.
   */
  readState?: () => { input: ReconcileInput; verdict: ReconcileVerdict };
  /** Internal: which converge pass this is (1-based). */
  pass?: number;
}

function defaultApply(): boolean {
  // #156: typing `shieldcortex repair` at a terminal IS the consent — that is
  // what the command means. The RESTART gate already worked this way; RECONCILE
  // and CANARY did not, so an operator had to discover and combine THREE env
  // vars to fix his own install, and omitting one bought a paragraph of jargon.
  // Headless/agent/cron runs are unchanged and still require the explicit env:
  // those are the contexts the zeroth law is about, where an agent running
  // INSIDE the gateway must never restart it out from under itself.
  return resolveRepairConsent({ env: process.env, isTty: Boolean(process.stdin.isTTY) }).reconcile;
}

/** The subset of `spawnSync`'s return shape `describeSpawnOutcome` needs. */
export interface RawSpawnResult {
  status: number | null;
  stdout?: string | null;
  stderr?: string | null;
  error?: NodeJS.ErrnoException;
  signal?: NodeJS.Signals | null;
}

/**
 * Translate a raw spawnSync-shaped result into `{status, output}`, preserving
 * WHY the command did not run cleanly (#248).
 *
 * `spawnSync` reports a missing binary AND a timeout identically —
 * `status: null`, no stdout/stderr — and only `result.error.code` (ENOENT /
 * ETIMEDOUT) or `result.signal` (the kill signal) tell them apart. The old
 * `status: r.status ?? 1` collapsed both into "the command ran and exited 1",
 * which sends an operator chasing a config problem that was never there —
 * the same trap `validateOpenClawConfig` already avoids explicitly.
 *
 * Pulled out as its own function because `defaultRunCommand` cannot be driven
 * through a real spawn under Jest — it is gated both by its own
 * `JEST_WORKER_ID` check and by `resolveRepairConsent`, which is
 * unconditionally hostile under Jest by design (repair-consent.ts). This
 * seam is pure and needs neither.
 */
export function describeSpawnOutcome(command: string, r: RawSpawnResult): { status: number; output: string } {
  if (r.error) {
    const code = r.error.code;
    if (code === 'ENOENT') return { status: 1, output: `openclaw binary not found (ENOENT): ${command}` };
    if (code === 'ETIMEDOUT') return { status: 1, output: `openclaw command timed out: ${command}` };
    return { status: 1, output: `spawn failed (${code ?? 'unknown error'}): ${command} — ${r.error.message}` };
  }
  if (r.signal) {
    return { status: 1, output: `openclaw command killed by signal ${r.signal}: ${command}` };
  }
  return { status: r.status ?? 1, output: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

/**
 * The default openclaw executor. GUARDED: never spawns under a Jest worker or
 * without the explicit reconcile consent env, mirroring the gateway-restart
 * gate. Returns a non-zero status with an explanatory line when skipped so the
 * caller does not mistake a skip for a success.
 */
export function defaultRunCommand(argv: string[]): { status: number; output: string } {
  if (process.env.JEST_WORKER_ID !== undefined) {
    return { status: 1, output: 'skipped under test runner' };
  }
  if (!resolveRepairConsent({ env: process.env, isTty: Boolean(process.stdin.isTTY) }).reconcile) {
    return { status: 1, output: 'reconcile execution needs a terminal, or SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 for automation' };
  }
  const r = spawnSync('openclaw', argv, {
    encoding: 'utf-8',
    timeout: 120000,
    env: { ...process.env },
  });
  return describeSpawnOutcome(`openclaw ${argv.join(' ')}`, r);
}

function defaultPruneDir(home: string, dirName: string): void {
  const target = path.join(home, '.openclaw', 'npm', 'projects', dirName);
  fs.rmSync(target, { recursive: true, force: true });
}

/**
 * Restore the registration for the EXISTING install in openclaw.json
 * (#222/#228 remediation).
 *
 * Deliberately not an install: the package is already on disk and correct, and
 * the state we are fixing is a config one. `verifyPluginRegistration` is reused
 * rather than reimplemented because it already merge-preserves every other
 * plugin's stanza (#112 regression) and re-reads the file afterwards, so a
 * write that silently did not land cannot be reported as a success — which is
 * why it is preferred here over a bare `trustLocalPlugin` write.
 */
async function defaultRestoreRegistration(home: string): Promise<{ ok: boolean; detail: string }> {
  const { verifyPluginRegistration, resolveConversationAccessConsent } = await import('./openclaw.js');
  // #226: repair closes the conversation-access gate too — but only when the
  // operator has asked for it on this run, exactly as the installer does.
  // Repairing an install is not consent to widen what it may read.
  const grantConversationAccess = resolveConversationAccessConsent({ argv: process.argv.slice(2), env: process.env });
  const r = verifyPluginRegistration(home, { grantConversationAccess });
  return { ok: r.registered, detail: r.detail };
}

async function defaultReloadGateway(): Promise<{ restarted: boolean; detail?: string }> {
  const { restartOpenClawGateway } = await import('./deep-clean.js');
  const r = await restartOpenClawGateway();
  return { restarted: r.restarted, detail: r.detail };
}

export async function reconcileOpenClawPluginState(options: ReconcileOptions): Promise<ReconcileExecResult> {
  const home = options.home ?? os.homedir();
  const pluginId = options.pluginId ?? REALTIME_PLUGIN_ID;
  const apply = options.apply ?? defaultApply();
  const runCommand = options.runCommand ?? defaultRunCommand;
  const reloadGateway = options.reloadGateway ?? defaultReloadGateway;
  const selfCheck = options.selfCheck
    ?? ((h: string, p: string) => runPluginSelfCheck(h, { pluginId: p, expectedVersion: options.expectedVersion }));
  const pruneDir = options.pruneDir ?? defaultPruneDir;
  const waitForGateway = options.waitForGateway ?? (opts => waitForGatewayReady(opts));

  const messages: string[] = [];
  const readState =
    options.readState ??
    (() => {
      const i = gatherReconcileInput(home, { pluginId, expectedVersion: options.expectedVersion });
      return { input: i, verdict: reconcilePluginState(i) };
    });
  const { input, verdict } = readState();
  messages.push(`state before remediation: ${verdict.state} (${verdict.severity}) — ${verdict.reasons[verdict.reasons.length - 1] ?? ''}`);

  // Determine which duplicate dirs are prunable. The keep-dir is resolved from
  // the AUTHORITATIVE SQLite index (never installs.json, which in a conflicted
  // state points at the STALE dir) so a prune can NEVER delete the live install
  // (#74 finding 4). enabled-not-loaded is included because aiquant hit the
  // silent drop WITH a leftover duplicate dir — the drop's precondition — and
  // the old code never pruned it (#74 finding 5). When the index cannot name a
  // live dir we REFUSE to prune and say so, rather than guess by name length.
  const mayHaveDuplicateDirs =
    verdict.state === 'duplicate-install' ||
    verdict.state === 'conflicted-metadata' ||
    verdict.state === 'enabled-not-loaded';
  let dupDirs: string[] = [];
  if (mayHaveDuplicateDirs) {
    const liveDir = canonicalProjectDirFromIndex(input.index, pluginId);
    const scan = scanPrunableDirs(home, pluginId, liveDir);
    dupDirs = scan.prune;
    if (scan.refused) messages.push(scan.refused);
  }

  const plan = planReconcileActions(verdict, {
    pluginId,
    packageName: PACKAGE_NAME,
    expectedVersion: options.expectedVersion,
    duplicateDirsToPrune: dupDirs,
  });

  const stepResults: StepResult[] = [];
  let selfCheckResult: SelfCheckRunResult | undefined;

  if (!apply) {
    messages.push('dry-run: computed plan without executing (pass apply:true / SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 to remediate)');
    return { verdict, plan, applied: false, stepResults, ok: verdict.severity === 'ok', messages };
  }

  for (const step of plan) {
    if (step.kind === 'self-check') {
      selfCheckResult = await selfCheck(home, pluginId);
      stepResults.push({ kind: step.kind, ok: selfCheckResult.ok, detail: selfCheckResult.reasons.join('; ') });
      continue;
    }
    if (step.kind === 'gateway-reload') {
      const reloadRequestedAt = Date.now();
      const r = await reloadGateway();
      // #156: WAIT for the gateway to actually come back before anything reads
      // the world again. `restartOpenClawGateway()` returns when the service
      // manager has STARTED the process, not when the gateway has booted and
      // registered its plugins — so the post-remediation re-read added by #145
      // was racing the very restart it was meant to observe. Live, 1 Aug 2026:
      // repair printed "FAILED … on-disk 4.47.22 is OLDER than expected
      // 4.47.24" while doctor, seconds later on the same box, showed the build
      // current and 29/32 green. The remediation had worked; the report was
      // reading the pre-restart world.
      let detail = r.detail ?? (r.restarted ? 'reloaded' : 'not reloaded');
      if (r.restarted) {
        const readiness = await waitForGateway({ startedAfterMs: reloadRequestedAt });
        detail = readiness.ready
          ? `reloaded and ready in ${(readiness.waitedMs / 1000).toFixed(1)}s`
          // Not proven ready is NOT the same claim as broken — on a host whose
          // boot-lifecycle table is unreadable we cannot bound the evidence at
          // all, and asserting failure there is the #142 overreach again.
          : `reloaded, but readiness ${readiness.reason === 'timeout' ? 'timed out' : 'could not be observed'} — the checks below may be reading a gateway that is still starting`;
      }
      stepResults.push({ kind: step.kind, ok: r.restarted, detail });
      continue;
    }
    // #222/#226: restore a wiped openclaw.json registration. The writer is
    // imported lazily — a static import would drag setup/openclaw.ts in at
    // module load, which is exactly why this orchestrator lives in its own file
    // (see header), and openclaw.ts already imports THIS module dynamically in
    // the other direction.
    if (step.kind === 'restore-registration') {
      let r: { ok: boolean; detail: string };
      try {
        r = options.restoreRegistration
          ? options.restoreRegistration(home, pluginId)
          : await defaultRestoreRegistration(home);
      } catch (err) {
        r = { ok: false, detail: `restore failed: ${err instanceof Error ? err.message : String(err)}` };
      }
      stepResults.push({ kind: step.kind, ok: r.ok, detail: r.detail });
      if (!r.ok) {
        messages.push(
          `SECURITY: could not restore the plugin registration in openclaw.json: ${r.detail} — the host stays UNPROTECTED until the plugin is registered again`,
        );
      }
      continue;
    }
    if (step.kind === 'prune-duplicate-dirs') {
      let ok = true;
      for (const d of step.dirs ?? []) {
        try {
          pruneDir(home, d);
        } catch (err) {
          ok = false;
          messages.push(`prune failed for ${d}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      stepResults.push({ kind: step.kind, ok, detail: `pruned ${(step.dirs ?? []).length} dir(s)` });
      continue;
    }
    // openclaw-* command steps.
    const r = runCommand(step.command ?? []);
    const ok = r.status === 0;
    // #221: was `split('\n').slice(-1)[0]` — the LAST line. When OpenClaw
    // refuses because its config is invalid, its last line is the reassurance
    // "Audit, status, health, logs, tasks list/audit, and doctor commands still
    // run with invalid config." — so the reported reason was the sign-off and
    // the actual cause, printed first, was discarded.
    //
    // `dropPluginChatter: false` because THIS command is a `plugins`
    // subcommand: `[plugins] …` lines are its own output, not a third party's,
    // and filtering them left a failed step with a blank reason. `mode` follows
    // the outcome — failure ranking on a successful command promotes whichever
    // line happens to contain a word like "conflict".
    // `neverEmpty` rather than a fallback here: a raw `r.output` fallback at
    // this call site skipped env-value redaction, home scrubbing and the line
    // caps, and a probe with NPM_TOKEN set proved it emitted the token verbatim
    // whenever the output was all `npm warn`. The guarantee belongs on the path
    // that owns the redaction.
    const summarised = summariseCommandOutput(r.output, {
      maxLines: 1,
      dropPluginChatter: false,
      mode: ok ? 'plain' : 'failure',
      neverEmpty: true,
    });
    const summary = summarised.lines[0] ?? '';
    stepResults.push({ kind: step.kind, ok, detail: summary });
    if (!ok) messages.push(`command failed (openclaw ${(step.command ?? []).join(' ')}): ${summary}`);
  }

  // #145: re-read the state AFTER remediation. The pre-remediation snapshot is
  // now history — a closing line shaped by it reported "version-regressed
  // (4.47.16 running)" seconds after the very reload that fixed it.
  const postVerdict = readState().verdict;
  messages.push(`state after remediation: ${postVerdict.state} (${postVerdict.severity}) — ${postVerdict.reasons[postVerdict.reasons.length - 1] ?? ''}`);

  // Honest-state contract: overall success ONLY if the self-check ran AND passed.
  const selfCheckOk = Boolean(selfCheckResult?.ok);
  // `restore-registration` counts as a remediation command: it is the whole
  // remediation for the #222 state, and a plan whose only action failed must
  // never come back ok just because it shells out to nothing.
  const commandsOk = stepResults
    .filter((s) => s.kind.startsWith('openclaw') || s.kind === 'restore-registration')
    .every((s) => s.ok);
  const ok = selfCheckOk && commandsOk;
  if (!ok) {
    if (!selfCheckResult) {
      messages.push('self-check did not run — cannot confirm the plugin loaded; treating as FAILED');
    } else if (selfCheckResult.rosterProof && selfCheckResult.versionProof !== false && !selfCheckResult.canaryProof) {
      // Roster + version proved; only the LIVE enforcement canary is unproven.
      // Per #74 finding 1 this is "loaded (enforcement not actively proven)" —
      // NOT the #74 roster drop, and NOT "UNPROTECTED". Report it as such.
      messages.push(`self-check: plugin loaded (roster) and version OK, but enforcement NOT actively proven by the live canary — ${selfCheckResult.canary?.detail ?? selfCheckResult.reasons.join('; ')}`);
    } else {
      messages.push(`self-check FAILED after remediation — plugin not confirmed loaded + enforcing: ${selfCheckResult.reasons.join('; ')}`);
    }
  } else {
    messages.push('reconciled: plugin confirmed loaded (roster) and enforcing (canary)');
  }

  const pass = options.pass ?? 1;
  if (!ok && postVerdict.severity !== 'ok' && pass < MAX_RECONCILE_PASSES) {
    messages.push(`state still ${postVerdict.state} after pass ${pass} — running another detect→remediate pass (#156)`);
    const retry = await reconcileOpenClawPluginState({ ...options, pass: pass + 1 });
    return {
      verdict,
      postVerdict: retry.postVerdict ?? postVerdict,
      plan: [...plan, ...retry.plan],
      applied: true,
      stepResults: [...stepResults, ...retry.stepResults],
      selfCheck: retry.selfCheck ?? selfCheckResult,
      ok: retry.ok,
      messages: [...messages, ...retry.messages],
      passes: retry.passes ?? pass + 1,
    };
  }

  return { verdict, postVerdict, plan, applied: true, stepResults, selfCheck: selfCheckResult, ok, messages, passes: pass };
}

/**
 * Render an operator-facing report for `shieldcortex repair`. Honest by
 * construction: it prints the confirmed-success line ONLY when the plan applied
 * and the self-check passed, and points a dry-run operator at the consent env
 * needed to actually remediate.
 */
export function formatReconcileReport(result: ReconcileExecResult): string[] {
  const lines: string[] = [];
  const { verdict } = result;

  // #156: the operator's question first, in English. The evidence still follows
  // in full — this codebase has spent a week learning not to hide evidence —
  // but it stops being the headline. An operator wants to know whether they are
  // protected and what the single next thing is; they should not have to parse
  // "roster proof"/"plugins_json"/"the 4.25.4 class" to find out.
  const summary = summariseRepair({
    applied: result.applied,
    canaryConsented: process.env.SHIELDCORTEX_ALLOW_GATEWAY_CANARY === '1' || Boolean(process.stdin.isTTY),
    readinessUnproven: result.stepResults.some(s => s.kind === 'gateway-reload' && /readiness (timed out|could not be observed)/.test(s.detail)),
    ...(result.selfCheck
      ? {
        selfCheck: {
          ok: result.selfCheck.ok,
          rosterState: result.selfCheck.rosterState,
          canaryProof: result.selfCheck.canaryProof,
          versionProof: result.selfCheck.versionProof,
        },
      }
      : {}),
    ...(result.postVerdict ? { postState: result.postVerdict.state } : {}),
  });
  lines.push(...renderRepairHeadline(summary));
  lines.push('');

  lines.push(`Plugin load state: ${verdict.state} [${verdict.severity}]`);
  for (const r of verdict.reasons) lines.push(`  • ${r}`);

  if (!result.applied) {
    if (verdict.state === 'healthy') {
      // #103: only claim "loaded" when the RUNNING gateway roster proves it.
      lines.push(
        verdict.loadedInLiveRoster === true
          ? '✓ realtime plugin healthy: enabled, loaded on the running gateway roster, versions agree.'
          : '⚠ realtime plugin installed and enabled, versions agree — NOT proven loaded: the running gateway boot roster could not be read. Restart the gateway, then re-run, or check `journalctl --user -u openclaw-gateway | grep "http server listening"` yourself.',
      );
      return lines;
    }
    lines.push('');
    lines.push('Planned remediation (dry-run — nothing was changed):');
    for (const step of result.plan) lines.push(`  → ${step.kind}: ${step.description}`);
    lines.push('');
    lines.push('To apply on a host where a gateway reload is acceptable, re-run with BOTH consent envs');
    lines.push('(RECONCILE gates the plan; the post-remediation reload uses the gateway-restart gate):');
    lines.push('  SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1 shieldcortex repair');
    lines.push('  (on an interactive TTY the RESTART gate is satisfied automatically.)');
    return lines;
  }

  lines.push('');
  lines.push('Applied remediation:');
  for (const s of result.stepResults) lines.push(`  ${s.ok ? '✓' : '✗'} ${s.kind}: ${s.detail}`);
  lines.push('');
  // #145: everything below this line describes the world AFTER remediation.
  if (result.postVerdict) {
    lines.push(`Plugin load state after remediation: ${result.postVerdict.state} [${result.postVerdict.severity}]`);
    for (const r of result.postVerdict.reasons) lines.push(`  • ${r}`);
    lines.push('');
  }
  if (result.ok) {
    lines.push('✓ reconciled: plugin confirmed loaded (roster) and enforcing (canary).');
  } else {
    lines.push('✗ FAILED: could not confirm the plugin is loaded AND enforcing.');
    for (const m of result.messages) {
      // Never echo the PRE-remediation state under the failure banner — that
      // is the exact false red #145 documents. Post-state and self-check
      // messages carry the current truth.
      if (m.startsWith('state before remediation')) continue;
      if (/fail|not confirmed|not run|did not/i.test(m)) lines.push(`  ${m}`);
    }
  }
  return lines;
}

/**
 * Compute which duplicate project dirs are safe to prune. HOST-SAFETY CRITICAL
 * (#74 finding 4): the keep-dir (`liveDir`) is the dir the AUTHORITATIVE SQLite
 * index resolves into — the one the loaded gateway actually runs from. We prune
 * every OTHER matching dir and NEVER the live one.
 *
 * We REFUSE (prune nothing, return a reason) rather than guess when:
 *   - the index cannot name a live dir (`liveDir == null`) — ambiguous, so a
 *     prune could delete the real install; or
 *   - the named live dir is not present on disk — we cannot confirm which of
 *     the on-disk dirs is real, so pruning any is unsafe.
 * The old shortest-name heuristic could drop the longer `__openclaw-generation__`
 * dir even when that was the registered/live one — that path is gone.
 */
function scanPrunableDirs(
  home: string,
  pluginId: string,
  liveDir: string | null,
): { prune: string[]; refused?: string } {
  let dirs: string[];
  try {
    dirs = fs
      .readdirSync(path.join(home, '.openclaw', 'npm', 'projects'))
      .filter((d) => d.includes(pluginId));
  } catch {
    return { prune: [] };
  }
  if (dirs.length <= 1) return { prune: [] };
  if (!liveDir) {
    return {
      prune: [],
      refused: `refusing to prune ${dirs.length} duplicate project dir(s): the authoritative SQLite index does not resolve a live install dir — cannot safely tell which to keep. Resolve manually.`,
    };
  }
  if (!dirs.includes(liveDir)) {
    return {
      prune: [],
      refused: `refusing to prune duplicate project dir(s): the index's live install dir (${liveDir}) is not present on disk — cannot safely tell which to keep. Resolve manually.`,
    };
  }
  return { prune: dirs.filter((d) => d !== liveDir) };
}
