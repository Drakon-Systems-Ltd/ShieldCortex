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
import { resolveConversationAccessConsent } from './conversation-access-consent.js';
import { summariseCommandOutput } from '../integrations/child-output.js';
import { gatewayBootLogAdvice, gatewayRestartCommand } from './gateway-restart-command.js';

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
  /** #977: `gateway-reload` steps only — what the restart came to. */
  restart?: GatewayRestartOutcome;
  /**
   * #977 review: `gateway-reload` steps only — gateway-affecting changes
   * landed after the reused restart was requested, so they are not loaded.
   * Set with `restart: 'pending'` (proven ready) AND with an unsafe readiness
   * outcome (`timed-out` / `unconfirmed`), where the restart is kept.
   */
  changesUnloaded?: boolean;
}

/**
 * #977 — what the run's gateway restart came to, for the closing screen.
 *   completed   restart issued and the gateway came back ready
 *   timed-out   restart issued, readiness wait timed out
 *   unconfirmed restart issued, readiness could not be observed (NOT a timeout)
 *   failed      the restart command itself failed
 *   skipped     a reload was wanted but not run (non-interactive / test runner)
 *   pending     this run's one restart happened BEFORE changes this pass made,
 *               so the gateway is not running them; a second restart is not
 *               issued in the same run (#977), so the operator must restart it.
 *               Only ever a restart PROVEN back up: an unproven one keeps
 *               timed-out / unconfirmed, which outrank pending (#977 review).
 */
export type GatewayRestartOutcome = 'completed' | 'timed-out' | 'unconfirmed' | 'failed' | 'skipped' | 'pending';

/**
 * #977 review: the command an operator runs to restart the gateway by hand,
 * or `shieldcortex doctor` on a platform we have no verified command for.
 */
export function manualGatewayRestartCommand(): string {
  return gatewayRestartCommand().command ?? 'shieldcortex doctor';
}

/** Result shape of the injectable gateway reload. */
export interface GatewayReloadResult {
  restarted: boolean;
  detail?: string;
  /** False when nothing was exec'd (consent gate, test runner). */
  attempted?: boolean;
  /** #977: an earlier request in this process already exec'd; this is its outcome. */
  reused?: boolean;
  /** #977: when that one exec was requested — readiness is measured from it. */
  requestedAtMs?: number;
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
  reloadGateway?: () => Promise<GatewayReloadResult>;
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
  /**
   * Did the operator ask for conversation access on THIS run (#226/#577)?
   *
   * `update` and `repair` now parse their own arguments once at the entry point
   * and pass the answer down, because the strict argument parsers added in #577
   * have to KNOW about every flag the command honours — a consent switch read
   * from `process.argv` several modules below the parser is invisible to it and
   * was rejected as an unknown argument. Omitted (`openclaw repair`, which has
   * already consumed its own argv) falls back to reading the process arguments,
   * exactly as before.
   */
  grantConversationAccess?: boolean;
  /** Internal: which converge pass this is (1-based). */
  pass?: number;
  /**
   * Internal (#977 review): when the latest gateway-affecting change of an
   * EARLIER pass started (epoch ms). A restart reused from before that moment
   * did not load it, even if this pass changes nothing itself.
   */
  lastChangeAtMs?: number;
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
async function defaultRestoreRegistration(
  home: string,
  grantConversationAccess: boolean,
): Promise<{ ok: boolean; detail: string }> {
  const { verifyPluginRegistration } = await import('./openclaw.js');
  // #226: repair closes the conversation-access gate too — but only when the
  // operator has asked for it on this run, exactly as the installer does.
  // Repairing an install is not consent to widen what it may read.
  const r = verifyPluginRegistration(home, { grantConversationAccess });
  return { ok: r.registered, detail: r.detail };
}

async function defaultReloadGateway(): Promise<GatewayReloadResult> {
  const { restartOpenClawGateway } = await import('./deep-clean.js');
  // #977: restartOpenClawGateway execs at most once per process, so pass 2 of
  // the converge loop gets pass 1's restart back (`reused`) instead of a
  // second `systemctl restart` landing on a gateway still draining its stop.
  const r = await restartOpenClawGateway();
  return {
    restarted: r.restarted,
    detail: r.detail,
    attempted: r.attempted,
    ...(r.reused ? { reused: true } : {}),
    ...(r.requestedAtMs !== undefined ? { requestedAtMs: r.requestedAtMs } : {}),
  };
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
  // #577: the callers with a strict argument parser (`update`, `repair`) pass
  // this in, so the flag they accept and the consent that reaches the registry
  // writer are the same value. `openclaw repair` still resolves it here.
  const grantConversationAccess =
    options.grantConversationAccess
    ?? resolveConversationAccessConsent({ argv: process.argv.slice(2), env: process.env });

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
    verdict.state === 'enabled-not-loaded' ||
    // #501: index-only omission is now unproven, but its existing metadata
    // repair still needs the same index-attested duplicate-dir safety check.
    (verdict.state === 'load-unproven' && verdict.recommendedAction !== 'none');
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
  // #977 review: when the latest gateway-affecting change LANDED, in this pass
  // or an earlier one. A reused restart requested before that moment never
  // loaded it. Only a step that changed something counts: a write that failed
  // left the world as the restart found it, so the readiness path still holds.
  let lastChangeAtMs: number | undefined = options.lastChangeAtMs;
  const noteChange = (): void => { lastChangeAtMs = Date.now(); };
  let restartPending = false;

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
      let restart: GatewayRestartOutcome = r.restarted
        ? 'completed'
        : r.attempted === false || /skipped|suppressed/i.test(r.detail ?? '')
          ? 'skipped'
          : 'failed';
      if (r.restarted) {
        // #977: a reused restart was requested earlier in this process; the
        // gateway it started booted after THAT moment, not after this pass.
        const readiness = await waitForGateway({ startedAfterMs: r.requestedAtMs ?? reloadRequestedAt });
        const timedOut = !readiness.ready && readiness.reason === 'timeout';
        restart = readiness.ready ? 'completed' : timedOut ? 'timed-out' : 'unconfirmed';
        detail = readiness.ready
          ? `reloaded and ready in ${(readiness.waitedMs / 1000).toFixed(1)}s`
          // Not proven ready is NOT the same claim as broken — on a host whose
          // boot-lifecycle table is unreadable we cannot bound the evidence at
          // all, and asserting failure there is the #142 overreach again.
          : `reloaded, but readiness ${timedOut ? 'timed out' : 'could not be observed'} — the checks below may be reading a gateway that is still starting`;
        if (r.reused) detail = `${detail} (restart issued earlier in this run, not repeated)`;
      }
      // #977 review: a reused restart requested before a change made since
      // (this pass, or an earlier one) never loaded that change. Keep the
      // one-restart rule, but say a restart is still owed — never "completed".
      // Missing timestamp on a reused restart: assume it predates the change.
      const predatesChange = r.reused === true && lastChangeAtMs !== undefined
        && (r.requestedAtMs === undefined || r.requestedAtMs <= lastChangeAtMs);
      const unloaded = r.restarted && predatesChange;
      if (unloaded && restart === 'completed') {
        restartPending = true;
        restart = 'pending';
        detail = `changes applied after this run's gateway restart — the running gateway has not loaded them; restart the gateway once more to load them: ${manualGatewayRestartCommand()}`;
        messages.push(
          `gateway restart pending: changes made after this run's gateway restart are not loaded yet, so protection is NOT confirmed until the gateway restarts once more: ${manualGatewayRestartCommand()}`,
        );
      } else if (unloaded) {
        // #977 review (r3): the one restart is not proven back up — it may
        // still be starting or draining. Owing a restart is NOT licence to
        // issue one into that window: keep the unsafe readiness outcome and
        // point at doctor, never at a restart command.
        restartPending = true;
        detail = `${detail}; changes applied after this run's gateway restart are not confirmed loaded — check readiness with shieldcortex doctor before any restart`;
        messages.push(
          'gateway restart not confirmed back up, and changes made after it are not loaded yet: protection is NOT confirmed — run shieldcortex doctor to check the gateway before restarting it',
        );
      }
      stepResults.push({
        kind: step.kind,
        ok: r.restarted && !predatesChange,
        detail,
        restart,
        ...(unloaded ? { changesUnloaded: true } : {}),
      });
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
          : await defaultRestoreRegistration(home, grantConversationAccess);
      } catch (err) {
        r = { ok: false, detail: `restore failed: ${err instanceof Error ? err.message : String(err)}` };
      }
      stepResults.push({ kind: step.kind, ok: r.ok, detail: r.detail });
      if (r.ok) noteChange();
      if (!r.ok) {
        messages.push(
          `SECURITY: could not restore the plugin registration in openclaw.json: ${r.detail} — the host stays UNPROTECTED until the plugin is registered again`,
        );
      }
      continue;
    }
    if (step.kind === 'prune-duplicate-dirs') {
      let ok = true;
      let pruned = 0;
      for (const d of step.dirs ?? []) {
        try {
          pruneDir(home, d);
          pruned += 1;
        } catch (err) {
          ok = false;
          messages.push(`prune failed for ${d}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      // A partial prune still changed the world the running gateway booted from.
      if (pruned > 0) noteChange();
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
    if (ok) noteChange();
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
  // #977 review: a self-check run against a gateway that has not loaded this
  // run's changes proves the OLD state. Never call that reconciled.
  const ok = selfCheckOk && commandsOk && !restartPending;
  if (!ok) {
    if (restartPending) {
      // The pending-restart message above already says what to do.
    } else if (!selfCheckResult) {
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
    const retry = await reconcileOpenClawPluginState({
      ...options,
      pass: pass + 1,
      ...(lastChangeAtMs !== undefined ? { lastChangeAtMs } : {}),
    });
    return {
      verdict,
      postVerdict: retry.postVerdict ?? postVerdict,
      plan: [...plan, ...retry.plan],
      applied: true,
      stepResults: [...stepResults, ...retry.stepResults],
      selfCheck: retry.selfCheck ?? selfCheckResult,
      // A restart still owed from pass 1 is not paid by pass 2 (#977 review).
      ok: retry.ok && !restartPending,
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
export interface FormatReconcileReportOptions {
  /**
   * Operator-facing short form (mobile / update footer). Headline + short
   * proof chips + one next step. Full forensic dump only when false/omitted
   * Update passes compact unless --verbose or SHIELDCORTEX_VERBOSE=1.
   */
  compact?: boolean;
}

function shortProofChips(result: ReconcileExecResult): string {
  const sc = result.selfCheck;
  const bits: string[] = [];
  if (sc) {
    if (sc.canaryProof) bits.push('guard live');
    else if (sc.canary?.ran) bits.push('guard unproven');
    const verStep = result.stepResults.find((s) => s.kind === 'openclaw-update' && s.ok);
    if (verStep) {
      const m = verStep.detail.match(/(\d+\.\d+\.\d+)/);
      if (m) bits.push(`v${m[1]}`);
    } else if (result.postVerdict?.onDiskVersion) {
      bits.push(`v${result.postVerdict.onDiskVersion}`);
    }
    if (sc.rosterState === 'loaded') bits.push('roster ok');
    else if (sc.rosterState === 'absent') bits.push('roster absent');
    else bits.push('roster unread');
  }
  const pruned = result.stepResults.find((s) => s.kind === 'prune-duplicate-dirs' && s.ok);
  if (pruned) bits.push('pruned dups');
  const reload = result.stepResults.find((s) => s.kind === 'gateway-reload' && s.ok);
  const restartOutcome = gatewayRestartOutcomeFromSteps(result.stepResults);
  const changesUnloaded = result.stepResults.some((s) => s.kind === 'gateway-reload' && s.changesUnloaded === true);
  if ((restartOutcome === 'timed-out' || restartOutcome === 'unconfirmed') && changesUnloaded) bits.push('gateway not confirmed up');
  else if (restartOutcome === 'pending') bits.push('gateway restart pending');
  else if (reload) bits.push('gateway reloaded');
  return bits.filter(Boolean).join(' · ');
}

export function formatReconcileReport(
  result: ReconcileExecResult,
  opts?: FormatReconcileReportOptions,
): string[] {
  const lines: string[] = [];
  const { verdict } = result;

  // Always compute the English headline first (#156).
  const summary = summariseRepair({
    applied: result.applied,
    onDiskVersion: (result.postVerdict ?? result.verdict).onDiskVersion,
    expectedVersion: (result.postVerdict ?? result.verdict).expectedVersion,
    canaryConsented: process.env.SHIELDCORTEX_ALLOW_GATEWAY_CANARY === '1' || Boolean(process.stdin.isTTY),
    ...restartVerdictInputs(result.stepResults),
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

  // Compact operator path (update footer / mobile): no double FAIL essay.
  if (opts?.compact) {
    const chips = shortProofChips(result);
    if (chips) lines.push(`   ${chips}`);
    // One short post-state line when useful — never dump full reasons twice.
    if (result.postVerdict && result.postVerdict.state !== 'healthy') {
      lines.push(`   state  ${result.postVerdict.state}`);
    } else if (result.applied && result.postVerdict?.state === 'healthy' && summary.outcome === 'protected-unproven') {
      lines.push('   state  installed · enabled · load line unread');
    }
    // Do NOT print ✗ FAILED when outcome is merely unproven.
    if (summary.outcome === 'unprotected') {
      lines.push('   status unprotected');
    }
    return lines;
  }

  lines.push('');

  lines.push(`Plugin load state: ${verdict.state} [${verdict.severity}]`);
  for (const r of verdict.reasons) lines.push(`  • ${r}`);

  if (!result.applied) {
    if (verdict.state === 'healthy') {
      // #103: only claim "loaded" when the RUNNING gateway roster proves it.
      lines.push(
        verdict.loadedInLiveRoster === true
          ? '✓ realtime plugin healthy: enabled, loaded on the running gateway roster, versions agree.'
          : `⚠ realtime plugin installed and enabled, versions agree — NOT proven loaded: the running gateway boot roster could not be read. Restart the gateway, then re-run, or check \`${gatewayBootLogAdvice()}\` yourself.`,
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
  if (result.ok || summary.outcome === 'protected' || summary.outcome === 'protected-unproven') {
    if (result.ok) {
      lines.push('✓ reconciled: plugin confirmed loaded (roster) and enforcing (canary).');
    } else {
      // Unproven is not FAILED — keep evidence without a red banner.
      lines.push(`⚠ ${summary.headline}`);
    }
  } else if (summary.outcome === 'unprotected') {
    lines.push('✗ FAILED: plugin is not protecting this gateway.');
    for (const m of result.messages) {
      if (m.startsWith('state before remediation')) continue;
      if (/fail|not confirmed|not run|did not|absent|OLDER/i.test(m)) lines.push(`  ${m}`);
    }
  } else {
    lines.push(`⚠ ${summary.headline}`);
    for (const m of result.messages) {
      if (m.startsWith('state before remediation')) continue;
      if (/fail|not confirmed|not run|did not/i.test(m)) lines.push(`  ${m}`);
    }
  }
  return lines;
}

/** Map reconcile+self-check to the update step ledger without false FAILED. */
/** Plain facts for the update summary screen. Read-only; decides nothing. */
export interface ProtectionFacts {
  /** Plugin seen on the running gateway's load list: yes / no / unknown. */
  loaded: 'yes' | 'no' | 'unknown';
  /** False only when the running build is proven older than expected. */
  versionOk?: boolean;
  pluginVersion: string | null;
  /** The plugin version this CLI expects (its own version). */
  expectedVersion?: string | null;
  gatewayReloaded: boolean;
  /**
   * #977: what the run's one gateway restart came to. Absent when no reload
   * was asked for. With two converge passes it is the LAST reload step's —
   * the latest readiness evidence about the same single restart.
   */
  gatewayRestart?: GatewayRestartOutcome;
  /**
   * #977 review: the manual restart command, when a restart failed or is
   * owed by a restart proven back up. Never with timed-out / unconfirmed.
   */
  restartCommand?: string;
  /** #977 review: changes landed after the run's one restart and are not loaded. */
  changesUnloaded?: boolean;
  nextCommand?: string;
}

/** #977: the restart outcome the closing screen reports, or undefined. */
export function gatewayRestartOutcomeFromSteps(stepResults: StepResult[]): GatewayRestartOutcome | undefined {
  const reloads = stepResults.filter((s) => s.kind === 'gateway-reload');
  const outcomes = reloads.map(reloadOutcome);
  // #977 review: every reload in one run shares the one latched restart. If
  // ANY pass could not prove it back up, it may still be starting — that
  // outranks a restart owed, because advising a restart into that window is
  // the #977 hazard itself. Timed-out is the stronger "still starting" claim.
  if (outcomes.includes('timed-out')) return 'timed-out';
  if (outcomes.includes('unconfirmed')) return 'unconfirmed';
  // A restart owed by ANY pass stays owed; a later pass reusing the same old
  // restart does not pay it.
  if (outcomes.includes('pending')) return 'pending';
  return outcomes[outcomes.length - 1];
}

function reloadOutcome(s: StepResult): GatewayRestartOutcome {
  if (s.restart) return s.restart;
  // Older/injected step shapes without the structured field.
  if (!s.ok) return /skipped|suppressed/i.test(s.detail) ? 'skipped' : 'failed';
  if (/readiness timed out/.test(s.detail)) return 'timed-out';
  if (/readiness could not be observed/.test(s.detail)) return 'unconfirmed';
  return 'completed';
}

/**
 * #977 review: the restart facts `summariseRepair` needs, read once for both
 * the repair report and the update ledger. The restart command is offered
 * ONLY when the run's restart is owed AND was proven back up.
 */
function restartVerdictInputs(stepResults: StepResult[]): {
  readinessUnproven: boolean;
  restartPending?: true;
  restartCommand?: string;
} {
  const outcome = gatewayRestartOutcomeFromSteps(stepResults);
  const readinessUnproven = outcome === 'timed-out' || outcome === 'unconfirmed';
  const owed = stepResults.some((s) => s.kind === 'gateway-reload' && (s.restart === 'pending' || s.changesUnloaded === true));
  return {
    readinessUnproven,
    ...(owed ? { restartPending: true as const } : {}),
    ...(owed && outcome === 'pending' ? { restartCommand: manualGatewayRestartCommand() } : {}),
  };
}

export function protectionFactsFromReconcile(
  result: ReconcileExecResult,
  nextCommand?: string,
): ProtectionFacts {
  const sc = result.selfCheck;
  const verStep = result.stepResults.find((s) => s.kind === 'openclaw-update' && s.ok);
  const fromStep = verStep?.detail.match(/(\d+\.\d+\.\d+)/)?.[1] ?? null;
  const restartOutcome = gatewayRestartOutcomeFromSteps(result.stepResults);
  // #977 review: never a restart command while the run's one restart is not
  // proven back up (timed-out / unconfirmed outrank pending above).
  const manualRestart = restartOutcome === 'failed' || restartOutcome === 'pending'
    ? gatewayRestartCommand().command
    : null;
  const changesUnloaded = result.stepResults.some((s) => s.kind === 'gateway-reload' && s.changesUnloaded === true);
  return {
    loaded: sc?.rosterState === 'loaded' ? 'yes' : sc?.rosterState === 'absent' ? 'no' : 'unknown',
    ...(sc && sc.versionProof === false ? { versionOk: false } : {}),
    pluginVersion: fromStep ?? (result.postVerdict ?? result.verdict).onDiskVersion ?? null,
    expectedVersion: (result.postVerdict ?? result.verdict).expectedVersion ?? null,
    gatewayReloaded: result.stepResults.some((s) => s.kind === 'gateway-reload' && s.ok),
    ...(restartOutcome ? { gatewayRestart: restartOutcome } : {}),
    ...(manualRestart ? { restartCommand: manualRestart } : {}),
    ...(changesUnloaded ? { changesUnloaded: true } : {}),
    ...(nextCommand ? { nextCommand } : {}),
  };
}

export function protectionLedgerFromReconcile(result: ReconcileExecResult): {
  status: 'ok' | 'unproven' | 'failed' | 'warn';
  summary: string;
  detail: string[];
  outcome: ReturnType<typeof summariseRepair>['outcome'];
  facts: ProtectionFacts;
} {
  const summary = summariseRepair({
    applied: result.applied,
    onDiskVersion: (result.postVerdict ?? result.verdict).onDiskVersion,
    expectedVersion: (result.postVerdict ?? result.verdict).expectedVersion,
    canaryConsented: process.env.SHIELDCORTEX_ALLOW_GATEWAY_CANARY === '1' || Boolean(process.stdin.isTTY),
    ...restartVerdictInputs(result.stepResults),
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
  const detail: string[] = [summary.headline];
  if (summary.nextCommand) detail.push(`next: ${summary.nextCommand}`);
  const facts = protectionFactsFromReconcile(result, summary.nextCommand);
  if (summary.outcome === 'protected') {
    return { status: 'ok', summary: 'protected', detail, outcome: summary.outcome, facts };
  }
  if (summary.outcome === 'unprotected') {
    return { status: 'failed', summary: 'unprotected', detail, outcome: summary.outcome, facts };
  }
  if (summary.outcome === 'protected-unproven') {
    // Do not hardcode Friday-class chips — other unproven classes exist
    // (roster loaded, canary not consented). Prefer the English headline.
    const chip = shortProofChips(result);
    return {
      status: 'unproven',
      summary: chip || 'protection unproven',
      detail,
      outcome: summary.outcome,
      facts,
    };
  }
  return { status: 'unproven', summary: 'protection unproven', detail, outcome: summary.outcome, facts };
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
