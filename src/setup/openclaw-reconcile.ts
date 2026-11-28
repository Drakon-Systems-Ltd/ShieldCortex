import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import {
  type ReconcileInput,
  gatherReconcileInput,
  reconcilePluginState,
  planReconcileActions,
  assessDuplicateProjectDirs,
  REALTIME_PLUGIN_ID,
  type ReconcileVerdict,
  type ReconcileStep,
} from '../integrations/openclaw-plugin-index.js';
import { runPluginSelfCheck, type SelfCheckRunResult } from './openclaw-selfcheck.js';
import { waitForGatewayReady } from './gateway-readiness.js';
import { summariseRepair, renderRepairHeadline, type RepairVerdictInput } from './repair-verdict.js';
import { resolveRepairConsent } from './repair-consent.js';
import { resolveConversationAccessConsent } from './conversation-access-consent.js';
import { summariseCommandOutput } from '../integrations/child-output.js';
import { gatewayBootLogAdvice, gatewayRestartCommand } from './gateway-restart-command.js';
import {
  BareRetryBudget,
  REALTIME_PLUGIN_PACKAGE,
  assessRealtimeReplacement,
  exactPluginPin,
  landedVersionVerdict,
  realtimePluginInstallCommand,
  runWithNpmSourceFallbackSync,
  type ExistingRealtimeInstall,
} from './openclaw-plugin-spec.js';
import { readRealtimeReplacementEvidence, readSelectedRealtimePluginVersion } from '../integrations/openclaw-realtime-install.js';
import { nextCausalSeq } from './causal-seq.js';

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
  /**
   * #260 Sol r2: `self-check` steps only — this run changed the host, and no
   * gateway restart PROVEN back up (a new process started after the request)
   * followed the change. Whatever the self-check saw, it saw the gateway as
   * it was before the change, so it cannot certify the repair.
   */
  preChangeEvidence?: boolean;
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
  /** #977 review: that exec's causal ticket — ordering is decided from it alone. */
  requestedSeq?: number;
  /** The service-manager command timed out: the restart may still be in progress. */
  timedOut?: boolean;
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
  /**
   * Injectable openclaw executor (defaults to a guarded spawnSync). `stderr` /
   * `stdout` are the child's own streams when the executor has them; only a
   * refusal on `stderr` can earn the one bare-spec retry (#1109 review), so an
   * executor that reports `output` alone never gets one.
   */
  runCommand?: (argv: string[]) => { status: number; output: string; stderr?: string; stdout?: string };
  /**
   * The ONE bare-spec retry this whole reconcile run may spend (#1109 review):
   * created by the first pass and handed to every later pass, so the
   * operation as a whole — not each pass — gets at most one.
   */
  bareRetryBudget?: BareRetryBudget;
  /** What realtime install is there now, for the never-clobber check (defaults to OpenClaw's own files under `home`). */
  readExistingInstall?: (home: string) => ExistingRealtimeInstall;
  /**
   * After a realtime install step exits 0: the version of the copy OpenClaw
   * SELECTED, or why it could not be told (#1109 round 2). Defaults to
   * OpenClaw's own install records under `home`.
   */
  readLandedVersion?: (home: string) => { version: string } | { version: null; reason: string };
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
   * Internal (#977 review): the causal ticket (`nextCausalSeq`) of the latest
   * gateway-affecting change of an EARLIER pass. A reused restart whose ticket
   * is older did not load it, even if this pass changes nothing itself.
   */
  lastChangeSeq?: number;
  /**
   * Internal (#260 Sol r2): the causal ticket of the latest gateway restart
   * PROVEN back up (readiness saw a process started after it was requested)
   * in an earlier pass. Changes with a later ticket are not loaded by it.
   */
  loadedThroughSeq?: number;
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
export function describeSpawnOutcome(
  command: string,
  r: RawSpawnResult,
): { status: number; output: string; stderr?: string; stdout?: string } {
  if (r.error) {
    const code = r.error.code;
    if (code === 'ENOENT') return { status: 1, output: `openclaw binary not found (ENOENT): ${command}` };
    if (code === 'ETIMEDOUT') return { status: 1, output: `openclaw command timed out: ${command}` };
    return { status: 1, output: `spawn failed (${code ?? 'unknown error'}): ${command} — ${r.error.message}` };
  }
  if (r.signal) {
    return { status: 1, output: `openclaw command killed by signal ${r.signal}: ${command}` };
  }
  return {
    status: r.status ?? 1,
    output: `${r.stdout ?? ''}${r.stderr ?? ''}`,
    stderr: typeof r.stderr === 'string' ? r.stderr : '',
    stdout: typeof r.stdout === 'string' ? r.stdout : '',
  };
}

/**
 * The default openclaw executor. GUARDED: never spawns under a Jest worker or
 * without the explicit reconcile consent env, mirroring the gateway-restart
 * gate. Returns a non-zero status with an explanatory line when skipped so the
 * caller does not mistake a skip for a success.
 */
export function defaultRunCommand(argv: string[]): { status: number; output: string; stderr?: string; stdout?: string } {
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
    ...(r.requestedSeq !== undefined ? { requestedSeq: r.requestedSeq } : {}),
    ...(r.timedOut ? { timedOut: true } : {}),
  };
}

export async function reconcileOpenClawPluginState(options: ReconcileOptions): Promise<ReconcileExecResult> {
  const home = options.home ?? os.homedir();
  const pluginId = options.pluginId ?? REALTIME_PLUGIN_ID;
  const apply = options.apply ?? defaultApply();
  const runCommand = options.runCommand ?? defaultRunCommand;
  const bareRetryBudget = options.bareRetryBudget ?? new BareRetryBudget();
  // #1109 round 3: the copy OpenClaw SELECTED and its link state — not the
  // highest version on disk.
  const readExistingInstall = options.readExistingInstall
    ?? ((h: string): ExistingRealtimeInstall => readRealtimeReplacementEvidence(h));
  const readLandedVersion = options.readLandedVersion ?? ((h: string) => readSelectedRealtimePluginVersion(h));
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
  // the old code never pruned it (#74 finding 5). #260 Sol r2: a dir the index
  // NAMES is not enough — the kept copy must be a verified build, named
  // unambiguously, and every removed dir an older or equal copy (or none);
  // otherwise nothing is pruned and the refusal says why.
  const mayHaveDuplicateDirs =
    verdict.state === 'duplicate-install' ||
    verdict.state === 'conflicted-metadata' ||
    verdict.state === 'enabled-not-loaded' ||
    // #501: index-only omission is now unproven, but its existing metadata
    // repair still needs the same index-attested duplicate-dir safety check.
    (verdict.state === 'load-unproven' && verdict.recommendedAction !== 'none');
  let dupDirs: string[] = [];
  if (mayHaveDuplicateDirs) {
    const scan = assessDuplicateProjectDirs(home, input.index, pluginId, PACKAGE_NAME);
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
  // #977 review: the causal ticket of the latest gateway-affecting change that
  // LANDED, in this pass or an earlier one. A reused restart with an older
  // ticket never loaded it. Tickets, not epoch ms: a change and a restart in
  // the same millisecond tie on the clock, and neither `<` nor `<=` orders
  // both cases right. Only a step that changed something counts: a write that
  // failed left the world as the restart found it, so readiness still holds.
  let lastChangeSeq: number | undefined = options.lastChangeSeq;
  const noteChange = (): void => { lastChangeSeq = nextCausalSeq(); };
  let restartPending = false;
  // #260 Sol r2: the latest restart PROVEN back up, by causal ticket. A
  // self-check only certifies this run's changes when one of those came after
  // the last change; otherwise it read the pre-change gateway.
  let loadedThroughSeq: number | undefined = options.loadedThroughSeq;
  let preChangeEvidence = false;

  if (!apply) {
    messages.push('dry-run: computed plan without executing (pass apply:true / SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 to remediate)');
    return { verdict, plan, applied: false, stepResults, ok: verdict.severity === 'ok', messages };
  }

  for (const step of plan) {
    if (step.kind === 'self-check') {
      selfCheckResult = await selfCheck(home, pluginId);
      // #260 Sol r2: evidence from a gateway that has not been PROVEN
      // restarted since this run's last change describes the host before the
      // repair. It may still be reported; it may not certify the repair.
      preChangeEvidence = lastChangeSeq !== undefined
        && (loadedThroughSeq === undefined || loadedThroughSeq < lastChangeSeq);
      stepResults.push({
        kind: step.kind,
        ok: selfCheckResult.ok && !preChangeEvidence,
        detail: preChangeEvidence
          ? `${selfCheckResult.reasons.join('; ')} — read from the gateway as it was BEFORE this run's changes (no restart proven back up since), so it does not confirm the repair`
          : selfCheckResult.reasons.join('; '),
        ...(preChangeEvidence ? { preChangeEvidence: true } : {}),
      });
      continue;
    }
    if (step.kind === 'gateway-reload') {
      const reloadRequestedAt = Date.now();
      // A fresh restart is requested after this ticket, so after every change
      // this run has made so far; a reused one carries its own (#977).
      const reloadRequestSeq = nextCausalSeq();
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
      // A timed-out service-manager command may have restarted the gateway:
      // the same "may still be starting, don't restart again" outcome as a
      // readiness timeout, never 'failed' (which offers a restart command).
      let restart: GatewayRestartOutcome = r.restarted
        ? 'completed'
        : r.timedOut
          ? 'timed-out'
          : r.attempted === false || /skipped|suppressed/i.test(r.detail ?? '')
            ? 'skipped'
            : 'failed';
      if (r.timedOut) {
        detail = `restart command timed out, so the gateway may still be restarting — check with shieldcortex doctor before restarting it again (${detail})`;
      }
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
      // Ordered by causal ticket only. Missing ticket on a reused restart:
      // assume it predates the change.
      const predatesChange = r.reused === true && lastChangeSeq !== undefined
        && (r.requestedSeq === undefined || r.requestedSeq < lastChangeSeq);
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
      // #260 Sol r2: only a restart PROVEN back up (a process started after
      // the request) loads what preceded it. Failed, skipped, timed-out and
      // unconfirmed restarts load nothing this report may rely on.
      if (restart === 'completed') {
        const seq = r.reused ? r.requestedSeq : (r.requestedSeq ?? reloadRequestSeq);
        if (seq !== undefined && (loadedThroughSeq === undefined || seq > loadedThroughSeq)) loadedThroughSeq = seq;
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
      const planned = step.dirs ?? [];
      const removed: string[] = [];
      const left: string[] = [];
      for (const d of planned) {
        try {
          pruneDir(home, d);
          removed.push(d);
        } catch (err) {
          left.push(d);
          messages.push(`prune failed for ${d}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      // A partial prune still changed the world the running gateway booted from.
      if (removed.length > 0) noteChange();
      // #260 Sol r2: say what was actually removed, not what was planned.
      const ok = left.length === 0;
      const detail = ok
        ? `pruned ${removed.length} dir(s)`
        : `pruned ${removed.length} of ${planned.length} dir(s); still on disk: ${left.join(', ')}`;
      if (!ok) {
        messages.push(`prune incomplete: removed ${removed.length} of ${planned.length} duplicate project dir(s) — ${left.join(', ')} still on disk, so a toggle can still re-resolve to it`);
      }
      stepResults.push({ kind: step.kind, ok, detail });
      continue;
    }
    // #1109 review: a realtime install is forced (`--force`), so before it
    // runs: it must carry an exact pin (the planner leaves the command empty
    // when there is none), and it must not replace a linked/path install or
    // one newer than the pin. Refused here, the step fails with the command —
    // nothing is run.
    const cmd = step.command ?? [];
    const realtimeInstall = (step.kind === 'openclaw-install' || step.kind === 'openclaw-install-pinned')
      && (cmd.length === 0 || cmd.some((a) => a.includes(REALTIME_PLUGIN_PACKAGE)));
    if (realtimeInstall) {
      const pin = exactPluginPin(options.expectedVersion);
      const refusal = !pin || cmd.length === 0
        ? `not installed — no exact plugin version to pin to (expected ${JSON.stringify(options.expectedVersion)}); run \`${realtimePluginInstallCommand(null)}\``
        : (() => {
          const keep = assessRealtimeReplacement(readExistingInstall(home), pin);
          return keep.replace ? null : `${keep.summary}; to replace it with v${pin}: \`${realtimePluginInstallCommand(pin)}\``;
        })();
      if (refusal) {
        stepResults.push({ kind: step.kind, ok: false, detail: refusal });
        messages.push(`plugin install skipped: ${refusal}`);
        continue;
      }
    }
    // openclaw-* command steps. An `npm:` install refused by a host that
    // predates the prefix (an anchored stderr line, nothing else wrong) is
    // retried with the bare, still pinned spec — once for this whole run,
    // across every pass; no other failure is retried.
    const { result: r, args: ranArgs } = runWithNpmSourceFallbackSync(
      step.command ?? [],
      runCommand,
      // `describeSpawnOutcome` drops both streams for a timeout, a signal or a
      // spawn failure, so those can never match the refusal allowlist.
      (out) => (out.status === 0 ? null : { stderr: out.stderr ?? '', stdout: out.stdout ?? '', exitCode: out.status }),
      bareRetryBudget,
    );
    let ok = r.status === 0;
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
    let summary = summarised.lines[0] ?? '';
    // #1109 round 2: a realtime install that exited 0 is checked here, on its
    // own step, against the pin — the copy OpenClaw selected, not just the
    // exit code. The later self-check still runs; this does not wait for it.
    let landedMismatch: string | null = null;
    if (ok && realtimeInstall) {
      const pin = exactPluginPin(options.expectedVersion)!;
      const landed = landedVersionVerdict(readLandedVersion(home), pin);
      if (!landed.ok) {
        ok = false;
        landedMismatch = `install exited 0, but ${landed.summary}; run \`${realtimePluginInstallCommand(pin)}\``;
        summary = landedMismatch;
      }
    }
    stepResults.push({ kind: step.kind, ok, detail: summary });
    // The install changed the host even when it left the wrong build.
    if (ok || landedMismatch) noteChange();
    if (landedMismatch) messages.push(`plugin install not finished: ${landedMismatch}`);
    else if (!ok) messages.push(`command failed (openclaw ${ranArgs.join(' ')}): ${summary}`);
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
  // #260 Sol r2: a prune that left a duplicate behind did not do its job
  // either — it counts like any other remediation step.
  const commandsOk = stepResults
    .filter((s) => s.kind.startsWith('openclaw') || s.kind === 'restore-registration' || s.kind === 'prune-duplicate-dirs')
    .every((s) => s.ok);
  // #977 review: a self-check run against a gateway that has not loaded this
  // run's changes proves the OLD state. Never call that reconciled. #260 Sol
  // r2: the same holds when the restart after them failed, was skipped, or
  // was not proven back up — not only when a reused restart predates them.
  const ok = selfCheckOk && commandsOk && !restartPending && !preChangeEvidence;
  if (!ok) {
    if (restartPending) {
      // The pending-restart message above already says what to do.
    } else if (preChangeEvidence) {
      const outcome = gatewayRestartOutcomeFromSteps(stepResults);
      const why = outcome === 'failed'
        ? 'the gateway restart after them failed'
        : outcome === 'skipped'
          ? 'the gateway was not restarted after them'
          : 'the gateway restart after them was not confirmed back up';
      messages.push(
        `this run's changes are not confirmed loaded: ${why}, so the self-check read the gateway as it was before the repair — protection by the repaired install is NOT confirmed`,
      );
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
      bareRetryBudget,
      pass: pass + 1,
      ...(lastChangeSeq !== undefined ? { lastChangeSeq } : {}),
      ...(loadedThroughSeq !== undefined ? { loadedThroughSeq } : {}),
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

/**
 * #1179 r2 (Astra): the post-remediation verdict's reading of the build
 * OpenClaw selected, or null. Only the post-state (never the pre-remediation
 * snapshot), and only a `selected-build` reading (never a disk-scan copy, a
 * record-path build or an install record).
 */
function selectedBuildRead(result: ReconcileExecResult): string | null {
  const post = result.postVerdict;
  return post?.installedVersionSource === 'selected-build' ? post.installedVersion ?? null : null;
}

/**
 * #1179 r3: the self-check's version proof failed with no version of its
 * own — unread, a known wrong source, or a source recorded for another folder.
 */
function selfCheckHadNoVersion(sc: ReconcileExecResult['selfCheck']): boolean {
  return sc?.versionProof === false &&
    (sc.versionUnread === true || sc.versionWrongSource === true || sc.versionProvenanceUnverified === true);
}

/**
 * #1179 r3 (Astra 1, 2c): the one plugin version the report names — the
 * compact chip and the ledger's `facts.pluginVersion` — so neither can
 * contradict the headline. In order: the version this run's update step
 * installed; the selected measurement (the post-state's selected-build
 * reading, else the self-check reader's own reading of the selected copy);
 * the disk scan's version, but only when the self-check did not fail for want
 * of a version of its own; otherwise none. Never another copy's version
 * standing in for the selected one. With no self-check at all (a dry run),
 * the scan version stays, as before.
 */
function reportedPluginVersion(result: ReconcileExecResult): string | null {
  const step = result.stepResults.find((s) => s.kind === 'openclaw-update' && s.ok);
  const fromStep = step?.detail.match(/(\d+\.\d+\.\d+)/)?.[1];
  if (fromStep) return fromStep;
  const selected = selectedBuildRead(result) ?? result.selfCheck?.selectedCopyVersion ?? null;
  if (selected) return selected;
  if (selfCheckHadNoVersion(result.selfCheck)) return null;
  return (result.postVerdict ?? result.verdict).onDiskVersion ?? null;
}

/**
 * What both report adapters (`formatReconcileReport`,
 * `protectionLedgerFromReconcile`) hand `summariseRepair`, built once so they
 * cannot drift (#1179 r2).
 */
function repairVerdictInput(result: ReconcileExecResult): RepairVerdictInput {
  const selected = selectedBuildRead(result);
  return {
    applied: result.applied,
    onDiskVersion: (result.postVerdict ?? result.verdict).onDiskVersion,
    expectedVersion: (result.postVerdict ?? result.verdict).expectedVersion,
    canaryConsented: process.env.SHIELDCORTEX_ALLOW_GATEWAY_CANARY === '1' || Boolean(process.stdin.isTTY),
    ...restartVerdictInputs(result.stepResults),
    // r2: the selected measurement and its source, as one pair.
    ...(selected ? { installedVersion: selected, installedVersionSource: 'selected-build' as const } : {}),
    ...(result.selfCheck
      ? {
        selfCheck: {
          ok: result.selfCheck.ok,
          rosterState: result.selfCheck.rosterState,
          canaryProof: result.selfCheck.canaryProof,
          versionProof: result.selfCheck.versionProof,
          // #1179 r1: an unread version stays unknown, never "behind".
          ...(result.selfCheck.versionUnread ? { versionUnread: true } : {}),
          // r2: a known wrong source is not an unread version.
          ...(result.selfCheck.versionWrongSource ? { versionWrongSource: true } : {}),
          // r3: a source recorded for another folder, and the selected copy's
          // own version when the proof failed on its source.
          ...(result.selfCheck.versionProvenanceUnverified ? { versionProvenanceUnverified: true } : {}),
          ...(result.selfCheck.selectedCopyVersion ? { selectedCopyVersion: result.selfCheck.selectedCopyVersion } : {}),
        },
      }
      : {}),
    ...(result.postVerdict ? { postState: result.postVerdict.state } : {}),
  };
}

function shortProofChips(result: ReconcileExecResult): string {
  const sc = result.selfCheck;
  const bits: string[] = [];
  if (sc) {
    if (sc.canaryProof) bits.push('guard live');
    else if (sc.canary?.ran) bits.push('guard unproven');
    // #1179 r3: the same version the ledger facts name (see reportedPluginVersion).
    const version = reportedPluginVersion(result);
    if (version) bits.push(`v${version}`);
    if (sc.rosterState === 'loaded') bits.push('roster ok');
    else if (sc.rosterState === 'absent') bits.push('roster absent');
    else bits.push('roster unread');
  }
  const prunes = result.stepResults.filter((s) => s.kind === 'prune-duplicate-dirs');
  if (prunes.some((s) => !s.ok)) bits.push('prune incomplete');
  else if (prunes.length > 0) bits.push('pruned dups');
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
  const summary = summariseRepair(repairVerdictInput(result));
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
  changesNotLoaded?: 'failed' | 'skipped' | 'unconfirmed';
} {
  const outcome = gatewayRestartOutcomeFromSteps(stepResults);
  const readinessUnproven = outcome === 'timed-out' || outcome === 'unconfirmed';
  const owed = stepResults.some((s) => s.kind === 'gateway-reload' && (s.restart === 'pending' || s.changesUnloaded === true));
  // #260 Sol r2: the LAST self-check read a gateway not proven restarted
  // since this run's changes. Owed restarts (#977) are reported as such.
  const selfChecks = stepResults.filter((s) => s.kind === 'self-check');
  const lastPreChange = selfChecks[selfChecks.length - 1]?.preChangeEvidence === true;
  const changesNotLoaded = !owed && lastPreChange
    ? (outcome === 'failed' ? 'failed' : outcome === 'skipped' ? 'skipped' : 'unconfirmed')
    : undefined;
  return {
    readinessUnproven,
    ...(owed ? { restartPending: true as const } : {}),
    ...(owed && outcome === 'pending' ? { restartCommand: manualGatewayRestartCommand() } : {}),
    // Nothing restarted (failed / skipped): a manual restart is safe. An
    // unconfirmed one may still be starting: doctor, never a restart.
    ...(changesNotLoaded && changesNotLoaded !== 'unconfirmed' ? { restartCommand: manualGatewayRestartCommand() } : {}),
    ...(changesNotLoaded ? { changesNotLoaded } : {}),
  };
}

export function protectionFactsFromReconcile(
  result: ReconcileExecResult,
  nextCommand?: string,
): ProtectionFacts {
  const sc = result.selfCheck;
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
    // #1179 r3 (Astra 1): the version the headline and the chip go by.
    pluginVersion: reportedPluginVersion(result),
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
  const summary = summariseRepair(repairVerdictInput(result));
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
