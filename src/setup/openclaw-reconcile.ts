import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import {
  gatherReconcileInput,
  reconcilePluginState,
  planReconcileActions,
  canonicalProjectDir,
  REALTIME_PLUGIN_ID,
  type ReconcileVerdict,
  type ReconcileStep,
} from '../integrations/openclaw-plugin-index.js';
import { runPluginSelfCheck, type SelfCheckRunResult } from './openclaw-selfcheck.js';

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

export interface ReconcileExecResult {
  verdict: ReconcileVerdict;
  plan: ReconcileStep[];
  applied: boolean;
  stepResults: StepResult[];
  selfCheck?: SelfCheckRunResult;
  ok: boolean;
  messages: string[];
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
}

function defaultApply(): boolean {
  return process.env.JEST_WORKER_ID === undefined && process.env.SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE === '1';
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
  if (process.env.SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE !== '1') {
    return { status: 1, output: 'reconcile execution requires SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1' };
  }
  const r = spawnSync('openclaw', argv, {
    encoding: 'utf-8',
    timeout: 120000,
    env: { ...process.env },
  });
  return { status: r.status ?? 1, output: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

function defaultPruneDir(home: string, dirName: string): void {
  const target = path.join(home, '.openclaw', 'npm', 'projects', dirName);
  fs.rmSync(target, { recursive: true, force: true });
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
  const selfCheck = options.selfCheck ?? ((h: string, p: string) => runPluginSelfCheck(h, { pluginId: p }));
  const pruneDir = options.pruneDir ?? defaultPruneDir;

  const messages: string[] = [];
  const verdict = reconcilePluginState(gatherReconcileInput(home, { pluginId, expectedVersion: options.expectedVersion }));
  messages.push(`state: ${verdict.state} (${verdict.severity}) — ${verdict.reasons[verdict.reasons.length - 1] ?? ''}`);

  // Determine which duplicate dirs are prunable (all matching dirs except the canonical one).
  const canonical = canonicalProjectDir(home);
  const dupDirs = (verdict.state === 'duplicate-install' || verdict.state === 'conflicted-metadata')
    ? scanDuplicateDirs(home, pluginId, canonical)
    : [];

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
      const r = await reloadGateway();
      stepResults.push({ kind: step.kind, ok: r.restarted, detail: r.detail ?? (r.restarted ? 'reloaded' : 'not reloaded') });
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
    stepResults.push({ kind: step.kind, ok, detail: r.output.trim().split('\n').slice(-1)[0] ?? '' });
    if (!ok) messages.push(`command failed (openclaw ${(step.command ?? []).join(' ')}): ${r.output.trim().split('\n').slice(-1)[0] ?? ''}`);
  }

  // Honest-state contract: overall success ONLY if the self-check ran AND passed.
  const selfCheckOk = Boolean(selfCheckResult?.ok);
  const commandsOk = stepResults.filter((s) => s.kind.startsWith('openclaw')).every((s) => s.ok);
  const ok = selfCheckOk && commandsOk;
  if (!ok) {
    if (!selfCheckResult) messages.push('self-check did not run — cannot confirm the plugin loaded; treating as FAILED');
    else if (!selfCheckOk) messages.push(`self-check FAILED after remediation — plugin not confirmed loaded + enforcing: ${selfCheckResult.reasons.join('; ')}`);
  } else {
    messages.push('reconciled: plugin confirmed loaded (roster) and enforcing (canary)');
  }

  return { verdict, plan, applied: true, stepResults, selfCheck: selfCheckResult, ok, messages };
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
  lines.push(`Plugin load state: ${verdict.state} [${verdict.severity}]`);
  for (const r of verdict.reasons) lines.push(`  • ${r}`);

  if (!result.applied) {
    if (verdict.state === 'healthy') {
      lines.push('✓ realtime plugin healthy: enabled, loaded in roster, versions agree.');
      return lines;
    }
    lines.push('');
    lines.push('Planned remediation (dry-run — nothing was changed):');
    for (const step of result.plan) lines.push(`  → ${step.kind}: ${step.description}`);
    lines.push('');
    lines.push('To apply on a host where a gateway reload is acceptable, re-run with:');
    lines.push('  SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 shieldcortex repair');
    return lines;
  }

  lines.push('');
  lines.push('Applied remediation:');
  for (const s of result.stepResults) lines.push(`  ${s.ok ? '✓' : '✗'} ${s.kind}: ${s.detail}`);
  lines.push('');
  if (result.ok) {
    lines.push('✓ reconciled: plugin confirmed loaded (roster) and enforcing (canary).');
  } else {
    lines.push('✗ FAILED: could not confirm the plugin is loaded AND enforcing.');
    for (const m of result.messages) {
      if (/fail|not confirmed|not run|did not/i.test(m)) lines.push(`  ${m}`);
    }
  }
  return lines;
}

function scanDuplicateDirs(home: string, pluginId: string, canonical: string | null): string[] {
  try {
    const dirs = fs
      .readdirSync(path.join(home, '.openclaw', 'npm', 'projects'))
      .filter((d) => d.includes(pluginId));
    if (canonical) return dirs.filter((d) => d !== canonical);
    // No canonical resolvable: keep the shortest (likely the base install), prune the rest.
    const sorted = [...dirs].sort((a, b) => a.length - b.length);
    return sorted.slice(1);
  } catch {
    return [];
  }
}
