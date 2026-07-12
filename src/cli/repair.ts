/**
 * `shieldcortex repair` — fix a broken install in place.
 *
 * Two passes:
 *  1. Heal the better-sqlite3 native binding (the #1 post-update breakage on
 *     arm64 / newer-than-prebuilt Node): verify → rebuild → re-verify.
 *  2. Reconcile the OpenClaw realtime plugin's install metadata (#74): detect
 *     the conflicted-metadata / silent-drop state across installs.json, the
 *     SQLite install index, and the config enable flag, and (with operator
 *     consent) route it through the correct remediation, then hard-verify the
 *     plugin actually loaded + enforces. Diagnosis is always safe; execution
 *     requires SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 because it reloads the
 *     gateway.
 */

import {
  ensureNativeBinding,
  rebuildNativeBinding,
  verifyNativeBindingInDir,
  nativeBindingRemediation,
  resolveSelfInstallDir,
} from '../setup/native-binding.js';
import { discoverShieldcortexInstalls } from '../setup/install-discovery.js';
import { createRequire } from 'module';
import fs from 'fs';

const require = createRequire(import.meta.url);
const pkg = require('../../package.json') as { version: string };

const isTTY = Boolean(process.stdout.isTTY);
const c = (code: string, s: string) => (isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);

export async function runRepair(_args: string[] = []): Promise<void> {
  process.stdout.write(`\n  ${c('35', '◆')} ${c('1', 'ShieldCortex repair')}\n\n`);
  process.stdout.write(`  ${c('90', 'Checking the native database engine (better-sqlite3)…')}\n`);

  const r = await ensureNativeBinding();

  if (r.status === 'ok') {
    process.stdout.write(`  ${c('32', '✓')}  Database engine: healthy (no rebuild needed)\n`);
  } else if (r.status === 'healed') {
    process.stdout.write(`  ${c('32', '✓')}  Database engine: rebuilt and verified\n`);
    process.stdout.write(`  ${c('90', 'Restart Claude Code / the OpenClaw gateway so running processes reload it.')}\n`);
  } else {
    // failed
    process.stdout.write(`  ${c('31', '✗')}  Database engine: still cannot load after a rebuild\n`);
    if (r.error) process.stdout.write(`     ${c('90', r.error.split('\n')[0])}\n`);

    // Surface the REAL build error, not just the load failure. `rebuildOutput`
    // is from the forced `--build-from-source` attempt, so it carries the
    // actual compiler/node-gyp output (e.g. "g++: command not found").
    const buildTail = (r.rebuildOutput ?? '').trim();
    if (buildTail) {
      const lines = buildTail.split('\n').slice(-12);
      process.stdout.write(`\n  ${c('90', 'Build output (last lines):')}\n`);
      for (const line of lines) process.stdout.write(`     ${c('90', line)}\n`);
    }

    process.stdout.write(`\n  ${c('1', 'Fix it manually:')}\n`);
    for (const line of (r.remediation ?? '').split('\n')) {
      process.stdout.write(`     ${c('33', line)}\n`);
    }
    process.stdout.write('\n');
    process.exitCode = 1;
    return; // A broken engine blocks the reconciler (it needs to read the index).
  }

  await repairOtherInstalls();

  await runPluginReconcilePass();
}

/**
 * Repair every OTHER discovered ShieldCortex install (#76, requirement 4).
 *
 * The engine check above heals only the RUNNING install. On a multi-install
 * host, an MCP client may spawn a different install whose binding is still
 * broken — the "layer split" that made `repair` report a false all-clear.
 * Discover all installs, warn if there's a split, and rebuild + verify each
 * other one in its own dir (verify runs in a subprocess so it checks THAT
 * install's binding, not this process's).
 */
async function repairOtherInstalls(): Promise<void> {
  let installs;
  try {
    installs = discoverShieldcortexInstalls();
  } catch {
    return; // Discovery is best-effort; never let it break the primary repair.
  }

  let self = resolveSelfInstallDir();
  try { self = fs.realpathSync(self); } catch { /* use raw */ }
  const others = installs.filter((i) => i.path !== self);

  if (others.length === 0) return;

  process.stdout.write(
    `\n  ${c('33', '⚠')}  Multi-install layer-split: ${installs.length} ShieldCortex installs found — ` +
    `healing the ${others.length} not running this command too.\n`,
  );
  for (const inst of installs) {
    const tag = inst.path === self ? ' (this command)' : '';
    process.stdout.write(`     ${c('90', `• ${inst.path} [${inst.sources.join(', ')}]${tag}`)}\n`);
  }

  for (const inst of others) {
    process.stdout.write(`\n  ${c('90', `Rebuilding ${inst.path}…`)}\n`);
    // A plain rebuild first, then verify in-dir; escalate to a source build if needed.
    await rebuildNativeBinding(inst.path);
    let v = await verifyNativeBindingInDir(inst.path);
    if (!v.ok) {
      await rebuildNativeBinding(inst.path, { fromSource: true });
      v = await verifyNativeBindingInDir(inst.path);
    }
    if (v.ok) {
      process.stdout.write(`  ${c('32', '✓')}  ${inst.path}: rebuilt and verified\n`);
    } else {
      process.stdout.write(`  ${c('31', '✗')}  ${inst.path}: still cannot load after a rebuild\n`);
      if (v.error) process.stdout.write(`     ${c('90', v.error.split('\n')[0])}\n`);
      for (const line of nativeBindingRemediation(inst.path).split('\n')) {
        process.stdout.write(`     ${c('33', line)}\n`);
      }
      process.exitCode = 1;
    }
  }
}

/**
 * Second repair pass: reconcile the OpenClaw plugin install metadata and verify
 * honest state. Best-effort — a host without OpenClaw simply reports "not
 * detected" and returns cleanly.
 */
async function runPluginReconcilePass(): Promise<void> {
  process.stdout.write(`\n  ${c('90', 'Checking the OpenClaw realtime plugin (install metadata + honest load state)…')}\n`);
  try {
    const { reconcileOpenClawPluginState, formatReconcileReport } = await import('../setup/openclaw-reconcile.js');
    const result = await reconcileOpenClawPluginState({ expectedVersion: pkg.version });
    for (const line of formatReconcileReport(result)) {
      process.stdout.write(`  ${line}\n`);
    }
    process.stdout.write('\n');
    // Applied-but-failed is a hard error (never report a false all-clear).
    if (result.applied && !result.ok) process.exitCode = 1;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stdout.write(`  ${c('90', `OpenClaw plugin check skipped — ${msg}`)}\n\n`);
  }
}
