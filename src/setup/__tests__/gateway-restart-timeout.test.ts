/**
 * A service-manager restart command that times out is uncertain, not failed.
 *
 * `systemctl --user restart` / `launchctl kickstart -k` run under execSync with
 * a 10s timeout. A gateway whose stop drains for longer (TimeoutStopUSec=330s
 * in the #977 field report) makes the command time out while the restart is
 * still in progress. Reported as a failed restart, the closing screen offered
 * the restart command, which is exactly the second restart #977 forbids. A
 * timeout now reads `timed-out`: "may still be starting", check with doctor.
 *
 * Nothing here execs anything: the failure is built from a fake error and the
 * reload is injected.
 */
import { describe, expect, it } from '@jest/globals';
import { gatewayRestartExecFailure } from '../deep-clean.js';
import {
  reconcileOpenClawPluginState,
  protectionFactsFromReconcile,
  type GatewayReloadResult,
} from '../openclaw-reconcile.js';
import { reconcilePluginState, type ReconcileInput } from '../../integrations/openclaw-plugin-index.js';
import { buildUpdateSummary } from '../../cli/update-summary.js';

/** What execSync throws: an Error carrying the spawnSync fields. */
function execError(fields: { code?: string; signal?: string; status?: number | null }): Error {
  return Object.assign(new Error('Command failed: systemctl --user restart openclaw-gateway'), fields);
}

describe('gatewayRestartExecFailure', () => {
  it('a timeout (ETIMEDOUT, killed by SIGTERM) is timedOut, not a plain failure', () => {
    for (const err of [execError({ code: 'ETIMEDOUT', signal: 'SIGTERM', status: null }), execError({ signal: 'SIGTERM', status: null })]) {
      expect(gatewayRestartExecFailure('systemctl --user', err)).toMatchObject({
        attempted: true, restarted: false, method: 'systemctl --user', timedOut: true,
      });
    }
  });

  it('a non-zero exit is still a failure', () => {
    const r = gatewayRestartExecFailure('launchctl kickstart', execError({ status: 1 }));
    expect(r).toMatchObject({ attempted: true, restarted: false, method: 'launchctl kickstart' });
    expect(r.timedOut).toBeUndefined();
  });
});

describe('reconcile and the closing screen read a timed-out restart command as uncertain', () => {
  const PLUGIN = 'shieldcortex-realtime';
  const wiped: ReconcileInput = {
    pluginId: PLUGIN,
    expectedVersion: '4.50.0',
    config: { enabled: null, inAllow: false, readable: true, present: true },
    installsJson: { version: '4.50.0', installPath: '/x' },
    index: {
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.50.0', installPath: '/x' } },
      plugins: [],
      warning: null,
    },
    onDiskVersion: '4.50.0',
    projectDirs: [],
    liveRoster: [],
  };
  const absent = { ok: false, rosterState: 'absent', rosterProof: false, canaryProof: false, versionProof: true, reasons: ['not loaded'] };

  async function reconcileWith(reload: GatewayReloadResult) {
    return reconcileOpenClawPluginState({
      home: '/tmp/sc-restart-timeout-never-read',
      pluginId: PLUGIN,
      expectedVersion: '4.50.0',
      apply: true,
      grantConversationAccess: false,
      readState: () => ({ input: wiped, verdict: reconcilePluginState(wiped) }),
      restoreRegistration: () => ({ ok: true, detail: 'restored' }),
      runCommand: () => ({ status: 0, output: 'ok' }),
      waitForGateway: async () => ({ ready: true, waitedMs: 5 }),
      reloadGateway: async () => reload,
      selfCheck: async () => absent as never,
    });
  }

  function gatewayRow(facts: ReturnType<typeof protectionFactsFromReconcile>) {
    const summary = buildUpdateSummary({
      fromVersion: '5.17.1', toVersion: '5.17.2', packageState: 'updated',
      engine: { ok: true }, plugin: { status: 'ok' }, skill: { status: 'ok' },
      guardOn: false,
      protection: { status: 'unproven', gatewayRestart: facts.gatewayRestart, ...(facts.restartCommand ? { restartCommand: facts.restartCommand } : {}) },
    });
    return JSON.stringify(summary.rows);
  }

  it('timedOut: outcome timed-out, no restart command, the screen says check with doctor', async () => {
    const failure = gatewayRestartExecFailure('systemctl --user', execError({ code: 'ETIMEDOUT', signal: 'SIGTERM', status: null }));
    const result = await reconcileWith({ restarted: false, attempted: true, detail: failure.detail, timedOut: true });
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads.length).toBeGreaterThan(0);
    for (const s of reloads) {
      expect(s.restart).toBe('timed-out');
      expect(s.detail).toMatch(/may still be restarting.*shieldcortex doctor/);
    }
    const facts = protectionFactsFromReconcile(result);
    expect(facts.gatewayRestart).toBe('timed-out');
    expect(facts.restartCommand).toBeUndefined();
    const row = gatewayRow(facts);
    expect(row).toContain('shieldcortex doctor');
    expect(row).not.toContain('systemctl');
  });

  it('control: a restart command that exited non-zero is still failed and offers the restart', async () => {
    const result = await reconcileWith({ restarted: false, attempted: true, detail: 'Command failed: exit 1' });
    const facts = protectionFactsFromReconcile(result);
    expect(facts.gatewayRestart).toBe('failed');
    expect(facts.restartCommand).toBeDefined();
  });
});
