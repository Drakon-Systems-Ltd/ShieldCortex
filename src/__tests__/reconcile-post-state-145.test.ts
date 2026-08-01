/**
 * Failing-first spec for #145 — repair's closing report must describe the
 * world AFTER remediation, never echo the pre-remediation snapshot.
 *
 * Field evidence, 31 Jul 2026: a real operator upgrade applied its plan,
 * reloaded the gateway, and then printed "FAILED … state: version-regressed
 * (fail) — running version 4.47.16 is older than expected 4.47.19". The
 * remediation had worked — the journal showed v4.47.19 registered during the
 * very reload repair performed, and doctor seconds later agreed. The false red
 * sends an operator to re-remediate a healthy box, and when two of our own
 * commands disagree about the same fact, the operator cannot know which to
 * believe.
 */
import { describe, it, expect } from '@jest/globals';
import {
  reconcileOpenClawPluginState,
  formatReconcileReport,
} from '../setup/openclaw-reconcile.js';
import type { ReconcileInput, ReconcileVerdict } from '../integrations/openclaw-plugin-index.js';
import { reconcilePluginState } from '../integrations/openclaw-plugin-index.js';

const PLUGIN = 'shieldcortex-realtime';

function inputWith(overrides: Partial<ReconcileInput>): ReconcileInput {
  return {
    pluginId: PLUGIN,
    expectedVersion: '4.47.19',
    config: { enabled: true, inAllow: true },
    installsJson: null,
    index: {
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.19' } },
      plugins: [{ pluginId: PLUGIN, enabled: true }],
      warning: null,
    },
    onDiskVersion: '4.47.19',
    projectDirs: [],
    liveRoster: [PLUGIN],
    ...overrides,
  };
}

/** The exact field timeline: regressed before, healthy after the reload. */
function twoPhaseReadState(): () => { input: ReconcileInput; verdict: ReconcileVerdict } {
  let calls = 0;
  return () => {
    calls += 1;
    const input =
      calls === 1
        ? inputWith({ onDiskVersion: '4.47.16', index: { installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.16' } }, plugins: [{ pluginId: PLUGIN, enabled: true }], warning: null } })
        : inputWith({});
    return { input, verdict: reconcilePluginState(input) };
  };
}

const passingSelfCheck = {
  ok: true,
  rosterProof: true,
  rosterState: 'loaded' as const,
  canaryProof: true,
  versionProof: true,
  reasons: ['roster proof', 'canary proof', 'version proof'],
  index: null,
  liveRoster: [PLUGIN],
  canary: { ran: true, denied: true, auditEntryFound: true },
};

describe('#145 — the closing state is re-read after remediation', () => {
  it('reports the POST-remediation state, not the pre-remediation snapshot', async () => {
    const result = await reconcileOpenClawPluginState({
      expectedVersion: '4.47.19',
      apply: true,
      readState: twoPhaseReadState(),
      runCommand: () => ({ status: 0, output: 'ok' }),
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
      pruneDir: () => void 0,
    });

    expect(result.ok).toBe(true);
    expect(result.postVerdict).toBeDefined();
    expect(result.postVerdict?.state).toBe('healthy');
    // The pre state is preserved as history, clearly labelled.
    expect(result.verdict.state).toBe('version-regressed');
    expect(result.messages.join(' ')).toMatch(/state after remediation: healthy/);
  });

  it('the rendered report never re-prints the stale pre state under the failure banner', async () => {
    // Failure case (canary withheld): the report must not echo the
    // pre-remediation "version-regressed" as if it were current.
    const result = await reconcileOpenClawPluginState({
      expectedVersion: '4.47.19',
      apply: true,
      readState: twoPhaseReadState(),
      runCommand: () => ({ status: 0, output: 'ok' }),
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => ({
        ...passingSelfCheck,
        ok: false,
        canaryProof: false,
        canary: { ran: false, denied: false, auditEntryFound: false, detail: 'no consent' },
        reasons: ['canary proof FAILED: enforcement canary was not executed'],
      }),
      pruneDir: () => void 0,
    });

    const report = formatReconcileReport(result).join('\n');
    expect(report).toMatch(/Plugin load state after remediation: healthy/);
    // The field bug, verbatim shape: pre-state echoed after FAILED.
    const afterFailed = report.slice(report.indexOf('FAILED'));
    expect(afterFailed).not.toMatch(/version-regressed/);
    expect(afterFailed).not.toMatch(/state before remediation/);
  });

  it('a dry-run carries no postVerdict — nothing changed, so there is nothing to re-read', async () => {
    const result = await reconcileOpenClawPluginState({
      expectedVersion: '4.47.19',
      apply: false,
      readState: twoPhaseReadState(),
      runCommand: () => ({ status: 0, output: 'ok' }),
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
      pruneDir: () => void 0,
    });
    expect(result.applied).toBe(false);
    expect(result.postVerdict).toBeUndefined();
  });
});
