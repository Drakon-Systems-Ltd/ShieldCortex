import { describe, expect, it } from '@jest/globals';
import { reconcileOpenClawPluginState } from '../openclaw-reconcile.js';
import {
  reconcilePluginState,
  type ReconcileInput,
} from '../../integrations/openclaw-plugin-index.js';

/**
 * #226 — the remediation for "installed on disk but not enabled in config" has
 * to write the config. It used to run `openclaw plugins install --force` /
 * `plugins update`: a reinstall of a package that was already present and
 * correct, which never touches `plugins.entries[id].enabled`. The plan ran, the
 * commands exited 0, and the host stayed exactly as unprotected as it started —
 * a remediation that reported success without changing the thing that was wrong.
 *
 * Everything here is injected: no gateway, no installer, no real openclaw.json.
 */

const PLUGIN = 'shieldcortex-realtime';

function wipedStanzaInput(): ReconcileInput {
  return {
    pluginId: PLUGIN,
    expectedVersion: '4.47.35',
    // Installed on disk, nothing in config enables it.
    config: { enabled: null, inAllow: false, readable: true, present: true },
    installsJson: { version: '4.47.35', installPath: '/x' },
    index: {
      installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.35', installPath: '/x' } },
      plugins: [],
      warning: null,
    },
    onDiskVersion: '4.47.35',
    projectDirs: [],
    liveRoster: [],
  };
}

function harness(over: { enableOk?: boolean } = {}) {
  const ran: string[][] = [];
  const enableCalls: Array<{ home: string; pluginId: string }> = [];
  const input = wipedStanzaInput();
  let enabled = false;

  return {
    ran,
    enableCalls,
    run: () =>
      reconcileOpenClawPluginState({
        home: '/tmp/does-not-exist-sc226',
        pluginId: PLUGIN,
        expectedVersion: '4.47.35',
        apply: true,
        readState: () => {
          // After the enable step lands, the world reads as enabled + loaded.
          const i: ReconcileInput = enabled
            ? {
              ...input,
              config: { enabled: true, inAllow: true, readable: true, present: true },
              index: {
                ...input.index!,
                plugins: [{ pluginId: PLUGIN, enabled: true }],
              },
              liveRoster: [PLUGIN],
            }
            : input;
          return { input: i, verdict: reconcilePluginState(i) };
        },
        enablePluginConfig: (home, pluginId) => {
          enableCalls.push({ home, pluginId });
          const ok = over.enableOk !== false;
          if (ok) enabled = true;
          return { ok, detail: ok ? 'restored: entry missing' : 'restore write failed' };
        },
        runCommand: (argv) => {
          ran.push(argv);
          return { status: 0, output: 'ok' };
        },
        reloadGateway: async () => ({ restarted: true, detail: 'reloaded' }),
        waitForGateway: async () => ({ ready: true, waitedMs: 10 }),
        selfCheck: async () => ({
          ok: enabled,
          rosterState: enabled ? 'present' : 'absent',
          rosterProof: enabled,
          canaryProof: enabled,
          versionProof: true,
          reasons: [enabled ? 'loaded + enforcing' : 'not loaded'],
        }) as never,
      }),
  };
}

describe('#226 reconcile executor — enable-plugin-config', () => {
  it('writes the config instead of shelling out to the installer', async () => {
    const h = harness();
    const result = await h.run();

    expect(result.plan.map((s) => s.kind)).toEqual([
      'enable-plugin-config',
      'gateway-reload',
      'self-check',
    ]);
    expect(h.enableCalls).toEqual([{ home: '/tmp/does-not-exist-sc226', pluginId: PLUGIN }]);
    // The regression in one line: no installer command was run.
    expect(h.ran).toEqual([]);
  });

  it('reports success only after the post-remediation re-read and self-check agree', async () => {
    const result = await harness().run();
    expect(result.ok).toBe(true);
    expect(result.postVerdict?.state).toBe('healthy');
    expect(result.stepResults.find((s) => s.kind === 'enable-plugin-config')?.ok).toBe(true);
  });

  it('a failed enable is a FAILED reconcile — never masked by a clean command list', async () => {
    // The old `commandsOk` filter only looked at steps whose kind starts with
    // "openclaw". A plan made entirely of a config write would have had an
    // empty command list, and `[].every(...)` is true.
    const result = await harness({ enableOk: false }).run();
    expect(result.ok).toBe(false);
    expect(result.stepResults.find((s) => s.kind === 'enable-plugin-config')?.ok).toBe(false);
    expect(result.messages.join(' ')).toMatch(/could not enable the plugin in openclaw\.json/i);
    expect(result.postVerdict?.state).toBe('installed-not-enabled');
  });
});
