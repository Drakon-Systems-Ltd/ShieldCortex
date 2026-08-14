/**
 * Failing-first spec for #156 — repair must converge, wait, and speak English.
 *
 * Field report, 1 Aug 2026. An operator ran repair on a host needing a pinned
 * reinstall. Every step succeeded, then:
 *
 *   ✗ FAILED: could not confirm the plugin is loaded AND enforcing.
 *   version proof FAILED: on-disk build 4.47.22 is OLDER than expected 4.47.24
 *
 * `shieldcortex doctor` seconds later: v4.47.24 current, running matches
 * on-disk, 29/32 green. The remediation had worked; repair re-read the state
 * before the gateway it had just restarted finished booting, and reported the
 * pre-restart world as the post-restart result.
 *
 * Three defects, all ours:
 *   1. the re-read raced the restart (#145's fix was half a fix),
 *   2. three env vars, where omitting one buys a paragraph of jargon,
 *   3. internal vocabulary — "roster proof", "plugins_json", "the 4.25.4
 *      class" — printed at an operator.
 */
import { describe, it, expect } from '@jest/globals';
import { waitForGatewayReady } from '../gateway-readiness.js';
import { resolveRepairConsent } from '../repair-consent.js';
import { reconcileOpenClawPluginState, MAX_RECONCILE_PASSES } from '../openclaw-reconcile.js';
import { reconcilePluginState, type ReconcileInput } from '../../integrations/openclaw-plugin-index.js';

// ── 1. The race that produced the false FAILED ─────────────────────────────

describe('#156 — repair waits for the gateway it just restarted', () => {
  /** A fake clock + process that turns over after `turnoverAfterPolls` polls. */
  function fakeGateway(opts: { turnoverAfterPolls: number; restartAt: number }) {
    let clock = opts.restartAt;
    let polls = 0;
    return {
      now: () => clock,
      sleep: async (ms: number) => { clock += ms; },
      readProcess: () => {
        polls += 1;
        return polls > opts.turnoverAfterPolls
          ? { pid: 999, startedAtMs: opts.restartAt + 1_000 }   // the NEW process
          : { pid: 111, startedAtMs: opts.restartAt - 60_000 }; // the OLD one, still there
      },
    };
  }

  it('does not accept the OLD process as proof the restart completed', async () => {
    // The exact bug: the pre-restart process is still visible for a moment, and
    // reading through it is what made a success look like a failure.
    const g = fakeGateway({ turnoverAfterPolls: 4, restartAt: 1_000_000 });
    const r = await waitForGatewayReady({ startedAfterMs: 1_000_000, ...g });
    expect(r.ready).toBe(true);
    if (r.ready) expect(r.process.startedAtMs).toBeGreaterThanOrEqual(1_000_000);
  });

  it('times out honestly when the process never turns over', async () => {
    const g = fakeGateway({ turnoverAfterPolls: Number.MAX_SAFE_INTEGER, restartAt: 1_000_000 });
    const r = await waitForGatewayReady({ startedAfterMs: 1_000_000, timeoutMs: 5_000, ...g });
    expect(r.ready).toBe(false);
    if (!r.ready) expect(r.reason).toBe('timeout');
  });

  it('distinguishes "cannot observe" from "did not restart"', async () => {
    // On a host with no boot-lifecycle table we cannot bound the evidence at
    // all. Calling that a failure would be the #142 overreach again.
    let clock = 0;
    const r = await waitForGatewayReady({
      startedAfterMs: 1_000_000,
      timeoutMs: 2_000,
      now: () => clock,
      sleep: async (ms) => { clock += ms; },
      readProcess: () => null,
    });
    expect(r.ready).toBe(false);
    if (!r.ready) expect(r.reason).toBe('unobservable');
  });

  it('returns immediately when the new process is already up', async () => {
    let clock = 5_000;
    const r = await waitForGatewayReady({
      startedAfterMs: 1_000,
      now: () => clock,
      sleep: async (ms) => { clock += ms; },
      readProcess: () => ({ pid: 7, startedAtMs: 4_000 }),
    });
    expect(r.ready).toBe(true);
    if (r.ready) expect(r.waitedMs).toBe(0);
  });
});

// ── 2. One command, not three environment variables ────────────────────────

describe('#156 — a human at a terminal has already consented', () => {
  const bare = { JEST_WORKER_ID: undefined } as NodeJS.ProcessEnv;

  it('an interactive run may reconcile, restart AND canary with no flags', () => {
    // The whole point of the command. Typing it IS the consent.
    const c = resolveRepairConsent({ env: bare, isTty: true });
    expect(c).toEqual({ reconcile: true, restart: true, canary: true, source: 'interactive' });
  });

  it('a headless run still requires each gate explicitly — the zeroth law is untouched', () => {
    const c = resolveRepairConsent({ env: bare, isTty: false });
    expect(c).toEqual({ reconcile: false, restart: false, canary: false, source: 'none' });
  });

  it('headless automation keeps the existing env vars working, per capability', () => {
    const c = resolveRepairConsent({
      env: { ...bare, SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE: '1', SHIELDCORTEX_ALLOW_GATEWAY_RESTART: '1' },
      isTty: false,
    });
    expect(c.reconcile).toBe(true);
    expect(c.restart).toBe(true);
    expect(c.canary).toBe(false);          // not asked for, not granted
    expect(c.source).toBe('env');
  });

  it('a test runner is never a consenting human, whatever the TTY says', () => {
    const c = resolveRepairConsent({ env: { JEST_WORKER_ID: '1' }, isTty: true });
    expect(c).toEqual({ reconcile: false, restart: false, canary: false, source: 'none' });
  });

  it('an agent inside the gateway cannot consent on the human\'s behalf', () => {
    // Non-TTY with no env is exactly the shape of an agent or cron run. It must
    // never restart the gateway it is itself running inside.
    expect(resolveRepairConsent({ env: bare, isTty: false }).restart).toBe(false);
  });
});

// ── 3. Detect → remediate → verify until stable, not one pass ──────────────

describe('#156 — repair converges instead of one-shot', () => {
  const PLUGIN = 'shieldcortex-realtime';

  function wiped(): ReconcileInput {
    return {
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
  }

  it('retries a restore that failed the first pass, then reports success', async () => {
    expect(MAX_RECONCILE_PASSES).toBeGreaterThanOrEqual(2);
    const input = wiped();
    let restores = 0;
    let enabled = false;
    const result = await reconcileOpenClawPluginState({
      home: '/tmp/sc-156-converge',
      pluginId: PLUGIN,
      expectedVersion: '4.50.0',
      apply: true,
      readState: () => {
        const i: ReconcileInput = enabled
          ? {
            ...input,
            config: { enabled: true, inAllow: true, readable: true, present: true },
            index: { ...input.index!, plugins: [{ pluginId: PLUGIN, enabled: true }] },
            liveRoster: [PLUGIN],
          }
          : input;
        return { input: i, verdict: reconcilePluginState(i) };
      },
      restoreRegistration: () => {
        restores += 1;
        if (restores === 1) return { ok: false, detail: 'first write raced' };
        enabled = true;
        return { ok: true, detail: 'restored on retry' };
      },
      runCommand: () => ({ status: 0, output: 'ok' }),
      reloadGateway: async () => ({ restarted: true, detail: 'reloaded' }),
      waitForGateway: async () => ({ ready: true, waitedMs: 5 }),
      selfCheck: async () => ({
        ok: enabled,
        rosterState: enabled ? 'present' : 'absent',
        rosterProof: enabled,
        canaryProof: enabled,
        versionProof: true,
        reasons: [enabled ? 'loaded' : 'not loaded'],
      }) as never,
    });
    expect(restores).toBeGreaterThanOrEqual(2);
    expect(result.ok).toBe(true);
    expect(result.passes).toBeGreaterThanOrEqual(2);
    expect(result.postVerdict?.state).toBe('healthy');
  });
});
