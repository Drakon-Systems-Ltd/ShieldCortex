/**
 * #260 Sol r2 — pre-change live evidence must not certify a changed repair.
 *
 * Repair changes the host (here: restores a wiped registration), restarts the
 * gateway, then runs the self-check. If that restart failed, was skipped, or
 * was never PROVEN back up (a new process started after the request), the
 * self-check read the gateway as it was before the change — the old process,
 * which may well still have the plugin loaded. Before r3 a passing self-check
 * there reported "Protected" and `ok: true`.
 *
 * Everything is injected; nothing touches a live gateway.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import type { GatewayReloadResult, ReconcileOptions } from '../openclaw-reconcile.js';
import type { ReconcileInput } from '../../integrations/openclaw-plugin-index.js';
import type { SelfCheckRunResult } from '../openclaw-selfcheck.js';
import { expectNoLaunch, installLaunchTripwire, isolateHostEnv } from '../../__tests__/support/openclaw-host-isolation.js';

// #260 r15 (Jarvis 1): a tripwire on every real launcher, before the code under test loads.
const tripwire = installLaunchTripwire();
const {
  reconcileOpenClawPluginState,
  formatReconcileReport,
  protectionLedgerFromReconcile,
  manualGatewayRestartCommand,
} = await import('../openclaw-reconcile.js');
const { reconcilePluginState } = await import('../../integrations/openclaw-plugin-index.js');

// #260 r15 (Jarvis 1): HOME is a temp dir (this suite's executor runs default
// to os.homedir()), host-pointing variables scrubbed, no real launcher runs.
let isolatedHome: string;
let restoreEnv: () => void;
beforeEach(() => {
  isolatedHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-260-evidence-'));
  restoreEnv = isolateHostEnv(isolatedHome);
  tripwire.reset();
});
afterEach(() => {
  try {
    expectNoLaunch(tripwire);
  } finally {
    restoreEnv();
    fs.rmSync(isolatedHome, { recursive: true, force: true });
  }
});

const PLUGIN = 'shieldcortex-realtime';

function wiped(): ReconcileInput {
  return {
    pluginId: PLUGIN,
    expectedVersion: '5.22.1',
    config: { enabled: null, inAllow: false, readable: true, present: true },
    installsJson: { version: '5.22.1', installPath: '/x' },
    index: {
      installRecords: { [PLUGIN]: { source: 'npm', version: '5.22.1', installPath: '/x' } },
      plugins: [],
      warning: null,
    },
    onDiskVersion: '5.22.1',
    projectDirs: [],
    liveRoster: [PLUGIN],
  };
}

function healthy(): ReconcileInput {
  return {
    ...wiped(),
    config: { enabled: true, inAllow: true, readable: true, present: true },
    index: { ...wiped().index!, plugins: [{ pluginId: PLUGIN, enabled: true }] },
  };
}

const passing = {
  ok: true, rosterProof: true, rosterState: 'loaded', canaryProof: true, versionProof: true, reasons: ['loaded and enforcing'],
  index: null, liveRoster: [PLUGIN], canary: { ran: true, denied: true, auditEntryFound: true },
} as SelfCheckRunResult;
const failing = { ...passing, ok: false, canaryProof: false, reasons: ['canary not confirmed'] } as SelfCheckRunResult;

/** States read in order; the last one repeats. */
function states(...seq: Array<() => ReconcileInput>): ReconcileOptions['readState'] {
  let i = 0;
  return () => {
    const input = seq[Math.min(i, seq.length - 1)]();
    i += 1;
    return { input, verdict: reconcilePluginState(input) };
  };
}

function run(over: Partial<ReconcileOptions>) {
  return reconcileOpenClawPluginState({
    home: '/nonexistent/sc-260-evidence',
    pluginId: PLUGIN,
    expectedVersion: '5.22.1',
    apply: true,
    readState: states(wiped, healthy),
    restoreRegistration: () => ({ ok: true, detail: 'restored' }),
    runCommand: () => ({ status: 0, output: '' }),
    selfCheck: async () => passing,
    ...over,
  });
}

const RELOADS: Array<[string, () => Promise<GatewayReloadResult>, ReconcileOptions['waitForGateway'], 'failed' | 'skipped' | 'unconfirmed']> = [
  ['the restart command failed', async () => ({ restarted: false, attempted: true, detail: 'systemctl exited 1' }), undefined, 'failed'],
  ['the restart was skipped (no consent)', async () => ({ restarted: false, attempted: false, detail: 'restart skipped' }), undefined, 'skipped'],
  ['readiness could not be observed', async () => ({ restarted: true }), async () => ({ ready: false, reason: 'unobservable', waitedMs: 0 }), 'unconfirmed'],
  ['readiness timed out', async () => ({ restarted: true }), async () => ({ ready: false, reason: 'timeout', waitedMs: 90_000 }), 'unconfirmed'],
];

describe('#260 Sol r2 — a self-check on the pre-change gateway does not certify the repair', () => {
  it.each(RELOADS)('change landed, then %s, self-check passes ⇒ not ok, never "Protected"', async (_l, reloadGateway, waitForGateway, why) => {
    const res = await run({ reloadGateway, ...(waitForGateway ? { waitForGateway } : {}) });
    expect(res.ok).toBe(false);
    const sc = res.stepResults.filter((s) => s.kind === 'self-check');
    expect(sc[sc.length - 1]).toMatchObject({ ok: false, preChangeEvidence: true });
    expect(sc[sc.length - 1].detail).toMatch(/BEFORE this run's changes/);
    expect(res.messages.join(' ')).toMatch(/changes are not confirmed loaded/);

    const ledger = protectionLedgerFromReconcile(res);
    expect(ledger.outcome).toBe('unknown');
    expect(ledger.status).not.toBe('ok');
    const report = formatReconcileReport(res).join('\n');
    expect(report).not.toMatch(/✓ reconciled|Protected —/);
    expect(report).toMatch(/read the gateway as it was before the repair/);
    if (why === 'unconfirmed') {
      // A restart may still be starting: check first, never restart into it.
      expect(ledger.detail.join(' ')).toMatch(/next: shieldcortex doctor/);
      expect(report).not.toContain(`Next: ${manualGatewayRestartCommand()}`);
    } else {
      expect(report).toMatch(why === 'failed' ? /restart after them failed/ : /not restarted after them/);
    }
  });

  it('no change landed (the restore failed) ⇒ the self-check is current evidence, not flagged pre-change (still not ok: the step failed)', async () => {
    const res = await run({
      readState: states(wiped),
      restoreRegistration: () => ({ ok: false, detail: 'write refused' }),
      reloadGateway: async () => ({ restarted: false, attempted: true, detail: 'failed' }),
    });
    expect(res.stepResults.some((s) => s.preChangeEvidence === true)).toBe(false);
    expect(res.ok).toBe(false);
  });

  it('positive control — the restart after the change is PROVEN back up (a process started after the request) ⇒ ok, Protected', async () => {
    const res = await run({
      reloadGateway: async () => ({ restarted: true }),
      waitForGateway: async ({ startedAfterMs }) => {
        expect(typeof startedAfterMs).toBe('number');
        return { ready: true, waitedMs: 12 };
      },
    });
    expect(res.ok).toBe(true);
    expect(res.stepResults.some((s) => s.preChangeEvidence === true)).toBe(false);
    expect(protectionLedgerFromReconcile(res)).toMatchObject({ outcome: 'protected', status: 'ok' });
    expect(formatReconcileReport(res).join('\n')).toMatch(/✓ reconciled/);
  });

  describe('both repair passes', () => {
    it('pass 1 changes and its restart fails; pass 2 changes again, the restart fails again, the self-check passes ⇒ not ok', async () => {
      let selfChecks = 0;
      const res = await run({
        readState: states(wiped, wiped, wiped, healthy),
        reloadGateway: async () => ({ restarted: false, attempted: true, detail: 'systemctl exited 1' }),
        selfCheck: async () => (++selfChecks === 1 ? failing : passing),
      });
      expect(res.passes).toBe(2);
      expect(selfChecks).toBe(2);
      expect(res.ok).toBe(false);
      const sc = res.stepResults.filter((s) => s.kind === 'self-check');
      expect(sc).toHaveLength(2);
      expect(sc[1]).toMatchObject({ preChangeEvidence: true, ok: false });
      expect(protectionLedgerFromReconcile(res).outcome).toBe('unknown');
    });

    it('pass 1 restart proven back up, pass 2 changes again and its restart is NOT proven ⇒ pass 1\'s proof does not cover pass 2\'s change', async () => {
      let selfChecks = 0;
      let waits = 0;
      const res = await run({
        readState: states(wiped, wiped, wiped, healthy),
        reloadGateway: async () => ({ restarted: true }),
        waitForGateway: async () => (++waits === 1 ? { ready: true, waitedMs: 5 } : { ready: false, reason: 'unobservable', waitedMs: 0 }),
        selfCheck: async () => (++selfChecks === 1 ? failing : passing),
      });
      expect(res.passes).toBe(2);
      expect(res.ok).toBe(false);
      const sc = res.stepResults.filter((s) => s.kind === 'self-check');
      expect(sc[0].preChangeEvidence).toBeUndefined();
      expect(sc[1]).toMatchObject({ preChangeEvidence: true });
    });

    it('positive control — each pass\'s restart is proven back up after its change ⇒ pass 2\'s passing self-check certifies', async () => {
      let selfChecks = 0;
      const res = await run({
        readState: states(wiped, wiped, wiped, healthy),
        reloadGateway: async () => ({ restarted: true }),
        waitForGateway: async () => ({ ready: true, waitedMs: 5 }),
        selfCheck: async () => (++selfChecks === 1 ? failing : passing),
      });
      expect(res.passes).toBe(2);
      expect(res.ok).toBe(true);
      expect(res.stepResults.some((s) => s.preChangeEvidence === true)).toBe(false);
      expect(protectionLedgerFromReconcile(res).outcome).toBe('protected');
    });
  });
});
