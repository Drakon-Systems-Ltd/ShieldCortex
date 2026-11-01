/**
 * #977 — one `shieldcortex update` process must exec the gateway restart at
 * most once.
 *
 * Field report: one update run issued two `systemctl --user restart
 * openclaw-gateway` calls 19s apart. The second landed while the first stop
 * was still draining (TimeoutStopUSec=330s); the gateway exited 1 and the
 * agent DB refused every turn until a manual `doctor --fix`. The second call
 * was reconcile pass 2 asking for another `gateway-reload`.
 *
 * Nothing here can reach a live gateway: the exec is always a fake, the
 * process latch is primed with that fake before any real call path runs, and
 * PATH points nowhere for the tests that open the consent gates, so even a
 * broken latch could not find `systemctl` / `launchctl`.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  createGatewayRestartOnce,
  processGatewayRestartLatch,
  resetGatewayRestartLatchForTests,
  restartOpenClawGateway,
  type GatewayRestartResult,
} from '../deep-clean.js';
import {
  reconcileOpenClawPluginState,
  protectionFactsFromReconcile,
  protectionLedgerFromReconcile,
  manualGatewayRestartCommand,
  type GatewayReloadResult,
  type ReconcileExecResult,
  type ReconcileOptions,
  type StepResult,
} from '../openclaw-reconcile.js';
import { summariseRepair } from '../repair-verdict.js';
import { reconcilePluginState, type ReconcileInput } from '../../integrations/openclaw-plugin-index.js';
import { buildUpdateSummary, type UpdateSummaryInput } from '../../cli/update-summary.js';

const OK: GatewayRestartResult = { attempted: true, restarted: true, method: 'fake' };

function countingExec(result: GatewayRestartResult = OK) {
  const exec = Object.assign(
    () => {
      exec.calls += 1;
      return result;
    },
    { calls: 0 },
  );
  return exec;
}

beforeEach(() => {
  resetGatewayRestartLatchForTests();
});

afterEach(() => {
  resetGatewayRestartLatchForTests();
});

describe('#977 — once-per-run restart coordinator (pure)', () => {
  it('plugin/install request then reconcile request: one exec, second gets the first outcome', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    const first = await once.run(exec);   // stand-in: installer / plugin step
    const second = await once.run(exec);  // stand-in: reconcile
    expect(exec.calls).toBe(1);
    expect(first.restarted).toBe(true);
    expect(first.reused).toBeUndefined();
    expect(second).toEqual({ ...first, reused: true });
  });

  it('reconcile pass 1 then pass 2 (and a later request): still one exec', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    const pass1 = await once.run(exec);
    const pass2 = await once.run(exec);
    const later = await once.run(exec);
    expect(exec.calls).toBe(1);
    expect(pass2.requestedAtMs).toBe(pass1.requestedAtMs);
    expect(later.requestedAtMs).toBe(pass1.requestedAtMs);
    expect(pass2.reused).toBe(true);
  });

  it('two overlapping requests share one in-flight execution', async () => {
    const once = createGatewayRestartOnce();
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let calls = 0;
    const slowExec = async (): Promise<GatewayRestartResult> => {
      calls += 1;
      await gate;
      return OK;
    };
    const a = once.run(slowExec);
    const b = once.run(slowExec);
    // Let any (wrongly) scheduled second exec start before releasing.
    await Promise.resolve();
    await Promise.resolve();
    release();
    const [ra, rb] = await Promise.all([a, b]);
    expect(calls).toBe(1);
    expect(rb).toEqual({ ...ra, reused: true });
  });

  it('a failed first restart is not retried in the same run', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec({ attempted: true, restarted: false, method: 'fake', detail: 'unit failed' });
    await once.run(exec);
    const again = await once.run(exec);
    expect(exec.calls).toBe(1);
    expect(again.restarted).toBe(false);
    expect(again.detail).toBe('unit failed');
  });

  it('a throwing exec settles as a failed restart and still latches', async () => {
    const once = createGatewayRestartOnce();
    let calls = 0;
    const boom = () => { calls += 1; throw new Error('boom'); };
    const r1 = await once.run(boom);
    const r2 = await once.run(boom);
    expect(calls).toBe(1);
    expect(r1).toMatchObject({ attempted: true, restarted: false, detail: 'boom' });
    expect(r2.reused).toBe(true);
  });

  it('reset() forgets the restart (test isolation only)', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    await once.run(exec);
    once.reset();
    await once.run(exec);
    expect(exec.calls).toBe(2);
  });
});

/** Open the consent gates for one test, with PATH pointing nowhere. */
async function withGatesOpen(fn: () => Promise<void>): Promise<void> {
  const keys = ['JEST_WORKER_ID', 'NODE_ENV', 'SHIELDCORTEX_SKIP_GATEWAY_RESTART', 'SHIELDCORTEX_ALLOW_GATEWAY_RESTART', 'PATH'] as const;
  const saved = new Map<string, string | undefined>(keys.map((k) => [k, process.env[k]]));
  delete process.env.JEST_WORKER_ID;
  process.env.NODE_ENV = 'production';
  delete process.env.SHIELDCORTEX_SKIP_GATEWAY_RESTART;
  process.env.SHIELDCORTEX_ALLOW_GATEWAY_RESTART = '1';
  process.env.PATH = '/nonexistent-sc977';
  try {
    await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

describe('#977 — restartOpenClawGateway goes through the process latch', () => {
  it('under Jest it still never execs and never touches the latch', async () => {
    expect(process.env.JEST_WORKER_ID).toBeDefined();
    const r = await restartOpenClawGateway();
    expect(r.method).toBe('skipped');
    expect(r.reused).toBeUndefined();
    // The latch is still free: a primed exec runs.
    const exec = countingExec();
    await processGatewayRestartLatch.run(exec);
    expect(exec.calls).toBe(1);
  });

  it('headless without consent still skips, latch or not', async () => {
    const exec = countingExec();
    await processGatewayRestartLatch.run(exec);
    const keys = ['JEST_WORKER_ID', 'NODE_ENV', 'SHIELDCORTEX_ALLOW_GATEWAY_RESTART'] as const;
    const saved = new Map<string, string | undefined>(keys.map((k) => [k, process.env[k]]));
    const tty = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
    Object.defineProperty(process.stdin, 'isTTY', { value: undefined, configurable: true });
    delete process.env.JEST_WORKER_ID;
    process.env.NODE_ENV = 'production';
    delete process.env.SHIELDCORTEX_ALLOW_GATEWAY_RESTART;
    try {
      const r = await restartOpenClawGateway();
      expect(r.method).toBe('skipped');
      expect(r.detail).toMatch(/non-interactive/);
      expect(r.reused).toBeUndefined();
    } finally {
      for (const [k, v] of saved) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      if (tty) Object.defineProperty(process.stdin, 'isTTY', tty);
      else Reflect.deleteProperty(process.stdin, 'isTTY');
    }
  });

  it('with consent, a second request returns the first restart instead of exec-ing', async () => {
    const exec = countingExec();
    const first = await processGatewayRestartLatch.run(exec); // the run's one restart
    await withGatesOpen(async () => {
      const second = await restartOpenClawGateway();
      expect(second).toEqual({ ...first, reused: true });
    });
    expect(exec.calls).toBe(1);
  });

  it('reconcile pass 1 and pass 2 (default reload path) cannot bypass the latch', async () => {
    const PLUGIN = 'shieldcortex-realtime';
    const input: ReconcileInput = {
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
    const exec = countingExec();
    const first = await processGatewayRestartLatch.run(exec); // the installer's restart
    const waits: number[] = [];
    let result!: ReconcileExecResult;
    await withGatesOpen(async () => {
      result = await reconcileOpenClawPluginState({
        home: '/tmp/sc-977-never-read',
        pluginId: PLUGIN,
        expectedVersion: '4.50.0',
        apply: true,
        grantConversationAccess: false,
        // Never converges, so pass 2 runs and plans another gateway-reload.
        readState: () => ({ input, verdict: reconcilePluginState(input) }),
        restoreRegistration: () => ({ ok: false, detail: 'still wiped' }),
        runCommand: () => ({ status: 0, output: 'ok' }),
        // reloadGateway deliberately NOT injected: the default path is the one under test.
        waitForGateway: async ({ startedAfterMs }) => {
          waits.push(startedAfterMs);
          return { ready: true, waitedMs: 5 };
        },
        selfCheck: async () => ({
          ok: false,
          rosterState: 'absent',
          rosterProof: false,
          canaryProof: false,
          versionProof: true,
          reasons: ['not loaded'],
        }) as never,
      });
    });
    expect(result.passes).toBe(2);
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads.length).toBe(2);
    expect(exec.calls).toBe(1);
    // The installer's restart predates both passes' registration writes, so
    // neither pass may call it a completed reload (#977 review).
    for (const s of reloads) {
      expect(s.ok).toBe(false);
      expect(s.restart).toBe('pending');
      expect(s.detail).toMatch(/restart pending/);
    }
    expect(result.ok).toBe(false);
    // Readiness is still measured from the ONE restart, not from each pass.
    expect(waits).toEqual([first.requestedAtMs, first.requestedAtMs]);
  });
});

describe('#977 review — a reused restart that predates later changes is owed, not completed', () => {
  const PLUGIN = 'shieldcortex-realtime';
  // Registration wiped: every pass plans restore-registration → reload → self-check.
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
  const proven = { ok: true, rosterState: 'loaded', rosterProof: true, canaryProof: true, versionProof: true, reasons: [] };

  function baseOptions(over: Partial<ReconcileOptions>): ReconcileOptions {
    return {
      home: '/tmp/sc-977-never-read',
      pluginId: PLUGIN,
      expectedVersion: '4.50.0',
      apply: true,
      grantConversationAccess: false,
      readState: () => ({ input: wiped, verdict: reconcilePluginState(wiped) }),
      restoreRegistration: () => ({ ok: true, detail: 'restored' }),
      runCommand: () => ({ status: 0, output: 'ok' }),
      waitForGateway: async () => ({ ready: true, waitedMs: 5 }),
      ...over,
    };
  }

  it('two passes: pass 1 restarts, pass 2 re-registers after it — pass 2 reports a pending restart and nothing claims protection', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    let selfChecks = 0;
    const result = await reconcileOpenClawPluginState(baseOptions({
      reloadGateway: () => once.run(exec) as Promise<GatewayReloadResult>,
      // Pass 1 sees the plugin absent; pass 2's self-check reads the gateway
      // pass 1's restart started — it may even look proven. It must not count.
      selfCheck: async () => ((selfChecks += 1) === 1 ? absent : proven) as never,
    }));
    expect(result.passes).toBe(2);
    expect(exec.calls).toBe(1); // the one-restart rule still holds
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads.map((s) => s.restart)).toEqual(['completed', 'pending']);
    expect(reloads.map((s) => s.ok)).toEqual([true, false]);
    expect(result.ok).toBe(false);
    expect(result.messages.join('\n')).toMatch(/gateway restart pending/);

    const ledger = protectionLedgerFromReconcile(result);
    expect(ledger.outcome).not.toBe('protected');
    expect(ledger.status).not.toBe('ok');
    expect(ledger.facts.gatewayRestart).toBe('pending');
    expect(ledger.detail.join(' ')).not.toMatch(/^Protected/);
    expect(ledger.facts.nextCommand).toBe(manualGatewayRestartCommand());
  });

  it('an earlier step restarted before pass 1 changed anything: the restart is owed, still one exec', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    await once.run(exec); // an earlier step's restart (e.g. the installer)
    const result = await reconcileOpenClawPluginState(baseOptions({
      reloadGateway: () => once.run(exec) as Promise<GatewayReloadResult>,
      selfCheck: async () => absent as never,
    }));
    expect(exec.calls).toBe(1);
    expect(protectionFactsFromReconcile(result).gatewayRestart).toBe('pending');
    expect(result.ok).toBe(false);
  });

  it('a reused restart requested AFTER the last change did load it — completed, not pending', async () => {
    const later = Date.now() + 60_000;
    const result = await reconcileOpenClawPluginState(baseOptions({
      reloadGateway: async () => ({ restarted: true, attempted: true, reused: true, requestedAtMs: later }),
      selfCheck: async () => proven as never,
    }));
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads.map((s) => s.restart)).toEqual(['completed']);
    expect(result.ok).toBe(true);
  });

  it('a fresh (non-reused) restart after changes is never pending', async () => {
    const result = await reconcileOpenClawPluginState(baseOptions({
      reloadGateway: async () => ({ restarted: true, attempted: true, requestedAtMs: Date.now() }),
      selfCheck: async () => proven as never,
    }));
    expect(result.stepResults.find((s) => s.kind === 'gateway-reload')?.restart).toBe('completed');
    expect(result.ok).toBe(true);
  });

  it('summariseRepair never says protected while a restart is owed', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      selfCheck: { ok: true, rosterState: 'loaded', canaryProof: true, versionProof: true },
      restartPending: true,
      restartCommand: 'systemctl --user restart openclaw-gateway',
    });
    expect(v.outcome).not.toBe('protected');
    expect(v.nextCommand).toBe('systemctl --user restart openclaw-gateway');
  });
});

describe('#977 — restart outcome reaches the closing screen', () => {
  function reconcileWith(steps: StepResult[]): ReconcileExecResult {
    const input: ReconcileInput = {
      pluginId: 'shieldcortex-realtime',
      expectedVersion: '5.0.0',
      config: { enabled: true, inAllow: true, readable: true, present: true },
      installsJson: { version: '5.0.0', installPath: '/x' },
      index: null,
      onDiskVersion: '5.0.0',
      projectDirs: [],
      liveRoster: [],
    } as unknown as ReconcileInput;
    const verdict = reconcilePluginState(input);
    return { verdict, postVerdict: verdict, plan: [], applied: true, stepResults: steps, ok: false, messages: [] };
  }
  const reload = (ok: boolean, detail: string, restart?: StepResult['restart']): StepResult =>
    ({ kind: 'gateway-reload', ok, detail, ...(restart ? { restart } : {}) });

  it('maps reload steps to completed / timed-out / unconfirmed / skipped / absent', () => {
    expect(protectionFactsFromReconcile(reconcileWith([reload(true, 'reloaded and ready in 1.0s', 'completed')])).gatewayRestart).toBe('completed');
    expect(protectionFactsFromReconcile(reconcileWith([
      reload(true, 'reloaded, but readiness timed out — the checks below may be reading a gateway that is still starting', 'timed-out'),
    ])).gatewayRestart).toBe('timed-out');
    // "could not be observed" is NOT a timeout.
    expect(protectionFactsFromReconcile(reconcileWith([
      reload(true, 'reloaded, but readiness could not be observed — …', 'unconfirmed'),
    ])).gatewayRestart).toBe('unconfirmed');
    expect(protectionFactsFromReconcile(reconcileWith([
      reload(false, 'non-interactive session — gateway restart skipped', 'skipped'),
    ])).gatewayRestart).toBe('skipped');
    expect(protectionFactsFromReconcile(reconcileWith([])).gatewayRestart).toBeUndefined();
  });

  it('falls back to the detail text for steps without the structured field', () => {
    expect(protectionFactsFromReconcile(reconcileWith([reload(true, 'reloaded, but readiness timed out — x')])).gatewayRestart).toBe('timed-out');
    expect(protectionFactsFromReconcile(reconcileWith([reload(true, 'reloaded, but readiness could not be observed — x')])).gatewayRestart).toBe('unconfirmed');
    expect(protectionFactsFromReconcile(reconcileWith([reload(false, 'gateway restart suppressed (test runner)')])).gatewayRestart).toBe('skipped');
  });

  it('a timed-out restart sets gatewayReloaded but the restart outcome says timed out', () => {
    const facts = protectionFactsFromReconcile(reconcileWith([reload(true, 'reloaded, but readiness timed out — x', 'timed-out')]));
    expect(facts.gatewayReloaded).toBe(true);
    expect(facts.gatewayRestart).toBe('timed-out');
  });

  function summaryInput(protection: Partial<UpdateSummaryInput['protection']>): UpdateSummaryInput {
    return {
      fromVersion: '5.17.0',
      toVersion: '5.17.1',
      packageState: 'updated',
      engine: { ok: true },
      plugin: { status: 'ok' },
      skill: { status: 'ok' },
      guardOn: false,
      protection: { status: 'ok', loaded: 'yes', pluginVersion: '5.17.1', ...protection },
    };
  }
  function openClawText(protection: Partial<UpdateSummaryInput['protection']>): string {
    const row = buildUpdateSummary(summaryInput(protection)).rows.find((r) => r.label === 'OpenClaw');
    expect(row).toBeDefined();
    return row!.text;
  }

  it('renders completed, timed out and skipped in plain words', () => {
    expect(openClawText({ gatewayReloaded: true, gatewayRestart: 'completed' })).toBe('plugin 5.17.1 loaded, gateway restarted');
    expect(openClawText({ gatewayReloaded: true, gatewayRestart: 'timed-out' })).toBe('plugin 5.17.1 loaded, gateway restart timed out');
    expect(openClawText({ gatewayReloaded: false, gatewayRestart: 'skipped' })).toBe('plugin 5.17.1 loaded, gateway restart skipped');
  });

  it('never calls an unobservable readiness a timeout', () => {
    const text = openClawText({ gatewayReloaded: true, gatewayRestart: 'unconfirmed' });
    expect(text).not.toMatch(/timed out/);
    expect(text).toMatch(/gateway restarted but not confirmed back up/);
  });

  function openClawRow(protection: Partial<UpdateSummaryInput['protection']>) {
    return buildUpdateSummary(summaryInput(protection)).rows.find((r) => r.label === 'OpenClaw')!;
  }

  it('#977 review: failed / timed-out / unconfirmed / pending restarts are never a green row', () => {
    for (const outcome of ['failed', 'timed-out', 'unconfirmed', 'pending'] as const) {
      for (const status of ['ok', 'unproven'] as const) {
        const row = openClawRow({ status, gatewayRestart: outcome, restartCommand: 'systemctl --user restart openclaw-gateway' });
        expect(row.mark).toBe('check');
        expect(row.command).toBeTruthy();
        expect(row.why).toBeTruthy();
      }
    }
    const headline = buildUpdateSummary(summaryInput({ gatewayRestart: 'timed-out' })).headline;
    expect(headline).toBe('check');
  });

  it('#977 review: the next action is safe for each outcome', () => {
    const cmd = 'systemctl --user restart openclaw-gateway';
    // Nothing restarted, or the one restart finished before later changes: restart.
    expect(openClawRow({ gatewayRestart: 'failed', restartCommand: cmd })).toMatchObject({ command: cmd, commandLabel: 'Fix' });
    expect(openClawRow({ gatewayRestart: 'pending', restartCommand: cmd })).toMatchObject({ command: cmd, commandLabel: 'Fix' });
    // A restart may still be in flight: restarting again is the #977 hazard.
    expect(openClawRow({ gatewayRestart: 'timed-out', restartCommand: cmd })).toMatchObject({ command: 'shieldcortex doctor', commandLabel: 'Check' });
    expect(openClawRow({ gatewayRestart: 'unconfirmed', restartCommand: cmd })).toMatchObject({ command: 'shieldcortex doctor', commandLabel: 'Check' });
    // No verified restart command on this platform: fall back to doctor.
    expect(openClawRow({ gatewayRestart: 'failed' })).toMatchObject({ command: 'shieldcortex doctor', commandLabel: 'Check' });
    expect(openClawText({ gatewayRestart: 'pending' })).toBe('plugin 5.17.1 loaded, gateway needs one more restart');
  });

  it('completed and skipped stay green', () => {
    expect(openClawRow({ gatewayRestart: 'completed' }).mark).toBe('ok');
    expect(openClawRow({ gatewayRestart: 'skipped' }).mark).toBe('ok');
  });

  it('says nothing about a restart when no outcome is given — even if gatewayReloaded is set', () => {
    expect(openClawText({})).toBe('plugin 5.17.1 loaded');
    expect(openClawText({ gatewayReloaded: true })).toBe('plugin 5.17.1 loaded');
  });
});
