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
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { nextCausalSeq } from '../causal-seq.js';
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
  gatewayRestartOutcomeFromSteps,
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
    // #977 review: the causal ticket is the first request's, on every reuse.
    expect(typeof pass1.requestedSeq).toBe('number');
    expect(pass2.requestedSeq).toBe(pass1.requestedSeq);
    expect(later.requestedSeq).toBe(pass1.requestedSeq);
  });

  it('the causal ticket is taken at request time and survives a throwing exec', async () => {
    const once = createGatewayRestartOnce();
    const before = nextCausalSeq();
    const r1 = await once.run(() => { throw new Error('boom'); });
    const after = nextCausalSeq();
    const r2 = await once.run(() => OK);
    expect(r1.requestedSeq).toBeGreaterThan(before);
    expect(r1.requestedSeq).toBeLessThan(after);
    expect(r2).toMatchObject({ reused: true, requestedSeq: r1.requestedSeq });
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
    // The reuse-with-nothing-changed case (#977 review): both restores FAILED,
    // so nothing was applied after the installer's restart and the readiness
    // path still speaks for the running gateway.
    for (const s of reloads) {
      expect(s.ok).toBe(true);
      expect(s.detail).toMatch(/not repeated/);
      expect(s.restart).toBe('completed');
    }
    expect(protectionFactsFromReconcile(result).gatewayRestart).toBe('completed');
    expect(result.messages.join('\n')).not.toMatch(/gateway restart pending/);
    // Readiness is measured from the ONE restart, not from each pass.
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
    expect(reloads[1].detail).toContain(manualGatewayRestartCommand());
    expect(reloads[1].detail).not.toMatch(/ready/);
    expect(result.ok).toBe(false);
    expect(result.messages.join('\n')).toMatch(/gateway restart pending/);
    expect(result.messages.join('\n')).not.toMatch(/reconciled: plugin confirmed/);

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

  it('a step that failed changed nothing: the reused restart keeps the readiness path', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    await once.run(exec); // an earlier step's restart
    const result = await reconcileOpenClawPluginState(baseOptions({
      restoreRegistration: () => ({ ok: false, detail: 'write did not land' }),
      reloadGateway: () => once.run(exec) as Promise<GatewayReloadResult>,
      selfCheck: async () => absent as never,
    }));
    expect(exec.calls).toBe(1);
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads.length).toBeGreaterThan(0);
    for (const s of reloads) expect(s).toMatchObject({ ok: true, restart: 'completed' });
    expect(protectionFactsFromReconcile(result).gatewayRestart).toBe('completed');
    expect(result.messages.join('\n')).not.toMatch(/gateway restart pending/);
    expect(result.ok).toBe(false); // the failed restore is the finding, not the restart
  });

  it('a reused restart requested AFTER the last change did load it — completed, not pending', async () => {
    const later = Date.now() + 60_000;
    const result = await reconcileOpenClawPluginState(baseOptions({
      // Ticket taken at reload time — after restore-registration's change.
      reloadGateway: async () => ({ restarted: true, attempted: true, reused: true, requestedAtMs: later, requestedSeq: nextCausalSeq() }),
      selfCheck: async () => proven as never,
    }));
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads.map((s) => s.restart)).toEqual(['completed']);
    expect(result.ok).toBe(true);
  });

  it('a fresh (non-reused) restart after changes is never pending', async () => {
    const result = await reconcileOpenClawPluginState(baseOptions({
      reloadGateway: async () => ({ restarted: true, attempted: true, requestedAtMs: Date.now(), requestedSeq: nextCausalSeq() }),
      selfCheck: async () => proven as never,
    }));
    expect(result.stepResults.find((s) => s.kind === 'gateway-reload')?.restart).toBe('completed');
    expect(result.ok).toBe(true);
  });

  it('a reused restart with no causal ticket after a change stays conservative: pending', async () => {
    const result = await reconcileOpenClawPluginState(baseOptions({
      reloadGateway: async () => ({ restarted: true, attempted: true, reused: true, requestedAtMs: Date.now() + 60_000 }),
      selfCheck: async () => proven as never,
    }));
    expect(protectionFactsFromReconcile(result).gatewayRestart).toBe('pending');
    expect(result.ok).toBe(false);
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

describe('#977 review r3 — an unproven restart that predates later changes is never "restart it now"', () => {
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
  const proven = { ok: true, rosterState: 'loaded', rosterProof: true, canaryProof: true, versionProof: true, reasons: [] };
  const RESTART = /systemctl|launchctl|openclaw gateway restart|restart the gateway once more|Restart the gateway/i;

  for (const [reason, expected] of [['timeout', 'timed-out'], ['unobservable', 'unconfirmed']] as const) {
    it(`pass 1 readiness ${reason}, pass 2 changes and reuses: stays ${expected}, doctor not a restart, one exec`, async () => {
      const once = createGatewayRestartOnce();
      const exec = countingExec();
      let selfChecks = 0;
      const result = await reconcileOpenClawPluginState({
        home: '/tmp/sc-977-never-read',
        pluginId: PLUGIN,
        expectedVersion: '4.50.0',
        apply: true,
        grantConversationAccess: false,
        readState: () => ({ input: wiped, verdict: reconcilePluginState(wiped) }),
        // Lands in BOTH passes — pass 2's lands after the run's one restart.
        restoreRegistration: () => ({ ok: true, detail: 'restored' }),
        runCommand: () => ({ status: 0, output: 'ok' }),
        reloadGateway: () => once.run(exec) as Promise<GatewayReloadResult>,
        waitForGateway: async () => ({ ready: false, reason, waitedMs: 90_000 }),
        // Pass 2's self-check may even look proven: it read an unproven gateway.
        selfCheck: async () => ((selfChecks += 1) === 1 ? absent : proven) as never,
      });
      expect(result.passes).toBe(2);
      expect(exec.calls).toBe(1); // exactly one real restart
      const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
      expect(reloads.map((s) => s.restart)).toEqual([expected, expected]);
      expect(reloads[1].ok).toBe(false);
      expect(reloads[1].changesUnloaded).toBe(true);
      expect(reloads[1].detail).toMatch(/not confirmed loaded/);
      expect(reloads[1].detail).toMatch(/shieldcortex doctor/);
      expect(reloads[1].detail).not.toContain(manualGatewayRestartCommand());
      expect(result.ok).toBe(false);
      const messages = result.messages.join('\n');
      expect(messages).not.toMatch(/gateway restart pending/);
      expect(messages).not.toContain(manualGatewayRestartCommand());
      expect(messages).not.toMatch(/reconciled: plugin confirmed/);
      expect(messages).toMatch(/shieldcortex doctor/);

      const facts = protectionFactsFromReconcile(result);
      expect(facts.gatewayRestart).toBe(expected);
      expect(facts.restartCommand).toBeUndefined();
      expect(facts.changesUnloaded).toBe(true);

      const ledger = protectionLedgerFromReconcile(result);
      expect(ledger.outcome).not.toBe('protected');
      expect(ledger.status).not.toBe('ok');
      expect(ledger.facts.gatewayRestart).toBe(expected);
      expect(ledger.facts.restartCommand).toBeUndefined();
      expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
      expect(ledger.detail.join('\n')).not.toMatch(RESTART);
      expect(ledger.detail.join('\n')).not.toContain(manualGatewayRestartCommand());

      // The closing screen, fed exactly as update.ts feeds it.
      const summary = buildUpdateSummary({
        fromVersion: '5.17.0',
        toVersion: '5.17.1',
        packageState: 'updated',
        engine: { ok: true },
        plugin: { status: 'ok' },
        skill: { status: 'ok' },
        guardOn: false,
        protection: {
          status: ledger.status,
          loaded: ledger.facts.loaded,
          pluginVersion: ledger.facts.pluginVersion,
          gatewayRestart: ledger.facts.gatewayRestart,
          ...(ledger.facts.restartCommand ? { restartCommand: ledger.facts.restartCommand } : {}),
          ...(ledger.facts.changesUnloaded ? { changesUnloaded: true } : {}),
          nextCommand: ledger.facts.nextCommand,
        },
      });
      const row = summary.rows.find((r) => r.label === 'OpenClaw')!;
      expect(row.mark).not.toBe('ok');
      expect(row).toMatchObject({ command: 'shieldcortex doctor', commandLabel: 'Check' });
      expect(row.why).toMatch(/Later changes aren't loaded yet/);
      expect(`${row.text} ${row.why}`).not.toMatch(/one more restart/);
      expect(JSON.stringify(summary)).not.toContain(manualGatewayRestartCommand());
    });
  }

  it('gatewayRestartOutcomeFromSteps: unsafe readiness outranks pending, pending outranks the last outcome', () => {
    const r = (restart: StepResult['restart'], ok = restart === 'completed'): StepResult =>
      ({ kind: 'gateway-reload', ok, detail: 'x', restart });
    expect(gatewayRestartOutcomeFromSteps([])).toBeUndefined();
    expect(gatewayRestartOutcomeFromSteps([r('timed-out'), r('pending')])).toBe('timed-out');
    expect(gatewayRestartOutcomeFromSteps([r('pending'), r('timed-out')])).toBe('timed-out');
    expect(gatewayRestartOutcomeFromSteps([r('unconfirmed'), r('pending')])).toBe('unconfirmed');
    expect(gatewayRestartOutcomeFromSteps([r('pending'), r('unconfirmed')])).toBe('unconfirmed');
    expect(gatewayRestartOutcomeFromSteps([r('unconfirmed'), r('timed-out')])).toBe('timed-out');
    expect(gatewayRestartOutcomeFromSteps([r('pending'), r('completed')])).toBe('pending');
    expect(gatewayRestartOutcomeFromSteps([r('completed'), r('pending')])).toBe('pending');
    expect(gatewayRestartOutcomeFromSteps([r('failed'), r('completed')])).toBe('completed');
    expect(gatewayRestartOutcomeFromSteps([r('completed'), r('skipped', false)])).toBe('skipped');
    // Legacy step shapes still read their readiness from the detail text.
    expect(gatewayRestartOutcomeFromSteps([
      { kind: 'gateway-reload', ok: true, detail: 'reloaded, but readiness timed out — x' },
      r('pending'),
    ])).toBe('timed-out');
  });

  it('summariseRepair: restartPending with readiness unproven gives doctor, never restart advice', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      selfCheck: { ok: true, rosterState: 'loaded', canaryProof: true, versionProof: true },
      readinessUnproven: true,
      restartPending: true,
      restartCommand: 'systemctl --user restart openclaw-gateway',
    });
    expect(v.outcome).not.toBe('protected');
    expect(v.nextCommand).toBe('shieldcortex doctor');
    expect(v.headline).not.toMatch(/Restart the gateway|restart it once more|systemctl/);
    expect(v.headline).toMatch(/not loaded yet/);
    expect(v.headline).toMatch(/not confirmed back up/);
  });
});

describe('#977 review 5727106863 — change/restart order is causal, not wall-clock', () => {
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
  const PINNED_MS = 1_790_000_000_000;

  beforeEach(() => {
    // Every event below lands in the same millisecond.
    jest.spyOn(Date, 'now').mockReturnValue(PINNED_MS);
  });
  afterEach(() => {
    jest.restoreAllMocks();
  });

  function options(over: Partial<ReconcileOptions>): ReconcileOptions {
    return {
      home: '/tmp/sc-977-never-read',
      pluginId: PLUGIN,
      expectedVersion: '4.50.0',
      apply: true,
      grantConversationAccess: false,
      readState: () => ({ input: wiped, verdict: reconcilePluginState(wiped) }),
      runCommand: () => ({ status: 0, output: 'ok' }),
      waitForGateway: async () => ({ ready: true, waitedMs: 0 }),
      selfCheck: async () => absent as never,
      ...over,
    };
  }

  it('the counter is strictly increasing even with the clock frozen', () => {
    const seen = Array.from({ length: 50 }, () => nextCausalSeq());
    for (let i = 1; i < seen.length; i += 1) expect(seen[i]).toBeGreaterThan(seen[i - 1]);
    expect(Date.now()).toBe(PINNED_MS);
  });

  it('change → restart in the same ms, then pass 2 changes nothing: the reused restart loaded the change — completed, not pending', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    let restores = 0;
    const result = await reconcileOpenClawPluginState(options({
      // Pass 1's restore lands; pass 2's write fails (no new change).
      restoreRegistration: () => ((restores += 1) === 1
        ? { ok: true, detail: 'restored' }
        : { ok: false, detail: 'write did not land' }),
      reloadGateway: () => once.run(exec) as Promise<GatewayReloadResult>,
    }));
    expect(result.passes).toBe(2);
    expect(exec.calls).toBe(1);
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads.map((s) => s.restart)).toEqual(['completed', 'completed']);
    expect(protectionFactsFromReconcile(result).gatewayRestart).toBe('completed');
    expect(protectionLedgerFromReconcile(result).facts.gatewayRestart).not.toBe('pending');
    expect(result.messages.join('\n')).not.toMatch(/gateway restart pending/);
  });

  it('restart → change in the same ms: the reused restart did NOT load the change — pending', async () => {
    const once = createGatewayRestartOnce();
    const exec = countingExec();
    await once.run(exec); // an earlier step's restart, same millisecond
    const result = await reconcileOpenClawPluginState(options({
      restoreRegistration: () => ({ ok: true, detail: 'restored' }),
      reloadGateway: () => once.run(exec) as Promise<GatewayReloadResult>,
    }));
    expect(exec.calls).toBe(1);
    const reloads = result.stepResults.filter((s) => s.kind === 'gateway-reload');
    expect(reloads[0].restart).toBe('pending');
    expect(protectionFactsFromReconcile(result).gatewayRestart).toBe('pending');
    expect(result.ok).toBe(false);
    expect(result.messages.join('\n')).toMatch(/gateway restart pending/);
  });
});
