/**
 * #1179 r1 (Astra 1): an applied repair on the exact unknown-index case the
 * reconciler now handles — OpenClaw's plugin list present but unreadable, no
 * install record or build found, openclaw.json not enabling the plugin, the
 * gateway roster unread — plans only the self-check. That self-check reads
 * the roster as unproven and finds no version to compare (versionProof false
 * for want of one). The operator report used to turn that into "The installed
 * plugin is behind this CLI" with a forced `openclaw plugins install` as
 * "Next". No version was measured: the headline stays unknown and names no
 * install. A version that WAS measured older, and a roster proven absent,
 * keep their verdicts.
 *
 * Pure: the verdict, the plan and the self-check verdict come from the real
 * pure functions over synthetic input; the report is rendered from them.
 * Nothing reads the host. `child_process` is tripwired anyway and the
 * environment is scrubbed and restored, so a report path that grew a launch
 * or a host-env read fails here instead of reaching the host.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import type { ReconcileExecResult } from '../openclaw-reconcile.js';
import type { CanaryResult, SelfCheckVerdict } from '../openclaw-selfcheck.js';
import type { ReconcileInput, ReconcileVerdict } from '../../integrations/openclaw-plugin-index.js';
import { expectNoLaunch, installLaunchTripwire, isolateHostEnv } from '../../__tests__/support/openclaw-host-isolation.js';

const tripwire = installLaunchTripwire();

const { formatReconcileReport, protectionLedgerFromReconcile } = await import('../openclaw-reconcile.js');
const { evaluateSelfCheck } = await import('../openclaw-selfcheck.js');
const { reconcilePluginState, planReconcileActions } = await import('../../integrations/openclaw-plugin-index.js');
const { summariseRepair, renderRepairHeadline, versionProofUnmeasured } = await import('../repair-verdict.js');

const PLUGIN = 'shieldcortex-realtime';
const PKG = '@drakon-systems/shieldcortex-realtime';
const CLI = '5.22.1';
/** A downgrade claim or an install instruction, in any of the report's words. */
const DOWNGRADE = /behind|older|downgrade/i;
const INSTALL = /plugins install|npm i -g|--force/;

let home: string;
let restoreEnv: () => void;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1179-report-'));
  restoreEnv = isolateHostEnv(home);
  tripwire.reset();
});

afterEach(() => {
  try {
    expectNoLaunch(tripwire);
  } finally {
    restoreEnv();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

const NO_CANARY: CanaryResult = { ran: false, denied: false, auditEntryFound: false, detail: 'live canary needs consent' };

/** The reconciler's verdict for the unknown-index case, from its real input. */
const unknownIndexVerdict = (config: ReconcileInput['config']): ReconcileVerdict => reconcilePluginState({
  pluginId: PLUGIN,
  expectedVersion: CLI,
  config,
  installsJson: null,
  index: null,
  indexUnreadable: true,
  onDiskVersion: null,
  liveRoster: null,
});

/**
 * An applied, self-check-only run, shaped as the executor records it: one
 * self-check step, its reasons in the step detail and the failure message, and
 * the post-state re-read unchanged.
 */
const appliedSelfCheckOnly = (verdict: ReconcileVerdict, check: SelfCheckVerdict, canary: CanaryResult = NO_CANARY): ReconcileExecResult => {
  const why = check.reasons.join('; ');
  const last = (v: ReconcileVerdict): string => v.reasons[v.reasons.length - 1] ?? '';
  return {
    verdict,
    postVerdict: verdict,
    plan: planReconcileActions(verdict, { pluginId: PLUGIN, packageName: PKG, expectedVersion: CLI }),
    applied: true,
    stepResults: [{ kind: 'self-check', ok: false, detail: why }],
    selfCheck: { ...check, index: null, liveRoster: null, canary },
    ok: false,
    messages: [
      `state before remediation: ${verdict.state} (${verdict.severity}) — ${last(verdict)}`,
      `state after remediation: ${verdict.state} (${verdict.severity}) — ${last(verdict)}`,
      `self-check FAILED after remediation — plugin not confirmed loaded + enforcing: ${why}`,
    ],
  };
};

/** The self-check over that host: roster unread, no canary, and no version to read. */
const unreadCheck = (over: Partial<Parameters<typeof evaluateSelfCheck>[0]> = {}): SelfCheckVerdict => evaluateSelfCheck({
  pluginId: PLUGIN,
  index: null,
  liveRoster: null,
  canary: NO_CANARY,
  expectedVersion: CLI,
  onDiskVersion: null,
  ...over,
});

describe('#1179 r1: an unmeasured version stays unknown in the applied repair report', () => {
  it.each([
    ['no stanza at all', { enabled: null, inAllow: false }],
    ['an explicit enabled:false', { enabled: false, inAllow: false }],
  ] as const)('unreadable index + nothing found + config not enabling (%s): unknown, no downgrade claim, no install command', (_label, config) => {
    const verdict = unknownIndexVerdict({ ...config });
    expect(verdict).toMatchObject({ state: 'index-unreadable', severity: 'warn', recommendedAction: 'none' });
    const check = unreadCheck();
    // The self-check facts the finding names: roster unproven, and the
    // version proof failed because nothing was read, not because it differed.
    expect(check).toMatchObject({ ok: false, rosterState: 'unproven', versionProof: false, versionUnread: true });
    const result = appliedSelfCheckOnly(verdict, check);
    expect(result.plan.map((s) => s.kind)).toEqual(['self-check']);

    const full = formatReconcileReport(result).join('\n');
    const compact = formatReconcileReport(result, { compact: true }).join('\n');
    const ledger = protectionLedgerFromReconcile(result);

    expect(ledger.outcome).toBe('unknown');
    expect(ledger.status).not.toBe('failed');
    for (const text of [full, compact, ledger.detail.join('\n')]) {
      expect(text).not.toMatch(DOWNGRADE);
      expect(text).not.toMatch(INSTALL);
      expect(text).not.toMatch(/Not protected|unprotected/i);
    }
    expect(full.split('\n')[0]).toMatch(/^⚠️\s+Could not read which plugin version OpenClaw uses/);
    expect(full).toContain('   Next: shieldcortex doctor');
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
  });

  it('the same unread version with the plugin loaded and enforcing proven: unknown, never "an older version is installed"', () => {
    const passing: CanaryResult = { ran: true, denied: true, auditEntryFound: true };
    const check = unreadCheck({ liveRoster: [PLUGIN], canary: passing, onDiskReason: 'could not tell which copy OpenClaw selected — two copies' });
    expect(check).toMatchObject({ rosterState: 'loaded', canaryProof: true, versionProof: false, versionUnread: true });
    const v = summariseRepair({
      applied: true,
      canaryConsented: true,
      expectedVersion: CLI,
      onDiskVersion: null,
      selfCheck: { ok: check.ok, rosterState: check.rosterState, canaryProof: check.canaryProof, versionProof: check.versionProof, versionUnread: true },
    });
    expect(v.outcome).toBe('unknown');
    const text = renderRepairHeadline(v).join('\n');
    expect(text).not.toMatch(DOWNGRADE);
    expect(text).not.toMatch(INSTALL);
    expect(v.nextCommand).toBe('shieldcortex doctor');
  });
});

describe('#1179 r1 controls: measured stale versions and real roster failures keep their verdicts', () => {
  it('a selected copy measured OLDER, roster unread: still "behind" with the pinned install', () => {
    const check = unreadCheck({ onDiskVersion: '5.20.0' });
    expect(check).toMatchObject({ versionProof: false, rosterState: 'unproven' });
    expect(check.versionUnread).toBeUndefined();
    const result = appliedSelfCheckOnly(unknownIndexVerdict({ enabled: null, inAllow: false }), check);
    const ledger = protectionLedgerFromReconcile(result);
    expect(ledger.outcome).toBe('protected-unproven');
    expect(ledger.detail.join('\n')).toMatch(/behind this CLI/);
    expect(ledger.detail).toContain(`next: openclaw plugins install --force npm:${PKG}@${CLI}`);
  });

  it('a selected copy measured OLDER on a loaded gateway: still the silent-downgrade fault', () => {
    const check = unreadCheck({ onDiskVersion: '5.20.0', liveRoster: [PLUGIN] });
    expect(check).toMatchObject({ versionProof: false, rosterState: 'loaded' });
    const v = summariseRepair({
      applied: true, canaryConsented: true, expectedVersion: CLI,
      selfCheck: { ok: check.ok, rosterState: check.rosterState, canaryProof: check.canaryProof, versionProof: check.versionProof },
    });
    expect(v.outcome).toBe('unprotected');
    expect(v.nextCommand).toMatch(/npm i -g shieldcortex/);
  });

  it('the self-check read no version, but another layer measured one older: that measurement stands', () => {
    const v = summariseRepair({
      applied: true, canaryConsented: false, expectedVersion: CLI, onDiskVersion: '5.20.0',
      selfCheck: { ok: false, rosterState: 'unproven', canaryProof: false, versionProof: false, versionUnread: true },
    });
    expect(v.outcome).toBe('protected-unproven');
    expect(v.nextCommand).toBe(`openclaw plugins install --force npm:${PKG}@${CLI}`);
  });

  it('a roster proven ABSENT still says not protected, version read or not', () => {
    const check = unreadCheck({ liveRoster: ['some-other-plugin'] });
    expect(check).toMatchObject({ rosterState: 'absent', versionUnread: true });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(unknownIndexVerdict({ enabled: false, inAllow: false }), check));
    expect(ledger.outcome).toBe('unprotected');
    expect(ledger.status).toBe('failed');
    expect(ledger.detail.join('\n')).toMatch(/Not protected: the running gateway started without the ShieldCortex plugin/);
  });

  it('a hand-built verdict input that says nothing about readability keeps its old meaning (measured)', () => {
    expect(versionProofUnmeasured({ versionProof: false })).toBe(false);
    expect(versionProofUnmeasured({ versionProof: true, versionUnread: true })).toBe(false);
    expect(versionProofUnmeasured(undefined)).toBe(false);
    expect(versionProofUnmeasured({ versionProof: false, versionUnread: true }, null, CLI)).toBe(true);
    // A newer version from another layer is not "behind" evidence either.
    expect(versionProofUnmeasured({ versionProof: false, versionUnread: true }, '9.0.0', CLI)).toBe(true);
  });
});
