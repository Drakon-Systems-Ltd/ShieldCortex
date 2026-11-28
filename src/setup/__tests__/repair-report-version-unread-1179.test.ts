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
const { evaluateSelfCheck, runPluginSelfCheck } = await import('../openclaw-selfcheck.js');
const { reconcilePluginState, planReconcileActions } = await import('../../integrations/openclaw-plugin-index.js');
const { summariseRepair, renderRepairHeadline, versionProofUnmeasured } = await import('../repair-verdict.js');
const { readSelectedRealtimePluginVersion, readSelectedRealtimePluginVersionDetail } = await import('../../integrations/openclaw-realtime-install.js');

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

/**
 * #1179 r2 (Astra r2). Two ways the r1 headline still misreported a version:
 *
 * 1. Conflicting copies. The post-remediation verdict read the build OpenClaw
 *    selected (its package.json unreadable, its own manifest 4.0.0) while a
 *    different copy on disk is 5.22.1. The self-check's stricter reader stops
 *    at the unreadable package.json, so its proof has no version. Both report
 *    paths passed only the other copy's 5.22.1, and the headline said the
 *    version "could not be read" over a post-state that read it stale. The
 *    headline now goes by the post-state's selected-build reading, and only
 *    that one: never another copy, an install record, or the pre-remediation
 *    snapshot.
 * 2. Known wrong source. A selected copy installed from somewhere other than
 *    npm or a local path was read, and its version is known; the proof fails
 *    on its source. That is no longer reported as an unread version.
 */
const SELECTED = '/linked/shieldcortex-realtime';
/** The reconciler over the conflicting copies: the selected build at `selected`, a current copy elsewhere on disk. */
const conflictingCopies = (selected: string, roster: string[] | null): ReconcileVerdict => reconcilePluginState({
  pluginId: PLUGIN,
  expectedVersion: CLI,
  config: { enabled: true, inAllow: true },
  installsJson: null,
  index: {
    installRecords: { [PLUGIN]: { source: 'npm', version: CLI, installPath: SELECTED } },
    plugins: [{ pluginId: PLUGIN, enabled: true, rootDir: SELECTED }],
  },
  indexRootDirExists: true,
  selectedVersion: selected,
  onDiskVersion: CLI,
  liveRoster: roster,
});
const STRICT_UNREAD = `could not tell which copy OpenClaw selected — the copy OpenClaw's install index roster names: ${SELECTED}/package.json could not be read (EACCES)`;
/** The headline and its Next line: the only lines the operator is told to act on. */
const head = (lines: string[]): string => lines.slice(0, 2).join('\n');

describe('#1179 r2: the post-state\'s selected-build reading classifies the headline', () => {
  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('conflicting copies (selected 4.0.0, a 5.22.1 copy elsewhere), self-check unread — %s: stale by the selected build, never "could not read", next doctor', (_l, roster) => {
    const post = conflictingCopies('4.0.0', roster ? [...roster] : null);
    expect(post).toMatchObject({
      state: 'version-regressed', installedVersion: '4.0.0', installedVersionSource: 'selected-build', onDiskVersion: CLI,
    });
    const check = unreadCheck({ liveRoster: roster ? [...roster] : null, onDiskReason: STRICT_UNREAD });
    expect(check).toMatchObject({ versionProof: false, versionUnread: true });
    const result = appliedSelfCheckOnly(post, check);

    const full = formatReconcileReport(result);
    const compact = formatReconcileReport(result, { compact: true });
    const ledger = protectionLedgerFromReconcile(result);
    for (const text of [head(full), head(compact), ledger.detail.join('\n')]) {
      expect(text).not.toMatch(/Could not read/i);
      expect(text).toMatch(/the build OpenClaw selected is v4\.0\.0, older than 5\.22\.1/);
      expect(text).not.toMatch(INSTALL);
    }
    // Major 4 under a 5.x CLI: the major-upgrade lag, as for any measured copy.
    expect(ledger.outcome).toBe('protected-unproven');
    expect(full[1]).toBe('   Next: shieldcortex doctor');
    expect(compact[1]).toBe('   Next: shieldcortex doctor');
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
    // The compact chip names the selected reading, not the other copy.
    expect(compact.join('\n')).toMatch(/\bv4\.0\.0\b/);
    expect(compact.join('\n')).not.toMatch(/\bv5\.22\.1\b/);
    expect(ledger.summary).toMatch(/\bv4\.0\.0\b/);
  });

  it('the same conflict one minor behind on a loaded gateway: the downgrade fault, named by the selected build, next doctor', () => {
    const post = conflictingCopies('5.20.0', [PLUGIN]);
    expect(post).toMatchObject({ installedVersion: '5.20.0', installedVersionSource: 'selected-build', onDiskVersion: CLI });
    const check = unreadCheck({ liveRoster: [PLUGIN], onDiskReason: STRICT_UNREAD });
    const result = appliedSelfCheckOnly(post, check);
    const full = formatReconcileReport(result);
    const compact = formatReconcileReport(result, { compact: true });
    const ledger = protectionLedgerFromReconcile(result);
    expect(ledger.outcome).toBe('unprotected');
    for (const text of [head(full), head(compact), ledger.detail.join('\n')]) {
      expect(text).toMatch(/Not protected by the build you expect: the build OpenClaw selected is v5\.20\.0, older than 5\.22\.1/);
      expect(text).not.toMatch(/Could not read/i);
      expect(text).not.toMatch(INSTALL);
    }
    expect(full[0]).toMatch(/^❌ Not protected/);
    expect(full[1]).toBe('   Next: shieldcortex doctor');
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
  });

  it('the reverse conflict (selected 5.22.1, an older copy elsewhere), self-check unread: not "behind" on the other copy; unknown, next doctor', () => {
    const v = summariseRepair({
      applied: true, canaryConsented: false, expectedVersion: CLI, onDiskVersion: '5.20.0',
      installedVersion: CLI, installedVersionSource: 'selected-build',
      selfCheck: { ok: false, rosterState: 'unproven', canaryProof: false, versionProof: false, versionUnread: true },
    });
    expect(v.outcome).toBe('unknown');
    expect(v.headline).not.toMatch(DOWNGRADE);
    expect(v.headline).not.toMatch(/Could not read/i);
    expect(v.headline).toMatch(/v5\.22\.1/);
    expect(v.nextCommand).toBe('shieldcortex doctor');
  });

  it.each(['disk', 'index-record', 'record-path-build', null] as const)('a %s reading is never taken as the selected copy: self-check unread, the other layer current ⇒ the r1 unread headline', (source) => {
    const v = summariseRepair({
      applied: true, canaryConsented: false, expectedVersion: CLI, onDiskVersion: CLI,
      installedVersion: '4.0.0', installedVersionSource: source,
      selfCheck: { ok: false, rosterState: 'unproven', canaryProof: false, versionProof: false, versionUnread: true },
    });
    expect(v).toMatchObject({ outcome: 'unknown', nextCommand: 'shieldcortex doctor' });
    expect(v.headline).toMatch(/^Could not read which plugin version OpenClaw uses/);
    expect(v.headline).not.toMatch(/4\.0\.0/);
  });

  it('an install-record claim from the real reconciler (selection unread, record 4.0.0, no scan build) stays the r1 unread headline', () => {
    const post = reconcilePluginState({
      pluginId: PLUGIN, expectedVersion: CLI, config: { enabled: true, inAllow: true }, installsJson: null,
      index: { installRecords: { [PLUGIN]: { source: 'npm', version: '4.0.0', installPath: SELECTED } }, plugins: [{ pluginId: PLUGIN, enabled: true, rootDir: SELECTED }] },
      indexRootDirExists: true, selectedVersion: null, onDiskVersion: null, liveRoster: null,
    });
    expect(post).toMatchObject({ installedVersion: '4.0.0', installedVersionSource: 'index-record' });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(post, unreadCheck({ onDiskReason: STRICT_UNREAD })));
    expect(ledger.outcome).toBe('unknown');
    expect(ledger.detail[0]).toMatch(/^Could not read which plugin version OpenClaw uses/);
    expect(ledger.detail.join('\n')).not.toMatch(INSTALL);
  });

  it('the pre-remediation snapshot is not the post-state: a stale selected build before, none read after ⇒ the r1 unread headline', () => {
    const before = conflictingCopies('4.0.0', null);
    const after = unknownIndexVerdict({ enabled: null, inAllow: false });
    const result = { ...appliedSelfCheckOnly(after, unreadCheck()), verdict: before };
    for (const lines of [formatReconcileReport(result), formatReconcileReport(result, { compact: true })]) {
      expect(lines[0]).toMatch(/^⚠️\s+Could not read which plugin version OpenClaw uses/);
      expect(head(lines)).not.toMatch(/4\.0\.0/);
    }
    expect(protectionLedgerFromReconcile(result).detail[0]).toMatch(/^Could not read which plugin version OpenClaw uses/);
  });

  it('a self-check that measured its own version keeps the r1 meaning: the post-state reading does not override it', () => {
    const check = unreadCheck({ onDiskVersion: '5.20.0' });
    expect(check.versionUnread).toBeUndefined();
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(conflictingCopies('5.20.0', null), check));
    expect(ledger.outcome).toBe('protected-unproven');
    expect(ledger.detail).toContain(`next: openclaw plugins install --force npm:${PKG}@${CLI}`);
  });
});

describe('#1179 r2: a known wrong source is not an unread version', () => {
  /** A copy installed from ClawHub at this CLI's version, recorded in installs.json (pre-2026.6.1 layout). */
  const clawhubCopy = (version: string): string => {
    const dir = path.join(home, '.openclaw', 'npm', 'projects', 'proj', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version }));
    fs.mkdirSync(path.join(home, '.openclaw', 'plugins'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({ installRecords: { [PLUGIN]: { source: 'clawhub', installPath: dir } } }));
    return dir;
  };
  const WRONG = 'the copy OpenClaw selected (v5.22.1) was installed from clawhub, not npm';

  it('the reader keeps its shape for every other caller; the detail marks the known mismatch', () => {
    clawhubCopy(CLI);
    expect(readSelectedRealtimePluginVersion(home)).toEqual({ version: null, reason: WRONG });
    expect(readSelectedRealtimePluginVersionDetail(home)).toEqual({ version: null, reason: WRONG, wrongSource: true });
  });

  it('the real self-check runner: versionWrongSource, never versionUnread, and the reason says the source', async () => {
    clawhubCopy(CLI);
    const check = await runPluginSelfCheck(home, {
      expectedVersion: CLI, readIndex: () => null, readLiveRoster: () => null, canaryProbe: async () => NO_CANARY,
    });
    expect(check).toMatchObject({ versionProof: false, versionWrongSource: true });
    expect(check.versionUnread).toBeUndefined();
    const why = check.reasons.join('\n');
    expect(why).toContain(`version proof FAILED: ${WRONG}, so it is not the pinned build expected at ${CLI}`);
    expect(why).not.toMatch(/could not read the selected plugin copy's version/);
  });

  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('full, compact and ledger: the source mismatch, not "could not read", no downgrade claim, no install — %s', (_l, roster) => {
    const check = unreadCheck({ liveRoster: roster ? [...roster] : null, onDiskReason: WRONG, onDiskWrongSource: true });
    expect(check).toMatchObject({ versionProof: false, versionWrongSource: true });
    expect(check.versionUnread).toBeUndefined();
    const result = appliedSelfCheckOnly(unknownIndexVerdict({ enabled: null, inAllow: false }), check);
    const full = formatReconcileReport(result);
    const compact = formatReconcileReport(result, { compact: true });
    const ledger = protectionLedgerFromReconcile(result);
    expect(ledger.outcome).toBe('unknown');
    for (const text of [head(full), head(compact), ledger.detail.join('\n')]) {
      expect(text).toMatch(/not installed from npm or a local path/);
      expect(text).not.toMatch(/Could not read/i);
      expect(text).not.toMatch(DOWNGRADE);
      expect(text).not.toMatch(INSTALL);
    }
    expect(full[1]).toBe('   Next: shieldcortex doctor');
    expect(compact[1]).toBe('   Next: shieldcortex doctor');
    // The full report keeps the failed proof's own reason.
    expect(full.join('\n')).toContain(WRONG);
    expect(full.join('\n')).not.toMatch(/could not read the selected plugin copy's version/);
  });

  it('a wrong-source copy the post-state read OLDER than this CLI is reported stale by that reading', () => {
    const check = unreadCheck({ onDiskReason: WRONG, onDiskWrongSource: true });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(conflictingCopies('4.0.0', null), check));
    expect(ledger.outcome).toBe('protected-unproven');
    expect(ledger.detail[0]).toMatch(/the build OpenClaw selected is v4\.0\.0, older than 5\.22\.1/);
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
  });
});
