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
import type { PluginInstallIndexState, ReconcileInput, ReconcileVerdict } from '../../integrations/openclaw-plugin-index.js';
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
let ttyDescriptor: PropertyDescriptor | undefined;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1179-report-'));
  restoreEnv = isolateHostEnv(home);
  tripwire.reset();
  // #1179 r3: the report takes canary consent from SHIELDCORTEX_ALLOW_GATEWAY_CANARY
  // (scrubbed above) or a TTY stdin. Pin the TTY off, so a row is consented
  // only when it sets the env itself, whatever terminal runs the suite.
  ttyDescriptor = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  Object.defineProperty(process.stdin, 'isTTY', { value: undefined, configurable: true, writable: true });
});

afterEach(() => {
  try {
    expectNoLaunch(tripwire);
  } finally {
    if (ttyDescriptor) Object.defineProperty(process.stdin, 'isTTY', ttyDescriptor);
    else delete (process.stdin as { isTTY?: boolean }).isTTY;
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

  // r3 (Astra 2) replaces r1's row here: that older reading is another copy's,
  // not the selected one. It keeps main's outcome class, but it is reported as
  // the copy found on disk, and the next step is doctor, never an install.
  it('the self-check read no version, but another layer read an older copy: main\'s class, worded as that copy, next doctor (r3)', () => {
    const v = summariseRepair({
      applied: true, canaryConsented: false, expectedVersion: CLI, onDiskVersion: '5.20.0',
      selfCheck: { ok: false, rosterState: 'unproven', canaryProof: false, versionProof: false, versionUnread: true },
    });
    expect(v.outcome).toBe('protected-unproven');
    expect(v.headline).toMatch(/A plugin copy found on disk is v5\.20\.0, older than 5\.22\.1/);
    expect(v.headline).toMatch(/the version OpenClaw selected is unverified/);
    expect(v.headline).not.toMatch(/installed plugin is behind|build OpenClaw selected is v5\.20\.0/);
    expect(v.nextCommand).toBe('shieldcortex doctor');
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
    // r3: the detail also carries the selected copy's version it read.
    expect(readSelectedRealtimePluginVersionDetail(home)).toEqual({ version: null, reason: WRONG, wrongSource: true, measuredVersion: CLI });
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

/**
 * #1179 r3 (bounded post-adjudication round). Report layer only: what the
 * full report, the compact report and the update ledger say. Repair's plan,
 * its replacement gate and its commands do not change.
 */
const FAILED_PROBE: CanaryResult = { ran: true, denied: false, auditEntryFound: false };
const consentCanary = (): void => {
  process.env.SHIELDCORTEX_ALLOW_GATEWAY_CANARY = '1';
};
const NOT_KNOWN_BROKEN = /not known-broken/;
const WRONG_CLI = `the copy OpenClaw selected (v${CLI}) was installed from clawhub, not npm`;

describe('#1179 r3 R1 (CASE-B1): a consented probe that did not confirm the plugin is never hidden behind the version line', () => {
  it.each([
    ['an unread version', {}, /which plugin version OpenClaw uses could not be read/],
    ['a known wrong source', { onDiskReason: WRONG_CLI, onDiskWrongSource: true, onDiskMeasuredVersion: CLI }, /not installed from npm or a local path/],
  ] as const)('loaded, consented, probe failed, %s: full, compact and ledger state the probe and the version fact; never "not known-broken"; next doctor --ai', (_l, over, fact) => {
    consentCanary();
    const check = unreadCheck({ liveRoster: [PLUGIN], canary: FAILED_PROBE, ...over });
    expect(check).toMatchObject({ rosterState: 'loaded', canaryProof: false, versionProof: false });
    const result = appliedSelfCheckOnly(unknownIndexVerdict({ enabled: null, inAllow: false }), check, FAILED_PROBE);
    const full = formatReconcileReport(result);
    const compact = formatReconcileReport(result, { compact: true });
    const ledger = protectionLedgerFromReconcile(result);
    // CASE's default: the probe verdict wins — unknown, ledger unproven.
    expect(ledger).toMatchObject({ outcome: 'unknown', status: 'unproven' });
    for (const text of [head(full), head(compact), ledger.detail.join('\n')]) {
      expect(text).toMatch(/the live enforcement probe did not confirm it/);
      expect(text).toMatch(fact);
      expect(text).not.toMatch(NOT_KNOWN_BROKEN);
      expect(text).not.toMatch(INSTALL);
      expect(text).not.toMatch(DOWNGRADE);
    }
    expect(full[1]).toBe('   Next: shieldcortex doctor --ai');
    expect(compact[1]).toBe('   Next: shieldcortex doctor --ai');
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor --ai');
  });

  it.each([
    ['unread', { versionUnread: true }, {}],
    ['wrong source', { versionWrongSource: true, selectedCopyVersion: CLI }, {}],
    ['provenance unverified', { versionProvenanceUnverified: true, selectedCopyVersion: CLI }, {}],
    ['unread, the post-state read the selected build current', { versionUnread: true }, { installedVersion: CLI, installedVersionSource: 'selected-build' as const }],
  ] as const)('consented probe failed + an unmeasured version (%s), roster loaded or unproven: the probe is stated, never "not known-broken", doctor --ai, no install', (_l, flags, extra) => {
    for (const rosterState of ['loaded', 'unproven'] as const) {
      const v = summariseRepair({
        applied: true, canaryConsented: true, expectedVersion: CLI, onDiskVersion: null, ...extra,
        selfCheck: { ok: false, rosterState, canaryProof: false, versionProof: false, ...flags },
      });
      expect(v.outcome).toBe('unknown');
      expect(v.headline).toMatch(/the live enforcement probe did not confirm it/);
      expect(v.headline).not.toMatch(NOT_KNOWN_BROKEN);
      expect(v.headline).not.toMatch(INSTALL);
      expect(v.nextCommand).toBe('shieldcortex doctor --ai');
    }
  });

  it('controls: a failed probe on a current version, and an unread version with the probe not consented, keep their headlines', () => {
    const current = summariseRepair({
      applied: true, canaryConsented: true, expectedVersion: CLI,
      selfCheck: { ok: false, rosterState: 'loaded', canaryProof: false, versionProof: true },
    });
    expect(current).toEqual({
      outcome: 'unknown',
      headline: 'The plugin is loaded, but the live enforcement probe did not confirm it. That needs a look.',
      nextCommand: 'shieldcortex doctor --ai',
    });
    const notConsented = summariseRepair({
      applied: true, canaryConsented: false, expectedVersion: CLI, onDiskVersion: null,
      selfCheck: { ok: false, rosterState: 'loaded', canaryProof: false, versionProof: false, versionUnread: true },
    });
    expect(notConsented).toMatchObject({ outcome: 'unknown', nextCommand: 'shieldcortex doctor' });
    expect(notConsented.headline).toMatch(/^Could not read which plugin version OpenClaw uses/);
  });
});

/** A post-state whose selected build could not be read at all (package.json and manifest), with `elsewhere` found by the disk scan. */
const unreadSelection = (elsewhere: string, roster: string[] | null): ReconcileVerdict => reconcilePluginState({
  pluginId: PLUGIN,
  expectedVersion: CLI,
  config: { enabled: true, inAllow: true },
  installsJson: null,
  index: {
    installRecords: { [PLUGIN]: { source: 'npm', version: CLI, installPath: SELECTED } },
    plugins: [{ pluginId: PLUGIN, enabled: true, rootDir: SELECTED }],
  },
  indexRootDirExists: null,
  indexRootDirUnreadable: true,
  onDiskVersion: elsewhere,
  liveRoster: roster,
});
const chipLine = (compact: string[]): string => compact.slice(2).join('\n');

describe('#1179 r3 R2 (Astra 1, 2c): one reported version for the compact chip and the ledger facts', () => {
  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('conflicting copies control (selected 4.0.0, 5.22.1 elsewhere) — %s: facts.pluginVersion is the selected 4.0.0, as the headline and the chip say', (_l, roster) => {
    const post = conflictingCopies('4.0.0', roster ? [...roster] : null);
    const check = unreadCheck({ liveRoster: roster ? [...roster] : null, onDiskReason: STRICT_UNREAD });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(post, check));
    expect(ledger.summary).toMatch(/\bv4\.0\.0\b/);
    expect(ledger.facts.pluginVersion).toBe('4.0.0');
  });

  it('the minor-behind conflict on a loaded gateway: facts.pluginVersion is the selected 5.20.0', () => {
    const check = unreadCheck({ liveRoster: [PLUGIN], onDiskReason: STRICT_UNREAD });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(conflictingCopies('5.20.0', [PLUGIN]), check));
    expect(ledger.facts.pluginVersion).toBe('5.20.0');
  });

  it('a self-check that measured its own version: the chip and the facts name the selected build, not the other copy on disk', () => {
    const check = unreadCheck({ onDiskVersion: '5.20.0' });
    const result = appliedSelfCheckOnly(conflictingCopies('5.20.0', null), check);
    expect(protectionLedgerFromReconcile(result).facts.pluginVersion).toBe('5.20.0');
    const chips = chipLine(formatReconcileReport(result, { compact: true }));
    expect(chips).toMatch(/\bv5\.20\.0\b/);
    expect(chips).not.toMatch(/\bv5\.22\.1\b/);
  });

  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('selected copy unread + a current leftover elsewhere — %s: no unqualified other-copy chip, pluginVersion null', (_l, roster) => {
    const post = unreadSelection(CLI, roster ? [...roster] : null);
    expect(post).toMatchObject({ state: 'version-unverified', installedVersion: null, onDiskVersion: CLI });
    const result = appliedSelfCheckOnly(post, unreadCheck({ liveRoster: roster ? [...roster] : null, onDiskReason: STRICT_UNREAD }));
    const compact = formatReconcileReport(result, { compact: true });
    expect(compact[0]).toMatch(/^⚠️\s+Could not read which plugin version OpenClaw uses/);
    expect(compact.join('\n')).not.toMatch(/\bv5\.22\.1\b/);
    const ledger = protectionLedgerFromReconcile(result);
    expect(ledger.facts.pluginVersion).toBeNull();
    expect(ledger.detail.join('\n')).not.toMatch(/\bv5\.22\.1\b/);
  });

  it('a wrong-source copy only the self-check read (no post-state reading): the chip and the facts name that copy', () => {
    const check = unreadCheck({ liveRoster: [PLUGIN], onDiskReason: 'the copy OpenClaw selected (v5.23.0) was installed from clawhub, not npm', onDiskWrongSource: true, onDiskMeasuredVersion: '5.23.0' });
    expect(check).toMatchObject({ versionWrongSource: true, selectedCopyVersion: '5.23.0' });
    const post = { ...unknownIndexVerdict({ enabled: null, inAllow: false }), onDiskVersion: '5.20.0' };
    const result = appliedSelfCheckOnly(post, check);
    expect(protectionLedgerFromReconcile(result).facts.pluginVersion).toBe('5.23.0');
    const chips = chipLine(formatReconcileReport(result, { compact: true }));
    expect(chips).toMatch(/\bv5\.23\.0\b/);
    expect(chips).not.toMatch(/\bv5\.20\.0\b/);
  });

  it('control: no self-check ran (a dry run): the facts keep the scan version, as before', () => {
    const verdict = conflictingCopies('4.0.0', null);
    const dry: ReconcileExecResult = { verdict, plan: [], applied: false, stepResults: [], ok: false, messages: [] };
    expect(protectionLedgerFromReconcile(dry).facts.pluginVersion).toBe(CLI);
  });
});

describe('#1179 r3 R3 (Astra 2): another copy never decides the headline or the action', () => {
  /**
   * Astra's host: an install record alone (no roster entry) selects a ClawHub
   * copy at 5.23.0; the CLI is 5.22.1; an old 5.20.0 npm project sits
   * elsewhere on disk. The index is injected; the copies are temp files.
   */
  const astraHost = (): Extract<PluginInstallIndexState, { state: 'ok' }>['row'] => {
    const hub = path.join(home, '.openclaw', 'clawhub', PLUGIN);
    fs.mkdirSync(hub, { recursive: true });
    fs.writeFileSync(path.join(hub, 'package.json'), JSON.stringify({ name: PKG, version: '5.23.0' }));
    const stale = path.join(home, '.openclaw', 'npm', 'projects', 'old', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(stale, { recursive: true });
    fs.writeFileSync(path.join(stale, 'package.json'), JSON.stringify({ name: PKG, version: '5.20.0' }));
    return { installRecords: { [PLUGIN]: { source: 'clawhub', installPath: hub } }, plugins: [] } as never;
  };

  it.each([
    ['roster unread', null],
    ['roster loaded', [PLUGIN]],
  ] as const)('Astra\'s record-only ClawHub 5.23.0 / CLI 5.22.1 / scan 5.20.0 — %s: no "behind" claim about the selected copy, no install command', async (_l, roster) => {
    const row = astraHost();
    const readIndex = (): PluginInstallIndexState => ({ state: 'ok', row });
    // The real reader over that host, through the real self-check runner.
    const check = await runPluginSelfCheck(home, {
      expectedVersion: CLI,
      readIndex: () => null,
      readLiveRoster: () => (roster ? [...roster] : null),
      readRegistrationSeenAfterBoot: () => false,
      findGatewayAttributedRegistration: () => null,
      findAnyRegistrationSince: () => null,
      canaryProbe: async () => NO_CANARY,
      readOnDiskVersion: (h) => readSelectedRealtimePluginVersionDetail(h, { readIndex }),
    });
    expect(check).toMatchObject({ versionProof: false, versionWrongSource: true, selectedCopyVersion: '5.23.0' });
    // The post-state: a record-only selection takes main's unchecked
    // precedence, the scan's 5.20.0 (source disk).
    const post = reconcilePluginState({
      pluginId: PLUGIN, expectedVersion: CLI, config: { enabled: true, inAllow: true }, installsJson: null,
      index: row, onDiskVersion: '5.20.0', liveRoster: roster ? [...roster] : null,
    });
    expect(post).toMatchObject({ installedVersion: '5.20.0', installedVersionSource: 'disk' });
    const result = appliedSelfCheckOnly(post, check);
    const full = formatReconcileReport(result);
    const compact = formatReconcileReport(result, { compact: true });
    const ledger = protectionLedgerFromReconcile(result);
    expect(ledger.outcome).toBe('unknown');
    for (const text of [head(full), head(compact), ledger.detail.join('\n')]) {
      expect(text).not.toMatch(DOWNGRADE);
      expect(text).not.toMatch(INSTALL);
      expect(text).toMatch(/\(v5\.23\.0\) was not installed from npm or a local path/);
      expect(text).not.toMatch(/5\.20\.0/);
    }
    expect(full[1]).toBe('   Next: shieldcortex doctor');
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
    expect(ledger.facts.pluginVersion).toBe('5.23.0');
    expect(chipLine(compact)).not.toMatch(/\bv5\.20\.0\b/);
  });

  it.each([
    ['roster unread', null],
    ['roster loaded', [PLUGIN]],
  ] as const)('the gather family (both selected files unreadable, 4.0.0 only elsewhere) — %s: a disk finding, the selected version unverified, next doctor, no install', (_l, roster) => {
    const post = unreadSelection('4.0.0', roster ? [...roster] : null);
    expect(post).toMatchObject({ state: 'version-regressed', versionUnverified: true, installedVersion: '4.0.0', installedVersionSource: 'disk' });
    const result = appliedSelfCheckOnly(post, unreadCheck({ liveRoster: roster ? [...roster] : null, onDiskReason: STRICT_UNREAD }));
    const full = formatReconcileReport(result);
    const compact = formatReconcileReport(result, { compact: true });
    const ledger = protectionLedgerFromReconcile(result);
    // Main's class for a 4.x copy under a 5.x CLI (the major-upgrade lag).
    expect(ledger.outcome).toBe('protected-unproven');
    for (const text of [head(full), head(compact), ledger.detail.join('\n')]) {
      expect(text).toMatch(/A plugin copy found on disk is v4\.0\.0, older than 5\.22\.1/);
      expect(text).toMatch(/the version OpenClaw selected is unverified/);
      expect(text).not.toMatch(/installed plugin is behind|build OpenClaw selected is v4/);
      expect(text).not.toMatch(INSTALL);
    }
    expect(full[1]).toBe('   Next: shieldcortex doctor');
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
    expect(ledger.facts.pluginVersion).toBeNull();
    expect(ledger.summary).not.toMatch(/\bv4\.0\.0\b/);
  });

  it('the same with 5.20.0 elsewhere on a loaded gateway: main\'s class (unprotected) kept, worded as a disk finding, next doctor', () => {
    const post = unreadSelection('5.20.0', [PLUGIN]);
    expect(post).toMatchObject({ installedVersion: '5.20.0', installedVersionSource: 'disk' });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(post, unreadCheck({ liveRoster: [PLUGIN], onDiskReason: STRICT_UNREAD })));
    expect(ledger).toMatchObject({ outcome: 'unprotected', status: 'failed' });
    expect(ledger.detail[0]).toMatch(/^Not proven protected by the build you expect: a plugin copy found on disk is v5\.20\.0, older than 5\.22\.1/);
    expect(ledger.detail.join('\n')).not.toMatch(INSTALL);
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
  });

  it('(2b) a wrong-source copy the post-state read OLDER keeps its known source in the stale headline', () => {
    const check = unreadCheck({ onDiskReason: WRONG_CLI, onDiskWrongSource: true });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(conflictingCopies('4.0.0', null), check));
    expect(ledger.outcome).toBe('protected-unproven');
    expect(ledger.detail[0]).toMatch(/the build OpenClaw selected is v4\.0\.0, older than 5\.22\.1, and that copy was not installed from npm or a local path/);
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
  });

  it('a wrong-source copy the self-check itself read OLDER (no post-state reading): stale by that reading, its source kept, next doctor, no install', () => {
    const check = unreadCheck({ onDiskReason: 'the copy OpenClaw selected (v5.20.0) was installed from clawhub, not npm', onDiskWrongSource: true, onDiskMeasuredVersion: '5.20.0' });
    const ledger = protectionLedgerFromReconcile(appliedSelfCheckOnly(unknownIndexVerdict({ enabled: null, inAllow: false }), check));
    expect(ledger.outcome).toBe('protected-unproven');
    expect(ledger.detail[0]).toMatch(/the build OpenClaw selected is v5\.20\.0, older than 5\.22\.1, and that copy was not installed from npm or a local path/);
    expect(ledger.detail.join('\n')).not.toMatch(INSTALL);
    expect(ledger.facts.nextCommand).toBe('shieldcortex doctor');
  });

  it('exhaustive: with the self-check unread, wrong-source or provenance-unverified, no install command is ever printed, and a consented failed probe is never "not known-broken"', () => {
    const versions = [null, '4.0.0', '5.20.0', CLI, '9.0.0'] as const;
    for (const flags of [{ versionUnread: true }, { versionWrongSource: true }, { versionProvenanceUnverified: true }] as const) {
      for (const rosterState of ['loaded', 'unproven'] as const) {
        for (const onDiskVersion of versions) {
          for (const selectedBuild of versions) {
            for (const copy of versions) {
              for (const canaryConsented of [true, false]) {
                const v = summariseRepair({
                  applied: true, canaryConsented, expectedVersion: CLI, onDiskVersion,
                  ...(selectedBuild ? { installedVersion: selectedBuild, installedVersionSource: 'selected-build' as const } : {}),
                  selfCheck: { ok: false, rosterState, canaryProof: false, versionProof: false, ...flags, ...(copy ? { selectedCopyVersion: copy } : {}) },
                });
                const text = renderRepairHeadline(v).join('\n');
                expect(text).not.toMatch(INSTALL);
                expect(v.nextCommand ?? '').not.toMatch(INSTALL);
                if (canaryConsented) expect(text).not.toMatch(NOT_KNOWN_BROKEN);
              }
            }
          }
        }
      }
    }
  });
});

describe('#1179 r3 R4 (Astra 3): a source is that copy\'s only when its record names the same folder', () => {
  /** The index roster selects folder A; the install record names folder B; both hold 5.22.1; B is recorded as ClawHub. */
  const rosterAndRecordApart = (): PluginInstallIndexState => {
    const write = (name: string): string => {
      const dir = path.join(home, '.openclaw', 'npm', 'projects', name, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version: CLI }));
      return dir;
    };
    const a = write('a');
    const b = write('b');
    return { state: 'ok', row: { installRecords: { [PLUGIN]: { source: 'clawhub', installPath: b } }, plugins: [{ pluginId: PLUGIN, enabled: true, rootDir: a }] } as never };
  };

  it('the self-check: provenance unverified — not "could not read", not a known mismatch; the proof still fails', () => {
    const check = unreadCheck({ onDiskReason: 'a different folder', onDiskProvenanceUnverified: true, onDiskMeasuredVersion: CLI });
    expect(check).toMatchObject({ ok: false, versionProof: false, versionProvenanceUnverified: true, selectedCopyVersion: CLI });
    expect(check.versionUnread).toBeUndefined();
    expect(check.versionWrongSource).toBeUndefined();
    const why = check.reasons.join('\n');
    expect(why).not.toMatch(/could not read the selected plugin copy's version/);
    expect(why).toMatch(/version proof FAILED: a different folder, so it is not proven to be the pinned build expected at 5\.22\.1/);
  });

  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('roster A / record B / both 5.22.1 / ClawHub on B, through the real runner and report — %s: provenance unverified, no definite mismatch, next doctor', async (_l, roster) => {
    const state = rosterAndRecordApart();
    const check = await runPluginSelfCheck(home, {
      expectedVersion: CLI,
      readIndex: () => null,
      readLiveRoster: () => (roster ? [...roster] : null),
      readRegistrationSeenAfterBoot: () => false,
      findGatewayAttributedRegistration: () => null,
      findAnyRegistrationSince: () => null,
      canaryProbe: async () => NO_CANARY,
      readOnDiskVersion: (h) => readSelectedRealtimePluginVersionDetail(h, { readIndex: () => state }),
    });
    expect(check).toMatchObject({ versionProof: false, versionProvenanceUnverified: true, selectedCopyVersion: CLI });
    expect(check.versionWrongSource).toBeUndefined();
    expect(check.versionUnread).toBeUndefined();
    const result = appliedSelfCheckOnly(unknownIndexVerdict({ enabled: null, inAllow: false }), check);
    const full = formatReconcileReport(result);
    const compact = formatReconcileReport(result, { compact: true });
    const ledger = protectionLedgerFromReconcile(result);
    expect(ledger.outcome).toBe('unknown');
    for (const text of [head(full), head(compact), ledger.detail.join('\n')]) {
      expect(text).toMatch(/where that copy was installed from is unverified/);
      expect(text).not.toMatch(/not installed from npm|installed from clawhub/);
      expect(text).not.toMatch(/Could not read/i);
      expect(text).not.toMatch(DOWNGRADE);
      expect(text).not.toMatch(INSTALL);
    }
    expect(full[1]).toBe('   Next: shieldcortex doctor');
    expect(full.join('\n')).not.toMatch(/installed from clawhub, not npm/);
  });
});
