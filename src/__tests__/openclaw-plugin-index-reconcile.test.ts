import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';
import {
  planReconcileActions,
  reconcilePluginState,
  safeForReason,
  type ReconcileInput,
} from '../integrations/openclaw-plugin-index.js';

/**
 * Regression suite for the #74 conflicted-metadata / silent-drop class.
 *
 * Drives the pure reconciler analyzer against the field-derived fixtures in
 * src/__fixtures__/openclaw-plugin-index/ (aiquant + jarvis, 2026-07-11). The
 * critical invariant: an `enabled:true` plugin missing from the loaded roster
 * must NEVER be classified healthy — that was the security fail-open.
 */
const thisFile = fileURLToPath(import.meta.url);
const fixturesDir = path.resolve(path.dirname(thisFile), '..', '__fixtures__', 'openclaw-plugin-index');

interface Fixture {
  description: string;
  input: ReconcileInput;
  expected: {
    state: string;
    severity: string;
    recommendedAction: string;
    loadedInIndex: boolean;
    enabledInConfig: boolean;
  };
}

function loadFixture(name: string): Fixture {
  const fixture = JSON.parse(fs.readFileSync(path.join(fixturesDir, `${name}.json`), 'utf-8')) as Fixture;
  // #501: the old index-only fixtures cannot prove a live unload. Supply an
  // explicit live absence for these silent-drop regression scenarios.
  if (name.startsWith('enabled-not-loaded')) fixture.input.liveRoster = ['brave', 'codex'];
  return fixture;
}

const CASES = [
  'healthy',
  'enabled-not-loaded',
  'version-regressed',
  'conflicted-metadata',
  'duplicate-install',
  'not-installed',
];

describe('reconcilePluginState — #74 field fixtures', () => {
  for (const name of CASES) {
    it(`classifies the "${name}" fixture as expected`, () => {
      const fx = loadFixture(name);
      const verdict = reconcilePluginState(fx.input);
      expect(verdict.state).toBe(fx.expected.state);
      expect(verdict.severity).toBe(fx.expected.severity);
      expect(verdict.recommendedAction).toBe(fx.expected.recommendedAction);
      expect(verdict.loadedInIndex).toBe(fx.expected.loadedInIndex);
      expect(verdict.enabledInConfig).toBe(fx.expected.enabledInConfig);
    });
  }

  it('SECURITY: enabled-but-not-loaded is a hard fail, never healthy', () => {
    const fx = loadFixture('enabled-not-loaded');
    const verdict = reconcilePluginState(fx.input);
    // The whole point of #74: this state was reported as protected while unprotected.
    expect(verdict.severity).toBe('fail');
    expect(verdict.state).not.toBe('healthy');
    expect(verdict.reasons.join(' ')).toMatch(/roster|loaded|drop/i);
  });

  it('routes OpenClaw-tracked plugins through update, not plain install', () => {
    const fx = loadFixture('enabled-not-loaded');
    const verdict = reconcilePluginState(fx.input);
    // Field lesson: `shieldcortex openclaw install` skips OpenClaw-tracked
    // plugins; they must be refreshed via `openclaw plugins update`.
    expect(verdict.recommendedAction).toBe('update-openclaw-tracked');
    expect(verdict.openClawTracked).toBe(true);
  });

  it('refuses a version downgrade (4.25.4 < 4.47.2) even though the plugin is loaded', () => {
    const fx = loadFixture('version-regressed');
    const verdict = reconcilePluginState(fx.input);
    expect(verdict.state).toBe('version-regressed');
    expect(verdict.severity).toBe('fail');
    expect(verdict.recommendedAction).toBe('reinstall-pinned');
  });

  it('flags installs.json vs index install-path disagreement as conflicted metadata', () => {
    const fx = loadFixture('conflicted-metadata');
    const verdict = reconcilePluginState(fx.input);
    expect(verdict.state).toBe('conflicted-metadata');
    expect(verdict.metadataConflict).toBe(true);
  });

  it('#74 finding 5: enabled-but-not-loaded WITH two project dirs is still a hard fail (aiquant)', () => {
    const fx = loadFixture('enabled-not-loaded-two-dirs');
    const verdict = reconcilePluginState(fx.input);
    expect(verdict.state).toBe('enabled-not-loaded');
    expect(verdict.severity).toBe('fail');
    // The pure classifier is unchanged by the extra dir; the ORCHESTRATOR prunes
    // the stale one (see openclaw-reconcile-prune.test.ts) — this fixture is the
    // input that masked finding 5 (the old enabled-not-loaded fixture had 1 dir).
    expect((fx.input.projectDirs ?? []).length).toBe(2);
  });

  it('#74 finding 2: an UNREADABLE index (null) with enabled+installed is index-unreadable (warn), NOT a false UNPROTECTED', () => {
    const fx = loadFixture('enabled-not-loaded');
    // Simulate a broken better-sqlite3 binding / locked DB / pre-2026.6.1 layout:
    // readPluginInstallIndex returns null. On-disk build is still present.
    const verdict = reconcilePluginState({ ...fx.input, index: null, liveRoster: null });
    expect(verdict.state).toBe('index-unreadable');
    expect(verdict.severity).toBe('warn');
    expect(verdict.indexReadable).toBe(false);
    // Must NOT be misreported as the security fail-open.
    expect(verdict.state).not.toBe('enabled-not-loaded');
    expect(verdict.reasons.join(' ')).toMatch(/unreadable|cannot read|sqlite/i);
  });

  it('#501: a READABLE index that omits the plugin is NOT live absence proof', () => {
    const fx = loadFixture('enabled-not-loaded');
    const verdict = reconcilePluginState({ ...fx.input, liveRoster: null });
    expect(verdict.indexReadable).toBe(true);
    expect(verdict.state).toBe('load-unproven');
    expect(verdict.severity).toBe('warn');
  });

  it('is pure: does not mutate its input', () => {
    const fx = loadFixture('enabled-not-loaded');
    const snapshot = JSON.stringify(fx.input);
    reconcilePluginState(fx.input);
    expect(JSON.stringify(fx.input)).toBe(snapshot);
  });
});

/**
 * #260 round 2 — the reconciler is pure and takes an injectable index, so it
 * cannot rely on the SQLite reader having validated what it is handed.
 */
describe('#260 r2 — malformed and stale index input', () => {
  const base = (over: Partial<ReconcileInput> = {}): ReconcileInput => ({
    pluginId: 'shieldcortex-realtime',
    expectedVersion: '5.22.1',
    config: { enabled: true, inAllow: true },
    installsJson: null,
    index: {
      installRecords: { 'shieldcortex-realtime': { source: 'npm', version: '5.22.1', installPath: '/gone' } },
      plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true }],
    },
    onDiskVersion: null,
    liveRoster: null,
    ...over,
  });

  it('a null plugins entry does not throw', () => {
    const input = base();
    input.index!.plugins = [null as never, { pluginId: 'shieldcortex-realtime', enabled: true }];
    const verdict = reconcilePluginState(input);
    expect(verdict.loadedInIndex).toBe(true);
    expect(verdict.state).toBe('healthy');
  });

  it('backward compatible: an index record with the path NOT checked keeps its verdict', () => {
    expect(reconcilePluginState(base())).toMatchObject({ state: 'healthy', severity: 'ok' });
    expect(reconcilePluginState(base({ indexInstallPathExists: null }))).toMatchObject({ state: 'healthy', severity: 'ok' });
    expect(reconcilePluginState(base({ indexInstallPathExists: true }))).toMatchObject({ state: 'healthy', severity: 'ok' });
  });

  it('the recorded path is confirmed MISSING and nothing is on disk: never healthy', () => {
    const verdict = reconcilePluginState(base({ indexInstallPathExists: false }));
    expect(verdict).toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: true });
    expect(verdict.reasons.join(' ')).toMatch(/records the plugin at \/gone, which holds no plugin build/);
  });

  it('indexPathMissing is false on every other verdict, including the other load-unproven ones', () => {
    expect(reconcilePluginState(base()).indexPathMissing).toBe(false);
    const rosterRace = reconcilePluginState(base({ liveRoster: [], registrationSeenAfterBoot: true }));
    expect(rosterRace).toMatchObject({ state: 'load-unproven', indexPathMissing: false });
  });

  it('…and a paper installs.json record cannot vouch for it either', () => {
    const verdict = reconcilePluginState(
      base({ indexInstallPathExists: false, installsJson: { version: '5.22.1', installPath: '/gone' } }),
    );
    expect(verdict).toMatchObject({ state: 'load-unproven', severity: 'warn', indexPathMissing: true });
  });

  it('…but a running gateway that provably loaded it is not convicted as uninstalled', () => {
    const verdict = reconcilePluginState(
      base({ indexInstallPathExists: false, liveRoster: ['shieldcortex-realtime'], liveLoadEvidence: 'boot-roster' }),
    );
    expect(verdict.state).not.toBe('enabled-not-installed');
    expect(verdict.severity).not.toBe('fail');
    expect(verdict.indexPathMissing).toBe(false);
    // #260 r4: load is proven, the version is not — and is not claimed.
    expect(verdict).toMatchObject({ state: 'healthy', severity: 'ok', recommendedAction: 'none', versionUnverified: true });
    expect(verdict.reasons.join(' ')).toMatch(/load proven by the running gateway; the installed version could not be verified/);
    expect(verdict.reasons.join(' ')).not.toMatch(/versions agree/);
  });

  // Sol r2 (r3 change): a stale-path host's scan build no longer counts as the
  // measured version — the load is proven, the version is not.
  it('versionUnverified is absent on an ordinary healthy verdict; set on a stale-path one even with a build on disk (#260 r4, Sol r2)', () => {
    expect(reconcilePluginState(base({ liveRoster: ['shieldcortex-realtime'] })).versionUnverified).toBeUndefined();
    const onDisk = reconcilePluginState(
      base({ indexInstallPathExists: false, liveRoster: ['shieldcortex-realtime'], onDiskVersion: '5.22.1' }),
    );
    expect(onDisk).toMatchObject({ state: 'healthy', severity: 'ok', versionUnverified: true });
    expect(onDisk.reasons.join(' ')).not.toMatch(/versions agree/);
  });

  // #260 r4 (Astra r3 BLOCKER 1): the stale path blocks a pass and nothing
  // else. A readable live roster that OMITS the plugin is a confirmed absence.
  it('a stale path never pre-empts a confirmed live absence: enabled-not-loaded / fail', () => {
    const verdict = reconcilePluginState(base({ indexInstallPathExists: false, liveRoster: ['brave'] }));
    expect(verdict).toMatchObject({ state: 'enabled-not-loaded', severity: 'fail', indexPathMissing: false });
    // …and the #142 registration race stays the ambiguity it was on main.
    const race = reconcilePluginState(base({ indexInstallPathExists: false, liveRoster: ['brave'], registrationSeenAfterBoot: true }));
    expect(race).toMatchObject({ state: 'load-unproven', severity: 'warn', indexPathMissing: false });
  });

  it('a stale path never pre-empts the other main rules (disabled-by-operator, config-unreadable, index says not loaded)', () => {
    expect(reconcilePluginState(base({ indexInstallPathExists: false, config: { enabled: false, inAllow: true } })))
      .toMatchObject({ state: 'disabled-by-operator', severity: 'warn' });
    expect(reconcilePluginState(base({ indexInstallPathExists: false, config: { enabled: true, inAllow: true, readable: false } })))
      .toMatchObject({ state: 'config-unreadable', severity: 'warn' });
    const notInIndex = base({ indexInstallPathExists: false });
    notInIndex.index!.plugins = [];
    // main's rule 4, with main's action — not the stale-path warn.
    expect(reconcilePluginState(notInIndex)).toMatchObject({
      state: 'load-unproven', severity: 'warn', recommendedAction: 'update-openclaw-tracked', indexPathMissing: false,
    });
  });

  it('…and the missing copy\'s recorded version is never the running version, live roster or not (#260 r3)', () => {
    const input = base({ indexInstallPathExists: false, liveRoster: ['shieldcortex-realtime'], liveLoadEvidence: 'boot-roster' });
    input.index!.installRecords['shieldcortex-realtime'].version = '4.0.0';
    const verdict = reconcilePluginState(input);
    expect(verdict.state).not.toBe('version-regressed');
    expect(verdict.severity).not.toBe('fail');
    // Control: with the path present, the same record IS a regression.
    expect(reconcilePluginState({ ...input, indexInstallPathExists: true }).state).toBe('version-regressed');
  });

  // #260 r4 (Astra r3 BLOCKER 2): a stale path must not turn a registration
  // loss into a silent "not installed" skip — main's #222 rule decides.
  it('…not registered in config either: main\'s #222 rule runs — installed-not-enabled, never not-installed', () => {
    const verdict = reconcilePluginState(base({ indexInstallPathExists: false, config: { enabled: null, inAllow: false } }));
    expect(verdict).toMatchObject({ state: 'installed-not-enabled', severity: 'fail', recommendedAction: 're-register' });
  });

  // Sol finding 3: a build on disk is an install, not a selection. With the
  // stale row as the only "enabled" evidence and no live proof, it is not a
  // pass (it was a false green at e97f4048).
  it('a missing path with a real build elsewhere on disk and no live proof: load-unproven, never healthy', () => {
    const input = base({ indexInstallPathExists: false, onDiskInstallPath: '/home/u/.openclaw/extensions/shieldcortex-realtime' });
    input.index!.installRecords['shieldcortex-realtime'].version = '4.0.0';
    const verdict = reconcilePluginState(input);
    // The stale record says 4.0.0 (< expected): not a regression, it is not what runs.
    expect(verdict.state).not.toBe('version-regressed');
    expect(verdict).toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: true });
    expect(verdict.reasons.join(' ')).toMatch(/a build exists elsewhere on disk, but nothing shows OpenClaw selected it/);
    expect(reconcilePluginState(base({ indexInstallPathExists: false, onDiskVersion: '5.22.1' })))
      .toMatchObject({ state: 'load-unproven', severity: 'warn', indexPathMissing: true });
    // Control: the same record with its path present IS the running version.
    expect(reconcilePluginState({ ...input, indexInstallPathExists: true }).state).toBe('version-regressed');
  });

  // Sol r2: the RUNNING gateway proves the load, but the build a disk scan
  // found elsewhere is not proven to be the copy it loaded — so its version is
  // not claimed (this row asserted the scan's version as measured until r3).
  it('positive control (Sol 3): the same host with the RUNNING gateway proving the load is healthy — version unverified, never the scan\'s', () => {
    const verdict = reconcilePluginState(base({
      indexInstallPathExists: false, onDiskVersion: '5.22.1', liveRoster: ['shieldcortex-realtime'], liveLoadEvidence: 'boot-roster',
    }));
    expect(verdict).toMatchObject({
      state: 'healthy', severity: 'ok', indexPathMissing: false,
      versionUnverified: true, installedVersion: null, installedVersionSource: null,
    });
    expect(verdict.reasons.join(' ')).toMatch(/not proven to be the copy it loaded/);
  });

  it('positive control (Sol 3): the index\'s own selection (rootDir) verified as a real build lets the ordinary rules decide', () => {
    const input = base({ indexInstallPathExists: false, indexRootDirExists: true, onDiskVersion: '5.22.1' });
    expect(reconcilePluginState(input)).toMatchObject({ state: 'healthy', severity: 'ok', indexPathMissing: false });
    // …and a rootDir that is NOT a build is no selection proof.
    expect(reconcilePluginState({ ...input, indexRootDirExists: false })).toMatchObject({ state: 'load-unproven', indexPathMissing: true });
    expect(reconcilePluginState({ ...input, indexRootDirExists: null })).toMatchObject({ state: 'load-unproven', indexPathMissing: true });
  });

  // Case blocking #1 / Sol finding 2, measured: base fixture, roster
  // ['brave'], boot-roster evidence, path gone. Merge-base 128a0734 gives
  // enabled-not-loaded / fail / update-openclaw-tracked; e97f4048 gave
  // load-unproven / warn / none. A read roster that lacks the plugin and an
  // unread roster are different evidence.
  it.each([
    ['a roster that names other plugins', ['brave']],
    ['an empty roster', [] as string[]],
  ])('Case #1: stale path + %s (read, plugin absent), no registration race ⇒ enabled-not-loaded / FAIL / update-openclaw-tracked', (_label, roster) => {
    for (const build of [{}, { onDiskVersion: '5.22.1' }, { onDiskInstallPath: '/x/ext' }]) {
      const verdict = reconcilePluginState(base({ liveRoster: roster, liveLoadEvidence: 'boot-roster', indexInstallPathExists: false, ...build }));
      expect(verdict).toMatchObject({
        state: 'enabled-not-loaded', severity: 'fail', recommendedAction: 'update-openclaw-tracked', loadedInLiveRoster: false, indexPathMissing: false,
      });
    }
  });

  it.each([
    ['a roster that names other plugins', ['brave']],
    ['an empty roster', [] as string[]],
  ])('Case #1: stale path + %s + a registration sighted after boot (#142) ⇒ still the #142 load-unproven warn, no action', (_label, roster) => {
    const verdict = reconcilePluginState(base({ liveRoster: roster, indexInstallPathExists: false, registrationSeenAfterBoot: true }));
    expect(verdict).toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: false });
    expect(verdict.reasons.join(' ')).toMatch(/registration was sighted after that snapshot/);
  });

  it('Case #1 control: an UNREAD roster on the same stale-path host is the stale-path warn, not a conviction', () => {
    expect(reconcilePluginState(base({ liveRoster: null, indexInstallPathExists: false })))
      .toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none', indexPathMissing: true });
  });
});

/**
 * #260 Sol finding 4 — an index that is PRESENT but unreadable is not a
 * confirmed absence. Nothing found where we look + an unreadable index used to
 * be rule 1's enabled-not-installed FAIL with install advice.
 */
describe('#260 Sol-4 — present-but-unreadable index vs confirmed absence', () => {
  const nothing = (over: Partial<ReconcileInput> = {}): ReconcileInput => ({
    pluginId: 'shieldcortex-realtime',
    expectedVersion: '5.22.1',
    config: { enabled: true, inAllow: true },
    installsJson: null,
    index: null,
    onDiskVersion: null,
    liveRoster: null,
    ...over,
  });

  it('unreadable index, no copy found, roster unread ⇒ index-unreadable / warn / none — never enabled-not-installed / install', () => {
    const verdict = reconcilePluginState(nothing({ indexUnreadable: true }));
    expect(verdict).toMatchObject({ state: 'index-unreadable', severity: 'warn', recommendedAction: 'none', indexUnreadable: true });
    expect(verdict.reasons.join(' ')).toMatch(/UNKNOWN, not absent/);
    // …and the planner turns it into a self-check, not an install.
    expect(planReconcileActions(verdict, { pluginId: 'shieldcortex-realtime', packageName: '@drakon-systems/shieldcortex-realtime', expectedVersion: '5.22.1' })
      .map((st) => st.kind)).toEqual(['self-check']);
  });

  it('confirmed-absence control: NO index (readable absence) + no copy ⇒ enabled-not-installed / fail / install, as on main', () => {
    expect(reconcilePluginState(nothing())).toMatchObject({ state: 'enabled-not-installed', severity: 'fail', recommendedAction: 'install' });
    expect(reconcilePluginState(nothing({ indexUnreadable: false }))).toMatchObject({ state: 'enabled-not-installed', recommendedAction: 'install' });
  });

  it('unreadable index + the running gateway proves the load ⇒ index-unreadable warn (says it is loaded), never a fail', () => {
    const verdict = reconcilePluginState(nothing({ indexUnreadable: true, liveRoster: ['shieldcortex-realtime'], liveLoadEvidence: 'boot-roster' }));
    expect(verdict).toMatchObject({ state: 'index-unreadable', severity: 'warn', recommendedAction: 'none' });
    expect(verdict.reasons.join(' ')).toMatch(/RUNNING gateway has the plugin loaded/);
  });

  it.each([
    ['a roster naming other plugins', ['brave']],
    ['an empty roster', [] as string[]],
  ])('unreadable index + a READ live roster without the plugin (%s) ⇒ enabled-not-loaded FAIL — independent evidence still convicts', (_label, roster) => {
    expect(reconcilePluginState(nothing({ indexUnreadable: true, liveRoster: roster })))
      .toMatchObject({ state: 'enabled-not-loaded', severity: 'fail', recommendedAction: 'reinstall-pinned' });
  });

  it('…with the #142 registration race ⇒ load-unproven / warn / none', () => {
    expect(reconcilePluginState(nothing({ indexUnreadable: true, liveRoster: ['brave'], registrationSeenAfterBoot: true })))
      .toMatchObject({ state: 'load-unproven', severity: 'warn', recommendedAction: 'none' });
  });

  it('not enabled in config: unchanged (the gap only matters when config claims the plugin)', () => {
    expect(reconcilePluginState(nothing({ indexUnreadable: true, config: { enabled: null, inAllow: false } })).state).toBe('not-installed');
  });

  it('a readable index wins over a stray flag: indexUnreadable only counts when index is null', () => {
    const verdict = reconcilePluginState(nothing({
      indexUnreadable: true,
      index: { installRecords: {}, plugins: [] },
    }));
    expect(verdict).toMatchObject({ state: 'enabled-not-installed', indexUnreadable: false });
  });
});

/**
 * #260 Case non-blocking — a recorded path goes into `reasons` (and so into
 * `--json` and verbose output) with control characters escaped.
 */
describe('#260 Case — control characters in a recorded path never reach reasons raw', () => {
  const hostile = '/x\n[OK] all good\u001b[2J\u202e\u0085';
  const input = (installPath: string, over: Partial<ReconcileInput> = {}): ReconcileInput => ({
    pluginId: 'shieldcortex-realtime',
    expectedVersion: '5.22.1',
    config: { enabled: true, inAllow: true },
    installsJson: null,
    index: { installRecords: { 'shieldcortex-realtime': { source: 'npm', version: '5.22.1', installPath } }, plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true }] },
    onDiskVersion: null,
    liveRoster: null,
    indexInstallPathExists: false,
    ...over,
  });
  // eslint-disable-next-line no-control-regex
  const RAW = /[\u0000-\u001f\u007f-\u009f\u202e]/;

  it('the stale-path reason', () => {
    const verdict = reconcilePluginState(input(hostile));
    expect(verdict.state).toBe('load-unproven');
    const text = verdict.reasons.join(' ');
    expect(text).not.toMatch(RAW);
    expect(text).toContain('/x\\u{a}[OK] all good\\u{1b}[2J\\u{202e}\\u{85}');
  });

  it('the path-conflict reason', () => {
    const verdict = reconcilePluginState(input(hostile, { indexInstallPathExists: true, installsJson: { version: '5.22.1', installPath: '/y\r\n' } }));
    expect(verdict.state).toBe('conflicted-metadata');
    expect(verdict.reasons.join(' ')).not.toMatch(RAW);
  });

  it('safeForReason: plain paths unchanged; long ones cut', () => {
    expect(safeForReason('/home/u/.openclaw/npm/projects/a b/é')).toBe('/home/u/.openclaw/npm/projects/a b/é');
    expect(safeForReason('a'.repeat(600))).toBe(`${'a'.repeat(512)}…(truncated)`);
  });
});
