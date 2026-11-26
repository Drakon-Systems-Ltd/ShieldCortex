import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';
import {
  reconcilePluginState,
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
    expect(verdict).toMatchObject({ state: 'enabled-not-installed', severity: 'fail', recommendedAction: 'install' });
  });

  it('…and a paper installs.json record cannot vouch for it either', () => {
    const verdict = reconcilePluginState(
      base({ indexInstallPathExists: false, installsJson: { version: '5.22.1', installPath: '/gone' } }),
    );
    expect(verdict).toMatchObject({ state: 'enabled-not-installed', severity: 'fail' });
  });

  it('…but a running gateway that provably loaded it is not convicted as uninstalled', () => {
    const verdict = reconcilePluginState(
      base({ indexInstallPathExists: false, liveRoster: ['shieldcortex-realtime'], liveLoadEvidence: 'boot-roster' }),
    );
    expect(verdict.state).not.toBe('enabled-not-installed');
    expect(verdict.severity).not.toBe('fail');
  });

  it('…not enabled in config either: plainly not installed, not the #222 wipe', () => {
    const verdict = reconcilePluginState(base({ indexInstallPathExists: false, config: { enabled: null, inAllow: false } }));
    expect(verdict).toMatchObject({ state: 'not-installed', severity: 'ok' });
  });

  it('a missing path with a real build on disk: the build decides, and the record\'s version is not the running version', () => {
    const input = base({ indexInstallPathExists: false, onDiskInstallPath: '/home/u/.openclaw/extensions/shieldcortex-realtime' });
    input.index!.installRecords['shieldcortex-realtime'].version = '4.0.0';
    // The stale record says 4.0.0 (< expected): not a regression, it is not what runs.
    expect(reconcilePluginState(input)).toMatchObject({ state: 'healthy', severity: 'ok' });
    // Control: the same record with its path present IS the running version.
    expect(reconcilePluginState({ ...input, indexInstallPathExists: true }).state).toBe('version-regressed');
  });
});
