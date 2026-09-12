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
  return JSON.parse(fs.readFileSync(path.join(fixturesDir, `${name}.json`), 'utf-8')) as Fixture;
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
    const verdict = reconcilePluginState({ ...fx.input, index: null });
    expect(verdict.state).toBe('index-unreadable');
    expect(verdict.severity).toBe('warn');
    expect(verdict.indexReadable).toBe(false);
    // Must NOT be misreported as the security fail-open.
    expect(verdict.state).not.toBe('enabled-not-loaded');
    expect(verdict.reasons.join(' ')).toMatch(/unreadable|cannot read|sqlite/i);
  });

  it('#74 finding 2: a READABLE index that omits the plugin from the roster IS the hard fail', () => {
    const fx = loadFixture('enabled-not-loaded');
    const verdict = reconcilePluginState(fx.input);
    expect(verdict.indexReadable).toBe(true);
    expect(verdict.state).toBe('enabled-not-loaded');
    expect(verdict.severity).toBe('fail');
  });

  it('is pure: does not mutate its input', () => {
    const fx = loadFixture('enabled-not-loaded');
    const snapshot = JSON.stringify(fx.input);
    reconcilePluginState(fx.input);
    expect(JSON.stringify(fx.input)).toBe(snapshot);
  });

  it('#459: a live boot roster that NAMES the plugin outranks plugins_json miss — not UNPROTECTED', () => {
    // Jarvis 2026-09-02: journal listen line includes shieldcortex-realtime,
    // conversation scanning inactive (consent) is a separate warn. LOAD must
    // not fail just because plugins_json omitted the id after a generation-dir
    // change. #74 still holds: this fixture WITHOUT liveRoster stays fail.
    const fx = loadFixture('enabled-not-loaded');
    const verdict = reconcilePluginState({
      ...fx.input,
      liveRoster: [
        'acpx', 'anthropic', 'browser', 'codex', 'ekho-adapter', 'elevenlabs',
        'memory-core', 'microsoft', 'multi-clawd', 'openai',
        'shieldcortex-realtime', 'signal', 'telegram', 'xai',
      ],
    });
    expect(verdict.loadedInLiveRoster).toBe(true);
    expect(verdict.state).not.toBe('enabled-not-loaded');
    expect(verdict.severity).not.toBe('fail');
  });

  it('#461: live-proven load with a READABLE plugins_json omitting the plugin is a WARN, not silent health', () => {
    // The #459 shape one step further: the live roster proves the gateway
    // loaded the plugin (so no UNPROTECTED fail), but the readable index's
    // plugins_json omits it. Ending healthy/ok buried the control-plane
    // disagreement — the index decides what loads at the NEXT restart.
    const fx = loadFixture('enabled-not-loaded');
    const verdict = reconcilePluginState({
      ...fx.input,
      liveRoster: ['telegram', 'shieldcortex-realtime'],
    });
    expect(verdict.loadedInLiveRoster).toBe(true); // live proof preserved…
    expect(verdict.severity).not.toBe('fail'); // …so #459 still holds: no false red…
    expect(verdict.state).toBe('loaded-not-indexed'); // …but the disagreement is classified…
    expect(verdict.severity).toBe('warn'); // …and surfaced at least warning.
    expect(verdict.indexReadable).toBe(true);
    expect(verdict.loadedInIndex).toBe(false);
    expect(verdict.reasons.join(' ')).toMatch(/protected right now/);
    expect(verdict.reasons.join(' ')).toMatch(/control plane|plugins_json/i);
    // NOT 'none'. 'none' plans a bare "verify the healthy state" self-check, so
    // doctor's "run repair" pointed at a command with no step for this — the
    // disagreement would survive every repair and report identically forever.
    // This fixture is OpenClaw-tracked (npm install record), so the smallest
    // correct lever is the tracked refresh, exactly as conflicted-metadata routes.
    expect(verdict.openClawTracked).toBe(true);
    expect(verdict.recommendedAction).toBe('update-openclaw-tracked');
  });

  it('#461: an UNTRACKED live-proven-but-unindexed install reinstalls PINNED, not a tracked update', () => {
    // Same divergence on a host OpenClaw does not track (no npm install
    // record): `openclaw plugins update` has nothing to update, so the local
    // install semantics take the other half of the existing split — a pinned
    // force-install, which cannot re-resolve to an older build.
    const fx = loadFixture('enabled-not-loaded');
    const verdict = reconcilePluginState({
      ...fx.input,
      index: { ...fx.input.index!, installRecords: {} },
      liveRoster: ['telegram', 'shieldcortex-realtime'],
    });
    expect(verdict.openClawTracked).toBe(false);
    expect(verdict.state).toBe('loaded-not-indexed');
    expect(verdict.severity).toBe('warn');
    expect(verdict.recommendedAction).toBe('reinstall-pinned');
  });

  it('#461: conflicted-metadata KEEPS priority over the new state, and its reasons still carry the divergence', () => {
    // The masking bug: the new state returned before rule 5, so a host with a
    // real installs.json↔index disagreement got the weaker verdict and lost the
    // conflict detail. conflicted-metadata is the more specific description of
    // the SAME host, so it keeps the verdict — and the live/index divergence is
    // not suppressed, it rides along in `reasons`.
    const fx = loadFixture('conflicted-metadata');
    const verdict = reconcilePluginState({
      ...fx.input,
      // plugins_json omits the plugin (the #461 half) on top of the conflict.
      index: { ...fx.input.index!, plugins: [{ pluginId: 'brave', enabled: true, origin: 'npm' }] },
      liveRoster: ['telegram', 'shieldcortex-realtime'],
    });
    expect(verdict.loadedInIndex).toBe(false);
    expect(verdict.loadedInLiveRoster).toBe(true);
    expect(verdict.metadataConflict).toBe(true);
    expect(verdict.state).toBe('conflicted-metadata');
    expect(verdict.severity).toBe('warn');
    expect(verdict.recommendedAction).toBe('update-openclaw-tracked');
    // Neither half is lost: the conflict detail AND the control-plane divergence.
    expect(verdict.reasons.join(' ')).toMatch(/install path disagrees with the SQLite index/);
    expect(verdict.reasons.join(' ')).toMatch(/protected right now/);
    expect(verdict.reasons.join(' ')).toMatch(/does NOT list it/);
    // doctor renders conflicted-metadata off the LAST reason — the #461 lines
    // must not displace the conflict detail there.
    expect(verdict.reasons[verdict.reasons.length - 1]).toMatch(/disagrees/);
  });

  it('#461: duplicate-install KEEPS priority — the stronger dedupe remediation is not replaced', () => {
    // dedupe-and-reload prunes the stale generation dir, which is what CAUSED
    // the index/gateway divergence on the field host. Returning the new state
    // first swapped that for a plan with no prune step at all — and
    // openclaw-reconcile.ts only scans for prunable dirs on duplicate-install /
    // conflicted-metadata / enabled-not-loaded, so the dirs stayed forever.
    const fx = loadFixture('duplicate-install');
    const verdict = reconcilePluginState({
      ...fx.input,
      index: { ...fx.input.index!, plugins: [{ pluginId: 'brave', enabled: true, origin: 'npm' }] },
      liveRoster: ['telegram', 'shieldcortex-realtime'],
    });
    expect(verdict.loadedInIndex).toBe(false);
    expect(verdict.loadedInLiveRoster).toBe(true);
    expect(verdict.state).toBe('duplicate-install');
    expect(verdict.recommendedAction).toBe('dedupe-and-reload');
    expect(verdict.reasons.join(' ')).toMatch(/plugin project dirs on disk/);
    expect(verdict.reasons.join(' ')).toMatch(/protected right now/);
    expect(verdict.reasons.join(' ')).toMatch(/does NOT list it/);
  });

  it('#461: version-regressed still outranks it — a downgrade is a fail, not a warn', () => {
    // Ordering above the new state is unchanged: a live-loaded but regressed
    // build is still the hard fail, never softened to warn by live proof.
    const fx = loadFixture('version-regressed');
    const verdict = reconcilePluginState({
      ...fx.input,
      index: { ...fx.input.index!, plugins: [] },
      liveRoster: ['telegram', 'shieldcortex-realtime'],
    });
    expect(verdict.state).toBe('version-regressed');
    expect(verdict.severity).toBe('fail');
  });

  it('#461: when plugins_json DOES list the live-loaded plugin there is no warn — healthy stands', () => {
    const fx = loadFixture('healthy');
    const verdict = reconcilePluginState({
      ...fx.input,
      liveRoster: ['telegram', 'shieldcortex-realtime'],
    });
    expect(verdict.loadedInIndex).toBe(true);
    expect(verdict.state).toBe('healthy');
    expect(verdict.severity).toBe('ok');
  });

  it('#459: unread live roster (null) + index omit remains the #74 fail — missing evidence is not a pass', () => {
    const fx = loadFixture('enabled-not-loaded');
    expect(fx.input.liveRoster).toBeUndefined();
    const verdict = reconcilePluginState(fx.input);
    expect(verdict.state).toBe('enabled-not-loaded');
    expect(verdict.severity).toBe('fail');
  });
});
