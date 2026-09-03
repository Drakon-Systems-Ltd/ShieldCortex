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

  it('#459: unread live roster (null) + index omit remains the #74 fail — missing evidence is not a pass', () => {
    const fx = loadFixture('enabled-not-loaded');
    expect(fx.input.liveRoster).toBeUndefined();
    const verdict = reconcilePluginState(fx.input);
    expect(verdict.state).toBe('enabled-not-loaded');
    expect(verdict.severity).toBe('fail');
  });
});
