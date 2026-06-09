import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, initDatabase } from '../database/init.js';
import {
  handleKillPhrase,
  activateIronDome,
  deactivateIronDome,
  IRON_DOME_PROFILES,
} from '../defence/iron-dome/index.js';
import type { IronDomeConfig } from '../defence/iron-dome/index.js';
import {
  isKillSwitchActive,
  deactivateKillSwitch,
  getControlStatus,
} from '../api/control.js';
import { checkAndTriggerKillSwitch } from '../server.js';

/**
 * Phase 1b regression guard for the kill-phrase emergency stop.
 *
 * server.ts checkAndTriggerKillSwitch() used to do
 *   const ironDome = require('./defence/iron-dome/index.js')
 * a bare CommonJS require that threw ReferenceError under ESM. The surrounding
 * try/catch swallowed it and returned false, so the kill-phrase stop was
 * COMPLETELY DEAD — the literal text 'cortex halt' could never trip the switch.
 * It is now a static `import { checkKillPhrase }`. check-no-bare-require.mjs
 * proves no bare require survives; this proves the behaviour it re-enabled.
 *
 * handleKillPhrase is a pure matcher (no DB, no global state). The wired
 * checkKillPhrase → loadConfig → activateKillSwitch path mutates GLOBAL state
 * in api/control.ts, so every test resets it via deactivateKillSwitch().
 */

// Minimal valid IronDomeConfig built from a real profile (which is
// Omit<IronDomeConfig, 'enabled'>) plus an explicit enabled flag.
function makeConfig(overrides: Partial<IronDomeConfig> = {}): IronDomeConfig {
  return {
    ...IRON_DOME_PROFILES.personal,
    enabled: true,
    ...overrides,
  };
}

describe('kill phrase trips the emergency stop', () => {
  beforeEach(() => {
    // Reset global kill-switch state in case a prior test in this worker left
    // it active — an active kill switch would block every subsequent op.
    deactivateKillSwitch('test-cleanup');
    closeDatabase();
    initDatabase(':memory:');
  });

  afterEach(() => {
    // CRITICAL: activateKillSwitch mutates module-level state in control.ts
    // that persists across tests in the same worker. Reset to 'active' so it
    // does not block unrelated suites. Also restore Iron Dome to disabled.
    deactivateKillSwitch('test-cleanup');
    deactivateIronDome();
    closeDatabase();
  });

  // ── Case 1: pure matcher, deterministic, no global state ──

  it('handleKillPhrase triggers when enabled and the phrase is present', () => {
    const result = handleKillPhrase(
      'please cortex halt now',
      makeConfig({ killPhrase: 'cortex halt' }),
    );
    expect(result.triggered).toBe(true);
    expect(result.phrase).toBe('cortex halt');
  });

  it('handleKillPhrase does NOT trigger when Iron Dome is disabled', () => {
    const result = handleKillPhrase(
      'please cortex halt now',
      makeConfig({ enabled: false, killPhrase: 'cortex halt' }),
    );
    expect(result.triggered).toBe(false);
  });

  it('handleKillPhrase does NOT trigger when the phrase is absent', () => {
    const result = handleKillPhrase(
      'completely benign text with no phrase',
      makeConfig({ killPhrase: 'cortex halt' }),
    );
    expect(result.triggered).toBe(false);
  });

  // ── Case 2: regression for the exact bug ──
  // Proves checkAndTriggerKillSwitch now EXECUTES its body (the static import
  // resolves) instead of throwing ReferenceError into the swallowed catch.

  it('checkAndTriggerKillSwitch runs its body on benign text: returns false, does not throw', () => {
    expect(isKillSwitchActive()).toBe(false);
    expect(() =>
      checkAndTriggerKillSwitch('completely benign text with no phrase', 'user'),
    ).not.toThrow();
    expect(
      checkAndTriggerKillSwitch('completely benign text with no phrase', 'user'),
    ).toBe(false);
    expect(isKillSwitchActive()).toBe(false);
  });

  // ── Case 3: end-to-end wired path ──
  // activateIronDome() persists { enabled: true, killPhrase: 'cortex halt' } to
  // the in-memory iron_dome_config table (NO disk write, NO ~/.shieldcortex
  // config). loadConfig() then reads enabled:true, so the kill phrase trips the
  // switch through the real checkKillPhrase → activateKillSwitch path.

  it('checkAndTriggerKillSwitch trips the global kill switch when the configured phrase appears', () => {
    expect(isKillSwitchActive()).toBe(false);

    const config = activateIronDome(); // default config: killPhrase 'cortex halt'
    expect(config.enabled).toBe(true);
    expect(config.killPhrase).toBe('cortex halt');

    const tripped = checkAndTriggerKillSwitch('please cortex halt now', 'user');

    expect(tripped).toBe(true);
    expect(isKillSwitchActive()).toBe(true);
  });

  // ── Suite-level cleanup proof ──

  it('global control state is clean (active, no kill switch) after cleanup', () => {
    const status = getControlStatus();
    expect(status.killSwitchActive).toBe(false);
    expect(status.mode).toBe('active');
  });
});
