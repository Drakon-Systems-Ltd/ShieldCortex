import { describe, expect, it } from '@jest/globals';
import { reconcilePluginState } from '../openclaw-plugin-index.js';

/**
 * Issue #222 — the failure mode that leaves a box unprotected was the exact
 * failure mode that silenced the alarm.
 *
 * Every unprotected-host rule in `reconcilePluginState` was gated on
 * `enabledInConfig`. When #214's installer wipe deleted the plugin entry AND
 * removed it from `plugins.allow`, `enabledInConfig` went false, all three
 * fail rules were skipped, and control fell through to
 * `state: 'healthy', severity: 'ok'` — doctor printed a green
 * "realtime plugin loaded" tick on a host with no memory firewall and no
 * action guard.
 *
 * The distinction the fix rests on: "not installed" is a legitimate ok state
 * (nothing to protect, nothing claimed). "Installed on disk but not enabled in
 * config" is NOT — the operator installed a security product, the files are
 * there, and the next gateway restart will boot without it. That is a fail.
 */

const BASE = {
  pluginId: 'shieldcortex-realtime',
  expectedVersion: '4.47.35',
  installsJson: null,
  index: { installRecords: {}, plugins: [], warning: null },
  onDiskVersion: '4.47.35',
  projectDirs: ['drakon-systems-shieldcortex-realtime-abc123'],
  liveRoster: null,
};

describe('#222 wiped stanza must never read healthy', () => {
  it('installed on disk + wiped from config (entry gone, not in allow) → FAIL', () => {
    const v = reconcilePluginState({
      ...BASE,
      config: { enabled: null, inAllow: false },
    });
    expect(v.severity).toBe('fail');
    expect(v.state).not.toBe('healthy');
    expect(v.enabledInConfig).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/config|enabled|unprotected/i);
  });

  it('explicitly disabled in config while installed → FAIL, not healthy', () => {
    const v = reconcilePluginState({
      ...BASE,
      config: { enabled: false, inAllow: true },
    });
    expect(v.severity).toBe('fail');
    expect(v.state).not.toBe('healthy');
  });

  it('the verdict names the remedy, not just the symptom', () => {
    const v = reconcilePluginState({
      ...BASE,
      config: { enabled: null, inAllow: false },
    });
    expect(v.recommendedAction).not.toBe('none');
  });

  it('genuinely NOT installed stays ok — nothing is claimed, so nothing is a lie', () => {
    const v = reconcilePluginState({
      ...BASE,
      onDiskVersion: null,
      projectDirs: [],
      index: null,
      config: { enabled: null, inAllow: false },
    });
    expect(v.state).toBe('not-installed');
    expect(v.severity).toBe('ok');
  });

  it('the healthy path still works — enabled, allow-listed, on the live roster', () => {
    const v = reconcilePluginState({
      ...BASE,
      config: { enabled: true, inAllow: true },
      index: {
        installRecords: { 'shieldcortex-realtime': { source: 'npm', version: '4.47.35' } },
        plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true }],
        warning: null,
      },
      liveRoster: ['shieldcortex-realtime'],
    });
    expect(v.state).toBe('healthy');
    expect(v.severity).toBe('ok');
  });

  it('a wiped stanza outranks an index that still lists it as loaded', () => {
    // The install index lags the config wipe — this is precisely the aiquant
    // shape, where every index-derived signal read healthy.
    const v = reconcilePluginState({
      ...BASE,
      config: { enabled: null, inAllow: false },
      index: {
        installRecords: { 'shieldcortex-realtime': { source: 'npm', version: '4.47.35' } },
        plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true }],
        warning: null,
      },
      liveRoster: ['shieldcortex-realtime'],
    });
    expect(v.severity).toBe('fail');
  });
});
