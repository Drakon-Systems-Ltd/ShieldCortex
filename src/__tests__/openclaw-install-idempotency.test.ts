import { describe, expect, it } from '@jest/globals';
import { pluginInstallNeedsWrite } from '../setup/openclaw';

/**
 * v4.12.11 — `trustLocalPlugin()` rewrote `~/.openclaw/openclaw.json`
 * on every invocation because it always set
 * `installs[shieldcortex-realtime].installedAt = new Date().toISOString()`
 * — even when the install path, version, source, allow membership and
 * entry enable state were all already correct. Every `shieldcortex
 * openclaw install` (which postinstall.mjs and `shieldcortex update`
 * invoke even when the plugin tree on disk is unchanged) bumped a
 * fresh timestamp into the file, churning the gateway's config-watcher
 * and bumping every backup file in the chain.
 *
 * The fix factors the comparison into a pure helper so we can prove
 * "no-op when state matches" cheaply, without booting the full installer
 * (which shells out to npm). `trustLocalPlugin` skips its write when
 * `pluginInstallNeedsWrite` returns false.
 *
 * v4.15 — OpenClaw 2026.5.x migrated `plugins.installs` out of
 * `openclaw.json` into `~/.openclaw/plugins/installs.json`. The contract
 * is now:
 *   - `plugins.allow` must contain the bare pluginId (no stale full-path
 *     entries beside it).
 *   - `plugins.entries[pluginId].enabled === true`.
 *   - `plugins.installs[pluginId]` MUST be absent — its presence is a
 *     legacy artefact that trips OpenClaw's migration-block on next
 *     config write.
 *
 * The `installDir` and `version` parameters are accepted for API
 * compatibility but no longer participate in the comparison.
 */
describe('pluginInstallNeedsWrite — idempotency comparison (v4.15 contract)', () => {
  const PLUGIN_ID = 'shieldcortex-realtime';
  const INSTALL_DIR = '/home/u/.openclaw/extensions/shieldcortex-realtime';
  const VERSION = '4.15.0';

  function correctConfig() {
    return {
      plugins: {
        allow: [PLUGIN_ID],
        entries: {
          [PLUGIN_ID]: { enabled: true },
        },
      },
    };
  }

  it('returns false when config already matches (no write needed)', () => {
    expect(pluginInstallNeedsWrite(correctConfig(), PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(false);
  });

  it('returns true when allow list is missing the plugin', () => {
    const cfg = correctConfig();
    cfg.plugins.allow = [];
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when allow contains a stale full-path entry alongside the bare id', () => {
    const cfg = correctConfig();
    cfg.plugins.allow = [`/legacy/path/${PLUGIN_ID}`, PLUGIN_ID];
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when entries[pluginId] is missing', () => {
    const cfg = correctConfig();
    delete (cfg.plugins.entries as Record<string, unknown>)[PLUGIN_ID];
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when entries[pluginId].enabled is false (drift)', () => {
    const cfg = correctConfig();
    cfg.plugins.entries[PLUGIN_ID] = { enabled: false };
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when entries[pluginId] lacks the enabled key entirely', () => {
    const cfg = correctConfig();
    cfg.plugins.entries[PLUGIN_ID] = {} as { enabled: true };
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when plugins block is entirely absent (fresh install)', () => {
    expect(pluginInstallNeedsWrite({}, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when a legacy plugins.installs[shieldcortex-realtime] entry is present', () => {
    // Even with allow + entries correct, an existing installs entry must
    // trigger a write so trustLocalPlugin can clean it up before OpenClaw
    // migration blocks the next config write.
    const cfg = correctConfig() as { plugins: Record<string, unknown> };
    cfg.plugins.installs = {
      [PLUGIN_ID]: { source: 'path', installPath: INSTALL_DIR, version: VERSION },
    };
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns false when plugins.installs has unrelated entries but not ours', () => {
    const cfg = correctConfig() as { plugins: Record<string, unknown> };
    cfg.plugins.installs = {
      'other-plugin': { source: 'npm', version: '1.0.0' },
    };
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(false);
  });

  it('preserves additional fields in entries[pluginId] (forward-compatible)', () => {
    // OpenClaw may add `config: {}`, `hooks`, `subagent`, etc. to the entry.
    // These shouldn't trigger a write as long as `enabled === true`.
    const cfg = correctConfig();
    cfg.plugins.entries[PLUGIN_ID] = { enabled: true, config: {} } as { enabled: true };
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(false);
  });
});
