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
 * (which shells out to npm). `trustLocalPlugin` now skips its write when
 * `pluginInstallNeedsWrite` returns false.
 *
 * The comparison is intentionally strict — any drift in source,
 * installPath, version, allow membership, or entries presence forces a
 * fresh write so the installer can correct corrupted/partial config.
 */
describe('pluginInstallNeedsWrite — idempotency comparison (v4.12.11)', () => {
  const PLUGIN_ID = 'shieldcortex-realtime';
  const INSTALL_DIR = '/home/u/.openclaw/extensions/shieldcortex-realtime';
  const VERSION = '4.12.11';

  function correctConfig() {
    return {
      plugins: {
        allow: [PLUGIN_ID],
        installs: {
          [PLUGIN_ID]: {
            source: 'path',
            installPath: INSTALL_DIR,
            version: VERSION,
            installedAt: '2026-04-25T00:00:00.000Z',  // any prior timestamp
          },
        },
        entries: {
          [PLUGIN_ID]: { enabled: true },
        },
      },
    };
  }

  it('returns false when config already matches (no write needed)', () => {
    expect(pluginInstallNeedsWrite(correctConfig(), PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(false);
  });

  it('returns true when version changed', () => {
    const cfg = correctConfig();
    cfg.plugins.installs[PLUGIN_ID].version = '4.12.10';
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when installPath changed', () => {
    const cfg = correctConfig();
    cfg.plugins.installs[PLUGIN_ID].installPath = '/different/path';
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when source drifted from "path" (e.g. corrupted to "npm")', () => {
    const cfg = correctConfig();
    (cfg.plugins.installs[PLUGIN_ID] as any).source = 'npm';
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
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
    delete (cfg.plugins.entries as any)[PLUGIN_ID];
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when installs.* is entirely missing', () => {
    const cfg = correctConfig();
    cfg.plugins.installs = {};
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('returns true when plugins block is entirely absent (fresh install)', () => {
    expect(pluginInstallNeedsWrite({}, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(true);
  });

  it('treats installedAt as transient — does not force a write when only it differs', () => {
    const cfg = correctConfig();
    cfg.plugins.installs[PLUGIN_ID].installedAt = 'literally any other value';
    expect(pluginInstallNeedsWrite(cfg, PLUGIN_ID, INSTALL_DIR, VERSION)).toBe(false);
  });
});
