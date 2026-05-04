import { describe, expect, it } from '@jest/globals';
import { isPluginRegisteredInOpenClawConfig } from '../deep-clean.js';

/**
 * Regression test for the 4 May 2026 doctor false-positive.
 *
 * Symptom: every Mac homebrew install (and any install where OpenClaw
 * registered the plugin natively via `openclaw plugins install <pkg>`)
 * had doctor reporting:
 *
 *   ⚠ OpenClaw residue: 2 orphans
 *     openclaw.json: .plugins.entries["shieldcortex-realtime"]
 *     openclaw.json: .plugins.allow[] contains "shieldcortex-realtime"
 *
 * Root cause: `detectInstallState()` only looked for the plugin file
 * on disk in three specific paths. None of them is where OpenClaw's
 * native plugin install puts the bytes — that's OpenClaw's own
 * internal tree, which we don't (and shouldn't) probe directly.
 *
 * Fix: when `plugins.entries[<id>]` AND `plugins.allow[]` both list
 * the plugin, trust OpenClaw's own registration. The plugin is loadable
 * by OpenClaw — that's the contract.
 */
describe('isPluginRegisteredInOpenClawConfig', () => {
  it('returns false when entries is missing', () => {
    const cfg = {
      plugins: {
        allow: ['shieldcortex-realtime'],
      },
    };
    expect(isPluginRegisteredInOpenClawConfig(cfg)).toBe(false);
  });

  it('returns false when allow is missing', () => {
    const cfg = {
      plugins: {
        entries: { 'shieldcortex-realtime': { enabled: true } },
      },
    };
    expect(isPluginRegisteredInOpenClawConfig(cfg)).toBe(false);
  });

  it('returns false when allow is present but does not include the plugin', () => {
    const cfg = {
      plugins: {
        entries: { 'shieldcortex-realtime': { enabled: true } },
        allow: ['anthropic', 'openai'],
      },
    };
    expect(isPluginRegisteredInOpenClawConfig(cfg)).toBe(false);
  });

  it('returns true on the symptom config (entries + allow both list the plugin)', () => {
    // Verbatim shape from the user-reported install on 4 May 2026 that
    // triggered the bug. Keeps any future regression honest.
    const cfg = {
      plugins: {
        allow: [
          'telegram', 'openai', 'openrouter', 'google', 'xai',
          'memory-core', 'anthropic', 'microsoft', 'shieldcortex-realtime',
        ],
        load: { paths: [] },
        entries: {
          openai: { enabled: true, config: { personality: 'off' } },
          openrouter: { enabled: true },
          google: { enabled: true },
          xai: { enabled: true },
          anthropic: { enabled: true },
          telegram: { enabled: true },
          microsoft: { enabled: true },
          'shieldcortex-realtime': { enabled: true },
        },
      },
    };
    expect(isPluginRegisteredInOpenClawConfig(cfg)).toBe(true);
  });

  it('returns false on an empty config', () => {
    expect(isPluginRegisteredInOpenClawConfig({})).toBe(false);
    expect(isPluginRegisteredInOpenClawConfig(null)).toBe(false);
  });

  it('does not match a plugin id that is a prefix of the registered id', () => {
    // The contains check uses strict equality against the array entries
    // (not substring), so 'shieldcortex' alone would not falsely match
    // 'shieldcortex-realtime' or vice versa.
    const cfg = {
      plugins: {
        entries: { 'shieldcortex-realtime': { enabled: true } },
        allow: ['shieldcortex'], // wrong id — should not be treated as registered
      },
    };
    expect(isPluginRegisteredInOpenClawConfig(cfg)).toBe(false);
  });
});
