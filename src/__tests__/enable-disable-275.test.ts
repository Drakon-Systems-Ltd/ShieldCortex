import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

/**
 * #275 — `shieldcortex enable|disable`.
 *
 * `doctor` used to prescribe a JSON key path (`actionGuard.notify.enabled: true`)
 * with no command that could set it: `shieldcortex config` is cloud-only, so the
 * only route was hand-editing `~/.shieldcortex/config.json`. That edit breaks the
 * embedded `_sig` HMAC, so the next read reports "possible tampering detected"
 * and forces `defenceMode: strict` — the tool's own remediation advice degraded
 * the install.
 *
 * The contract pinned here:
 *   1. Every toggle writes through the SIGNING writer, so a feature the operator
 *      enabled never reads back as tampered. This is the whole point.
 *   2. Unrelated settings survive (a config write must never wipe cloudApiKey).
 *   3. An unknown feature fails loudly and names the real ones — no silent no-op.
 *   4. Reading state never mutates the config.
 */

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;

describe('#275 — enable/disable toggles', () => {
  let tempDir: string;
  let configDir: string;
  let configFile: string;

  beforeEach(() => {
    jest.resetModules();
    tempDir = mkdtempSync(join(tmpdir(), 'sc-toggles-'));
    configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    configFile = join(configDir, 'config.json');
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  });

  afterEach(() => {
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
    rmSync(tempDir, { recursive: true, force: true });
  });

  const readConfig = () => JSON.parse(readFileSync(configFile, 'utf8')) as Record<string, unknown>;

  it('enabling a feature does NOT trip the integrity check (the #275 defect)', async () => {
    const { setCloudConfig, isConfigTampered, clearCloudConfigCache, readRawConfig } =
      await import('../cloud/config.js');
    const { applyToggle } = await import('../cli/toggles.js');

    // A legitimately-signed starting config, with a secret that must survive.
    setCloudConfig({ cloudApiKey: 'sc_live_' + 'KEEPME', cloudEnabled: true });
    expect(typeof readConfig()._sig).toBe('string');

    const result = applyToggle('notify', true, { openclaw: true });
    expect(result.ok).toBe(true);

    // The value landed…
    const guard = readRawConfig().actionGuard as Record<string, unknown>;
    const notify = guard.notify as Record<string, unknown>;
    expect(notify.enabled).toBe(true);
    expect(notify.openclaw).toBe(true);

    // …the file is still signed, and a FRESH read does not cry tampering.
    expect(typeof readConfig()._sig).toBe('string');
    clearCloudConfigCache();
    readRawConfig();
    expect(isConfigTampered()).toBe(false);
  });

  it('preserves unrelated settings — a toggle must never wipe the config', async () => {
    const { setCloudConfig, getCloudConfig, clearCloudConfigCache } = await import('../cloud/config.js');
    const { applyToggle } = await import('../cli/toggles.js');

    setCloudConfig({ cloudApiKey: 'sc_live_' + 'KEEPME', cloudEnabled: true });
    applyToggle('notify', true, { openclaw: true });

    clearCloudConfigCache();
    const cloud = getCloudConfig();
    expect(cloud.cloudApiKey).toBe('sc_live_' + 'KEEPME');
    expect(cloud.cloudEnabled).toBe(true);
  });

  it('disable turns the feature off without removing neighbouring keys', async () => {
    const { readRawConfig, clearCloudConfigCache } = await import('../cloud/config.js');
    const { applyToggle } = await import('../cli/toggles.js');

    applyToggle('notify', true, { webhookUrl: 'https://ops.example/hook' });
    applyToggle('notify', false, {});

    clearCloudConfigCache();
    const notify = (readRawConfig().actionGuard as Record<string, unknown>).notify as Record<string, unknown>;
    expect(notify.enabled).toBe(false);
    // The endpoint is retained so re-enabling does not require re-entering it.
    expect(notify.webhookUrl).toBe('https://ops.example/hook');
  });

  it('rejects an unknown feature and names the real ones', async () => {
    const { applyToggle, listToggles } = await import('../cli/toggles.js');
    const result = applyToggle('nonsense', true, {});
    expect(result.ok).toBe(false);
    const ids = listToggles().map((t) => t.id);
    expect(ids).toContain('notify');
    for (const id of ids) expect(typeof id).toBe('string');
    // The error has to be actionable — it must list what IS valid.
    expect(ids.some((id) => result.message.includes(id))).toBe(true);
  });

  it('refuses a webhook URL that is not http(s) rather than storing a spoofed channel', async () => {
    const { applyToggle } = await import('../cli/toggles.js');
    const result = applyToggle('notify', true, { webhookUrl: 'javascript:alert(1)' });
    expect(result.ok).toBe(false);
  });

  it('listing state never mutates the config', async () => {
    const { listToggles } = await import('../cli/toggles.js');
    writeFileSync(configFile, JSON.stringify({ deviceId: 'abc' }, null, 2) + '\n', { mode: 0o600 });
    const before = readFileSync(configFile, 'utf8');
    listToggles();
    expect(readFileSync(configFile, 'utf8')).toBe(before);
  });

  it('every registered toggle reports a state and a one-line summary', async () => {
    const { listToggles } = await import('../cli/toggles.js');
    for (const t of listToggles()) {
      expect(t.summary.length).toBeGreaterThan(0);
      expect(['on', 'off', 'unknown']).toContain(t.state);
    }
  });
});

/**
 * Pins EXISTING behaviour (config.ts:554 clears the flag on a legitimate write).
 * Written while checking a claim in #275 that the flag was never cleared — it is,
 * on any signed write; it is only stale after a HAND-heal outside the product.
 * Kept as a regression test so the healing path cannot silently rot.
 */
describe('#275 — a signed write clears the tampered flag', () => {
  let tempDir: string;
  let configDir: string;

  beforeEach(() => {
    jest.resetModules();
    tempDir = mkdtempSync(join(tmpdir(), 'sc-tamperflag-'));
    configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  });

  afterEach(() => {
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('a healed config stops reporting tampered once the cache is cleared', async () => {
    const { setCloudConfig, readRawConfig, isConfigTampered, clearCloudConfigCache } =
      await import('../cloud/config.js');
    const configFile = join(configDir, 'config.json');

    setCloudConfig({ cloudEnabled: false });
    // Hand-edit while keeping the now-stale `_sig` — the naive operator edit.
    const bad = JSON.parse(readFileSync(configFile, 'utf8')) as Record<string, unknown>;
    bad.somethingNew = true;
    writeFileSync(configFile, JSON.stringify(bad, null, 2) + '\n', { mode: 0o600 });
    clearCloudConfigCache();
    readRawConfig();
    expect(isConfigTampered()).toBe(true);

    // Heal it the way the product does (a signed write), then clear the cache.
    setCloudConfig({ cloudEnabled: false });
    clearCloudConfigCache();
    readRawConfig();
    expect(isConfigTampered()).toBe(false);
  });
});
