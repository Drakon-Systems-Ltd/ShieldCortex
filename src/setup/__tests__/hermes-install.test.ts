import { mkdtempSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, afterEach } from '@jest/globals';
import { installHermes, hermesPluginInstalled, uninstallHermes } from '../hermes.js';

describe('hermes install', () => {
  const homes: string[] = [];
  afterEach(() => {
    for (const home of homes) rmSync(home, { recursive: true, force: true });
    homes.length = 0;
  });

  it('copies plugin.yaml into ~/.hermes/plugins/shieldcortex', async () => {
    const home = mkdtempSync(join(tmpdir(), 'sc-hermes-'));
    homes.push(home);
    expect(hermesPluginInstalled(home)).toBe(false);
    await installHermes(home);
    expect(hermesPluginInstalled(home)).toBe(true);
    expect(existsSync(join(home, '.hermes', 'plugins', 'shieldcortex', 'plugin.yaml'))).toBe(true);
    await uninstallHermes(home);
    expect(hermesPluginInstalled(home)).toBe(false);
  });

  it('install copy does not claim Guard is on by default', async () => {
    const home = mkdtempSync(join(tmpdir(), 'sc-hermes-'));
    homes.push(home);
    const logs: string[] = [];
    const orig = console.log;
    console.log = (...args: unknown[]) => { logs.push(args.map(String).join(' ')); };
    try {
      await installHermes(home);
    } finally {
      console.log = orig;
    }
    const text = logs.join('\n');
    expect(text).toMatch(/Action Guard stays off/);
    expect(text).not.toMatch(/Enforce is ON by default/);
  });

  it('warns — and moves nothing — when a shadowing copy is already there (#569)', async () => {
    const home = mkdtempSync(join(tmpdir(), 'sc-hermes-'));
    homes.push(home);
    // Sorts after `shieldcortex`, so Hermes loads THIS on the next start and
    // the install we are about to do never runs.
    const shadow = join(home, '.hermes', 'plugins', 'shieldcortex.bak-pre510-x');
    mkdirSync(shadow, { recursive: true });
    writeFileSync(join(shadow, 'plugin.yaml'), 'name: shieldcortex\nkind: standalone\n');

    const warnings: string[] = [];
    const origWarn = console.warn;
    const origLog = console.log;
    console.warn = (...args: unknown[]) => { warnings.push(args.map(String).join(' ')); };
    console.log = () => {};
    try {
      await installHermes(home);
    } finally {
      console.warn = origWarn;
      console.log = origLog;
    }

    const text = warnings.join('\n');
    expect(text).toMatch(/shieldcortex\.bak-pre510-x/);
    expect(text).toMatch(/LOADED BY HERMES/);
    expect(text).toMatch(/--fix-hermes-plugin-copies/);
    // Warn only: the copy is the operator's, and which one they meant to keep
    // is not a decision the installer gets to make mid-install. Nothing was
    // relocated, and `backups/` — the directory the repair reserves under —
    // was never even created.
    expect(existsSync(join(shadow, 'plugin.yaml'))).toBe(true);
    expect(existsSync(join(home, '.hermes', 'backups'))).toBe(false);
    expect(hermesPluginInstalled(home)).toBe(true);
  });
});
