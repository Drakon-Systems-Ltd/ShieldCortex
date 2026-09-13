import { mkdtempSync, existsSync, rmSync } from 'node:fs';
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
});
