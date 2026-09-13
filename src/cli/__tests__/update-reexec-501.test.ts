import { describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { reexecUpdatedCli, stepOpenClawPlugin } from '../update.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

describe('update executes the newly installed CLI', () => {
  it('passes identical command args without a shell and sets the one-hop sentinel', async () => {
    const launch = jest.fn(async (_bin: string, _args: string[], _env: NodeJS.ProcessEnv) => 7);
    expect(await reexecUpdatedCli('4.54.15', {
      readVersion: () => '5.0.0', env: {}, argv: ['update', '--force', '--verbose'], launch,
    })).toBe(7);
    expect(launch).toHaveBeenCalledWith(process.execPath, [path.join(root, 'dist/index.js'), 'update', '--force', '--verbose'], {
      SHIELDCORTEX_UPDATE_REEXEC: '1',
      SHIELDCORTEX_UPDATE_FROM_VERSION: '4.54.15',
    });
  });

  it('matching disk versions or an existing sentinel never launch a second process', async () => {
    const launch = jest.fn(async () => 0);
    expect(await reexecUpdatedCli('5.0.0', { readVersion: () => '5.0.0', env: {}, launch })).toBeNull();
    expect(await reexecUpdatedCli('4.54.15', { readVersion: () => '5.0.0', env: { SHIELDCORTEX_UPDATE_REEXEC: '1' }, launch })).toBeNull();
    expect(launch).not.toHaveBeenCalled();
  });

  it('a failed spawn warns and returns promptly for an unproven fallback', async () => {
    const warn = jest.fn();
    expect(await reexecUpdatedCli('4.54.15', {
      readVersion: () => '5.0.0', env: {}, warn,
      launch: async () => { throw new Error('ENOENT'); },
    })).toBe('failed');
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/could not start.*protection unproven/i));
  });

  it('runUpdate hands off after npm success, before engine/plugin work, and exits with child status', () => {
    const src = fs.readFileSync(path.join(root, 'src/cli/update.ts'), 'utf8');
    const body = src.slice(src.indexOf('export async function runUpdate'));
    expect(body.indexOf('await reexecUpdatedCli')).toBeGreaterThan(body.indexOf('await stepNpmPackage'));
    expect(body.indexOf('await reexecUpdatedCli')).toBeLessThan(body.indexOf('await stepVerifyEngine'));
    expect(body).toMatch(/if \(mainUpdated\)/);
    expect(body).toMatch(/process\.exit\(handoff\)/);
    expect(body).toMatch(/reexecFailed[\s\S]*protection unproven/);
    expect(src).toMatch(/shell: false/);
    expect(body).toContain('maybePrintActionGuardDefaultOffNotice(mainUpdated)');
    expect(src).toContain('SHIELDCORTEX_UPDATE_FROM_VERSION');
    expect(body).toMatch(/maybePrint411Notice\(fromVersion/);
  });
});

describe('plugin update reads the installed version against the fresh CLI', () => {
  async function runCase(before: string, after: string | null, expected = '5.0.0') {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc501-plugin-'));
    try {
      const dir = path.join(home, '.openclaw/plugins');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'installs.json'), JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }));
      let reads = 0;
      return await stepOpenClawPlugin(home, {
        run: async () => ({ stdout: '', stderr: '' }),
        readPluginVersion: () => reads++ === 0 ? before : after,
        readCliVersion: () => expected,
      });
    } finally { fs.rmSync(home, { recursive: true, force: true }); }
  }

  it('a pinned old install is WARN, not up to date', async () => {
    const result = await runCase('4.54.15', '4.54.15');
    expect(result.status).toBe('warn');
    expect(result.summary).toContain('still v4.54.15 — CLI is v5.0.0');
    expect(result.summary).not.toContain('up to date');
  });

  it('only matching versions can be called up to date', async () => {
    expect(await runCase('5.0.0', '5.0.0')).toMatchObject({ status: 'ok', summary: 'up to date (v5.0.0)' });
    expect((await runCase('5.0.1', '5.0.1')).summary).not.toContain('up to date');
    expect((await runCase('5.0.0', null)).status).toBe('warn');
  });

  it('reports transitions, retaining WARN if a transition still lags', async () => {
    expect(await runCase('4.54.15', '5.0.0')).toMatchObject({ status: 'ok', summary: '4.54.15 → 5.0.0' });
    const lag = await runCase('4.54.14', '4.54.15');
    expect(lag.status).toBe('warn');
    expect(lag.summary).toContain('4.54.14 → 4.54.15');
  });
});
