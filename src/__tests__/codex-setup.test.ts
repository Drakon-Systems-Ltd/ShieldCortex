import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { installCodex, uninstallCodex } from '../setup/codex.js';

/**
 * codex install resolves the MCP command as an ABSOLUTE node interpreter +
 * absolute `dist/index.js` (the #76 PATH-immune fix) — never a bare shebang bin
 * (dies with -32000 when a GUI/launchd spawn lacks `node` on PATH) nor `npx -y`
 * (hash-thrash). `process.execPath` is the node running these tests, so that is
 * the expected command string in the TOML block.
 */

describe('Codex setup', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  let tempHome: string;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let errorSpy: jest.SpiedFunction<typeof console.error>;
  let existsSpy: jest.SpiedFunction<typeof fs.existsSync>;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-codex-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
    const realExists = fs.existsSync.bind(fs);
    existsSpy = jest.spyOn(fs, 'existsSync').mockImplementation((target: fs.PathLike) => {
      const resolved = String(target);
      if (resolved.endsWith(`${path.sep}src${path.sep}index.js`) || resolved.endsWith(`${path.sep}dist${path.sep}index.js`)) {
        return true;
      }
      return realExists(target);
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
    existsSpy.mockRestore();
    homedirSpy.mockRestore();
    if (originalHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = originalHome;
    }
    if (originalUserProfile === undefined) {
      delete process.env.USERPROFILE;
    } else {
      process.env.USERPROFILE = originalUserProfile;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function configPath(): string {
    return path.join(tempHome, '.codex', 'config.toml');
  }

  function readConfig(): string {
    return fs.readFileSync(configPath(), 'utf-8');
  }

  it('dedupes repeated shieldcortex MCP blocks on install', async () => {
    fs.mkdirSync(path.dirname(configPath()), { recursive: true });
    fs.writeFileSync(
      configPath(),
      [
        'model = "gpt-5.4"',
        '',
        '[mcp_servers.shieldcortex-memory]',
        'command = "node"',
        'args = ["/tmp/dev.js"]',
        '',
        '[mcp_servers.shieldcortex-memory]',
        'command = "node"',
        'args = ["/tmp/global.js"]',
        '',
        '[mcp_servers.other]',
        'command = "node"',
        'args = ["/tmp/other.js"]',
        '',
      ].join('\n'),
      'utf-8',
    );

    await installCodex();

    const content = readConfig();
    const matches = content.match(/\[mcp_servers\.shieldcortex-memory\]/g) ?? [];
    expect(matches).toHaveLength(1);
    expect(content).toContain('[mcp_servers.other]');
    expect(content).toContain('shieldcortex');
    // The resolved command is either the absolute global binary or
    // `node <dist/index.js>` — never `npx -y` (the hash-thrash class).
    expect(content).not.toContain('npx');
    // #76: absolute node interpreter + absolute bundled dist entry.
    expect(content).toContain(`command = "${process.execPath}"`);
    expect(content).toContain('index.js');
    expect(content).not.toContain('/tmp/dev.js');
    expect(content).not.toContain('/tmp/global.js');
  });

  it('refreshes a stale shieldcortex MCP entry on re-install (absolute command, no npx)', async () => {
    fs.mkdirSync(path.dirname(configPath()), { recursive: true });
    // A stale entry from an older version: npx -y shieldcortex (the exact form
    // the v4.11.1 fix exists to eliminate).
    fs.writeFileSync(
      configPath(),
      [
        '[mcp_servers.shieldcortex-memory]',
        'command = "npx"',
        'args = ["-y", "shieldcortex"]',
        '',
      ].join('\n'),
      'utf-8',
    );

    await installCodex();

    const content = readConfig();
    const matches = content.match(/\[mcp_servers\.shieldcortex-memory\]/g) ?? [];
    expect(matches).toHaveLength(1);
    // Stale npx form must be gone; replaced by an absolute node + dist command.
    expect(content).not.toContain('command = "npx"');
    expect(content).toContain(`command = "${process.execPath}"`);
    expect(content).toContain('index.js');
  });

  it('removes only the shieldcortex MCP block on uninstall', async () => {
    fs.mkdirSync(path.dirname(configPath()), { recursive: true });
    fs.writeFileSync(
      configPath(),
      [
        'model = "gpt-5.4"',
        '',
        '[mcp_servers.shieldcortex-memory]',
        'command = "node"',
        'args = ["/tmp/current.js"]',
        '',
        '[mcp_servers.other]',
        'command = "node"',
        'args = ["/tmp/other.js"]',
        '',
      ].join('\n'),
      'utf-8',
    );

    await uninstallCodex();

    const content = readConfig();
    expect(content).not.toContain('[mcp_servers.shieldcortex-memory]');
    expect(content).toContain('[mcp_servers.other]');
    expect(content).toContain('model = "gpt-5.4"');
  });
});
