import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * v4.12.11 — `shieldcortex uninstall` did not remove the
 * `mcpServers.memory` entry that `setupClaudeMd()` writes to
 * `~/.claude.json`. After uninstall, that entry still pointed at the
 * (now-missing) shieldcortex binary, and every Claude Code session that
 * loaded `~/.claude.json` tried to spawn it, failed, and the failure
 * cascaded into the fleet-wide context loss this user has been tracking
 * for weeks. A peer agent (Edith) confirmed manual cleanup of the entry
 * stabilised an affected host within minutes.
 *
 * Two safety constraints on the cleanup:
 *  1. `mcpServers.memory` is a generic key — the official upstream
 *     `@modelcontextprotocol/server-memory` registers under the same
 *     name. We MUST verify the entry is ShieldCortex-owned before
 *     deleting it, otherwise the uninstall would clobber a user's
 *     unrelated MCP server.
 *  2. The cleanup must be invoked from BOTH `uninstallSetup()` AND
 *     `uninstallAll()` — `shieldcortex uninstall --deep` (the most
 *     commonly-used path) goes through `uninstallAll()`. Wiring only to
 *     `uninstallSetup()` would leave the orphan in the worst-case path.
 *
 * This file unit-tests `removeMcpEntry()` directly (the function the
 * uninstallers call). The full uninstaller would otherwise demand
 * `--confirm` or an interactive TTY and exit early under Jest.
 */
describe('removeMcpEntry — cleans only SC-owned mcpServers.memory entries (v4.12.11)', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  let tempHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let warnSpy: jest.SpiedFunction<typeof console.warn>;

  beforeEach(() => {
    jest.resetModules();
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-uninstall-mcp-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    homedirSpy.mockRestore();
    logSpy.mockRestore();
    warnSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function mcpPath(): string {
    return path.join(tempHome, '.claude.json');
  }

  it('removes a ShieldCortex-owned memory entry (global-bin form) and preserves siblings', async () => {
    fs.writeFileSync(mcpPath(), JSON.stringify({
      mcpServers: {
        memory: { type: 'stdio', command: '/usr/local/bin/shieldcortex', args: [] },
        somethingElse: { type: 'stdio', command: '/usr/bin/other' },
      },
      otherTopLevel: 'preserved',
    }, null, 2));

    const { removeMcpEntry } = await import('../setup/uninstall.js');
    removeMcpEntry();

    const after = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
    expect(after.mcpServers.memory).toBeUndefined();
    expect(after.mcpServers.somethingElse).toBeDefined();
    expect(after.otherTopLevel).toBe('preserved');
  });

  it('removes a ShieldCortex-owned memory entry (npx -y shieldcortex form)', async () => {
    fs.writeFileSync(mcpPath(), JSON.stringify({
      mcpServers: {
        memory: { type: 'stdio', command: 'npx', args: ['-y', 'shieldcortex', 'mcp'] },
      },
    }, null, 2));

    const { removeMcpEntry } = await import('../setup/uninstall.js');
    removeMcpEntry();

    const after = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
    expect(after.mcpServers.memory).toBeUndefined();
  });

  it('does NOT remove an unrelated memory entry (e.g. official @modelcontextprotocol/server-memory)', async () => {
    fs.writeFileSync(mcpPath(), JSON.stringify({
      mcpServers: {
        memory: { type: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory'] },
      },
    }, null, 2));

    const { removeMcpEntry } = await import('../setup/uninstall.js');
    removeMcpEntry();

    const after = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
    expect(after.mcpServers.memory).toBeDefined();
    expect(after.mcpServers.memory.args).toContain('@modelcontextprotocol/server-memory');
  });

  it('matches the shield-cortex (with hyphen) variant in args', async () => {
    fs.writeFileSync(mcpPath(), JSON.stringify({
      mcpServers: {
        memory: { type: 'stdio', command: 'node', args: ['/opt/shield-cortex/dist/index.js'] },
      },
    }, null, 2));
    const { removeMcpEntry } = await import('../setup/uninstall.js');
    removeMcpEntry();
    const after = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
    expect(after.mcpServers.memory).toBeUndefined();
  });

  it('is a no-op when ~/.claude.json does not exist', async () => {
    const { removeMcpEntry } = await import('../setup/uninstall.js');
    expect(() => removeMcpEntry()).not.toThrow();
  });

  it('is a no-op when no memory entry is registered', async () => {
    fs.writeFileSync(mcpPath(), JSON.stringify({ mcpServers: { other: {} } }, null, 2));
    const { removeMcpEntry } = await import('../setup/uninstall.js');
    removeMcpEntry();
    const after = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
    expect(after.mcpServers.other).toBeDefined();
  });

  it('does not corrupt invalid JSON — logs warning and exits cleanly', async () => {
    fs.writeFileSync(mcpPath(), '{ this is not json');
    const { removeMcpEntry } = await import('../setup/uninstall.js');
    expect(() => removeMcpEntry()).not.toThrow();
    expect(warnSpy).toHaveBeenCalled();
    expect(fs.readFileSync(mcpPath(), 'utf-8')).toBe('{ this is not json');
  });
});
