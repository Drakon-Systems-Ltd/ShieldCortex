import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * The resolver under test (#76) is now deterministic and PATH-immune: it always
 * emits an ABSOLUTE node interpreter (`process.execPath`) + the absolute bundled
 * `dist/index.js`, regardless of whether a `shieldcortex` bin is on PATH. No
 * `which` shell-out, no `npx -y` fallback — so these assertions no longer depend
 * on the ambient environment.
 */

describe('MCP global server registration (guards against npx-y hash thrash)', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  const originalPath = process.env.PATH;
  let tempHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let logSpy: jest.SpiedFunction<typeof console.log>;

  beforeEach(() => {
    jest.resetModules();
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-mcp-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    homedirSpy.mockRestore();
    logSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function mcpPath(): string {
    return path.join(tempHome, '.claude.json');
  }

  // Call setupGlobalMcp directly rather than the full setupClaudeMd flow.
  // setupClaudeMd also runs setupHooks + isOpenClawInstalled (2 execSyncs)
  // + potentially installOpenClawHook — none of that affects the .claude.json
  // assertions below, and on some machines it pushed runtime past the 10s
  // jest timeout (the historical flake in this suite).
  async function runSetup() {
    const { setupGlobalMcp } = await import('../setup/claude-md.js');
    setupGlobalMcp();
  }

  describe('emits an absolute node + dist entry (PATH-immune, #76)', () => {
    it('writes { command: <absolute node>, args: [<absolute index.js>] }', async () => {
      await runSetup();

      const written = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
      const entry = written.mcpServers.memory;
      expect(entry.type).toBe('stdio');
      expect(entry.command).toBe(process.execPath);
      expect(path.isAbsolute(entry.command)).toBe(true);
      expect(Array.isArray(entry.args)).toBe(true);
      expect(entry.args).toHaveLength(1);
      expect(path.isAbsolute(entry.args[0])).toBe(true);
      expect(entry.args[0].endsWith('index.js')).toBe(true);
      // Never the fragile forms it replaces.
      expect(entry.command).not.toBe('npx');
      expect(JSON.stringify(entry.args)).not.toContain('npx');
    });

    it('upgrades a stale `npx -y shieldcortex` registration to the stable node+dist path', async () => {
      fs.writeFileSync(
        mcpPath(),
        JSON.stringify({
          mcpServers: {
            memory: { type: 'stdio', command: 'npx', args: ['-y', 'shieldcortex'] },
          },
          otherUserField: 'preserve-me',
        }) + '\n',
      );

      await runSetup();

      const written = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
      expect(written.mcpServers.memory.command).toBe(process.execPath);
      expect(written.mcpServers.memory.args).toHaveLength(1);
      expect(written.mcpServers.memory.command).not.toBe('npx');
      expect(written.otherUserField).toBe('preserve-me');
    });

    it('is idempotent — running setup twice with a stable binary does not rewrite', async () => {
      await runSetup();
      const firstMtime = fs.statSync(mcpPath()).mtimeMs;

      // Wait long enough that a rewrite would produce a different mtime on all
      // filesystems (some macOS HFS+ volumes round to whole seconds).
      await new Promise((r) => setTimeout(r, 1100));

      await runSetup();
      const secondMtime = fs.statSync(mcpPath()).mtimeMs;

      expect(secondMtime).toBe(firstMtime);
    });
  });
});
