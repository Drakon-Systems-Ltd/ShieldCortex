import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * The MCP registration is now PATH-immune (issue #76): it always emits the
 * ABSOLUTE node binary (`process.execPath`) + the ABSOLUTE `dist/index.js`,
 * regardless of whether a `shieldcortex` binary is on PATH. It never emits the
 * shebang bin as the command (which dies when node isn't on the spawn PATH →
 * bare -32000) and never `npx -y` (hash-thrash).
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

  describe('PATH-immune registration (#76)', () => {
    it('writes an absolute node binary + absolute dist/index.js (never a shebang bin, never npx)', async () => {
      await runSetup();

      const written = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
      const entry = written.mcpServers.memory;
      expect(entry.type).toBe('stdio');
      expect(entry.command).toBe(process.execPath);
      expect(entry.command).not.toBe('npx');
      expect(Array.isArray(entry.args)).toBe(true);
      expect(entry.args.length).toBeGreaterThanOrEqual(1);
      const script = entry.args[entry.args.length - 1];
      expect(path.isAbsolute(script)).toBe(true);
      expect(path.basename(script)).toBe('index.js');
    });

    it('upgrades a stale `npx -y shieldcortex` registration to the PATH-immune command', async () => {
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
      expect(written.mcpServers.memory.command).not.toBe('npx');
      expect(path.basename(written.mcpServers.memory.args.at(-1))).toBe('index.js');
      expect(written.otherUserField).toBe('preserve-me');
    });

    it('is idempotent — running setup twice does not rewrite', async () => {
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
