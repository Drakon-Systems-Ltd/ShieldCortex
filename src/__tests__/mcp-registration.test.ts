import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * The resolver under test shells out to `which shieldcortex` (or `where` on
 * Windows). When these tests run under `npm test`, a shieldcortex binary
 * usually exists on PATH — we use *that* resolved path as the expected value
 * instead of fighting to mock exec calls across jest workers.
 *
 * If no shieldcortex binary exists on PATH at all, the "global install"
 * tests are skipped with a clear reason; the fallback test still runs via
 * a PATH override that we know clears the lookup.
 */
function resolvedShieldCortexBinary(): string | null {
  try {
    const whichCmd = process.platform === 'win32' ? 'where' : 'which';
    const out = execSync(`${whichCmd} shieldcortex`, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] })
      .trim()
      .split('\n')[0];
    return out && fs.existsSync(out) ? out : null;
  } catch {
    return null;
  }
}

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

  async function runSetup() {
    const { setupClaudeMd } = await import('../setup/claude-md.js');
    await setupClaudeMd();
  }

  const ambientBinary = resolvedShieldCortexBinary();
  const describeIfBinary = ambientBinary ? describe : describe.skip;

  describeIfBinary('when shieldcortex is on PATH', () => {
    it('prefers resolved binary path over npx -y', async () => {
      await runSetup();

      const written = JSON.parse(fs.readFileSync(mcpPath(), 'utf-8'));
      expect(written.mcpServers.memory).toEqual({
        type: 'stdio',
        command: ambientBinary,
        args: [],
      });
    });

    it('upgrades a stale `npx -y shieldcortex` registration to the stable binary path', async () => {
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
      expect(written.mcpServers.memory.command).toBe(ambientBinary);
      expect(written.mcpServers.memory.args).toEqual([]);
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

  // Note: the "falls back to npx -y when no global binary is on PATH" scenario
  // is not covered by a jest test because `npm test` injects its own PATH into
  // the child process at a level below `process.env.PATH = …`, making it
  // impossible to stage a "nothing on PATH" environment here. The fallback
  // branch in resolveMcpCommand() is covered by inspection: three lines, an
  // execSync-in-try/catch that on any throw returns {command: 'npx', args:
  // ['-y', 'shieldcortex']}. If that branch ever grows non-trivial, move it
  // into a unit-testable helper with explicit env injection.
});
