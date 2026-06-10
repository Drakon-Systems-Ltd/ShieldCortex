import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { installCopilot } from '../setup/copilot.js';

/**
 * copilot install resolves the MCP command via `which shieldcortex` (the
 * v4.11.1 stable-binary fix). Under `npm test` a shieldcortex binary usually
 * exists on PATH; use that as the expected command. Fallback is
 * `node <dist/index.js>`. Either way it must NEVER be `npx -y` (hash-thrash).
 */
function resolvedShieldCortexBinary(): string | null {
  try {
    const whichCmd = process.platform === 'win32' ? 'where' : 'which';
    const out = execSync(`${whichCmd} shieldcortex`, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] })
      .trim()
      .split('\n')[0]
      .trim();
    return out && fs.existsSync(out) ? out : null;
  } catch {
    return null;
  }
}

/** Expected command/args the resolver should produce in this environment. */
function expectedCommand(): { command: string; argsLengthAtLeast: number } {
  const ambient = resolvedShieldCortexBinary();
  return ambient
    ? { command: ambient, argsLengthAtLeast: 0 }
    : { command: 'node', argsLengthAtLeast: 1 };
}

// VS Code (darwin) lives under ~/Library/Application Support/Code/User; Cursor
// under ~/.cursor. We stage a temp HOME and create those dirs so findVsCodeDirs
// / findCursorDir discover them. The MCP entry existence check is satisfied via
// an fs.existsSync mock (same approach as codex-setup.test.ts) since there's no
// real dist/ in a fresh checkout.
describe('Copilot/Cursor setup', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  let tempHome: string;
  let cursorMcpPath: string;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let warnSpy: jest.SpiedFunction<typeof console.warn>;
  let errorSpy: jest.SpiedFunction<typeof console.error>;
  let existsSpy: jest.SpiedFunction<typeof fs.existsSync>;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-copilot-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;

    // Stage a Cursor config dir (most portable across CI platforms).
    fs.mkdirSync(path.join(tempHome, '.cursor'), { recursive: true });
    cursorMcpPath = path.join(tempHome, '.cursor', 'mcp.json');

    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
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
    warnSpy.mockRestore();
    errorSpy.mockRestore();
    existsSpy.mockRestore();
    homedirSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function readCursor(): any {
    return JSON.parse(fs.readFileSync(cursorMcpPath, 'utf-8'));
  }

  it('writes an absolute resolved command (never npx -y) to a fresh Cursor config', async () => {
    await installCopilot();

    const config = readCursor();
    const entry = config.mcpServers['shieldcortex-memory'];
    expect(entry).toBeDefined();
    expect(entry.command).not.toBe('npx');
    expect(JSON.stringify(entry.args)).not.toContain('npx');

    const { command, argsLengthAtLeast } = expectedCommand();
    expect(entry.command).toBe(command);
    expect(Array.isArray(entry.args)).toBe(true);
    expect(entry.args.length).toBeGreaterThanOrEqual(argsLengthAtLeast);
    // Cursor schema omits the `type` field.
    expect(entry.type).toBeUndefined();
  });

  it('refreshes a STALE shieldcortex entry on re-install (npx -y → absolute command)', async () => {
    // Pre-seed a stale entry exactly as an older version would have written it.
    fs.writeFileSync(
      cursorMcpPath,
      JSON.stringify({
        mcpServers: {
          'shieldcortex-memory': { command: 'npx', args: ['-y', 'shieldcortex'] },
          other: { command: 'node', args: ['/tmp/other.js'] },
        },
      }) + '\n',
      'utf-8',
    );

    await installCopilot();

    const config = readCursor();
    const entry = config.mcpServers['shieldcortex-memory'];
    expect(entry.command).not.toBe('npx');
    expect(entry.command).toBe(expectedCommand().command);
    // Unrelated servers are preserved untouched.
    expect(config.mcpServers.other).toEqual({ command: 'node', args: ['/tmp/other.js'] });
  });

  it('leaves a NON-ShieldCortex entry parked under the same name alone', async () => {
    fs.writeFileSync(
      cursorMcpPath,
      JSON.stringify({
        mcpServers: {
          'shieldcortex-memory': { command: 'node', args: ['/opt/somebody-elses-server.js'] },
        },
      }) + '\n',
      'utf-8',
    );

    await installCopilot();

    const config = readCursor();
    // Foreign entry untouched (looksLikeShieldcortex guard).
    expect(config.mcpServers['shieldcortex-memory']).toEqual({
      command: 'node',
      args: ['/opt/somebody-elses-server.js'],
    });
  });

  it('does not rewrite an already-current entry (idempotent)', async () => {
    await installCopilot(); // first write
    const firstMtime = fs.statSync(cursorMcpPath).mtimeMs;

    await new Promise((r) => setTimeout(r, 1100));
    await installCopilot(); // second run — should be a no-op
    const secondMtime = fs.statSync(cursorMcpPath).mtimeMs;

    expect(secondMtime).toBe(firstMtime);
  });
});
