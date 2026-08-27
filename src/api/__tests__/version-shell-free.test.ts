/**
 * #429 — version helpers must never spawn a shell.
 *
 * SKILL.md promises the update flow never spawns a shell (user-run admin
 * commands are the documented, separately-listed exception). These tests pin
 * version.ts to execFile/execFileSync argv-arrays: the command and every
 * argument are separate array elements, so shell metacharacters can never be
 * interpreted, and the shell-string APIs are never called.
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

const execFileSyncMock = jest.fn();
const execFileMock = jest.fn();
const execSyncMock = jest.fn();
const execMock = jest.fn();

// The mock must provide every export the module under test could link,
// including the shell-string APIs — so a regression back to them shows up
// as a failed call-count assertion, not an ESM link error.
jest.unstable_mockModule('child_process', () => ({
  execFileSync: execFileSyncMock,
  execFile: execFileMock,
  execSync: execSyncMock,
  exec: execMock,
  default: {
    execFileSync: execFileSyncMock,
    execFile: execFileMock,
    execSync: execSyncMock,
    exec: execMock,
  },
}));

const version = await import('../version.js');

beforeEach(() => {
  execFileSyncMock.mockReset();
  execFileMock.mockReset();
  execSyncMock.mockReset();
  execMock.mockReset();
});

describe('checkForUpdates (#429)', () => {
  it('queries the npm registry via execFileSync argv-array, no shell', async () => {
    execFileSyncMock.mockReturnValue('9.9.9\n');

    const info = await version.checkForUpdates(true);

    expect(execFileSyncMock).toHaveBeenCalledTimes(1);
    const [cmd, args, opts] = execFileSyncMock.mock.calls[0] as [string, string[], Record<string, unknown>];
    expect(cmd).toBe('npm');
    expect(args).toEqual(['view', 'shieldcortex', 'version']);
    expect(opts.shell).toBeUndefined();
    expect(info.latestVersion).toBe('9.9.9');
    expect(execSyncMock).not.toHaveBeenCalled();
    expect(execMock).not.toHaveBeenCalled();
  });

  it('reports no update on registry failure, still without a shell', async () => {
    execFileSyncMock.mockImplementation(() => {
      throw new Error('ENOTFOUND registry.npmjs.org');
    });

    const info = await version.checkForUpdates(true);

    expect(info.latestVersion).toBeNull();
    expect(info.updateAvailable).toBe(false);
    expect(execSyncMock).not.toHaveBeenCalled();
    expect(execMock).not.toHaveBeenCalled();
  });
});

describe('performUpdate (#429)', () => {
  it('runs npm update via execFile argv-array, no shell', async () => {
    execFileMock.mockImplementation((...call: unknown[]) => {
      const cb = call[call.length - 1] as (e: Error | null, stdout: string, stderr: string) => void;
      cb(null, '', '');
    });

    const result = await version.performUpdate();

    expect(execFileMock).toHaveBeenCalledTimes(1);
    const [cmd, args, opts] = execFileMock.mock.calls[0] as [string, string[], Record<string, unknown>, unknown];
    expect(cmd).toBe('npm');
    expect(args).toEqual(['update', '-g', 'shieldcortex']);
    expect(opts.shell).toBeUndefined();
    expect(result.success).toBe(true);
    expect(execMock).not.toHaveBeenCalled();
    expect(execSyncMock).not.toHaveBeenCalled();
  });

  it('surfaces npm failure without falling back to a shell', async () => {
    execFileMock.mockImplementation((...call: unknown[]) => {
      const cb = call[call.length - 1] as (e: Error | null, stdout: string, stderr: string) => void;
      cb(new Error('command failed'), '', 'EACCES: permission denied');
    });

    const result = await version.performUpdate();

    expect(result.success).toBe(false);
    expect(result.error).toContain('sudo npm update -g shieldcortex');
    expect(execMock).not.toHaveBeenCalled();
    expect(execSyncMock).not.toHaveBeenCalled();
  });
});

describe('restartMcpServers (#429)', () => {
  it('finds MCP processes via execFileSync pgrep argv-array, no shell', () => {
    execFileSyncMock.mockReturnValue('');

    const killed = version.restartMcpServers();

    expect(killed).toBe(0);
    expect(execFileSyncMock).toHaveBeenCalledTimes(1);
    const [cmd, args, opts] = execFileSyncMock.mock.calls[0] as [string, string[], Record<string, unknown>];
    expect(cmd).toBe('pgrep');
    expect(args).toEqual(['-f', 'shieldcortex']);
    expect(opts.shell).toBeUndefined();
    expect(execSyncMock).not.toHaveBeenCalled();
    expect(execMock).not.toHaveBeenCalled();
  });

  it('treats pgrep no-match (non-zero exit throw) as zero restarts', () => {
    // Without shell `|| true` plumbing, pgrep exits 1 when nothing matches
    // and execFileSync throws — that must mean "nothing to restart".
    execFileSyncMock.mockImplementation(() => {
      throw new Error('Command failed: pgrep -f shieldcortex');
    });

    expect(version.restartMcpServers()).toBe(0);
  });
});

describe('version.ts source (#429)', () => {
  it('links only the shell-free child_process APIs', () => {
    const src = readFileSync(fileURLToPath(new URL('../version.ts', import.meta.url)), 'utf-8');

    expect(src).toMatch(/execFileSync/);
    expect(src).not.toMatch(/\bexecSync\b/);
    expect(src).not.toMatch(/\bexec\s*[(]/);
    expect(src).not.toMatch(/shell\s*:/);
  });
});
