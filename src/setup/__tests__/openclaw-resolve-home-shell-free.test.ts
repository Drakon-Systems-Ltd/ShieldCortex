/**
 * #429 — sudo-home resolution must never build a shell string from SUDO_USER.
 *
 * SKILL.md promises the package never uses `eval` (shell or JS) and never
 * interpolates environment-controlled values into shell commands. The
 * installer's resolveUserHome() used to run `getent passwd ${SUDO_USER}` and
 * `eval echo ~${SUDO_USER}` through execSync — SUDO_USER is attacker-
 * influenceable in some sudo setups, making both injectable. These tests pin
 * the replacement: usernames are validated, getent runs as an execFileSync
 * argv-array, and there is no shell-eval fallback of any kind.
 *
 * Exercised through openClawConfigPath(), which resolves the user home on
 * every call with no other child_process traffic on its path.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir, homedir } from 'os';

const execFileSyncMock = jest.fn();
const execFileMock = jest.fn();
const execSyncMock = jest.fn();
const execMock = jest.fn();
const spawnSyncMock = jest.fn();
const spawnMock = jest.fn();

// Every export the module under test could link, including the shell-string
// APIs — a regression back to them must fail a call-count assertion, not
// crash on an ESM link error.
jest.unstable_mockModule('child_process', () => ({
  execFileSync: execFileSyncMock,
  execFile: execFileMock,
  execSync: execSyncMock,
  exec: execMock,
  spawnSync: spawnSyncMock,
  spawn: spawnMock,
  default: {
    execFileSync: execFileSyncMock,
    execFile: execFileMock,
    execSync: execSyncMock,
    exec: execMock,
    spawnSync: spawnSyncMock,
    spawn: spawnMock,
  },
}));

const openclaw = await import('../openclaw.js');
const deepClean = await import('../deep-clean.js');

let prevSudoUser: string | undefined;

beforeEach(() => {
  prevSudoUser = process.env.SUDO_USER;
  execFileSyncMock.mockReset();
  execFileMock.mockReset();
  execSyncMock.mockReset();
  execMock.mockReset();
  spawnSyncMock.mockReset();
  spawnMock.mockReset();
});

afterEach(() => {
  if (prevSudoUser === undefined) delete process.env.SUDO_USER;
  else process.env.SUDO_USER = prevSudoUser;
});

describe('resolveUserHome via openClawConfigPath (#429)', () => {
  it('never passes a SUDO_USER with shell metacharacters to any child process', () => {
    process.env.SUDO_USER = 'mallory; touch /tmp/pwned';

    const configPath = openclaw.openClawConfigPath();

    // An invalid username is rejected before any lookup — neither the
    // shell-string APIs nor the argv-array APIs ever see it.
    expect(execSyncMock).not.toHaveBeenCalled();
    expect(execMock).not.toHaveBeenCalled();
    expect(execFileSyncMock).not.toHaveBeenCalled();
    expect(configPath).toBe(join(homedir(), '.openclaw', 'openclaw.json'));
  });

  it('looks up a valid SUDO_USER via execFileSync argv-array getent, no shell', () => {
    const sudoHome = mkdtempSync(join(tmpdir(), 'sc-sudo-home-'));
    try {
      process.env.SUDO_USER = 'alice';
      execFileSyncMock.mockReturnValue(
        `alice:x:1000:1000:Alice:${sudoHome}:/bin/bash\n`,
      );

      const configPath = openclaw.openClawConfigPath();

      expect(execFileSyncMock).toHaveBeenCalledTimes(1);
      const [cmd, args, opts] = execFileSyncMock.mock.calls[0] as [
        string,
        string[],
        Record<string, unknown>,
      ];
      expect(cmd).toBe('getent');
      expect(args).toEqual(['passwd', 'alice']);
      expect((opts as { shell?: unknown }).shell).toBeUndefined();
      expect(configPath).toBe(join(sudoHome, '.openclaw', 'openclaw.json'));
      expect(execSyncMock).not.toHaveBeenCalled();
      expect(execMock).not.toHaveBeenCalled();
    } finally {
      rmSync(sudoHome, { recursive: true, force: true });
    }
  });

  it('falls back without shell eval when getent is unavailable', () => {
    // A username that passes validation but exists on no box — the direct
    // /home and /Users probes miss, so resolution lands on os.homedir().
    process.env.SUDO_USER = 'sc-no-such-user-429';
    execFileSyncMock.mockImplementation(() => {
      throw new Error('getent: command not found');
    });

    const configPath = openclaw.openClawConfigPath();

    // The old code ran `eval echo ~${SUDO_USER}` through execSync here.
    expect(execSyncMock).not.toHaveBeenCalled();
    expect(execMock).not.toHaveBeenCalled();
    expect(configPath).toBe(join(homedir(), '.openclaw', 'openclaw.json'));
  });

  it('rejects a getent entry whose home field does not exist on disk', () => {
    process.env.SUDO_USER = 'alice';
    execFileSyncMock.mockReturnValue(
      'alice:x:1000:1000:Alice:/nonexistent-sc-429-home:/bin/bash\n',
    );

    const configPath = openclaw.openClawConfigPath();

    expect(execSyncMock).not.toHaveBeenCalled();
    expect(configPath).toBe(join(homedir(), '.openclaw', 'openclaw.json'));
  });
});

describe('deep-clean resolveHome via scanForResidue (#429)', () => {
  // deep-clean.ts mirrors openclaw.ts's sudo-home resolution and had the same
  // injectable `getent passwd ${SUDO_USER}` shell string. Same pins apply.
  it('never passes a SUDO_USER with shell metacharacters to any child process', () => {
    process.env.SUDO_USER = 'mallory; touch /tmp/pwned';

    deepClean.scanForResidue();

    expect(execSyncMock).not.toHaveBeenCalled();
    expect(execMock).not.toHaveBeenCalled();
    expect(execFileSyncMock).not.toHaveBeenCalled();
  });

  it('looks up a valid SUDO_USER via execFileSync argv-array getent, no shell', () => {
    const sudoHome = mkdtempSync(join(tmpdir(), 'sc-sudo-home-'));
    try {
      process.env.SUDO_USER = 'alice';
      execFileSyncMock.mockReturnValue(
        `alice:x:1000:1000:Alice:${sudoHome}:/bin/bash\n`,
      );

      const report = deepClean.scanForResidue();

      expect(execFileSyncMock).toHaveBeenCalledWith(
        'getent',
        ['passwd', 'alice'],
        expect.objectContaining({ timeout: 5000 }),
      );
      expect(execSyncMock).not.toHaveBeenCalled();
      // The resolved sudo home actually drives the scan.
      const scannedPaths = report.paths.map((p) =>
        p.removal.kind === 'delete-directory' ? p.removal.path : p.removal.file,
      );
      expect(scannedPaths.some((p) => p.startsWith(sudoHome))).toBe(true);
    } finally {
      rmSync(sudoHome, { recursive: true, force: true });
    }
  });
});
