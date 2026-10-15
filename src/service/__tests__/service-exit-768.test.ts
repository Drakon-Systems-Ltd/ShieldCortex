import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { handleServiceCommand, installService, repairService, serviceStatus } from '../install.js';

/**
 * #768 — on a host without systemd user services, `service install --headless`
 * wrote the unit, printed "Failed to enable service: ..." and exited 0, and
 * `service status` afterwards exited 0 too. Automation reading the exit code
 * saw a healthy headless install that did not exist.
 *
 * Contract pinned here:
 *   install / repair — non-zero whenever the service could not be activated,
 *                      with a line saying what to do instead;
 *   status           — non-zero when the unit is not installed, not
 *                      enabled/loaded, or cannot be queried; 0 when installed
 *                      and enabled/loaded and running.
 *
 * Every platform command goes through an injected exec stub. No real
 * systemctl, launchctl or loginctl is ever spawned by this suite.
 */

type Rule = { pattern: RegExp; run: (command: string) => string };

/** Per-pattern scripted exec; unmatched commands succeed with empty output. */
function scriptedExec(rules: Rule[] = []) {
  const calls: string[] = [];
  const exec = (command: string): string => {
    calls.push(command);
    for (const rule of rules) {
      if (rule.pattern.test(command)) return rule.run(command);
    }
    return '';
  };
  return { calls, exec };
}

type ExecError = Error & { status?: number | null; code?: string; stdout?: string | null; stderr?: string | null };

/**
 * What execSync throws under `stdio: 'inherit'` when /bin/sh cannot find the
 * binary: exit status 127, nothing captured. This is the shape the issue's
 * clean-box run hit (`/bin/sh: 1: systemctl: not found`).
 */
function shellNotFound(command: string): never {
  const err = new Error(`Command failed: ${command}`) as ExecError;
  err.status = 127;
  err.stdout = null;
  err.stderr = null;
  throw err;
}

/** What execSync throws when the spawn itself fails: ENOENT, no status. */
function spawnEnoent(command: string): never {
  const bin = command.split(' ')[0];
  const err = new Error(`spawnSync ${bin} ENOENT`) as ExecError;
  err.code = 'ENOENT';
  err.status = null;
  throw err;
}

/** A status query under `2>&1` + encoding: the shell's complaint lands in stdout. */
function queryShellNotFound(command: string): never {
  const err = new Error(`Command failed: ${command}`) as ExecError;
  err.status = 127;
  err.stdout = '/bin/sh: 1: systemctl: not found\n';
  throw err;
}

/** `systemctl is-enabled|is-active` reporting a non-success state word with a non-zero exit. */
function unitState(word: string, status: number) {
  return (command: string): never => {
    const err = new Error(`Command failed: ${command}`) as ExecError;
    err.status = status;
    err.stdout = `${word}\n`;
    throw err;
  };
}

function mockFailure(command: string): never {
  throw new Error(`mock failure: ${command}`);
}

describe('#768 service exit codes', () => {
  const origPlatform = process.platform;
  const origHome = process.env.HOME;
  let suiteEntryExitCode: typeof process.exitCode;
  let previousExitCode: typeof process.exitCode;
  let tmpHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let errSpy: jest.SpiedFunction<typeof console.error>;
  let stdout: string[];
  let stderr: string[];

  beforeAll(() => {
    suiteEntryExitCode = process.exitCode;
  });

  // The functions under test set process.exitCode on purpose; the per-test
  // restore below must leave the worker's exit code exactly as it found it.
  afterAll(() => {
    expect(process.exitCode).toBe(suiteEntryExitCode);
  });

  beforeEach(() => {
    previousExitCode = process.exitCode;
    tmpHome = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-768-')));
    process.env.HOME = tmpHome;
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    stdout = [];
    stderr = [];
    logSpy = jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      stdout.push(args.map(String).join(' '));
    });
    errSpy = jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      stderr.push(args.map(String).join(' '));
    });
  });

  afterEach(() => {
    process.exitCode = previousExitCode ?? undefined;
    Object.defineProperty(process, 'platform', { value: origPlatform });
    homedirSpy.mockRestore();
    logSpy.mockRestore();
    errSpy.mockRestore();
    if (origHome === undefined) delete process.env.HOME; else process.env.HOME = origHome;
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  function setPlatform(p: NodeJS.Platform): void {
    Object.defineProperty(process, 'platform', { value: p });
  }

  const linuxUnit = () => path.join(tmpHome, '.config', 'systemd', 'user', 'shieldcortex-dashboard.service');
  const macPlist = () => path.join(tmpHome, 'Library', 'LaunchAgents', 'com.shieldcortex.dashboard.plist');

  /**
   * Write a real unit through install with every command succeeding. Dashboard
   * mode on purpose: worker/api installs go on to `loginctl enable-linger`,
   * which is not behind the exec seam, and this suite must never run a real
   * systemd command.
   */
  async function installHealthyLinuxUnit(): Promise<void> {
    const { exec } = scriptedExec();
    await installService({ mode: 'dashboard', exec });
    expect(fs.existsSync(linuxUnit())).toBe(true);
    stdout.length = 0;
    stderr.length = 0;
  }

  describe('installService on Linux', () => {
    beforeEach(() => setPlatform('linux'));

    it('exits 1 with foreground guidance when systemctl is missing (sh: not found)', async () => {
      const { calls, exec } = scriptedExec([{ pattern: /^systemctl /, run: shellNotFound }]);

      await installService({ mode: 'worker', exec });

      expect(process.exitCode).toBe(1);
      // The unit that was already written stays in place, and we say where.
      expect(fs.existsSync(linuxUnit())).toBe(true);
      const err = stderr.join('\n');
      expect(err).toContain('Failed to enable service: Command failed: systemctl --user daemon-reload');
      expect(err).toMatch(/systemd user services are not available on this host/);
      expect(err).toContain('shieldcortex worker');
      expect(err).toContain(linuxUnit());
      // Stopped at the first failure; linger was never attempted.
      expect(calls).toEqual(['systemctl --user daemon-reload']);
    });

    it('exits 1 with the same guidance when the systemctl spawn fails with ENOENT', async () => {
      const { exec } = scriptedExec([{ pattern: /^systemctl /, run: spawnEnoent }]);

      await installService({ mode: 'worker', exec });

      expect(process.exitCode).toBe(1);
      const err = stderr.join('\n');
      expect(err).toContain('Failed to enable service: spawnSync systemctl ENOENT');
      expect(err).toMatch(/systemd user services are not available on this host/);
      expect(err).toContain('shieldcortex worker');
    });

    it('exits 1 without the no-systemd claim when systemctl exists but enable fails', async () => {
      const { exec } = scriptedExec([{ pattern: /systemctl --user enable/, run: unitState('', 1) }]);

      await installService({ mode: 'worker', exec });

      expect(process.exitCode).toBe(1);
      const err = stderr.join('\n');
      expect(err).toContain('Failed to enable service: Command failed: systemctl --user enable shieldcortex-dashboard.service');
      expect(err).not.toMatch(/not available on this host/);
      expect(err).toContain('systemctl --user status shieldcortex-dashboard.service');
      expect(err).toContain('shieldcortex worker');
    });

    it('names the foreground command for the mode that was installed', async () => {
      const { exec } = scriptedExec([{ pattern: /^systemctl /, run: shellNotFound }]);

      await installService({ mode: 'dashboard', exec });

      expect(process.exitCode).toBe(1);
      expect(stderr.join('\n')).toContain('shieldcortex dashboard');
    });

    it('leaves the exit code untouched and keeps its output when activation succeeds', async () => {
      // Dashboard mode: see installHealthyLinuxUnit for why not worker.
      const { calls, exec } = scriptedExec();

      await installService({ mode: 'dashboard', exec });

      expect(process.exitCode).toBe(previousExitCode);
      expect(process.exitCode).not.toBe(1);
      expect(stderr).toEqual([]);
      const out = stdout.join('\n');
      expect(out).toContain(`Service file written to: ${linuxUnit()}`);
      expect(out).toContain('Service enabled via systemd.');
      expect(out).toContain('will now auto-start');
      expect(calls).toEqual([
        'systemctl --user daemon-reload',
        'systemctl --user enable shieldcortex-dashboard.service',
        'systemctl --user restart shieldcortex-dashboard.service',
      ]);
    });
  });

  describe('serviceStatus on Linux', () => {
    beforeEach(() => setPlatform('linux'));

    it('exits 1 when no unit file is installed', async () => {
      const { calls, exec } = scriptedExec();

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(1);
      expect(stdout.join('\n')).toContain('Installed: no');
      expect(calls).toEqual([]);
    });

    it('exits 1 when the unit exists but systemctl cannot be queried', async () => {
      await installHealthyLinuxUnit();
      const { exec } = scriptedExec([{ pattern: /^systemctl /, run: queryShellNotFound }]);

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(1);
      const out = stdout.join('\n');
      expect(out).toContain('Installed: yes');
      expect(out).toMatch(/could not query/i);
      // The hint names the mode the unit was installed with.
      expect(out).toContain('shieldcortex dashboard');
    });

    it('exits 1 when the unit exists but is not enabled', async () => {
      await installHealthyLinuxUnit();
      const { exec } = scriptedExec([
        { pattern: /is-enabled/, run: unitState('disabled', 1) },
        { pattern: /is-active/, run: unitState('inactive', 3) },
      ]);

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(1);
      const out = stdout.join('\n');
      expect(out).toContain('Enabled:   no');
      expect(out).toContain('Running:   no');
    });

    it('exits 1 when the unit is enabled but not running', async () => {
      await installHealthyLinuxUnit();
      const { exec } = scriptedExec([
        { pattern: /is-enabled/, run: () => 'enabled\n' },
        { pattern: /is-active/, run: unitState('failed', 3) },
      ]);

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(1);
      const out = stdout.join('\n');
      expect(out).toContain('Enabled:   yes');
      expect(out).toContain('Running:   no');
    });

    it('keeps exit 0 when the unit is enabled and active', async () => {
      await installHealthyLinuxUnit();
      const { exec } = scriptedExec([
        { pattern: /is-enabled/, run: () => 'enabled\n' },
        { pattern: /is-active/, run: () => 'active\n' },
      ]);

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(previousExitCode);
      expect(process.exitCode).not.toBe(1);
      const out = stdout.join('\n');
      expect(out).toContain('Installed: yes');
      expect(out).toContain('Healthy:   yes');
      expect(out).toContain('Running:   yes');
    });

    it('keeps exit 0 for a stale-but-running unit and still prints the repair hint', async () => {
      fs.mkdirSync(path.dirname(linuxUnit()), { recursive: true });
      fs.writeFileSync(linuxUnit(), [
        '[Service]',
        'ExecStart=/usr/bin/node /home/u/.npm/_npx/abc123/node_modules/shieldcortex/dist/index.js --mode worker',
        'StandardOutput=journal',
      ].join('\n'));
      const { exec } = scriptedExec([
        { pattern: /is-enabled/, run: () => 'enabled\n' },
        { pattern: /is-active/, run: () => 'active\n' },
      ]);

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(previousExitCode);
      const out = stdout.join('\n');
      expect(out).toContain('Healthy:   no (repair recommended)');
      expect(out).toContain('Repair:    shieldcortex service repair');
      expect(out).toContain('Running:   yes');
    });
  });

  describe('installService on macOS', () => {
    beforeEach(() => setPlatform('darwin'));

    it('exits 1 when launchctl bootstrap fails and keeps the plist guidance', async () => {
      // Not loaded (print fails), then bootstrap fails — same stub shape as activate-service.test.ts.
      const { exec } = scriptedExec([
        { pattern: /launchctl print /, run: mockFailure },
        { pattern: /launchctl bootstrap/, run: mockFailure },
      ]);

      await installService({ mode: 'dashboard', exec });

      expect(process.exitCode).toBe(1);
      expect(fs.existsSync(macPlist())).toBe(true);
      const err = stderr.join('\n');
      expect(err).toContain('Failed to enable service: mock failure: launchctl bootstrap');
      expect(err).toContain(`launchctl bootstrap gui/$(id -u) "${macPlist()}"`);
    });

    it('leaves the exit code untouched when launchctl succeeds', async () => {
      const { exec } = scriptedExec([{ pattern: /launchctl print /, run: mockFailure }]);

      await installService({ mode: 'dashboard', exec });

      expect(process.exitCode).toBe(previousExitCode);
      expect(stderr).toEqual([]);
      expect(stdout.join('\n')).toContain('Service loaded via launchctl.');
    });
  });

  describe('serviceStatus on macOS', () => {
    beforeEach(() => setPlatform('darwin'));

    it('exits 1 when the plist exists but launchctl print fails (not loaded)', async () => {
      fs.mkdirSync(path.dirname(macPlist()), { recursive: true });
      fs.writeFileSync(macPlist(), '<plist></plist>');
      const { exec } = scriptedExec([{ pattern: /launchctl print /, run: mockFailure }]);

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(1);
      expect(stdout.join('\n')).toContain('Running:   no');
    });

    it('keeps exit 0 when the agent is loaded and running', async () => {
      fs.mkdirSync(path.dirname(macPlist()), { recursive: true });
      fs.writeFileSync(macPlist(), '<plist></plist>');
      const { exec } = scriptedExec([
        { pattern: /launchctl print /, run: () => 'com.shieldcortex.dashboard = {\n\tstate = running\n\tpid = 4242\n}\n' },
      ]);

      await serviceStatus({ exec });

      expect(process.exitCode).toBe(previousExitCode);
      expect(stdout.join('\n')).toContain('Running:   yes (PID 4242)');
    });
  });

  describe('handleServiceCommand', () => {
    it('prints usage and exits 0 for --help and -h', async () => {
      const exitSpy = jest.spyOn(process, 'exit').mockImplementation(((code?: number | string | null) => {
        throw new Error(`process.exit(${code})`);
      }) as typeof process.exit);
      try {
        await handleServiceCommand('--help', []);
        await handleServiceCommand('-h', []);
      } finally {
        exitSpy.mockRestore();
      }

      expect(process.exitCode).toBe(previousExitCode);
      const usage = stdout.filter((line) => line.startsWith('Usage: shieldcortex service <install|repair|uninstall|status>'));
      expect(usage).toHaveLength(2);
    });

    it('status dispatch carries the exit code through the injected exec', async () => {
      setPlatform('linux');
      const { exec } = scriptedExec();

      await handleServiceCommand('status', [], { exec });

      expect(process.exitCode).toBe(1);
      expect(stdout.join('\n')).toContain('Installed: no');
    });

    it('repair reuses install and exits 1 when the host has no systemctl', async () => {
      setPlatform('linux');
      await installHealthyLinuxUnit();
      const { calls, exec } = scriptedExec([{ pattern: /^systemctl /, run: shellNotFound }]);

      await repairService({ mode: 'worker', exec });

      expect(process.exitCode).toBe(1);
      expect(stderr.join('\n')).toMatch(/systemd user services are not available on this host/);
      // uninstall's disable went through the stub too — nothing real ran.
      expect(calls[0]).toBe('systemctl --user disable --now shieldcortex-dashboard.service');
      expect(calls).toContain('systemctl --user daemon-reload');
    });
  });
});
