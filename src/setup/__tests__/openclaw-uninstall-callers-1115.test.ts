/**
 * #1115 r3 — caller-level checks the helper regressions do not cover.
 * Temporary directories only. Restart is a mock. No live openclaw, no
 * gateway, no real uninstall of a host install.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { uninstallOpenClawHook } from '../openclaw.js';
import { cleanResidue, runDeepClean, scanForResidue, type ResidueReport } from '../deep-clean.js';

const PKG = '@drakon-systems/shieldcortex-realtime';
const ID = 'shieldcortex-realtime';

let home: string;
let otherHome: string;
let prev: Record<string, string | undefined>;
let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
let logSpy: jest.SpiedFunction<typeof console.log>;
let errorSpy: jest.SpiedFunction<typeof console.error>;
let warnSpy: jest.SpiedFunction<typeof console.warn>;
let prevExit: typeof process.exitCode;

const TARGETING = [
  'OPENCLAW_HOME',
  'OPENCLAW_STATE_DIR',
  'CLAWDBOT_STATE_DIR',
  'OPENCLAW_CONFIG_PATH',
  'CLAWDBOT_CONFIG_PATH',
  'OPENCLAW_PROFILE',
  'SUDO_USER',
] as const;

function restartMock() {
  return jest.fn(async () => ({ attempted: true, restarted: true, method: 'test' as const }));
}

function plantForeignExtensions(root: string): string {
  const dir = path.join(root, '.openclaw', 'extensions', ID);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'someone-elses-plugin', version: '1.0.0' }));
  fs.writeFileSync(path.join(dir, 'marker'), 'keep');
  return dir;
}

function plantOursExtensions(root: string): string {
  const dir = path.join(root, '.openclaw', 'extensions', ID);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version: '5.22.1' }));
  fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: '5.22.1' }));
  fs.writeFileSync(path.join(dir, 'index.js'), 'export default {};\n');
  return dir;
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1115-r3-'));
  otherHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1115-r3-other-'));
  fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
  fs.mkdirSync(path.join(otherHome, '.openclaw'), { recursive: true });
  prev = {};
  for (const key of TARGETING) {
    prev[key] = process.env[key];
    delete process.env[key];
  }
  process.env.OPENCLAW_HOME = home;
  prevExit = process.exitCode;
  process.exitCode = undefined;
  homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(otherHome);
  logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  homedirSpy.mockRestore();
  logSpy.mockRestore();
  errorSpy.mockRestore();
  warnSpy.mockRestore();
  for (const key of TARGETING) {
    if (prev[key] === undefined) delete process.env[key];
    else process.env[key] = prev[key];
  }
  process.exitCode = prevExit;
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(otherHome, { recursive: true, force: true });
});

describe('#1115 deep-clean caller does not remove the extensions directory', () => {
  it('leaves a same-name directory the helper classifies as not ours', async () => {
    const dir = plantForeignExtensions(home);
    const hook = path.join(home, '.openclaw', 'hooks', 'cortex-memory');
    fs.mkdirSync(hook, { recursive: true });
    fs.writeFileSync(path.join(hook, 'marker'), 'hook');
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({
      plugins: { entries: { [ID]: { enabled: true } }, allow: [ID] },
    }));

    const out = await runDeepClean();

    expect(out.pluginRemoval.status).toBe('absent');
    expect(fs.readFileSync(path.join(dir, 'marker'), 'utf-8')).toBe('keep');
    expect(fs.existsSync(hook)).toBe(false);
    expect(out.result.removed).not.toContain(dir);
    const cfg = JSON.parse(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8'));
    expect(cfg.plugins.entries[ID]).toBeUndefined();
    const listed = scanForResidue().paths.find((p) => p.category === 'plugin-dir');
    expect(listed?.removal.kind).toBe('report-only');
    expect(listed?.present).toBe(true);
  });

  it('the generic cleaner does not delete a hand-built extensions path', () => {
    const dir = plantForeignExtensions(home);
    const report: ResidueReport = {
      paths: [{
        description: dir,
        removal: { kind: 'delete-directory', path: dir },
        present: true,
        category: 'plugin-dir',
      }],
      dirtyCount: 1,
      cleanCount: 0,
    };

    const cleaned = cleanResidue(report);

    expect(fs.readFileSync(path.join(dir, 'marker'), 'utf-8')).toBe('keep');
    expect(cleaned.removed).not.toContain(dir);
    expect(cleaned.errors).toEqual([]);
  });

  it('still removes a verified legacy copy through the uninstall helper', async () => {
    const dir = plantOursExtensions(home);
    const restart = restartMock();

    const out = await runDeepClean({ restartGateway: true, restart: restart as never });

    expect(out.pluginRemoval.status).toBe('removed');
    expect(fs.existsSync(dir)).toBe(false);
    expect(fs.existsSync(path.dirname(dir))).toBe(true);
    expect(restart).toHaveBeenCalledTimes(1);
    expect(out.gateway).toEqual({ attempted: true, restarted: true, method: 'test' });
  });
});

describe('#1115 deep-clean restart counts a verified managed removal', () => {
  it('restarts when the only change is a verified removed plugin result', async () => {
    const restart = restartMock();

    const out = await runDeepClean({
      restartGateway: true,
      pluginRemoval: { status: 'removed', detail: 'openclaw plugins uninstall finished and the install record is gone.' },
      restart: restart as never,
    });

    expect(out.result.removed).toEqual([]);
    expect(restart).toHaveBeenCalledTimes(1);
    expect(out.gateway).toEqual({ attempted: true, restarted: true, method: 'test' });
  });

  it('a removed result does not delete a same-name directory the helper left in place', async () => {
    const dir = plantForeignExtensions(home);
    const restart = restartMock();

    const out = await runDeepClean({
      restartGateway: true,
      pluginRemoval: { status: 'removed', detail: 'openclaw plugins uninstall finished and the install record is gone.' },
      restart: restart as never,
    });

    expect(fs.readFileSync(path.join(dir, 'marker'), 'utf-8')).toBe('keep');
    expect(out.result.removed).not.toContain(dir);
    expect(restart).toHaveBeenCalledTimes(1);
  });

  it('does not restart on a dry run even when the plugin result says removed', async () => {
    const restart = restartMock();

    const out = await runDeepClean({
      dryRun: true,
      restartGateway: true,
      pluginRemoval: { status: 'removed', detail: 'injected' },
      restart: restart as never,
    });

    expect(restart).not.toHaveBeenCalled();
    expect(out.gateway).toBeUndefined();
    expect(out.pluginRemoval.status).toBe('removed');
  });

  it('does not restart when removal is incomplete, even if other residue was purged', async () => {
    const hook = path.join(home, '.openclaw', 'hooks', 'cortex-memory');
    fs.mkdirSync(hook, { recursive: true });
    const restart = restartMock();

    const out = await runDeepClean({
      restartGateway: true,
      pluginRemoval: { status: 'failed', detail: 'still registered' },
      restart: restart as never,
    });

    expect(fs.existsSync(hook)).toBe(false);
    expect(out.result.removed.length).toBeGreaterThan(0);
    expect(restart).not.toHaveBeenCalled();
    expect(out.gateway).toBeUndefined();
  });

  it('does not treat an absent plugin result with no other residue as a change', async () => {
    const restart = restartMock();

    const out = await runDeepClean({
      restartGateway: true,
      pluginRemoval: { status: 'absent', detail: 'not installed' },
      restart: restart as never,
    });

    expect(out.result.removed).toEqual([]);
    expect(restart).not.toHaveBeenCalled();
    expect(out.gateway).toBeUndefined();
  });
});

describe('#1115 callers refuse an ambiguous target before OpenClaw writes', () => {
  it('deep clean does not write hook, config, or workspace-lock residue on the fallback home', async () => {
    const relative = 'relative-profile';
    const cwdCopy = path.join(process.cwd(), relative);
    const hook = path.join(otherHome, '.openclaw', 'hooks', 'cortex-memory');
    fs.mkdirSync(hook, { recursive: true });
    fs.writeFileSync(path.join(hook, 'marker'), 'keep');
    const configFile = path.join(otherHome, '.openclaw', 'openclaw.json');
    const configBefore = JSON.stringify({ hooks: { shieldcortex: { enabled: true } } }, null, 2) + '\n';
    fs.writeFileSync(configFile, configBefore);
    const lockFile = path.join(otherHome, '.openclaw', 'workspace', '.clawhub', 'lock.json');
    fs.mkdirSync(path.dirname(lockFile), { recursive: true });
    const lockBefore = JSON.stringify({ skills: { shieldcortex: { version: '5.22.1' }, other: { version: '1.0.0' } } }, null, 2) + '\n';
    fs.writeFileSync(lockFile, lockBefore);
    const foreign = plantForeignExtensions(otherHome);
    process.env.OPENCLAW_HOME = relative;
    const restart = restartMock();

    try {
      const out = await runDeepClean({ restartGateway: true, restart: restart as never });

      expect(out.pluginRemoval.status).toBe('refused');
      expect(out.pluginRemoval.detail).toMatch(/unresolvable/);
      expect(out.pluginRemoval.detail).not.toContain(path.resolve(relative));
      expect(out.result.removed).toEqual([]);
      expect(out.gateway).toBeUndefined();
      expect(restart).not.toHaveBeenCalled();
      expect(fs.readFileSync(path.join(hook, 'marker'), 'utf-8')).toBe('keep');
      expect(fs.readFileSync(configFile, 'utf-8')).toBe(configBefore);
      expect(fs.readFileSync(lockFile, 'utf-8')).toBe(lockBefore);
      expect(fs.readFileSync(path.join(foreign, 'marker'), 'utf-8')).toBe('keep');
      expect(fs.existsSync(path.join(home, '.openclaw', 'openclaw.json'))).toBe(false);
      expect(fs.existsSync(cwdCopy)).toBe(false);
    } finally {
      fs.rmSync(cwdCopy, { recursive: true, force: true });
    }
  });

  it('openclaw uninstall does not remove hooks or an owned skill on the fallback home', async () => {
    const relative = 'relative-profile';
    const cwdCopy = path.join(process.cwd(), relative);
    const hook = path.join(otherHome, '.openclaw', 'hooks', 'cortex-memory');
    fs.mkdirSync(hook, { recursive: true });
    fs.writeFileSync(path.join(hook, 'marker'), 'keep');
    const skill = path.join(otherHome, '.openclaw', 'workspace', 'skills', 'shieldcortex');
    fs.mkdirSync(skill, { recursive: true });
    fs.writeFileSync(path.join(skill, 'SKILL.md'), '---\nname: shieldcortex\n---\nkeep\n');
    fs.writeFileSync(path.join(skill, 'marker'), 'keep');
    const configFile = path.join(otherHome, '.openclaw', 'openclaw.json');
    const configBefore = JSON.stringify({
      plugins: { allow: ['/abs/path/shieldcortex-realtime/index.js', 'other-plugin'] },
      hooks: { shieldcortex: { enabled: true } },
    }, null, 2) + '\n';
    fs.writeFileSync(configFile, configBefore);
    process.env.OPENCLAW_HOME = relative;

    try {
      const result = await uninstallOpenClawHook();

      expect(result.status).toBe('refused');
      expect(result.detail).toMatch(/unresolvable/);
      expect(process.exitCode).toBe(1);
      expect(errorSpy).toHaveBeenCalledWith(expect.stringMatching(/unresolvable/));
      expect(fs.readFileSync(path.join(hook, 'marker'), 'utf-8')).toBe('keep');
      expect(fs.readFileSync(path.join(skill, 'marker'), 'utf-8')).toBe('keep');
      expect(fs.readFileSync(configFile, 'utf-8')).toBe(configBefore);
      expect(logSpy).not.toHaveBeenCalledWith(expect.stringMatching(/Removed cortex-memory hook/));
      expect(logSpy).not.toHaveBeenCalledWith(expect.stringMatching(/Skill: removed/));
      expect(fs.existsSync(cwdCopy)).toBe(false);
    } finally {
      fs.rmSync(cwdCopy, { recursive: true, force: true });
    }
  });

  it('a resolvable home still removes the hook and an owned skill', async () => {
    const hook = path.join(home, '.openclaw', 'hooks', 'cortex-memory');
    fs.mkdirSync(hook, { recursive: true });
    fs.writeFileSync(path.join(hook, 'marker'), 'x');
    const skill = path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex');
    fs.mkdirSync(skill, { recursive: true });
    fs.writeFileSync(path.join(skill, 'SKILL.md'), '---\nname: shieldcortex\n---\n');

    const result = await uninstallOpenClawHook();

    expect(result.status).toBe('absent');
    expect(process.exitCode).toBeUndefined();
    expect(fs.existsSync(hook)).toBe(false);
    expect(fs.existsSync(skill)).toBe(false);
    expect(fs.existsSync(path.join(otherHome, '.openclaw', 'hooks'))).toBe(false);
  }, 30000);
});
