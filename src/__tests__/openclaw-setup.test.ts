import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { installOpenClawHook, openClawHookStatus, uninstallOpenClawHook } from '../setup/openclaw.js';

describe('OpenClaw setup', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  const originalSkipNative = process.env.SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL;
  let tempHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let warnSpy: jest.SpiedFunction<typeof console.warn>;
  let errorSpy: jest.SpiedFunction<typeof console.error>;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-openclaw-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    delete process.env.SUDO_USER;
    process.env.SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL = '1';

    fs.mkdirSync(path.join(tempHome, '.openclaw', 'hooks', 'internal', 'cortex-memory'), { recursive: true });
    fs.mkdirSync(path.join(tempHome, '.openclaw', 'extensions'), { recursive: true });

    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    homedirSpy.mockRestore();
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
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
    if (originalSkipNative === undefined) {
      delete process.env.SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL;
    } else {
      process.env.SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL = originalSkipNative;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function preferredHookDir(): string {
    return path.join(tempHome, '.openclaw', 'hooks', 'cortex-memory');
  }

  function legacyHookDir(): string {
    return path.join(tempHome, '.openclaw', 'hooks', 'internal', 'cortex-memory');
  }

  function openClawConfigPath(): string {
    return path.join(tempHome, '.openclaw', 'openclaw.json');
  }

  it('migrates legacy internal hook installs to the preferred path', async () => {
    fs.writeFileSync(path.join(legacyHookDir(), 'HOOK.md'), '# legacy hook\n', 'utf-8');
    fs.writeFileSync(path.join(legacyHookDir(), 'handler.ts'), '// legacy handler\n', 'utf-8');

    await installOpenClawHook();

    expect(fs.existsSync(path.join(preferredHookDir(), 'HOOK.md'))).toBe(true);
    expect(fs.existsSync(path.join(preferredHookDir(), 'handler.ts'))).toBe(true);
    expect(fs.existsSync(legacyHookDir())).toBe(false);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Detected legacy OpenClaw hook layout'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Removed legacy cortex-memory hook'));
  });

  it('removes both preferred and legacy hook locations on uninstall', async () => {
    fs.mkdirSync(preferredHookDir(), { recursive: true });
    fs.writeFileSync(path.join(preferredHookDir(), 'HOOK.md'), '# new hook\n', 'utf-8');
    fs.writeFileSync(path.join(preferredHookDir(), 'handler.ts'), '// new handler\n', 'utf-8');
    fs.writeFileSync(path.join(legacyHookDir(), 'HOOK.md'), '# legacy hook\n', 'utf-8');
    fs.writeFileSync(path.join(legacyHookDir(), 'handler.ts'), '// legacy handler\n', 'utf-8');

    await uninstallOpenClawHook();

    expect(fs.existsSync(preferredHookDir())).toBe(false);
    expect(fs.existsSync(legacyHookDir())).toBe(false);
  });

  it('reports legacy-only installs as migration-needed in status output', async () => {
    fs.writeFileSync(path.join(legacyHookDir(), 'HOOK.md'), '# legacy hook\n', 'utf-8');
    fs.writeFileSync(path.join(legacyHookDir(), 'handler.ts'), '// legacy handler\n', 'utf-8');

    await openClawHookStatus();

    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('legacy install: internal/cortex-memory'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('rerun `shieldcortex openclaw install` to migrate'));
  });

  it('pins the copied realtime plugin path into plugins.allow on fallback install', async () => {
    fs.writeFileSync(openClawConfigPath(), JSON.stringify({}, null, 2) + '\n', 'utf-8');

    await installOpenClawHook();

    const config = JSON.parse(fs.readFileSync(openClawConfigPath(), 'utf-8'));
    expect(config.plugins.allow).toContain(
      path.join(tempHome, '.openclaw', 'extensions', 'shieldcortex-realtime', 'index.js'),
    );
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Trusted local OpenClaw plugin path via plugins.allow'));
  });
});
