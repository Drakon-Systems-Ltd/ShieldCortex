import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

describe('OpenClaw setup', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  const originalSkipNative = process.env.SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL;
  const originalPluginSource = process.env.SHIELDCORTEX_PLUGIN_SOURCE;
  let tempHome: string;
  let tempPluginSource: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let warnSpy: jest.SpiedFunction<typeof console.warn>;
  let errorSpy: jest.SpiedFunction<typeof console.error>;

  beforeEach(() => {
    jest.resetModules();
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-openclaw-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    delete process.env.SUDO_USER;
    process.env.SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL = '1';

    // Hermetic plugin-source: stub a fake `plugins/openclaw/dist/` so the
    // fallback install path doesn't depend on a prior `npm run build`.
    tempPluginSource = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-plugin-src-'));
    fs.writeFileSync(
      path.join(tempPluginSource, 'index.js'),
      'export default {};\n',
      'utf-8',
    );
    fs.writeFileSync(
      path.join(tempPluginSource, 'interceptor.js'),
      'export {};\n',
      'utf-8',
    );
    fs.writeFileSync(
      path.join(tempPluginSource, 'intercept-ingest.js'),
      'export {};\n',
      'utf-8',
    );
    fs.writeFileSync(
      path.join(tempPluginSource, 'openclaw.plugin.json'),
      '{"id":"shieldcortex-realtime","version":"0.0.0-test"}\n',
      'utf-8',
    );
    process.env.SHIELDCORTEX_PLUGIN_SOURCE = tempPluginSource;

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
    if (originalPluginSource === undefined) {
      delete process.env.SHIELDCORTEX_PLUGIN_SOURCE;
    } else {
      process.env.SHIELDCORTEX_PLUGIN_SOURCE = originalPluginSource;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
    fs.rmSync(tempPluginSource, { recursive: true, force: true });
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

  async function loadOpenClawModule() {
    return import('../setup/openclaw.js');
  }

  it('migrates legacy internal hook installs to the preferred path', async () => {
    const { installOpenClawHook } = await loadOpenClawModule();
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
    const { uninstallOpenClawHook } = await loadOpenClawModule();
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
    const { openClawHookStatus } = await loadOpenClawModule();
    fs.writeFileSync(path.join(legacyHookDir(), 'HOOK.md'), '# legacy hook\n', 'utf-8');
    fs.writeFileSync(path.join(legacyHookDir(), 'handler.ts'), '// legacy handler\n', 'utf-8');

    await openClawHookStatus();

    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('legacy install: internal/cortex-memory'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('rerun `shieldcortex openclaw install` to migrate'));
  });

  it('registers plugin in plugins.allow + plugins.entries[id].enabled on fallback install (no plugins.installs write)', async () => {
    const { installOpenClawHook } = await loadOpenClawModule();
    fs.writeFileSync(openClawConfigPath(), JSON.stringify({}, null, 2) + '\n', 'utf-8');

    await installOpenClawHook();

    const config = JSON.parse(fs.readFileSync(openClawConfigPath(), 'utf-8'));
    expect(config.plugins.allow).toContain('shieldcortex-realtime');
    expect(config.plugins.entries['shieldcortex-realtime']).toEqual({ enabled: true });
    // OpenClaw 2026.5.x manages plugins.installs in
    // ~/.openclaw/plugins/installs.json. Authoring it from openclaw.json
    // can trip OpenClaw's migration-block on next config write. We must
    // NOT write it from trustLocalPlugin.
    expect(config.plugins.installs?.['shieldcortex-realtime']).toBeUndefined();
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Registered plugin in OpenClaw config'));
  });

  it('cleans up legacy plugins.installs[shieldcortex-realtime] from pre-v4.15 config', async () => {
    const { installOpenClawHook } = await loadOpenClawModule();
    fs.writeFileSync(
      openClawConfigPath(),
      JSON.stringify(
        {
          plugins: {
            installs: {
              'shieldcortex-realtime': {
                source: 'path',
                installPath: '/legacy/path/shieldcortex-realtime',
                version: '4.10.0',
                installedAt: '2026-04-01T00:00:00.000Z',
              },
              'other-plugin': { source: 'npm', version: '1.0.0' },
            },
          },
        },
        null,
        2,
      ) + '\n',
      'utf-8',
    );

    await installOpenClawHook();

    const config = JSON.parse(fs.readFileSync(openClawConfigPath(), 'utf-8'));
    expect(config.plugins.installs?.['shieldcortex-realtime']).toBeUndefined();
    // Other plugins' installs entries are NOT touched — their migration is OpenClaw's concern.
    expect(config.plugins.installs?.['other-plugin']).toEqual({ source: 'npm', version: '1.0.0' });
    expect(config.plugins.allow).toContain('shieldcortex-realtime');
    expect(config.plugins.entries['shieldcortex-realtime'].enabled).toBe(true);
  });

  it('drops plugins.installs entirely if removing our entry leaves it empty', async () => {
    const { installOpenClawHook } = await loadOpenClawModule();
    fs.writeFileSync(
      openClawConfigPath(),
      JSON.stringify(
        {
          plugins: {
            installs: {
              'shieldcortex-realtime': { source: 'path', installPath: '/legacy', version: '4.10.0' },
            },
          },
        },
        null,
        2,
      ) + '\n',
      'utf-8',
    );

    await installOpenClawHook();

    const config = JSON.parse(fs.readFileSync(openClawConfigPath(), 'utf-8'));
    expect(config.plugins.installs).toBeUndefined();
  });

  it('reports trusted local fallback clearly in status output', async () => {
    const { installOpenClawHook, openClawHookStatus } = await loadOpenClawModule();
    fs.writeFileSync(openClawConfigPath(), JSON.stringify({}, null, 2) + '\n', 'utf-8');

    await installOpenClawHook();
    logSpy.mockClear();

    await openClawHookStatus();

    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('trusted via plugins.allow'));
  });

  it('reports plugin as installed when only index.ts is present (native OpenClaw install)', async () => {
    const { openClawHookStatus } = await loadOpenClawModule();
    const extDir = path.join(tempHome, '.openclaw', 'extensions', 'shieldcortex-realtime');
    fs.mkdirSync(extDir, { recursive: true });
    // Simulate what `openclaw plugins install @drakon-systems/shieldcortex-realtime` leaves behind:
    // the published tarball ships index.ts (no index.js), plus the canonical manifest.
    fs.writeFileSync(path.join(extDir, 'index.ts'), 'export default {};\n', 'utf-8');
    fs.writeFileSync(path.join(extDir, 'openclaw.plugin.json'), '{"id":"shieldcortex-realtime","version":"4.10.3"}\n', 'utf-8');
    fs.writeFileSync(openClawConfigPath(), JSON.stringify({
      plugins: {
        allow: ['shieldcortex-realtime'],
        installs: { 'shieldcortex-realtime': { source: 'npm', version: '4.10.3' } },
        entries: { 'shieldcortex-realtime': { enabled: true } },
      },
    }, null, 2), 'utf-8');

    await openClawHookStatus();

    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Real-time plugin: installed'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[index.ts]'));
  });

  it('reports config/disk drift when config references plugin but files are missing', async () => {
    const { openClawHookStatus } = await loadOpenClawModule();
    // Config says plugin is installed, but extensions dir is empty — the bug case from issue #20
    // where `openclaw plugins install` succeeded and wrote config, but a later
    // state-change removed the files without cleaning config.
    fs.writeFileSync(openClawConfigPath(), JSON.stringify({
      plugins: {
        allow: ['shieldcortex-realtime'],
        installs: { 'shieldcortex-realtime': { source: 'npm', version: '4.10.3' } },
        entries: { 'shieldcortex-realtime': { enabled: true } },
      },
    }, null, 2), 'utf-8');

    await openClawHookStatus();

    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('config references'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('no files on disk'));
  });

  it('reports a managed npm-project install as installed, not "no files on disk" (#77)', async () => {
    const { openClawHookStatus } = await loadOpenClawModule();
    // OpenClaw 2026.6.x installs the realtime plugin as a managed npm project under
    // ~/.openclaw/npm/projects/drakon-systems-shieldcortex-realtime-<hash>/, NOT under
    // extensions/. The legacy path-probe was blind to this and reported "no files on
    // disk" on healthy boxes (issue #77).
    const projectRoot = path.join(
      tempHome, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-a1b2c3',
    );
    const pkgDir = path.join(projectRoot, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), '{"name":"@drakon-systems/shieldcortex-realtime","version":"4.47.3"}\n', 'utf-8');
    // The managed-project root carries its own generated package.json (managed deps).
    fs.writeFileSync(path.join(projectRoot, 'package.json'), '{"name":"drakon-systems-shieldcortex-realtime-a1b2c3","version":"0.0.0"}\n', 'utf-8');
    // Config references the plugin (loaded + enforcing), but nothing lives under extensions/.
    fs.writeFileSync(openClawConfigPath(), JSON.stringify({
      plugins: {
        allow: ['shieldcortex-realtime'],
        entries: { 'shieldcortex-realtime': { enabled: true } },
      },
    }, null, 2), 'utf-8');

    await openClawHookStatus();

    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('Real-time plugin: installed'));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[managed]'));
    // The false-negative message must NOT appear for a healthy managed install.
    const emittedNoFiles = logSpy.mock.calls.some(
      (call) => typeof call[0] === 'string' && call[0].includes('no files on disk'),
    );
    expect(emittedNoFiles).toBe(false);
  });
});
