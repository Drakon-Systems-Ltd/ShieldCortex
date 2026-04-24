import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

describe('deep-clean — OpenClaw residue purge', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  const originalSudoUser = process.env.SUDO_USER;
  let tempHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;

  beforeEach(() => {
    jest.resetModules();
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-deep-clean-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    delete process.env.SUDO_USER;

    fs.mkdirSync(path.join(tempHome, '.openclaw'), { recursive: true });
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
  });

  afterEach(() => {
    homedirSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    if (originalSudoUser === undefined) delete process.env.SUDO_USER;
    else process.env.SUDO_USER = originalSudoUser;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  const openclawJsonPath = () => path.join(tempHome, '.openclaw', 'openclaw.json');
  const clawhubLockPath = () => path.join(tempHome, '.openclaw', 'workspace', '.clawhub', 'lock.json');

  async function loadModule() {
    return import('../setup/deep-clean.js');
  }

  function writeOpenClawJson(data: unknown): void {
    fs.writeFileSync(openclawJsonPath(), JSON.stringify(data, null, 2), 'utf-8');
  }

  function writeClawhubLock(data: unknown): void {
    fs.mkdirSync(path.dirname(clawhubLockPath()), { recursive: true });
    fs.writeFileSync(clawhubLockPath(), JSON.stringify(data, null, 2), 'utf-8');
  }

  it('reports zero residue when config is absent and no directories exist', async () => {
    const { scanForResidue } = await loadModule();
    const report = scanForResidue();
    expect(report.dirtyCount).toBe(0);
    expect(report.paths.every((p) => !p.present)).toBe(true);
    // Should cover all the residue locations we care about
    expect(report.paths.length).toBeGreaterThanOrEqual(14);
  });

  it('detects every known residue location when populated', async () => {
    // Populate all config-level residue
    writeOpenClawJson({
      plugins: {
        installs: { 'shieldcortex-realtime': { source: 'path', version: '4.10.5' }, 'other-plugin': { source: 'npm' } },
        entries: { 'shieldcortex-realtime': { enabled: true }, 'other-plugin': { enabled: true } },
        allow: ['shieldcortex-realtime', 'other-plugin'],
        load: { paths: ['/tmp/shieldcortex-realtime/index.js', '/tmp/other-plugin'] },
      },
      hooks: {
        shieldcortex: { enabled: true },
        internal: {
          installs: { shieldcortex: { version: '3.4.37' } },
          entries: { shieldcortex: { enabled: true } },
          allow: ['shieldcortex', 'other-hook'],
        },
      },
    });
    writeClawhubLock({ skills: { shieldcortex: { version: '4.10.5' }, other: { version: '1.0.0' } } });

    // Populate filesystem residue
    const dirs = [
      path.join(tempHome, '.openclaw', 'hooks', 'cortex-memory'),
      path.join(tempHome, '.openclaw', 'hooks', 'internal', 'cortex-memory'),
      path.join(tempHome, '.openclaw', 'hooks', 'shieldcortex'),
      path.join(tempHome, '.claude', 'hooks', 'cortex-memory'),
      path.join(tempHome, '.claude', 'hooks', 'internal', 'cortex-memory'),
      path.join(tempHome, '.openclaw', 'extensions', 'shieldcortex-realtime'),
    ];
    for (const d of dirs) fs.mkdirSync(d, { recursive: true });

    const { scanForResidue } = await loadModule();
    const report = scanForResidue();
    const dirty = report.paths.filter((p) => p.present).map((p) => p.description);

    // Every configured residue path should be detected
    expect(dirty).toContain('openclaw.json: .plugins.installs["shieldcortex-realtime"]');
    expect(dirty).toContain('openclaw.json: .plugins.entries["shieldcortex-realtime"]');
    expect(dirty).toContain('openclaw.json: .plugins.allow[] contains "shieldcortex-realtime"');
    expect(dirty).toContain('openclaw.json: .plugins.load.paths[] contains "shieldcortex-realtime"');
    expect(dirty).toContain('openclaw.json: .hooks.shieldcortex');
    expect(dirty).toContain('openclaw.json: .hooks.internal.installs.shieldcortex');
    expect(dirty).toContain('openclaw.json: .hooks.internal.entries.shieldcortex');
    expect(dirty).toContain('openclaw.json: .hooks.internal.allow[] contains "shieldcortex"');
    expect(dirty).toContain('clawhub/lock.json: .skills.shieldcortex');
    for (const d of dirs) expect(dirty).toContain(d);

    expect(report.dirtyCount).toBeGreaterThanOrEqual(15);
  });

  it('surgically removes only ShieldCortex entries and preserves siblings', async () => {
    writeOpenClawJson({
      plugins: {
        installs: { 'shieldcortex-realtime': { source: 'path' }, 'other-plugin': { source: 'npm' } },
        entries: { 'shieldcortex-realtime': { enabled: true }, 'other-plugin': { enabled: true } },
        allow: ['shieldcortex-realtime', 'other-plugin', '/abs/path/shieldcortex-realtime/index.js'],
        load: { paths: ['/abs/shieldcortex-realtime/index.js', '/abs/other-plugin'] },
      },
      hooks: {
        shieldcortex: { enabled: true },
        'custom-hook': { enabled: true },
        internal: {
          installs: { shieldcortex: {}, 'other-hook': {} },
          entries: { shieldcortex: {}, 'other-hook': {} },
          allow: ['shieldcortex', 'shieldcortex-legacy', 'other-hook'],
        },
      },
      otherTopLevel: { preserved: true },
    });
    writeClawhubLock({ skills: { shieldcortex: { version: '4.10.5' }, 'genuine-skill': { version: '1.0.0' } } });

    const { scanForResidue, cleanResidue } = await loadModule();
    const report = scanForResidue();
    const result = cleanResidue(report);

    expect(result.errors).toEqual([]);
    expect(result.removed.length).toBeGreaterThanOrEqual(9);

    // Verify siblings preserved
    const cfg = JSON.parse(fs.readFileSync(openclawJsonPath(), 'utf-8'));
    expect(cfg.plugins.installs['shieldcortex-realtime']).toBeUndefined();
    expect(cfg.plugins.installs['other-plugin']).toEqual({ source: 'npm' });
    expect(cfg.plugins.entries['shieldcortex-realtime']).toBeUndefined();
    expect(cfg.plugins.entries['other-plugin']).toEqual({ enabled: true });
    expect(cfg.plugins.allow).toEqual(['other-plugin']);
    expect(cfg.plugins.load.paths).toEqual(['/abs/other-plugin']);
    expect(cfg.hooks.shieldcortex).toBeUndefined();
    expect(cfg.hooks['custom-hook']).toEqual({ enabled: true });
    expect(cfg.hooks.internal.installs.shieldcortex).toBeUndefined();
    expect(cfg.hooks.internal.installs['other-hook']).toEqual({});
    expect(cfg.hooks.internal.entries.shieldcortex).toBeUndefined();
    expect(cfg.hooks.internal.allow).toEqual(['other-hook']);
    expect(cfg.otherTopLevel).toEqual({ preserved: true });

    const lock = JSON.parse(fs.readFileSync(clawhubLockPath(), 'utf-8'));
    expect(lock.skills.shieldcortex).toBeUndefined();
    expect(lock.skills['genuine-skill']).toEqual({ version: '1.0.0' });
  });

  it('is idempotent — second run finds nothing to clean', async () => {
    writeOpenClawJson({
      plugins: { installs: { 'shieldcortex-realtime': { source: 'path' } } },
    });

    const { scanForResidue, cleanResidue } = await loadModule();
    const first = cleanResidue(scanForResidue());
    expect(first.removed.length).toBe(1);

    const second = cleanResidue(scanForResidue());
    expect(second.removed.length).toBe(0);
    expect(second.errors).toEqual([]);
  });

  it('dryRun leaves config untouched', async () => {
    writeOpenClawJson({ plugins: { installs: { 'shieldcortex-realtime': { source: 'path' } } } });

    const { scanForResidue, cleanResidue } = await loadModule();
    const before = fs.readFileSync(openclawJsonPath(), 'utf-8');
    const result = cleanResidue(scanForResidue(), { dryRun: true });
    const after = fs.readFileSync(openclawJsonPath(), 'utf-8');

    expect(result.removed.length).toBeGreaterThan(0);
    expect(before).toBe(after);
  });

  it('removes orphan config entries even when the extension directory is gone', async () => {
    // This is the real-world incident: files were cleaned manually but config entries
    // persisted and kept producing "references without files" warnings.
    writeOpenClawJson({
      plugins: {
        installs: { 'shieldcortex-realtime': { source: 'path' } },
        entries: { 'shieldcortex-realtime': { enabled: true } },
        allow: ['shieldcortex-realtime'],
      },
    });
    // Deliberately no filesystem residue

    const { scanForResidue, cleanResidue } = await loadModule();
    const result = cleanResidue(scanForResidue());

    const cfg = JSON.parse(fs.readFileSync(openclawJsonPath(), 'utf-8'));
    expect(cfg.plugins.installs['shieldcortex-realtime']).toBeUndefined();
    expect(cfg.plugins.entries['shieldcortex-realtime']).toBeUndefined();
    expect(cfg.plugins.allow).toEqual([]);
    expect(result.errors).toEqual([]);
  });

  it('handles malformed JSON without throwing', async () => {
    fs.writeFileSync(openclawJsonPath(), '{ not valid json', 'utf-8');

    const { scanForResidue } = await loadModule();
    const report = scanForResidue();
    // Invalid JSON is treated as an empty config — no residue reported for that file
    const configEntries = report.paths.filter((p) =>
      p.description.startsWith('openclaw.json'),
    );
    expect(configEntries.every((p) => !p.present)).toBe(true);
  });

  it('runDeepClean returns structured report and skips gateway restart when nothing to do', async () => {
    const { runDeepClean } = await loadModule();
    const { report, result, gateway } = await runDeepClean({ restartGateway: true });

    expect(report.dirtyCount).toBe(0);
    expect(result.removed).toEqual([]);
    // No residue → no restart attempt
    expect(gateway).toBeUndefined();
  });
});

describe('deep-clean — orphan detection (doctor path)', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  const originalSudoUser = process.env.SUDO_USER;
  let tempHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;

  beforeEach(() => {
    jest.resetModules();
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-orphans-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    delete process.env.SUDO_USER;
    fs.mkdirSync(path.join(tempHome, '.openclaw'), { recursive: true });
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
  });

  afterEach(() => {
    homedirSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    if (originalSudoUser === undefined) delete process.env.SUDO_USER;
    else process.env.SUDO_USER = originalSudoUser;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  async function loadModule() {
    return import('../setup/deep-clean.js');
  }

  function installPluginDir(): void {
    const extDir = path.join(tempHome, '.openclaw', 'extensions', 'shieldcortex-realtime');
    fs.mkdirSync(extDir, { recursive: true });
    fs.writeFileSync(path.join(extDir, 'openclaw.plugin.json'), '{"id":"shieldcortex-realtime","version":"4.12.1"}\n', 'utf-8');
    fs.writeFileSync(path.join(extDir, 'index.ts'), 'export default {};\n', 'utf-8');
  }

  function installHookDir(): void {
    fs.mkdirSync(path.join(tempHome, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
  }

  function writeHealthyInstallConfig(): void {
    fs.writeFileSync(
      path.join(tempHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        plugins: {
          installs: { 'shieldcortex-realtime': { source: 'npm', version: '4.12.1' } },
          entries: { 'shieldcortex-realtime': { enabled: true } },
          allow: ['shieldcortex-realtime'],
        },
        hooks: {
          internal: {
            installs: { shieldcortex: { version: '4.12.1' } },
            entries: { shieldcortex: { enabled: true } },
            allow: ['shieldcortex'],
          },
        },
      }, null, 2),
      'utf-8',
    );
  }

  it('reports zero orphans when plugin+hook are installed and config references them (v4.12.0 bug fix)', async () => {
    // Reproduces the fleet scenario: `shieldcortex openclaw install` on Case
    // populated config entries AND copied the plugin/hook to disk. The v4.12.0
    // doctor flagged all the config entries as "residue"; it should not have.
    installPluginDir();
    installHookDir();
    writeHealthyInstallConfig();

    const { scanForOrphans } = await loadModule();
    const report = scanForOrphans();

    expect(report.orphanCount).toBe(0);
    expect(report.installState.pluginInstalled).toBe(true);
    expect(report.installState.hookInstalled).toBe(true);
  });

  it('flags plugin-config entries as orphans when the plugin dir is gone', async () => {
    // Partial uninstall — config still references the plugin but the dir is gone.
    writeHealthyInstallConfig();
    installHookDir(); // keep hook installed to isolate plugin-config detection

    const { scanForOrphans } = await loadModule();
    const report = scanForOrphans();

    expect(report.orphanCount).toBeGreaterThanOrEqual(3); // installs, entries, allow
    expect(report.paths.every((p) => p.category !== 'hook-config')).toBe(true);
    expect(report.paths.some((p) => p.category === 'plugin-config')).toBe(true);
  });

  it('flags hook-config entries as orphans when no hook dir exists', async () => {
    writeHealthyInstallConfig();
    installPluginDir(); // keep plugin installed to isolate hook-config detection

    const { scanForOrphans } = await loadModule();
    const report = scanForOrphans();

    expect(report.paths.some((p) => p.category === 'hook-config')).toBe(true);
    expect(report.paths.every((p) => p.category !== 'plugin-config')).toBe(true);
  });

  it('flags legacy hook dirs as orphans even when current install is healthy', async () => {
    installPluginDir();
    installHookDir();
    writeHealthyInstallConfig();

    // Also drop a legacy hook dir that should have been migrated off
    const legacyDir = path.join(tempHome, '.openclaw', 'hooks', 'internal', 'cortex-memory');
    fs.mkdirSync(legacyDir, { recursive: true });

    const { scanForOrphans } = await loadModule();
    const report = scanForOrphans();

    expect(report.orphanCount).toBeGreaterThanOrEqual(1);
    expect(report.paths.some((p) => p.category === 'legacy-hook-dir' && p.description === legacyDir)).toBe(true);
  });

  it('flags clawhub skill lock as orphan (SC does not manage skills automatically)', async () => {
    installPluginDir();
    installHookDir();
    writeHealthyInstallConfig();

    const lockPath = path.join(tempHome, '.openclaw', 'workspace', '.clawhub', 'lock.json');
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    fs.writeFileSync(lockPath, JSON.stringify({ skills: { shieldcortex: { version: '4.10.5' } } }, null, 2), 'utf-8');

    const { scanForOrphans } = await loadModule();
    const report = scanForOrphans();

    expect(report.paths.some((p) => p.category === 'clawhub-skill-lock')).toBe(true);
  });

  it('does NOT flag the plugin extensions dir or the current hook dir themselves as orphans', async () => {
    installPluginDir();
    installHookDir();
    writeHealthyInstallConfig();

    const { scanForOrphans } = await loadModule();
    const report = scanForOrphans();

    expect(report.paths.some((p) => p.category === 'plugin-dir')).toBe(false);
    expect(report.paths.some((p) => p.category === 'hook-dir')).toBe(false);
  });

  it('tags every residue path with a category (migration regression guard)', async () => {
    writeHealthyInstallConfig();
    installPluginDir();
    installHookDir();

    const { scanForResidue } = await loadModule();
    const report = scanForResidue();

    for (const p of report.paths) {
      expect(p.category).toBeDefined();
      expect([
        'plugin-config',
        'hook-config',
        'clawhub-skill-lock',
        'plugin-dir',
        'hook-dir',
        'legacy-hook-dir',
      ]).toContain(p.category);
    }
  });
});
