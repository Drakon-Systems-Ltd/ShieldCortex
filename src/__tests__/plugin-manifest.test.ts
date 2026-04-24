import fs from 'fs';
import path from 'path';
import { describe, expect, it } from '@jest/globals';

/**
 * Locks in the plugin package/manifest shape that OpenClaw 2026.4.23 expects
 * for host-package linking (#70462) and compatibility hinting. Regressions
 * in these fields silently break peer-only SDK imports after install.
 */
describe('shieldcortex-realtime plugin manifest', () => {
  const repoRoot = path.resolve(__dirname, '..', '..');
  const pluginDir = path.join(repoRoot, 'plugins', 'openclaw');

  const pkg = JSON.parse(fs.readFileSync(path.join(pluginDir, 'package.json'), 'utf-8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(pluginDir, 'openclaw.plugin.json'), 'utf-8'));

  it('declares openclaw as a peer dependency (enables 2026.4.23 host-package linking)', () => {
    expect(pkg.peerDependencies).toBeDefined();
    expect(pkg.peerDependencies.openclaw).toBeDefined();
    expect(pkg.peerDependencies.openclaw).toMatch(/2026\./);
  });

  it('marks openclaw peer as optional so older installs still resolve', () => {
    expect(pkg.peerDependenciesMeta).toBeDefined();
    expect(pkg.peerDependenciesMeta.openclaw).toEqual({ optional: true });
  });

  it('keeps shieldcortex peer dependency intact', () => {
    expect(pkg.peerDependencies.shieldcortex).toBeDefined();
  });

  it('records a recommended OpenClaw engine version in package.json', () => {
    expect(pkg.engines).toBeDefined();
    expect(pkg.engines.openclaw).toBeDefined();
    expect(pkg.engines.openclaw).toMatch(/2026\.4\.23/);
  });

  it('records engine hints inside the OpenClaw plugin manifest', () => {
    expect(manifest.engines).toBeDefined();
    expect(manifest.engines.openclaw).toMatch(/2026\./);
    expect(manifest.engines.recommended).toMatch(/2026\.4\.23/);
  });

  it('keeps id and activation hooks stable (uninstall scripts key off these)', () => {
    expect(manifest.id).toBe('shieldcortex-realtime');
    expect(manifest.activation.hooks).toEqual(
      expect.arrayContaining(['llm_input', 'llm_output', 'before_tool_call', 'session_end']),
    );
  });

  it('plugin package version matches the root package version', () => {
    const rootPkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'));
    expect(pkg.version).toBe(rootPkg.version);
    expect(manifest.version).toBe(rootPkg.version);
  });
});
