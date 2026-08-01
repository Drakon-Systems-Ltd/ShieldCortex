import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * Locks in the plugin package/manifest shape that OpenClaw 2026.4.23 expects
 * for host-package linking (#70462) and compatibility hinting. Regressions
 * in these fields silently break peer-only SDK imports after install.
 */
describe('shieldcortex-realtime plugin manifest', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
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

  it('declares explicit startup activation policy for OpenClaw compatibility', () => {
    // This test used to assert `onStartup: false` — pinning the exact value
    // that left two fleet hosts silently unprotected (see the startup-intent
    // suite below). A security interceptor is a startup plugin, full stop.
    expect(manifest.activation.onStartup).toBe(true);
  });

  it('plugin package version matches the root package version', () => {
    const rootPkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'));
    expect(pkg.version).toBe(rootPkg.version);
    expect(manifest.version).toBe(rootPkg.version);
  });
});

/**
 * Field incident, 1 Aug 2026 (aiquant + Michael's Mac): the 2026.7.x gateway
 * builds its startup plugin set from DEMAND — a plugin loads at boot only if
 * some predicate says the config needs it (configured channel, provider,
 * harness runtime, hook capability, or `activation.onStartup === true`).
 *
 * Our manifest said `onStartup: false` and listed hooks under a key the
 * loader's intent check never reads (`activation.hooks`; it reads
 * `activation.onCapabilities`). Result: on any host whose config entry lacked
 * an explicit `hooks` policy block, the gateway had ZERO reason to load the
 * interceptor — enabled, allow-listed, index-coherent, and silently absent
 * from every boot. Two fleet hosts ran unprotected this way; two others
 * loaded only because their config entries happened to carry
 * `hooks.allowConversationAccess`, which the loader accepts as intent.
 *
 * A security interceptor must never depend on a config accident to exist.
 */
describe('gateway startup intent (the aiquant silent-skip, 1 Aug 2026)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const manifest = JSON.parse(
    fs.readFileSync(path.join(repoRoot, 'plugins', 'openclaw', 'openclaw.plugin.json'), 'utf-8'),
  );

  it('declares onStartup: true — the gateway must always consider us at boot', () => {
    expect(manifest.activation.onStartup).toBe(true);
  });

  it('declares the hook capability in the key the loader actually reads', () => {
    expect(manifest.activation.onCapabilities).toEqual(expect.arrayContaining(['hook']));
  });
});
