import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * Contract test for `installPlugin()` modes.
 *
 * Today the function returns one of five PluginInstallMode values:
 *   - 'native-package'      — registered via `openclaw plugins install <pkg>`
 *   - 'native-link'         — registered via `openclaw plugins install --link <path>`
 *   - 'trusted-local-copy'  — copied to ~/.openclaw/extensions/ and registered in plugins.allow
 *   - 'untrusted-local-copy'— copied to ~/.openclaw/extensions/ but trust registration failed
 *   - 'skipped'             — Docker / --no-plugins / OpenClaw not installed / source missing
 *
 * The audit (May 2026) flagged "five install paths is a smell — every one
 * is a distinct failure mode the doctor command must recognise." A future
 * refactor will likely consolidate these into:
 *   - 'native'  (success — either package or link install registered)
 *   - 'local'   (with `trusted: boolean` field for the partial-success case)
 *   - 'skipped'
 *
 * This test pins the current contract. When the consolidation lands:
 *   1. The mode list here will need to shrink (and this test updated).
 *   2. Every consumer (the install command's "What was installed" log,
 *      the doctor command, the postinstall script) needs the new contract
 *      threaded through.
 *
 * That cross-cut is exactly the kind of work that bit us in v4.12.6→14
 * (nine patch releases in eight days, every one a fix). Don't ship it
 * blind — write the consumer-side tests first.
 */
describe('installPlugin — mode contract (May 2026 baseline)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const openclawSource = fs.readFileSync(
    path.join(repoRoot, 'src', 'setup', 'openclaw.ts'),
    'utf-8',
  );

  it('declares exactly the five expected PluginInstallMode values', () => {
    // The literal type union — any addition or removal here is a contract change.
    const typeMatch = openclawSource.match(/type PluginInstallMode\s*=\s*([^;]+);/);
    expect(typeMatch).not.toBeNull();
    const declared = (typeMatch?.[1] ?? '')
      .split('|')
      .map((s) => s.trim().replace(/^['"]|['"]$/g, ''));
    expect(declared.sort()).toEqual([
      'native-link',
      'native-package',
      'skipped',
      'trusted-local-copy',
      'untrusted-local-copy',
    ]);
  });

  it('tries native install before falling back to the local-copy path', () => {
    // tryNativeOpenClawPluginInstall MUST be called before findExtensionsDir
    // in installPlugin's body — otherwise we'd register two copies of the
    // plugin (one native, one local) and OpenClaw warns / refuses on the
    // duplicate plugin ID.
    const installPluginMatch = openclawSource.match(
      /function installPlugin\([^)]*\)[^{]*\{([\s\S]*?)\n\}/,
    );
    expect(installPluginMatch).not.toBeNull();
    const body = installPluginMatch![1];
    const nativeIdx = body.indexOf('tryNativeOpenClawPluginInstall(');
    const findExtIdx = body.indexOf('findExtensionsDir(');
    expect(nativeIdx).toBeGreaterThan(-1);
    expect(findExtIdx).toBeGreaterThan(-1);
    expect(nativeIdx).toBeLessThan(findExtIdx);
  });

  it('tries the package install before the linked install', () => {
    // The native-install attempts list inside tryNativeOpenClawPluginInstall
    // is ordered: package install first (production path), --link second
    // (dev fallback). Reversing this would silently regress production
    // installs to the dev-only --link path.
    const fnMatch = openclawSource.match(
      /function tryNativeOpenClawPluginInstall\(\)[^{]*\{([\s\S]*?)\n\}/,
    );
    expect(fnMatch).not.toBeNull();
    const body = fnMatch![1];
    const packageIdx = body.indexOf("'package install'");
    const linkIdx = body.indexOf("'linked install'");
    expect(packageIdx).toBeGreaterThan(-1);
    expect(linkIdx).toBeGreaterThan(-1);
    expect(packageIdx).toBeLessThan(linkIdx);
  });

  it('returns "skipped" without doing fs work when --no-plugins is set', () => {
    // The very first branch of installPlugin must check noPlugins and bail
    // before any extensions-dir lookup or plugin copy. Anything else is a
    // performance + side-effect bug on machines that explicitly opted out.
    const installPluginMatch = openclawSource.match(
      /function installPlugin\([^)]*\)[^{]*\{([\s\S]*?)\n\}/,
    );
    const body = installPluginMatch![1];
    const noPluginsIdx = body.indexOf('options.noPlugins');
    const dockerIdx = body.indexOf('isDockerEnvironment(');
    const tryNativeIdx = body.indexOf('tryNativeOpenClawPluginInstall(');
    expect(noPluginsIdx).toBeGreaterThan(-1);
    expect(noPluginsIdx).toBeLessThan(dockerIdx);
    expect(noPluginsIdx).toBeLessThan(tryNativeIdx);
  });

  it('checks Docker before any plugin install attempt', () => {
    // Docker check must precede tryNativeOpenClawPluginInstall — running
    // `openclaw plugins install` inside a container has crashed gateways
    // in the past (#16). Reordering would re-open that hole.
    const installPluginMatch = openclawSource.match(
      /function installPlugin\([^)]*\)[^{]*\{([\s\S]*?)\n\}/,
    );
    const body = installPluginMatch![1];
    const dockerIdx = body.indexOf('isDockerEnvironment(');
    const tryNativeIdx = body.indexOf('tryNativeOpenClawPluginInstall(');
    expect(dockerIdx).toBeGreaterThan(-1);
    expect(dockerIdx).toBeLessThan(tryNativeIdx);
  });

  it('reports a distinct user-facing log line for each non-skipped mode', () => {
    // Each mode should produce a unique installed-message branch in the
    // install command — otherwise the doctor command can't tell modes apart
    // when reading user logs to debug field installs.
    const expectedModes = [
      'native-package',
      'native-link',
      'trusted-local-copy',
      'untrusted-local-copy',
    ];
    for (const mode of expectedModes) {
      expect(openclawSource).toContain(`pluginInstallMode === '${mode}'`);
    }
  });
});
