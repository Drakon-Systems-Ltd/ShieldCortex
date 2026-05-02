import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * v4.12.3-v4.12.13's `installPlugin()` had a "fast path" branch that
 * checked `npm root -g` against a hardcoded list of "OpenClaw-searched"
 * paths (/usr/lib/node_modules, /usr/local/lib/node_modules,
 * /opt/homebrew/lib/node_modules). When the npm global was on that list,
 * the branch:
 *
 *   1. Deleted the existing extension dir at ~/.openclaw/extensions/
 *      shieldcortex-realtime/.
 *   2. Pointed `trustLocalPlugin` at the plugin's npm-install path.
 *   3. Returned 'native-package'.
 *
 * The premise was wrong: OpenClaw only discovers plugins from its stock
 * dir and ~/.openclaw/extensions/, not from arbitrary global node_modules
 * trees. Every Mac homebrew install (and every Linux global install) hit
 * the branch, lost its working extension dir, and ended up with an
 * unregistered plugin and a "plugin not found" doctor warning.
 *
 * v4.12.14 removes the branch entirely. `installPlugin()` now always
 * calls `tryNativeOpenClawPluginInstall()` first (which uses
 * `openclaw plugins install <pkg>` — the correct registration path) and
 * falls back to the extensions-dir copy.
 */
describe('installPlugin — npm-global-path branch removal (v4.12.14)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const openclawSource = fs.readFileSync(
    path.join(repoRoot, 'src', 'setup', 'openclaw.ts'),
    'utf-8',
  );

  // Isolate the body of installPlugin so the assertions don't false-trigger
  // on other code (eg the explanatory comment that references the deleted
  // identifier).
  const installPluginBody = (() => {
    const match = openclawSource.match(
      /function installPlugin\([^)]*\)[^{]*\{([\s\S]*?)\n\}/,
    );
    if (!match) throw new Error('Could not locate installPlugin function');
    return match[1].replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');
  })();

  it('does not check npm root against a hardcoded openclawSearchPaths list', () => {
    expect(installPluginBody).not.toMatch(/openclawSearchPaths/);
    expect(installPluginBody).not.toMatch(/isInOpenClawSearchPath/);
  });

  it('does not call npm root -g inside installPlugin', () => {
    expect(installPluginBody).not.toMatch(/npm\s+root\s+-g/);
  });

  it('does not delete the existing extension dir as a side-effect of the install fast-path', () => {
    // The deletion lives inside tryNativeOpenClawPluginInstall() (so it only
    // happens when a real OpenClaw native install is about to run). It must
    // NOT live directly inside installPlugin().
    expect(installPluginBody).not.toMatch(/fs\.rmSync\([^)]*PLUGIN_DIR_NAME/);
  });

  it('calls tryNativeOpenClawPluginInstall and never inlines a native-package return path', () => {
    // installPlugin must delegate to tryNativeOpenClawPluginInstall — the only
    // function that registers via `openclaw plugins install <pkg>`.
    expect(installPluginBody).toMatch(/tryNativeOpenClawPluginInstall\(\)/);
    // The deleted fast-path was the only place that inlined a literal
    // `return 'native-package'` inside installPlugin. Now the only way the
    // function emits that mode is by returning the value of
    // tryNativeOpenClawPluginInstall, so the literal string must not appear.
    expect(installPluginBody).not.toMatch(/return\s+['"]native-package['"]/);
  });
});
