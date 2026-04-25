import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * v4.12.3-v4.12.6's native-package install code recorded the wrong
 * `installPath` in `openclaw.json`:
 *
 *   path.dirname(path.dirname(globalPluginPath))   ← package root
 *   path.dirname(globalPluginPath)                 ← dist dir (the manifest's parent)
 *
 * Only the second one is the dir that contains `openclaw.plugin.json`,
 * which is the convention `detectInstallState()` checks. v4.12.7 fixes
 * the writer so the recorded path matches the convention used by every
 * other code path (trusted-local-copy passes the dest dir directly).
 */
describe('installPlugin — native-package installPath (v4.12.7)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const openclawSource = fs.readFileSync(
    path.join(repoRoot, 'src', 'setup', 'openclaw.ts'),
    'utf-8',
  );

  it('passes path.dirname(globalPluginPath) to trustLocalPlugin (the dist dir)', () => {
    const nativePackageBlock = openclawSource.match(
      /isInOpenClawSearchPath[\s\S]*?return\s+['"]native-package['"];/,
    );
    expect(nativePackageBlock).not.toBeNull();
    expect(nativePackageBlock![0]).toMatch(/trustLocalPlugin\(\s*pluginDir/);
  });

  it('does NOT pass path.dirname(path.dirname(globalPluginPath)) — that was the bug', () => {
    const nativePackageBlock = openclawSource.match(
      /isInOpenClawSearchPath[\s\S]*?return\s+['"]native-package['"];/,
    );
    expect(nativePackageBlock).not.toBeNull();
    // Strip comments (the buggy pattern is intentionally referenced in the
    // explanatory comment block) before checking the actual code.
    const codeOnly = nativePackageBlock![0]
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\/\/[^\n]*/g, '');
    expect(codeOnly).not.toMatch(/path\.dirname\(\s*path\.dirname\(/);
  });

  it('logs the same dir to the user as it records to config (no install/log mismatch)', () => {
    // Earlier code printed `path.dirname(globalPluginPath)` ("Installed to .../dist")
    // while writing `path.dirname(path.dirname(...))` to config — confusing
    // any operator who tried to verify by hand. Both should now use pluginDir.
    const nativePackageBlock = openclawSource.match(
      /isInOpenClawSearchPath[\s\S]*?return\s+['"]native-package['"];/,
    );
    expect(nativePackageBlock).not.toBeNull();
    expect(nativePackageBlock![0]).toMatch(/Installed real-time plugin to \$\{pluginDir\}/);
    expect(nativePackageBlock![0]).toMatch(/trustLocalPlugin\(\s*pluginDir/);
  });
});
