import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { beforeAll, describe, expect, it } from '@jest/globals';

/**
 * Regression guard for the v4.18.2 OpenClaw packaging bug (Jarvis,
 * 2026-05-16). After `openclaw update` pulled `shieldcortex@4.18.2`,
 * OpenClaw config validation failed with:
 *
 *   plugins: plugin manifest not found:
 *   /home/ubuntu/.openclaw/npm/node_modules/shieldcortex/openclaw.plugin.json
 *
 * Root cause: the *main* `shieldcortex` package.json carries an
 * `openclaw.extensions` entry, so OpenClaw's npm auto-discovery treats the
 * bare package as a plugin and looks for a *root* `openclaw.plugin.json`.
 * The package only shipped the manifest at
 * `plugins/openclaw/dist/openclaw.plugin.json`, never at the package root,
 * so discovery failed and the gateway refused the config.
 *
 * The robust fix is a package-layout fix: the bare `shieldcortex` tarball
 * must carry a root `openclaw.plugin.json`, kept byte-identical to the
 * canonical `plugins/openclaw/openclaw.plugin.json`, and the declared
 * `openclaw.extensions[0]` must be resolvable from the package root within
 * the published files.
 */
describe('shieldcortex bare-package OpenClaw root manifest', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');

  const rootPkg = JSON.parse(
    fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'),
  ) as { version: string; files: string[]; openclaw?: { extensions?: string[] } };

  const canonicalManifestPath = path.join(
    repoRoot,
    'plugins',
    'openclaw',
    'openclaw.plugin.json',
  );
  const rootManifestPath = path.join(repoRoot, 'openclaw.plugin.json');

  let packedFiles: string[];

  beforeAll(() => {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: repoRoot,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const meta = JSON.parse(out) as Array<{ files: Array<{ path: string }> }>;
    packedFiles = meta[0].files.map((f) => f.path.replace(/\\/g, '/'));
  }, 60000);

  it('declares openclaw.plugin.json in the package files allow-list', () => {
    expect(rootPkg.files).toContain('openclaw.plugin.json');
  });

  it('ships a root openclaw.plugin.json in the published bare package', () => {
    expect(packedFiles).toContain('openclaw.plugin.json');
  });

  it('keeps the root manifest byte-identical to the canonical plugin manifest', () => {
    expect(fs.existsSync(rootManifestPath)).toBe(true);
    const root = fs.readFileSync(rootManifestPath, 'utf-8');
    const canonical = fs.readFileSync(canonicalManifestPath, 'utf-8');
    expect(root).toBe(canonical);
  });

  it('root manifest is a valid OpenClaw manifest matching the package version', () => {
    const manifest = JSON.parse(fs.readFileSync(rootManifestPath, 'utf-8')) as {
      id: string;
      version: string;
    };
    expect(manifest.id).toBe('shieldcortex-realtime');
    expect(manifest.version).toBe(rootPkg.version);
  });

  it('declared openclaw.extensions[0] is resolvable from the published package root', () => {
    const ext = rootPkg.openclaw?.extensions?.[0];
    expect(typeof ext).toBe('string');
    const rel = (ext as string).replace(/^\.\//, '');
    expect(packedFiles).toContain(rel);
  });
});
