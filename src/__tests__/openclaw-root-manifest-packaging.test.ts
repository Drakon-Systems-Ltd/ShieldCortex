import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { beforeAll, describe, expect, it } from '@jest/globals';

/**
 * Regression guard for the v4.21.1 packaging change: the *main* `shieldcortex`
 * package ships NEITHER `openclaw.extensions` in package.json NOR a root
 * `openclaw.plugin.json` — both are independent OpenClaw discovery vectors.
 *
 * Background. v4.18.2 → v4.18.3 added a root `openclaw.plugin.json` because
 * OpenClaw was discovering the bare package via package.json's
 * `openclaw.extensions` and crash-looping when no manifest existed. v4.20.0
 * removed `openclaw.extensions` from the main package, intending to close
 * the discovery vector. The defensive root manifest was kept "for one
 * release" while we waited for fleet evidence.
 *
 * Fleet evidence (edith, 2026-05-24) showed OpenClaw's `bundledDiscovery: "compat"`
 * scans `node_modules/*​/openclaw.plugin.json` **independently of**
 * package.json's `openclaw.extensions`. The bare `shieldcortex` was still
 * being discovered via the root-manifest vector and registered under
 * `pluginId: shieldcortex-realtime` — duplicate plugin id every session.
 *
 * v4.21.1 drops the root manifest from the published tarball. With neither
 * discovery vector present, the bare package is fully invisible to OpenClaw
 * discovery. The dedicated `@drakon-systems/shieldcortex-realtime` plugin is
 * the only thing discoverable, no race, no duplicate registration.
 */
describe('shieldcortex bare-package OpenClaw discovery contract (post-v4.21.1)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');

  const rootPkg = JSON.parse(
    fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'),
  ) as {
    version: string;
    files: string[];
    openclaw?: { hooks?: unknown; extensions?: unknown };
  };

  const rootManifestPath = path.join(repoRoot, 'openclaw.plugin.json');

  let packedFiles: string[];

  beforeAll(() => {
    // This suite only needs the packed file MANIFEST, not a real build. Run
    // pack with `--ignore-scripts` so the `prepack` lifecycle (which chmods
    // dist/index.js and `process.exit(1)`s when dist/ is absent) cannot make
    // `npm pack` exit non-zero. Without this the suite failed on CI with a
    // bare "Command failed: npm pack" whenever dist/ wasn't present at the
    // moment pack ran (e.g. another test having rebuilt it). The file list is
    // identical with or without scripts. Capture stderr too, so any future
    // pack failure surfaces its reason instead of being swallowed.
    let out: string;
    try {
      out = execFileSync(
        'npm',
        ['pack', '--dry-run', '--json', '--ignore-scripts'],
        { cwd: repoRoot, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] },
      );
    } catch (err) {
      const e = err as { stderr?: string; message?: string };
      throw new Error(
        `npm pack failed: ${e.message ?? err}\n--- npm stderr ---\n${e.stderr ?? '(none)'}`,
      );
    }
    const meta = JSON.parse(out) as Array<{ files: Array<{ path: string }> }>;
    packedFiles = meta[0].files.map((f) => f.path.replace(/\\/g, '/'));
  }, 60000);

  it('does NOT declare openclaw.extensions on the main package (this is the v4.20.0 contract)', () => {
    expect(rootPkg.openclaw?.extensions).toBeUndefined();
  });

  it('still declares openclaw.hooks for the documented `openclaw hooks install` flow', () => {
    expect(Array.isArray(rootPkg.openclaw?.hooks)).toBe(true);
    expect((rootPkg.openclaw?.hooks as unknown[]).length).toBeGreaterThan(0);
  });

  it('does NOT ship a root openclaw.plugin.json in the published tarball (the v4.21.1 contract)', () => {
    expect(rootPkg.files).not.toContain('openclaw.plugin.json');
    expect(packedFiles).not.toContain('openclaw.plugin.json');
  });

  it('does NOT keep a checked-in root openclaw.plugin.json in the repo (so the build cannot accidentally re-include it)', () => {
    expect(fs.existsSync(rootManifestPath)).toBe(false);
  });
});
