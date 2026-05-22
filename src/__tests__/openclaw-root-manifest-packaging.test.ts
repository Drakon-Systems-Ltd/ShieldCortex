import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { beforeAll, describe, expect, it } from '@jest/globals';

/**
 * Regression guard for the v4.20.0 packaging change: the *main* `shieldcortex`
 * package no longer declares `openclaw.extensions`.
 *
 * Background. In v4.18.2 `openclaw update` failed config validation with:
 *
 *   plugins: plugin manifest not found:
 *   /home/ubuntu/.openclaw/npm/node_modules/shieldcortex/openclaw.plugin.json
 *
 * Root cause: the main package.json carried `openclaw.extensions`, so
 * OpenClaw's npm discovery walked the bare package as if it were a plugin
 * and looked for a root manifest. The v4.18.2 fix added a root manifest;
 * v4.20.0 takes the structural fix one step further by removing the
 * extensions declaration from the main package altogether. OpenClaw's
 * discovery is gated on `openclaw.extensions` being present, so without it
 * the bare `shieldcortex` is invisible to discovery — no duplicate-plugin-id
 * warning, no manifest dependency, no race against the dedicated
 * `@drakon-systems/shieldcortex-realtime` plugin.
 *
 * The defensive root `openclaw.plugin.json` is kept for one release in case
 * any fleet box still has cached discovery state from an older OpenClaw
 * version; it can be removed in a follow-up once that's confirmed clear.
 */
describe('shieldcortex bare-package OpenClaw discovery contract (post-v4.20.0)', () => {
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
    const out = execFileSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: repoRoot,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
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

  it('keeps the defensive root openclaw.plugin.json in the package files allow-list (one-release shim)', () => {
    expect(rootPkg.files).toContain('openclaw.plugin.json');
    expect(packedFiles).toContain('openclaw.plugin.json');
    expect(fs.existsSync(rootManifestPath)).toBe(true);
  });
});
