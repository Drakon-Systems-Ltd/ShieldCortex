/**
 * #513 (SC-14) — the dashboard's locked dependency tree must sit above the
 * vulnerable ranges npm audit reported, and the install-time OpenClaw refresh
 * must be documented next to its opt-out.
 *
 * Offline and deterministic: reads dashboard/package-lock.json rather than
 * calling the registry. Floors are the first patched version of each advisory
 * range (production audit of dashboard/, 2026-09-20).
 */
import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (rel: string) => readFileSync(join(repoRoot, rel), 'utf8');

function cmp(a: string, b: string): number {
  const pa = a.split('-')[0].split('.').map(Number);
  const pb = b.split('-')[0].split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0);
  }
  return 0;
}

// package → first version outside the advisory range
const FLOORS: Record<string, string> = {
  next: '16.3.3', // vulnerable: 9.3.4-canary.0 - 16.3.2
  postcss: '8.5.23', // GHSA-qx2v-qp2m-jg93, GHSA-6g55-p6wh-862q, GHSA-fxqj-rqcc-2cmp, GHSA-r28c-9q8g-f849
  sharp: '0.35.4', // GHSA-f88m-g3jw-g9cj, GHSA-rgj7-g3m4-5g8c
  nanoid: '3.3.18', // vulnerable: <=3.3.17
  'lodash-es': '4.17.24', // vulnerable: <=4.17.23
};

describe('#513 dashboard dependency advisories', () => {
  const lock = JSON.parse(read('dashboard/package-lock.json')) as {
    packages: Record<string, { version?: string }>;
  };

  it.each(Object.entries(FLOORS))('every locked copy of %s is >= %s', (name, floor) => {
    const copies = Object.entries(lock.packages)
      .filter(([path]) => path.split('node_modules/').pop() === name)
      .map(([path, meta]) => ({ path, version: meta.version ?? '0.0.0' }));
    expect(copies.length).toBeGreaterThan(0);
    expect(copies.filter(c => cmp(c.version, floor) < 0)).toEqual([]);
  });

  it('stays on the next 16 / react 19 majors', () => {
    const pkg = JSON.parse(read('dashboard/package.json')) as { dependencies: Record<string, string> };
    expect(pkg.dependencies.next).toMatch(/^16\./);
    expect(pkg.dependencies.react).toMatch(/^19\./);
    expect(pkg.dependencies['react-dom']).toMatch(/^19\./);
  });
});

describe('#513 postinstall OpenClaw refresh is documented', () => {
  it('the opt-out the script honours is the one the docs name', () => {
    const script = read('scripts/postinstall.mjs');
    const doc = read('docs/openclaw-integration.md');
    expect(script).toContain('SHIELDCORTEX_SKIP_AUTO_OPENCLAW');
    expect(doc).toContain('## Install-time refresh (postinstall)');
    expect(doc).toContain('SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1');
  });
});
