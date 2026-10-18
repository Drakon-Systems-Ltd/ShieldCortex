import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

describe('OpenClaw README ShieldCortex compatibility (#823)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const pluginDir = path.join(repoRoot, 'plugins', 'openclaw');
  const pkg = JSON.parse(fs.readFileSync(path.join(pluginDir, 'package.json'), 'utf-8'));
  const readme = fs.readFileSync(path.join(pluginDir, 'README.md'), 'utf-8');
  const compatibility = readme.split(/^## Compatibility\s*$/m)[1]?.split(/^###? /m)[0];
  const bullet = compatibility?.split('\n').find((line) => line.startsWith('- **ShieldCortex** —'));
  const peerRange: string = pkg.peerDependencies.shieldcortex;

  it('states the declared ShieldCortex peer range verbatim in backticks', () => {
    expect(bullet).toBeDefined();
    expect(bullet).toContain(`\`${peerRange}\``);
  });

  it('does not state a minimum below the peer range lower bound', () => {
    expect(bullet).toBeDefined();
    const lowerBound = peerRange.match(/^(?:\^|>=)\s*(\d+)\.(\d+)\.(\d+)$/);
    expect(lowerBound).not.toBeNull();
    const minimums = [...(bullet ?? '').matchAll(/(?:≥|>=)\s*(\d+)\.(\d+)\.(\d+)/g)];
    for (const minimum of minimums) {
      const stated = minimum.slice(1).map(Number);
      const bound = lowerBound!.slice(1).map(Number);
      expect(stated[0] > bound[0] ||
        (stated[0] === bound[0] && (stated[1] > bound[1] ||
          (stated[1] === bound[1] && stated[2] >= bound[2])))).toBe(true);
    }
  });
});
