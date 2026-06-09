import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import path from 'path';

const dist = path.join(process.cwd(), 'dist');

// Build-output guard. Skips if dist is absent (pure-source CI), runs when dist exists.
(existsSync(dist) ? describe : describe.skip)('dist has no ESM-unsafe require()', () => {
  it('passes the static guard', () => {
    execFileSync('node', ['scripts/check-no-bare-require.mjs'], { stdio: 'pipe' });
  });
});
