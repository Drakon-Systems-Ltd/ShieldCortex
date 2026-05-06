import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, it, expect } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPTS = path.resolve(__dirname, '..', '..', 'scripts');

/**
 * Regression guard for #42: every hook that writes memories must derive
 * its project key via the shared deriveProjectKey() helper. A local
 * extractProjectFromPath copy reintroduces the basename/git-origin mismatch
 * and silently breaks recall.
 */

const HOOK_FILES = [
  'stop-hook.mjs',
  'session-end-hook.mjs',
  'pre-compact-hook.mjs',
  'session-start-hook.mjs',
  'prompt-recall-hook.mjs',
];

describe('hook scripts — project-key derivation alignment (#42)', () => {
  for (const file of HOOK_FILES) {
    const fullPath = path.join(SCRIPTS, file);

    it(`${file} imports deriveProjectKey from the shared helper`, () => {
      const src = fs.readFileSync(fullPath, 'utf-8');
      expect(src).toMatch(/from\s+['"]\.\/lib\/project-key\.mjs['"]/);
      expect(src).toMatch(/deriveProjectKey/);
    });

    it(`${file} does not define a local extractProjectFromPath`, () => {
      const src = fs.readFileSync(fullPath, 'utf-8');
      expect(src).not.toMatch(/function\s+extractProjectFromPath\b/);
    });
  }
});
