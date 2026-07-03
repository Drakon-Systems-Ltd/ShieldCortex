import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';
import { BUILT_IN_HOOKS } from '../setup/hooks.js';

/**
 * Every built-in hook script must be shipped in the npm tarball. package.json
 * "files" whitelists hook scripts INDIVIDUALLY, so adding a hook to
 * BUILT_IN_HOOKS without whitelisting its script publishes a package whose
 * settings.json wiring points at a missing file — the hook exits 1 on every
 * fire with no build/test failure anywhere. This locks the two lists together.
 */
describe('built-in hook scripts — npm packaging contract', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8')) as {
    files: string[];
  };

  it.each(Object.entries(BUILT_IN_HOOKS))(
    'hook "%s" script is whitelisted in package.json files',
    (_hookName, scriptFile) => {
      expect(pkg.files).toContain(`scripts/${scriptFile}`);
    },
  );

  it.each(Object.entries(BUILT_IN_HOOKS))(
    'hook "%s" script exists on disk',
    (_hookName, scriptFile) => {
      expect(fs.existsSync(path.join(repoRoot, 'scripts', scriptFile))).toBe(true);
    },
  );
});
