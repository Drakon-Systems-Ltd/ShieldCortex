import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { describe, expect, it } from '@jest/globals';

/**
 * Issue #134 §1 — `shieldcortex` is ESM-only at the package root and every
 * subpath, and `require('shieldcortex')` used to fail with a bare
 * `ERR_PACKAGE_PATH_NOT_EXPORTED` that names neither shieldcortex nor the
 * real cause (repro: `node -e "require('shieldcortex')"`).
 *
 * Decision taken (documented in README.md "ESM only" + the PR): stay
 * ESM-only — there is no CJS build, and pointing `require` at the compiled
 * ESM output would just trade one confusing runtime failure for another
 * (ERR_REQUIRE_ESM). Instead, every `exports` entry gets an explicit
 * "require" condition pointing at a real, loadable CommonJS file
 * (scripts/lib/cjs-not-supported.cjs) that throws an actionable error
 * naming the package, the cause, and the fix. `import`/`import()` keep
 * resolving to the real ESM build untouched.
 */
const require = createRequire(import.meta.url);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf-8'));

const SUBPATH_EXPORTS = [
  '.',
  './integrations/langchain',
  './integrations/universal',
  './integrations/openclaw',
  './integrations',
  './defence',
  './scan',
  './environment',
  './lib',
];

describe('#134 §1 — package.json exports honestly handle require()', () => {
  it.each(SUBPATH_EXPORTS)('exports[%s] declares a "require" condition (not silence, not ESM output)', (key) => {
    const entry = pkg.exports[key];
    expect(entry).toBeDefined();
    expect(typeof entry).toBe('object');
    expect(entry.require).toBe('./scripts/lib/cjs-not-supported.cjs');
    // Must NOT point require at the ESM build — that fails a DIFFERENT,
    // equally-confusing way (ERR_REQUIRE_ESM) instead of not working at all.
    expect(entry.require).not.toBe(entry.import);
  });

  it.each(SUBPATH_EXPORTS)('exports[%s] still resolves "import" to the real ESM build (unchanged)', (key) => {
    const entry = pkg.exports[key];
    expect(typeof entry.import).toBe('string');
    expect(entry.import.startsWith('./dist/')).toBe(true);
  });

  it('the require-condition target file actually exists in the package', () => {
    const shimPath = path.join(repoRoot, 'scripts', 'lib', 'cjs-not-supported.cjs');
    expect(fs.existsSync(shimPath)).toBe(true);
  });

  it('is listed in package.json "files" so it actually ships in the published tarball', () => {
    expect(Array.isArray(pkg.files)).toBe(true);
    // scripts/lib as a whole directory is already whitelisted — confirm that
    // stays true rather than assuming; a narrower "files" edit elsewhere
    // could silently drop this file from the tarball.
    expect(pkg.files).toContain('scripts/lib');
  });

  it('require()ing the shim throws an actionable, shieldcortex-specific error — not a bare Node resolution error', () => {
    const shimPath = path.join(repoRoot, 'scripts', 'lib', 'cjs-not-supported.cjs');
    let thrown: unknown = null;
    try {
      require(shimPath);
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    const message = (thrown as Error).message;
    expect(message).toMatch(/shieldcortex/i);
    expect(message).toMatch(/ESM.only/i);
    expect(message).toMatch(/import/i);
    // The specific opaque error this replaces — must never resemble it.
    expect(message).not.toMatch(/ERR_PACKAGE_PATH_NOT_EXPORTED/);
  });
});
