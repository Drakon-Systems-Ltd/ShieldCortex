/**
 * Tests for the self-healing native-binding helper.
 *
 * The orchestration (ensureNativeBinding) is tested via injected verify/rebuild
 * so we can exercise the heal paths without a real native-module failure.
 */
import { describe, it, expect } from '@jest/globals';
import {
  verifyNativeBinding,
  resolveSelfInstallDir,
  nativeBindingRemediation,
  nativeRebuildCommand,
  ensureNativeBinding,
} from '../setup/native-binding.js';
import { existsSync, readFileSync } from 'fs';
import path from 'path';

describe('native-binding helper', () => {
  describe('resolveSelfInstallDir', () => {
    it('resolves to the package root (the dir whose package.json is shieldcortex)', () => {
      const dir = resolveSelfInstallDir();
      const pkgPath = path.join(dir, 'package.json');
      expect(existsSync(pkgPath)).toBe(true);
      expect(JSON.parse(readFileSync(pkgPath, 'utf-8')).name).toBe('shieldcortex');
    });
  });

  describe('verifyNativeBinding', () => {
    it('reports ok in this environment (better-sqlite3 is installed)', () => {
      const r = verifyNativeBinding();
      expect(r.ok).toBe(true);
    });
  });

  describe('nativeRebuildCommand', () => {
    it('normal rebuild uses `npm rebuild better-sqlite3` in the install dir', () => {
      const c = nativeRebuildCommand('/opt/install/shieldcortex', false);
      expect(c.cmd).toBe('npm');
      expect(c.args).toEqual(['rebuild', 'better-sqlite3', '--no-audit', '--no-fund']);
      expect(c.cwd).toBe('/opt/install/shieldcortex');
    });

    it('fromSource uses `npm run build-release` IN the better-sqlite3 dir (bypasses prebuild-install no-op)', () => {
      const c = nativeRebuildCommand('/opt/install/shieldcortex', true);
      expect(c.cmd).toBe('npm');
      expect(c.args).toEqual(['run', 'build-release']);
      expect(c.cwd).toBe(path.join('/opt/install/shieldcortex', 'node_modules', 'better-sqlite3'));
      // It must NOT be the no-op `npm rebuild --build-from-source` form.
      expect(c.args).not.toContain('--build-from-source');
    });
  });

  describe('nativeBindingRemediation', () => {
    it('points at `npm run build-release` in the better-sqlite3 dir, with a toolchain hint', () => {
      const text = nativeBindingRemediation('/opt/install/shieldcortex');
      // The reliable forced compile — NOT the prebuild-install no-op forms.
      expect(text).toContain(path.join('/opt/install/shieldcortex', 'node_modules', 'better-sqlite3'));
      expect(text).toContain('npm run build-release');
      expect(text).not.toContain('npm rebuild better-sqlite3');
      // platform toolchain hint — at least one of the known package managers
      expect(/apt|xcode-select|build tools|python3|make|g\+\+/.test(text)).toBe(true);
    });
  });

  describe('ensureNativeBinding', () => {
    it('returns ok and does NOT rebuild when the binding already loads', async () => {
      let rebuilt = 0;
      const r = await ensureNativeBinding({
        verify: () => ({ ok: true }),
        rebuild: async () => { rebuilt++; return { ok: true, output: '' }; },
        installDir: () => '/x',
      });
      expect(r.status).toBe('ok');
      expect(rebuilt).toBe(0);
    });

    it('rebuilds and reports healed when a rebuild fixes the binding', async () => {
      let rebuilt = 0;
      let verifyCalls = 0;
      const r = await ensureNativeBinding({
        verify: () => ({ ok: ++verifyCalls > 1 }),     // fail first, ok after rebuild
        rebuild: async () => { rebuilt++; return { ok: true, output: 'gyp ok' }; },
        installDir: () => '/x',
      });
      expect(rebuilt).toBe(1);
      expect(r.status).toBe('healed');
    });

    it('reports failed with remediation when the rebuild does not fix it', async () => {
      const r = await ensureNativeBinding({
        verify: () => ({ ok: false, error: 'Could not locate the bindings file' }),
        rebuild: async () => ({ ok: false, output: 'gyp ERR! python not found' }),
        installDir: () => '/opt/install/shieldcortex',
      });
      expect(r.status).toBe('failed');
      expect(r.remediation).toContain('/opt/install/shieldcortex');
      expect(r.remediation).toContain('npm run build-release');
    });

    it('escalates to a forced source build when a plain rebuild reports success but does not heal, and surfaces the real build error', async () => {
      const fromSourceFlags: boolean[] = [];
      const r = await ensureNativeBinding({
        verify: () => ({ ok: false, error: 'Could not locate the bindings file' }),
        rebuild: async (_dir, opts) => {
          fromSourceFlags.push(opts?.fromSource === true);
          // The clawdbot1 trap: a plain rebuild reports success while the binary
          // never built; the forced source build then reveals the real error.
          return opts?.fromSource
            ? { ok: false, output: 'gyp ERR! stack Error: not found: make\ng++: command not found' }
            : { ok: false, output: 'rebuilt dependencies successfully' };
        },
        installDir: () => '/opt/install/shieldcortex',
      });
      // Plain rebuild first, then a forced source build.
      expect(fromSourceFlags).toEqual([false, true]);
      expect(r.status).toBe('failed');
      // The failed result carries the REAL compiler error, not the misleading
      // "rebuilt dependencies successfully".
      expect(r.rebuildOutput).toContain('command not found');
      expect(r.rebuildOutput).not.toContain('rebuilt dependencies successfully');
      // The toolchain hint is ALWAYS present in the failed remediation — it must
      // not be suppressed just because the (first) rebuild output had no error text.
      expect(/apt|xcode-select|build tools/i.test(r.remediation ?? '')).toBe(true);
    });

    it('heals via the forced source build when the plain rebuild did not (no third attempt)', async () => {
      let verifyCalls = 0;
      let rebuilds = 0;
      const r = await ensureNativeBinding({
        verify: () => ({ ok: ++verifyCalls > 2 }), // fail, fail, then ok after the 2nd rebuild
        rebuild: async () => { rebuilds++; return { ok: false, output: '' }; },
        installDir: () => '/x',
      });
      expect(rebuilds).toBe(2);
      expect(r.status).toBe('healed');
    });
  });
});
