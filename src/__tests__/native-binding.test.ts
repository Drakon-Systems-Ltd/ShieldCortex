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

  describe('nativeBindingRemediation', () => {
    it('includes the install-dir cd, the rebuild command, and a toolchain hint', () => {
      const text = nativeBindingRemediation('/opt/install/shieldcortex');
      expect(text).toContain('/opt/install/shieldcortex');
      expect(text).toContain('npm rebuild better-sqlite3');
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
      expect(r.remediation).toContain('npm rebuild better-sqlite3');
    });
  });
});
