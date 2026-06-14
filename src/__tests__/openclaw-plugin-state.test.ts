import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  resolveRealtimePluginInstallPath,
  readInstalledRealtimePluginVersion,
  resolveRealtimeProjectDir,
  readRealtimeProjectManifest,
  findEoverrideRiskPins,
  findLatentEoverridePins,
  stripManagedPinsFromManifest,
  isRealtimePluginDisabledInConfig,
} from '../integrations/openclaw-plugin-state.js';

/**
 * Regression (2026-06-09): OpenClaw 2026.6.1 moved authoritative plugin state
 * into a SQLite index and stopped updating the legacy `installs.json` `version`
 * field. After `openclaw plugins install @latest` bumped the realtime plugin to
 * 4.31.0 on disk, `installs.json` still read 4.30.2 — so `shieldcortex doctor`
 * (which read that field) wrongly reported "v4.30.2 installed, v4.31.0
 * available". The fix reads the ACTUAL on-disk package.json version (ground
 * truth — the code OpenClaw loads), not the stale registry field.
 */

const PKG_REL = path.join(
  'node_modules', '@drakon-systems', 'shieldcortex-realtime',
);

function makeHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocstate-'));
}

/** Create an on-disk plugin install at a hashed projects dir, return installPath. */
function writeInstalledPackage(home: string, version: string, hash = 'abc123'): string {
  const installPath = path.join(home, '.openclaw', 'npm', 'projects', `drakon-systems-shieldcortex-realtime-${hash}`, PKG_REL);
  fs.mkdirSync(installPath, { recursive: true });
  fs.writeFileSync(path.join(installPath, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version }));
  return installPath;
}

function writeInstalls(home: string, json: unknown): void {
  const dir = path.join(home, '.openclaw', 'plugins');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'installs.json'), JSON.stringify(json, null, 2));
}

describe('openclaw-plugin-state — on-disk version is ground truth', () => {
  let home: string;
  beforeEach(() => { home = makeHome(); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  it('reads the on-disk package.json version even when installs.json is STALE (the reported bug)', () => {
    const installPath = writeInstalledPackage(home, '4.31.0');
    // installs.json still records the OLD version + the correct installPath.
    writeInstalls(home, { installRecords: { 'shieldcortex-realtime': { version: '4.30.2', installPath } } });
    expect(readInstalledRealtimePluginVersion(home)).toBe('4.31.0');
  });

  it('resolves installPath from installs.json when present', () => {
    const installPath = writeInstalledPackage(home, '4.31.0');
    writeInstalls(home, { installRecords: { 'shieldcortex-realtime': { version: '4.30.2', installPath } } });
    expect(resolveRealtimePluginInstallPath(home)).toBe(installPath);
  });

  it('falls back to scanning the projects dir when installs.json lacks installPath (SQLite-only box)', () => {
    writeInstalledPackage(home, '4.31.0');
    // No installs.json at all — must still find the on-disk install.
    expect(readInstalledRealtimePluginVersion(home)).toBe('4.31.0');
  });

  it('falls back to the installs.json recorded version when no on-disk package resolves', () => {
    writeInstalls(home, { installRecords: { 'shieldcortex-realtime': { version: '4.29.0' } } });
    expect(readInstalledRealtimePluginVersion(home)).toBe('4.29.0');
  });

  it('returns null when nothing is installed or registered', () => {
    expect(resolveRealtimePluginInstallPath(home)).toBeNull();
    expect(readInstalledRealtimePluginVersion(home)).toBeNull();
  });

  it('does not throw on a malformed installs.json (returns null/scan fallback)', () => {
    fs.mkdirSync(path.join(home, '.openclaw', 'plugins'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), '{ not json');
    expect(() => readInstalledRealtimePluginVersion(home)).not.toThrow();
    expect(readInstalledRealtimePluginVersion(home)).toBeNull();
  });
});

// ── EOVERRIDE drift detection (v4.33.0 auto-repair) ─────────────────────────

describe('findEoverrideRiskPins — the EOVERRIDE drift signature', () => {
  it('flags a package pinned in BOTH dependencies and overrides at DIFFERENT versions', () => {
    const risks = findEoverrideRiskPins({
      dependencies: { hono: '4.12.23', zod: '3.25.76' },
      overrides: { hono: '4.12.21', axios: '1.16.0' },
    });
    expect(risks).toEqual([{ name: 'hono', dependencyVersion: '4.12.23', overrideVersion: '4.12.21' }]);
  });

  it('does NOT flag a package present in both at the SAME version (npm accepts that)', () => {
    expect(findEoverrideRiskPins({ dependencies: { hono: '4.12.21' }, overrides: { hono: '4.12.21' } })).toEqual([]);
  });

  it('does NOT flag dependency-only or override-only packages', () => {
    expect(findEoverrideRiskPins({ dependencies: { zod: '3.25.76' }, overrides: { axios: '1.16.0' } })).toEqual([]);
  });

  it('ignores non-string override values (nested override objects are not the trap)', () => {
    expect(findEoverrideRiskPins({ dependencies: { hono: '4.12.23' }, overrides: { hono: { '.': '4.12.21' } } })).toEqual([]);
  });

  it('returns [] for empty / missing / non-object manifests', () => {
    expect(findEoverrideRiskPins({})).toEqual([]);
    expect(findEoverrideRiskPins(null)).toEqual([]);
    expect(findEoverrideRiskPins({ dependencies: {}, overrides: {} })).toEqual([]);
  });
});

// ── LATENT EOVERRIDE detection (v4.33.2) ────────────────────────────────────
//
// The v4.33.0 detector (findEoverrideRiskPins) only catches a CURRENT version
// mismatch. But the field failure on edith (2026-06-14) showed the mismatch is
// born DURING `openclaw plugins install`: OpenClaw refreshes the override from
// its bundled workspace (hono 4.12.18 → 4.12.21) while preserving the stale
// dependency pin (4.12.18) via `nextDependencies[x] = dependencies[x] ?? spec`.
// At REST the manifest looked clean (4.12.18 == 4.12.18), so repair stripped
// nothing and its own reinstall then threw EOVERRIDE. The durable signal is
// CO-PRESENCE (a managed-peer pin that is also an override), regardless of
// whether the versions currently match — those two values are maintained by
// independent mechanisms that WILL drift on the next override bump.

describe('findLatentEoverridePins — co-presence is the latent trap', () => {
  it('flags a package present in BOTH dependencies and overrides even when versions MATCH', () => {
    expect(findLatentEoverridePins({
      dependencies: { hono: '4.12.18', shieldcortex: '4.33.1' },
      overrides: { hono: '4.12.18', axios: '1.16.0' },
    })).toEqual(['hono']);
  });

  it('flags a co-present package that is currently mismatched too', () => {
    expect(findLatentEoverridePins({
      dependencies: { hono: '4.12.18' },
      overrides: { hono: '4.12.21' },
    })).toEqual(['hono']);
  });

  it('does NOT flag dependency-only (e.g. shieldcortex/zod) or override-only packages', () => {
    expect(findLatentEoverridePins({
      dependencies: { shieldcortex: '4.33.1', zod: '3.25.76' },
      overrides: { hono: '4.12.21', axios: '1.16.0' },
    })).toEqual([]);
  });

  it('ignores non-string override values', () => {
    expect(findLatentEoverridePins({ dependencies: { hono: '4.12.18' }, overrides: { hono: { '.': '4.12.18' } } })).toEqual([]);
  });

  it('returns [] for empty / missing / non-object manifests', () => {
    expect(findLatentEoverridePins({})).toEqual([]);
    expect(findLatentEoverridePins(null)).toEqual([]);
  });
});

describe('stripManagedPinsFromManifest — removes latent pins from deps AND managedPeerDependencies', () => {
  it('deletes the named pins from dependencies and from openclaw.managedPeerDependencies', () => {
    const manifest = {
      dependencies: { hono: '4.12.18', shieldcortex: '4.33.1', zod: '3.25.76' },
      overrides: { hono: '4.12.18' },
      openclaw: { managedPeerDependencies: ['ajv', 'express', 'hono', 'shieldcortex', 'zod'] },
    };
    const out = stripManagedPinsFromManifest(manifest, ['hono']);
    expect((out.dependencies as Record<string, unknown>).hono).toBeUndefined();
    expect((out.dependencies as Record<string, unknown>).shieldcortex).toBe('4.33.1'); // untouched
    expect((out.openclaw as { managedPeerDependencies: string[] }).managedPeerDependencies)
      .toEqual(['ajv', 'express', 'shieldcortex', 'zod']);
  });

  it('leaves overrides untouched (OpenClaw owns those; the override must govern)', () => {
    const out = stripManagedPinsFromManifest(
      { dependencies: { hono: '4.12.18' }, overrides: { hono: '4.12.18' }, openclaw: { managedPeerDependencies: ['hono'] } },
      ['hono'],
    );
    expect((out.overrides as Record<string, unknown>).hono).toBe('4.12.18');
  });

  it('is a no-op for names not present, and tolerates a missing openclaw block', () => {
    const out = stripManagedPinsFromManifest({ dependencies: { shieldcortex: '4.33.1' } }, ['hono']);
    expect((out.dependencies as Record<string, unknown>).shieldcortex).toBe('4.33.1');
  });
});

describe('realtime managed-project manifest + disabled-state helpers', () => {
  let home: string;
  beforeEach(() => { home = makeHome(); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  function projectRoot(hash = 'abc123'): string {
    return path.join(home, '.openclaw', 'npm', 'projects', `drakon-systems-shieldcortex-realtime-${hash}`);
  }
  function writeProjectManifest(manifest: unknown, hash = 'abc123'): string {
    const root = projectRoot(hash);
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest, null, 2));
    return root;
  }
  function writeConfig(cfg: unknown): void {
    const dir = path.join(home, '.openclaw');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'openclaw.json'), JSON.stringify(cfg, null, 2));
  }

  it('resolveRealtimeProjectDir returns the project ROOT, not the nested package dir', () => {
    writeInstalledPackage(home, '4.32.8');          // <root>/node_modules/@drakon-systems/shieldcortex-realtime
    const root = writeProjectManifest({ dependencies: { hono: '4.12.23' }, overrides: { hono: '4.12.21' } });
    expect(resolveRealtimeProjectDir(home)).toBe(root);
  });

  it('readRealtimeProjectManifest reads the managed manifest (deps + overrides)', () => {
    writeInstalledPackage(home, '4.32.8');
    writeProjectManifest({ dependencies: { hono: '4.12.23' }, overrides: { hono: '4.12.21' } });
    const m = readRealtimeProjectManifest(home);
    expect(m?.dependencies).toEqual({ hono: '4.12.23' });
    expect(findEoverrideRiskPins(m)).toEqual([{ name: 'hono', dependencyVersion: '4.12.23', overrideVersion: '4.12.21' }]);
  });

  it('readRealtimeProjectManifest returns null when nothing is installed', () => {
    expect(readRealtimeProjectManifest(home)).toBeNull();
    expect(resolveRealtimeProjectDir(home)).toBeNull();
  });

  it('isRealtimePluginDisabledInConfig is true only when enabled===false', () => {
    writeConfig({ plugins: { entries: { 'shieldcortex-realtime': { enabled: false } } } });
    expect(isRealtimePluginDisabledInConfig(home)).toBe(true);
  });

  it('isRealtimePluginDisabledInConfig is false when enabled, absent, or no config', () => {
    expect(isRealtimePluginDisabledInConfig(home)).toBe(false); // no config file
    writeConfig({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true } } } });
    expect(isRealtimePluginDisabledInConfig(home)).toBe(false);
    writeConfig({ plugins: { entries: {} } });
    expect(isRealtimePluginDisabledInConfig(home)).toBe(false);
  });
});
