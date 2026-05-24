import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkOpenClawPluginPackage } from '../cli/doctor.js';

/**
 * Regression guard for the OpenClaw gateway crash-loop incident (Jarvis,
 * 2026-05-15). A stale/bare `shieldcortex` package landed in OpenClaw's
 * plugin node_modules (where only `@drakon-systems/shieldcortex-realtime`
 * belongs) and the gateway restart-looped. The fleet had no way to
 * self-detect this — the user had to SSH in and diagnose by hand.
 *
 * This check makes `shieldcortex doctor` surface the state directly. It
 * keys on the *confirmed-anomalous* condition (bare main package present,
 * extension entry missing) — NOT on a guess about the exact crash
 * exception, which remains under investigation pending the gateway log.
 */
describe('doctor — OpenClaw plugin package placement', () => {
  let npmDir: string;

  beforeEach(() => {
    npmDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocplugin-'));
  });

  afterEach(() => {
    fs.rmSync(npmDir, { recursive: true, force: true });
  });

  function writePkg(rel: string, pkg: object): string {
    const dir = path.join(npmDir, rel);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg), 'utf-8');
    return dir;
  }

  it('skips when the OpenClaw npm dir does not exist', async () => {
    const r = await checkOpenClawPluginPackage(path.join(npmDir, 'nope'));
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/skipped/i);
  });

  it('passes on a healthy install (only @drakon-systems/shieldcortex-realtime present)', async () => {
    writePkg('@drakon-systems/shieldcortex-realtime', {
      name: '@drakon-systems/shieldcortex-realtime',
      version: '4.18.1',
    });
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('pass');
  });

  it('FAILs when a bare shieldcortex is present with a missing extension entry (the crash-loop state)', async () => {
    writePkg('shieldcortex', {
      name: 'shieldcortex',
      version: '4.13.1',
      openclaw: { extensions: ['./plugins/openclaw/dist/index.js'] },
    });
    // Note: plugins/openclaw/dist/index.js intentionally NOT created → stale/unbuilt.
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/shieldcortex/i);
    expect(r.fix).toMatch(/@drakon-systems\/shieldcortex-realtime|remove/i);
  });

  it('WARNs when a bare shieldcortex is present but its extension entry exists', async () => {
    const pkgDir = writePkg('shieldcortex', {
      name: 'shieldcortex',
      version: '4.18.1',
      openclaw: { extensions: ['./plugins/openclaw/dist/index.js'] },
    });
    const ext = path.join(pkgDir, 'plugins', 'openclaw', 'dist');
    fs.mkdirSync(ext, { recursive: true });
    fs.writeFileSync(path.join(ext, 'index.js'), '// stub', 'utf-8');
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/not the supported|misplaced|@drakon-systems/i);
  });

  it('WARNs when the bare shieldcortex package.json is unparseable', async () => {
    const dir = path.join(npmDir, 'shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), '{ not json', 'utf-8');
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
  });

  // ── v4.21.2 visibility-first contract ──────────────────────────────
  // OpenClaw discovers bare packages via TWO independent vectors:
  // (1) `openclaw.extensions` in package.json (closed in v4.20.0)
  // (2) Root `openclaw.plugin.json` file (closed in v4.21.1)
  //
  // A v4.21.1+ bare has neither — fully invisible to OpenClaw discovery,
  // duplicate-plugin-id warning cannot fire. INFO.
  //
  // If EITHER vector is present, OpenClaw will register the bare under
  // `pluginId: shieldcortex-realtime` (colliding with the dedicated plugin)
  // and emit `duplicate plugin id detected` on every session. Version
  // alignment does NOT help — both copies share the same pluginId. WARN.

  function writeBare(version: string): string {
    const pkgDir = writePkg('shieldcortex', {
      name: 'shieldcortex',
      version,
      openclaw: { extensions: ['./plugins/openclaw/dist/index.js'] },
    });
    const ext = path.join(pkgDir, 'plugins', 'openclaw', 'dist');
    fs.mkdirSync(ext, { recursive: true });
    fs.writeFileSync(path.join(ext, 'index.js'), '// stub', 'utf-8');
    return pkgDir;
  }

  function writeBareNoVectors(version: string): string {
    // v4.21.1+ shape: package.json has NO `openclaw.extensions` field, NO
    // root `openclaw.plugin.json`. Fully invisible to OpenClaw discovery.
    return writePkg('shieldcortex', {
      name: 'shieldcortex',
      version,
      // intentionally no openclaw.extensions
    });
  }

  function writeRealtime(version: string, peerRange: string = '^' + version): void {
    writePkg('@drakon-systems/shieldcortex-realtime', {
      name: '@drakon-systems/shieldcortex-realtime',
      version,
      peerDependencies: { shieldcortex: peerRange },
    });
  }

  function writeRootManifest(pkgDir: string): void {
    fs.writeFileSync(
      path.join(pkgDir, 'openclaw.plugin.json'),
      JSON.stringify({ name: 'shieldcortex-realtime', version: '1' }),
      'utf-8',
    );
  }

  it('INFOs when bare has neither discovery vector (v4.21.1+ steady state)', async () => {
    writeBareNoVectors('4.21.1');
    writeRealtime('4.21.1', '>=4.18.3 <5.0.0');
    // intentionally NO root manifest — v4.21.1+ ships without one
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/invisible to OpenClaw discovery/);
    expect(r.message).toContain('4.21.1');
    expect(r.fix).toBeUndefined();
  });

  it('INFOs when bare has no vectors and realtime sibling is absent (harmless leftover)', async () => {
    writeBareNoVectors('4.21.1');
    // no realtime — but bare can't be discovered, so it's still harmless
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/invisible to OpenClaw discovery/);
    expect(r.message).toMatch(/harmless leftover|safe to remove/);
  });

  it('INFOs (with note) when bare has no vectors but peer range is not satisfied', async () => {
    writeBareNoVectors('4.17.0');
    writeRealtime('4.21.1', '>=4.18.3 <5.0.0');
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/invisible to OpenClaw discovery/);
    expect(r.message).toMatch(/does not satisfy/);
    expect(r.message).toContain('4.17.0');
  });

  it('WARNs when bare carries both legacy discovery vectors (pre-v4.20.0 shape)', async () => {
    const barePkgDir = writeBare('4.19.0');
    writeRealtime('4.21.1', '>=4.18.3 <5.0.0');
    writeRootManifest(barePkgDir);
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/discoverable by OpenClaw/);
    expect(r.message).toMatch(/openclaw\.extensions/);
    expect(r.message).toMatch(/root .*openclaw\.plugin\.json/);
    expect(r.message).toMatch(/duplicate plugin id/);
    expect(r.fix).toMatch(/v4\.21\.1 or later/);
    expect(r.fix).toMatch(/npm install shieldcortex@latest/);
  });

  it('WARNs when bare has only the root-manifest vector (v4.20.0..v4.21.0 shape)', async () => {
    const barePkgDir = writeBareNoVectors('4.20.0');
    writeRealtime('4.21.1', '>=4.18.3 <5.0.0');
    writeRootManifest(barePkgDir);
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/discoverable by OpenClaw/);
    expect(r.message).toMatch(/root .*openclaw\.plugin\.json/);
    // extensions vector NOT in the message — only the manifest one
    expect(r.message).not.toMatch(/openclaw\.extensions.*declared/);
  });

  it('WARNs when bare has only the extensions vector (modified package, edge case)', async () => {
    const barePkgDir = writeBare('4.19.0');
    writeRealtime('4.21.1', '>=4.18.3 <5.0.0');
    // intentionally no root manifest
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/discoverable by OpenClaw/);
    expect(r.message).toMatch(/openclaw\.extensions/);
    expect(r.message).not.toMatch(/root .*openclaw\.plugin\.json/);
    expect(barePkgDir).toBeTruthy();
  });

  it('WARNs when bare is discoverable and the realtime sibling is absent (the misplaced-bare case)', async () => {
    const barePkgDir = writeBare('4.19.0');
    writeRootManifest(barePkgDir);
    // no realtime
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/active discovery vector/);
    expect(r.message).toMatch(/@drakon-systems\/shieldcortex-realtime/);
    expect(r.fix).toMatch(/Remove/);
  });

  it('reports peer-range satisfaction in the WARN message when applicable', async () => {
    const barePkgDir = writeBare('4.18.3');
    writeRealtime('4.21.1', '>=4.18.3 <5.0.0');
    writeRootManifest(barePkgDir);
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/peer range.*satisfied/);
  });

  it('reports peer-range NOT-satisfied in the WARN message when out-of-range', async () => {
    const barePkgDir = writeBare('4.17.0');
    writeRealtime('4.21.1', '>=4.18.3 <5.0.0');
    writeRootManifest(barePkgDir);
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/peer range.*NOT satisfied/);
  });
});
