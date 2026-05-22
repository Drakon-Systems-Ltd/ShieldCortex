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

  // ── Expected peer-dep state — INFO, not WARN ───────────────────────
  // Since v4.18.3 the bare `shieldcortex` is the *expected* steady state of
  // a healthy install: OpenClaw resolves `@drakon-systems/shieldcortex-realtime`'s
  // `peerDependencies.shieldcortex` by installing the main package alongside.
  // The 4.18.3 root-manifest fix made this safe. The doctor's WARN here was
  // conservative noise that drowned in operator inboxes — fleet-wide healthy
  // installs report WARN despite being functionally correct.
  //
  // Recognise the expected state and downgrade to INFO; keep WARN/FAIL for
  // actual anomalies (missing peer sibling, missing root manifest, version
  // mismatch — all genuine surprises that justify operator attention).

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

  function writeRealtime(version: string): void {
    writePkg('@drakon-systems/shieldcortex-realtime', {
      name: '@drakon-systems/shieldcortex-realtime',
      version,
    });
  }

  function writeRootManifest(pkgDir: string): void {
    fs.writeFileSync(
      path.join(pkgDir, 'openclaw.plugin.json'),
      JSON.stringify({ name: 'shieldcortex-realtime', version: '1' }),
      'utf-8',
    );
  }

  it('INFOs when bare version matches realtime peer and root manifest is present (the expected post-4.18.3 state)', async () => {
    const barePkgDir = writeBare('4.19.0');
    writeRealtime('4.19.0');
    writeRootManifest(barePkgDir);
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/peer/i);
    expect(r.message).toMatch(/@drakon-systems\/shieldcortex-realtime/);
    expect(r.message).toContain('4.19.0');
    expect(r.fix).toBeUndefined();
  });

  it('still WARNs when bare and realtime versions disagree (genuine surprise)', async () => {
    const barePkgDir = writeBare('4.18.3');
    writeRealtime('4.19.0');
    writeRootManifest(barePkgDir);
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/mismatch|not the supported|misplaced/i);
  });

  it('still WARNs when the realtime peer is absent (bare is genuinely misplaced)', async () => {
    const barePkgDir = writeBare('4.19.0');
    // no realtime sibling
    writeRootManifest(barePkgDir);
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
  });

  it('still WARNs when root openclaw.plugin.json is missing (the 4.18.3 architecture is not in place)', async () => {
    writeBare('4.19.0');
    writeRealtime('4.19.0');
    // no root openclaw.plugin.json — without it the auto-discovery path is unsafe
    const r = await checkOpenClawPluginPackage(npmDir);
    expect(r.status).toBe('warn');
  });
});
