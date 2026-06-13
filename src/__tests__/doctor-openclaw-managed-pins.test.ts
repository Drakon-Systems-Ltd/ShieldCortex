import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkOpenClawManagedPinDrift } from '../cli/doctor.js';

/**
 * Guards the v4.33.0 detection for OpenClaw's EOVERRIDE trap (openclaw#91772):
 * a managed-peer dependency pin that has drifted to a different version than the
 * imported workspace override for the same package will throw `EOVERRIDE` on the
 * next `openclaw update` and OpenClaw silently disables the plugin. The check
 * surfaces both the pre-failure drift (warn) and the already-disabled state (fail).
 */
describe('doctor — OpenClaw managed-pin drift / disabled realtime plugin', () => {
  let home: string;
  const HASH = 'abc123';

  beforeEach(() => { home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-ocpins-')); });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  function projectRoot(): string {
    return path.join(home, '.openclaw', 'npm', 'projects', `drakon-systems-shieldcortex-realtime-${HASH}`);
  }
  /** Write the generated project manifest + the nested plugin package (so the
   * install resolves) — the shape OpenClaw creates on disk. */
  function install(manifest: Record<string, unknown>): void {
    const root = projectRoot();
    const pkgDir = path.join(root, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '4.32.8' }));
    fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest, null, 2));
  }
  function setEnabled(enabled: boolean): void {
    const dir = path.join(home, '.openclaw');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'openclaw.json'), JSON.stringify({ plugins: { entries: { 'shieldcortex-realtime': { enabled } } } }, null, 2));
  }

  it('skips (info) when ~/.openclaw does not exist', async () => {
    const r = await checkOpenClawManagedPinDrift(path.join(home, 'nope'));
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/skipped/i);
  });

  it('skips (info) when the realtime plugin is not installed', async () => {
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not installed/i);
  });

  it('passes when deps and overrides agree and the plugin is enabled', async () => {
    install({ dependencies: { hono: '4.12.21', shieldcortex: '4.32.8' }, overrides: { hono: '4.12.21' } });
    setEnabled(true);
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('pass');
  });

  it('warns when a managed pin has drifted from its override (pre-failure)', async () => {
    install({ dependencies: { hono: '4.12.23', shieldcortex: '4.32.8' }, overrides: { hono: '4.12.21' } });
    setEnabled(true);
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/EOVERRIDE/);
    expect(r.message).toContain('hono');
    expect(r.fix).toMatch(/shieldcortex openclaw repair/);
  });

  it('fails when the plugin has been auto-disabled', async () => {
    install({ dependencies: { hono: '4.12.23' }, overrides: { hono: '4.12.21' } });
    setEnabled(false);
    const r = await checkOpenClawManagedPinDrift(home);
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/disabled/i);
    expect(r.fix).toMatch(/shieldcortex openclaw repair/);
  });
});
