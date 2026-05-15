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
});
