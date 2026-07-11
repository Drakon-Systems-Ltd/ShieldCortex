import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { checkOpenClawPluginLoadState } from '../doctor.js';

/**
 * Doctor must surface the #74 silent-drop honestly: an `enabled:true` plugin
 * missing from the loaded roster is a FAIL (protection reports ON while OFF),
 * pointing at the reconciler repair. Fully isolated in a temp HOME.
 */
const PLUGIN = 'shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');
let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-load-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function setup(opts: { enabled: boolean; roster: Array<{ pluginId: string; enabled: boolean }>; onDisk: string; recordVersion: string }): void {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  const dirName = 'drakon-systems-shieldcortex-realtime-abc';
  const pkgDir = path.join(oc, 'npm', 'projects', dirName, PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version: opts.onDisk }));
  fs.writeFileSync(
    path.join(oc, 'openclaw.json'),
    JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: opts.enabled } }, allow: [PLUGIN] } }),
  );
  fs.writeFileSync(
    path.join(oc, 'plugins', 'installs.json'),
    JSON.stringify({ installRecords: { [PLUGIN]: { version: opts.recordVersion, installPath: pkgDir } } }),
  );
  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  db.exec(`CREATE TABLE installed_plugin_index (
    index_key TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL,
    host_contract_version TEXT NOT NULL, compat_registry_version TEXT NOT NULL,
    migration_version INTEGER NOT NULL, policy_hash TEXT NOT NULL,
    generated_at_ms INTEGER NOT NULL, refresh_reason TEXT,
    install_records_json TEXT NOT NULL, plugins_json TEXT NOT NULL,
    diagnostics_json TEXT NOT NULL, warning TEXT, updated_at_ms INTEGER NOT NULL);`);
  db.prepare(`INSERT INTO installed_plugin_index VALUES ('k',1,'v','x',1,'h',1,'r',@ir,@pj,'[]',NULL,1)`).run({
    ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: opts.recordVersion, installPath: pkgDir } }),
    pj: JSON.stringify(opts.roster),
  });
  db.close();
}

describe('checkOpenClawPluginLoadState', () => {
  it('skips (info) when OpenClaw is not present', async () => {
    const r = await checkOpenClawPluginLoadState(home, '4.47.2');
    expect(r.status).toBe('info');
  });

  it('FAILS when enabled in config but absent from the loaded roster (#74 silent drop)', async () => {
    setup({ enabled: true, roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2', recordVersion: '4.47.2' });
    const r = await checkOpenClawPluginLoadState(home, '4.47.2');
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/not loaded|roster|unprotected/i);
    expect(r.fix).toMatch(/repair/i);
  });

  it('passes when enabled and present + enabled in the roster', async () => {
    setup({ enabled: true, roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.47.2', recordVersion: '4.47.2' });
    const r = await checkOpenClawPluginLoadState(home, '4.47.2');
    expect(r.status).toBe('pass');
  });

  it('FAILS on a version regression even when loaded', async () => {
    setup({ enabled: true, roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4', recordVersion: '4.25.4' });
    const r = await checkOpenClawPluginLoadState(home, '4.47.2');
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/regress|downgrade|older/i);
  });
});
