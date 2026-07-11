import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { reconcileOpenClawPluginState } from '../setup/openclaw-reconcile.js';
import type { SelfCheckRunResult } from '../setup/openclaw-selfcheck.js';

/**
 * The reconciler orchestrator: gather → classify → plan → (execute behind
 * guards) → honest-state self-check. Tested end-to-end with an INJECTED openclaw
 * executor + self-check so nothing touches a live gateway (#74 zeroth law).
 */
const PLUGIN = 'shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');
let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-orch-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function setup(opts: { roster: Array<{ pluginId: string; enabled: boolean }>; onDisk: string }): void {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  const pkgDir = path.join(oc, 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version: opts.onDisk }));
  fs.writeFileSync(path.join(oc, 'openclaw.json'), JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } }, allow: [PLUGIN] } }));
  fs.writeFileSync(path.join(oc, 'plugins', 'installs.json'), JSON.stringify({ installRecords: { [PLUGIN]: { version: opts.onDisk, installPath: pkgDir } } }));
  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  db.exec(`CREATE TABLE installed_plugin_index (index_key TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL, host_contract_version TEXT NOT NULL, compat_registry_version TEXT NOT NULL, migration_version INTEGER NOT NULL, policy_hash TEXT NOT NULL, generated_at_ms INTEGER NOT NULL, refresh_reason TEXT, install_records_json TEXT NOT NULL, plugins_json TEXT NOT NULL, diagnostics_json TEXT NOT NULL, warning TEXT, updated_at_ms INTEGER NOT NULL);`);
  db.prepare(`INSERT INTO installed_plugin_index VALUES ('k',1,'v','x',1,'h',1,'r',@ir,@pj,'[]',NULL,1)`).run({
    ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: opts.onDisk, installPath: pkgDir } }),
    pj: JSON.stringify(opts.roster),
  });
  db.close();
}

const passingSelfCheck: SelfCheckRunResult = {
  ok: true, rosterProof: true, canaryProof: true, reasons: ['ok'],
  index: null, canary: { ran: true, denied: true, auditEntryFound: true },
};

describe('reconcileOpenClawPluginState', () => {
  it('dry-run (apply:false) computes verdict + plan without executing any command', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2' });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: false,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      selfCheck: async () => passingSelfCheck,
    });
    expect(res.verdict.state).toBe('enabled-not-loaded');
    expect(res.plan.some((s) => s.kind === 'openclaw-update')).toBe(true);
    expect(res.applied).toBe(false);
    expect(calls).toHaveLength ? expect(calls.length).toBe(0) : expect(calls.length).toBe(0);
  });

  it('apply: executes the silent-drop remediation via `plugins update`, then self-checks', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2' });
    const calls: string[][] = [];
    let reloaded = false;
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => { reloaded = true; return { restarted: true }; },
      selfCheck: async () => passingSelfCheck,
    });
    expect(calls).toContainEqual(['plugins', 'update', '@drakon-systems/shieldcortex-realtime']);
    expect(reloaded).toBe(true);
    expect(res.applied).toBe(true);
    expect(res.ok).toBe(true);
    expect(res.selfCheck?.ok).toBe(true);
  });

  it('HARD FAILS when the self-check does not pass after remediation', async () => {
    setup({ roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2' });
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: () => ({ status: 0, output: '' }),
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => ({ ...passingSelfCheck, ok: false, canaryProof: false, reasons: ['canary not run'] }),
    });
    expect(res.ok).toBe(false);
    expect(res.messages.join(' ')).toMatch(/self-check|not.*(load|enforc|confirm)/i);
  });

  it('version regression executes a PINNED reinstall, never @latest', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.25.4' });
    const calls: string[][] = [];
    await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    const install = calls.find((a) => a.includes('install'));
    expect(install).toEqual(['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@4.47.2']);
    expect(install!.join(' ')).not.toMatch(/@latest/);
  });

  it('healthy state runs only the self-check, executes no openclaw command', async () => {
    setup({ roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.47.2' });
    const calls: string[][] = [];
    const res = await reconcileOpenClawPluginState({
      home, expectedVersion: '4.47.2', apply: true,
      runCommand: (argv) => { calls.push(argv); return { status: 0, output: '' }; },
      reloadGateway: async () => ({ restarted: true }),
      selfCheck: async () => passingSelfCheck,
    });
    expect(res.verdict.state).toBe('healthy');
    expect(calls.length).toBe(0);
    expect(res.ok).toBe(true);
  });
});

describe('reconcile executor — gateway-safety guard', () => {
  it('the default openclaw executor is guarded by a consent env before spawning', () => {
    const thisFile = fileURLToPath(import.meta.url);
    const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw-reconcile.ts'), 'utf-8');
    expect(src).toMatch(/JEST_WORKER_ID/);
    expect(src).toMatch(/SHIELDCORTEX_ALLOW_GATEWAY_(RESTART|CANARY|RECONCILE)/);
  });
});
