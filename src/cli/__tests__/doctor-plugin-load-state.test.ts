import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { checkOpenClawPluginLoadState, renderPluginLoadVerdict } from '../doctor.js';
import { gatherReconcileInput, reconcilePluginState } from '../../integrations/openclaw-plugin-index.js';

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
    // #226: a fully-registered stanza now also carries the conversation-hook
    // grant. Without it OpenClaw refuses the plugin's llm_input/llm_output
    // registrations, and the load-state check says so rather than green-ticking
    // — that downgrade has its own coverage in
    // doctor-conversation-access-226.test.ts. These fixtures are about LOAD
    // state, so they grant it and keep the two concerns separate.
    JSON.stringify({
      plugins: {
        entries: { [PLUGIN]: { enabled: opts.enabled, hooks: { allowConversationAccess: true } } },
        allow: [PLUGIN],
      },
    }),
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

  it('WARNS when only the install index omits the plugin and live logs are unread', async () => {
    setup({ enabled: true, roster: [{ pluginId: 'brave', enabled: true }], onDisk: '4.47.2', recordVersion: '4.47.2' });
    const r = await checkOpenClawPluginLoadState(home, '4.47.2');
    expect(r.status).toBe('warn');
    // Plain words since the calm-update-screen change: a check that could
    // not run, never a fault.
    expect(r.message).toMatch(/couldn't confirm the gateway loaded the plugin/i);
    expect(r.message).not.toMatch(/UNPROTECTED/);
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

  it('#74 finding 2: WARNS (diagnostic-unavailable), never FAILS "UNPROTECTED", when the SQLite index is UNREADABLE', async () => {
    // Healthy box whose only fault is a broken better-sqlite3 binding / locked DB:
    // enabled + on-disk present, but the index cannot be read. Reporting a security
    // fail-open here would be a false alarm — it must be a warn pointing at repair.
    setup({ enabled: true, roster: [{ pluginId: PLUGIN, enabled: true }], onDisk: '4.47.2', recordVersion: '4.47.2' });
    fs.writeFileSync(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'), 'not a sqlite database at all');
    const r = await checkOpenClawPluginLoadState(home, '4.47.2');
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/couldn't read OpenClaw's plugin list/i);
    expect(r.message).not.toMatch(/UNPROTECTED/);
    expect(r.fix).toMatch(/repair/i);
  });
});

/**
 * #260 round 2 — the migrated (config_machine_state) layout through the real
 * doctor check. A stale index record must not reach the "installed and
 * enabled" pass.
 */
describe('#260 r2 — checkOpenClawPluginLoadState on a migrated index', () => {
  function migrated(
    installPath: string,
    opts: { registered?: boolean; recordVersion?: string; rootDir?: string } = {},
  ): void {
    const oc = path.join(home, '.openclaw');
    fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
    fs.writeFileSync(
      path.join(oc, 'openclaw.json'),
      JSON.stringify({
        plugins: opts.registered === false
          ? { entries: {}, allow: [] }
          : {
              entries: { [PLUGIN]: { enabled: true, hooks: { allowConversationAccess: true } } },
              allow: [PLUGIN],
            },
      }),
    );
    const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
    db.exec('CREATE TABLE config_machine_state (state_key TEXT NOT NULL PRIMARY KEY, value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL)');
    db.prepare("INSERT INTO config_machine_state VALUES ('plugins.installedIndex', ?, 1)").run(
      JSON.stringify({
        revision: 1,
        index: {
          installRecords: { [PLUGIN]: { source: 'npm', version: opts.recordVersion ?? '5.22.1', installPath } },
          plugins: [{ pluginId: PLUGIN, enabled: true, ...(opts.rootDir ? { rootDir: opts.rootDir } : {}) }],
        },
      }),
    );
    db.close();
  }
  /** The same gather + reconcile + render doctor runs, with the live roster injected. */
  const renderWithRoster = (roster: string[] | null) =>
    renderPluginLoadVerdict(
      reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => roster })),
    );
  const pkgDir = (): string => path.join(home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH);

  it('the recorded directory is there: passes', async () => {
    fs.mkdirSync(pkgDir(), { recursive: true });
    fs.writeFileSync(path.join(pkgDir(), 'package.json'), JSON.stringify({ version: '5.22.1' }));
    migrated(pkgDir());
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe('pass');
  });

  // #260 r3: unproven, not uninstalled — a warn that says what was seen, in
  // plain words, and does not borrow the boot-record copy.
  const expectStalePathWarn = (r: { status: string; message: string; fix?: string }): void => {
    expect(r.status).toBe('warn');
    expect(r.message).not.toMatch(/installed and enabled/i);
    expect(r.message).toMatch(/points to a folder that is no longer there/);
    expect(r.message).not.toMatch(/start-up|sqlite|config_machine_state|roster|index/i);
    expect(r.fix ?? '').not.toMatch(/repair/i);
  };

  it('the recorded directory is GONE and nothing else is on disk: WARNS, never "installed and enabled", never a fail', async () => {
    migrated(pkgDir());
    expectStalePathWarn(await checkOpenClawPluginLoadState(home, '5.22.1'));
  });

  it('an EMPTY directory left at the recorded path is not an install: warns, does not pass', async () => {
    fs.mkdirSync(pkgDir(), { recursive: true });
    migrated(pkgDir());
    expectStalePathWarn(await checkOpenClawPluginLoadState(home, '5.22.1'));
  });

  it('a real extension copy with dist/index.js (no root index.js) beside the stale record is not reported uninstalled', async () => {
    migrated(pkgDir());
    const ext = path.join(home, '.openclaw', 'extensions', PLUGIN);
    fs.mkdirSync(path.join(ext, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(ext, 'dist', 'index.js'), '');
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).not.toBe('fail');
    expect(r.status).not.toBe('pass');
  });

  // #260 r4 (Astra r3 BLOCKER 2): a wiped registration behind a stale record
  // was rendered "skipped (realtime plugin not installed)".
  it('no config entry + stale record + a real packaged extension at the roster rootDir: FAILS as not registered, never "skipped … not installed"', async () => {
    const ext = path.join(home, '.openclaw', 'extensions', PLUGIN);
    fs.mkdirSync(path.join(ext, 'dist'), { recursive: true });
    fs.writeFileSync(path.join(ext, 'dist', 'index.js'), '');
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    migrated(pkgDir(), { registered: false, rootDir: ext });
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe('fail');
    expect(r.message).not.toMatch(/skipped|not installed/i);
    expect(reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null })).state)
      .toBe('installed-not-enabled');
  });

  // #260 r4 (Astra r3 BLOCKER 1): a confirmed live absence is not a warning.
  it('an empty recorded directory + a readable live roster that omits the plugin: FAILS (not loaded)', () => {
    fs.mkdirSync(pkgDir(), { recursive: true });
    migrated(pkgDir());
    const r = renderWithRoster(['brave']);
    expect(r.status).toBe('fail');
    expect(r.message).not.toMatch(/points to a folder that is no longer there/);
  });

  // #260 r4 (Astra r3 SHOULD-FIX): the roster proves the load, not a version.
  it('gone directory + live roster names the plugin + stale record 4.0.0: passes roster-confirmed with "version unverified", never v5.22.1', () => {
    migrated(pkgDir(), { recordVersion: '4.0.0' });
    const r = renderWithRoster([PLUGIN]);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/roster-confirmed, version unverified\)/);
    expect(r.message).not.toMatch(/5\.22\.1|4\.0\.0/);
  });

  it('control: directory present + live roster names the plugin: roster-confirmed with the measured version', () => {
    fs.mkdirSync(pkgDir(), { recursive: true });
    fs.writeFileSync(path.join(pkgDir(), 'package.json'), JSON.stringify({ version: '5.22.1' }));
    migrated(pkgDir());
    const r = renderWithRoster([PLUGIN]);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/roster-confirmed, v5\.22\.1\)/);
  });
});
