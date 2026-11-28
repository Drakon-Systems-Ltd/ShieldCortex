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

/** The npm package layout OpenClaw loads: package.json `main`, the manifest, the entry point. */
function writeRealBuild(dir: string, version: string): void {
  fs.mkdirSync(path.join(dir, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version, main: './dist/index.js' }));
  fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version }));
  fs.writeFileSync(path.join(dir, 'dist', 'index.js'), '');
}

function setup(opts: { enabled: boolean; roster: Array<{ pluginId: string; enabled: boolean }>; onDisk: string; recordVersion: string }): void {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  const dirName = 'drakon-systems-shieldcortex-realtime-abc';
  const pkgDir = path.join(oc, 'npm', 'projects', dirName, PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  // A real npm build (#260 Sol-3: package.json alone is leftover metadata,
  // not an install): manifest naming the plugin + the `main` entry point.
  writeRealBuild(pkgDir, opts.onDisk);
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
          version: 1,
          hostContractVersion: '2026.11.10',
          compatRegistryVersion: 'x',
          migrationVersion: 1,
          policyHash: 'h',
          generatedAtMs: 1,
          diagnostics: [],
          installRecords: { [PLUGIN]: { source: 'npm', version: opts.recordVersion ?? '5.22.1', installPath } },
          // Upstream-shaped (OpenClaw 2026.11.x requires rootDir + enabled):
          // rootDir is the recorded install unless the case names another.
          plugins: [{
            pluginId: PLUGIN,
            manifestPath: path.join(opts.rootDir ?? installPath, 'openclaw.plugin.json'),
            manifestHash: 'h',
            rootDir: opts.rootDir ?? installPath,
            origin: 'global',
            enabled: true,
            startup: { sidecar: false, memory: false, agentHarnesses: [] },
            compat: [],
          }],
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

  it('the recorded directory holds a real build: passes', async () => {
    writeRealBuild(pkgDir(), '5.22.1');
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

  // Sol finding 3: a real npm build in ANOTHER project dir is an install, not
  // proof that OpenClaw selected it. Before: a green "installed and enabled".
  it('stale record + a real build in another project dir, no live proof: WARNS (no pass, no repair advice)', async () => {
    migrated(pkgDir());
    writeRealBuild(path.join(home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-other', PKG_SUBPATH), '5.22.1');
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expectStalePathWarn(r);
  });

  // Sol r2 (r3 change): load proven by the roster; the other project dir's
  // build is not the selected copy, so its version is not printed as measured.
  it('positive control: the same host with the live roster naming the plugin passes roster-confirmed, version unverified', () => {
    migrated(pkgDir());
    writeRealBuild(path.join(home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-other', PKG_SUBPATH), '5.22.1');
    const r = renderWithRoster([PLUGIN]);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/roster-confirmed, version unverified\)/);
    expect(r.message).not.toMatch(/5\.22\.1/);
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

  // #260 r3 (Case r2 #1): the record path is gone and the SELECTED rootDir
  // is a verified build outside every place the disk scan looks. Its own
  // version is measured — a regression still fails — and an unreadable one is
  // "version unverified" in BOTH passes, never the expected v5.22.1.
  const outOfScan = (): string => path.join(home, 'src', 'realtime');
  it.each([
    ['roster unread', null],
    ['roster-proven', [PLUGIN]],
  ] as const)('out-of-scan rootDir at 4.0.0 (%s): FAILS as regressed to v4.0.0', (_l, roster) => {
    writeRealBuild(outOfScan(), '4.0.0');
    migrated(pkgDir(), { recordVersion: '4.0.0', rootDir: outOfScan() });
    const r = renderWithRoster(roster ? [...roster] : null);
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/regressed to v4\.0\.0 \(older than expected v5\.22\.1\)/);
  });

  it.each([
    ['roster unread', '5.22.1', null, /installed and enabled \(v5\.22\.1\)/],
    ['roster-proven', '5.22.1', [PLUGIN], /roster-confirmed, v5\.22\.1\)/],
    ['roster unread', '5.23.0', null, /installed and enabled \(v5\.23\.0\)/],
    ['roster-proven', '5.23.0', [PLUGIN], /roster-confirmed, v5\.23\.0\)/],
  ] as const)('out-of-scan rootDir (%s) at v%s: passes with the MEASURED version', (_l, version, roster, expected) => {
    writeRealBuild(outOfScan(), version);
    migrated(pkgDir(), { recordVersion: '4.0.0', rootDir: outOfScan() });
    const r = renderWithRoster(roster ? [...roster] : null);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(expected);
  });

  // jarvis r3: was `pass` "(version unverified)" at 2e119972. A version check
  // that cannot measure never passes: warn, still never v5.22.1.
  it.each([
    ['roster unread', null, /version unverified\) — and the running gateway's start-up list could not be read/],
    ['roster-proven', [PLUGIN], /version unverified\) — the running gateway loaded it/],
  ] as const)('out-of-scan rootDir whose version cannot be read (%s): WARNS "version unverified", never passes, never v5.22.1', (_l, roster, expected) => {
    writeRealBuild(outOfScan(), '5.22.1');
    fs.writeFileSync(path.join(outOfScan(), 'package.json'), '{ not json');
    migrated(pkgDir(), { recordVersion: '5.22.1', rootDir: outOfScan() });
    const r = renderWithRoster(roster ? [...roster] : null);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(expected);
    expect(r.message).not.toMatch(/5\.22\.1/);
  });

  // jarvis r3 rows a/b through the real doctor check (roster unread: the temp
  // HOME has no gateway log), and row d as the warn.
  it.each([
    ['a. corrupt package.json, record 4.0.0 (path gone)', (): void => fs.writeFileSync(path.join(outOfScan(), 'package.json'), '{ not json'), '4.0.0', 'fail'],
    ['b. no version anywhere, record 4.0.0 (path gone)', (): void => {
      fs.writeFileSync(path.join(outOfScan(), 'package.json'), JSON.stringify({ main: './dist/index.js' }));
      fs.writeFileSync(path.join(outOfScan(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN }));
    }, '4.0.0', 'fail'],
    ['d. corrupt package.json, record at expected', (): void => fs.writeFileSync(path.join(outOfScan(), 'package.json'), '{ not json'), '5.22.1', 'warn'],
  ] as const)('checkOpenClawPluginLoadState, verified rootDir with an unreadable version — %s: %s, never pass', async (_l, damage, recordVersion, status) => {
    writeRealBuild(outOfScan(), '5.22.1');
    damage();
    migrated(pkgDir(), { recordVersion, rootDir: outOfScan() });
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe(status);
    if (status === 'fail') {
      expect(r.message).toMatch(/regressed to v4\.0\.0 \(older than expected v5\.22\.1\).*the copy OpenClaw uses has no readable version/);
    } else {
      expect(r.message).toMatch(/version unverified/);
      expect(r.message).not.toMatch(/v5\.22\.1/);
    }
  });

  it('renderer: a hand-built healthy verdict with no measured version never prints the expected version', () => {
    const r = renderPluginLoadVerdict({
      ...reconcilePluginState(gatherReconcileInput(home, { expectedVersion: '5.22.1', readLiveRoster: () => null })),
      state: 'healthy', severity: 'ok', recommendedAction: 'none', onDiskVersion: null, indexVersion: null,
      installedVersion: undefined, versionUnverified: undefined, loadedInLiveRoster: null,
    });
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/version unverified/);
    expect(r.message).not.toMatch(/5\.22\.1/);
  });

  it('control: directory present + live roster names the plugin: roster-confirmed with the measured version', () => {
    writeRealBuild(pkgDir(), '5.22.1');
    migrated(pkgDir());
    const r = renderWithRoster([PLUGIN]);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/roster-confirmed, v5\.22\.1\)/);
  });
});

/**
 * #260 Sol finding 4 through the real doctor check: an index that is there
 * but unreadable, with NO on-disk copy, warns without an install
 * recommendation; a confirmed absence still FAILS with one.
 */
describe('#260 Sol-4 — doctor on a present-but-unreadable index with no copy on disk', () => {
  const enabledConfig = (): void => {
    const oc = path.join(home, '.openclaw');
    fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
    fs.writeFileSync(path.join(oc, 'openclaw.json'), JSON.stringify({
      plugins: { entries: { [PLUGIN]: { enabled: true, hooks: { allowConversationAccess: true } } }, allow: [PLUGIN] },
    }));
  };
  const machineStateDb = (valueJson: string | null): void => {
    const db = new Database(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'));
    db.exec('CREATE TABLE config_machine_state (state_key TEXT NOT NULL PRIMARY KEY, value_json TEXT NOT NULL, updated_at_ms INTEGER NOT NULL)');
    if (valueJson !== null) db.prepare("INSERT INTO config_machine_state VALUES ('plugins.installedIndex', ?, 1)").run(valueJson);
    db.close();
  };

  it.each([
    ['malformed JSON', '{"revision": 1, "index": {'],
    ['no numeric revision', JSON.stringify({ index: { installRecords: {}, plugins: [] } })],
  ])('index row with %s: WARNS, no install command, no repair advice', async (_label, valueJson) => {
    enabledConfig();
    machineStateDb(valueJson);
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/couldn't read OpenClaw's plugin list/i);
    expect(`${r.message} ${r.fix ?? ''}`).not.toMatch(/Install the plugin|plugins install|no package is installed/i);
    expect(r.fix ?? '').toMatch(/Do not run repair from this warning/);
  });

  it('confirmed-absence control: a readable migrated DB with no index row + no copy FAILS with the install fix', async () => {
    enabledConfig();
    machineStateDb(null);
    const r = await checkOpenClawPluginLoadState(home, '5.22.1');
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/no package is installed/);
    expect(r.fix ?? '').toMatch(/Install the plugin/);
  });

  it('a hand-built enabled-not-installed verdict carrying indexUnreadable renders the warn, not the install advice', () => {
    const verdict = reconcilePluginState({
      pluginId: PLUGIN, expectedVersion: '5.22.1', config: { enabled: true, inAllow: true }, installsJson: null, index: null, onDiskVersion: null,
    });
    expect(renderPluginLoadVerdict(verdict).status).toBe('fail');
    const r = renderPluginLoadVerdict({ ...verdict, indexUnreadable: true });
    expect(r.status).toBe('warn');
    expect(r.fix ?? '').not.toMatch(/Install the plugin/);
  });
});
