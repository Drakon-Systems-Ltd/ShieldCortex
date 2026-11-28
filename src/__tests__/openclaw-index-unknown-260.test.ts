/**
 * #260 r15 (Jarvis 3): an install index that is present but cannot be read is
 * UNKNOWN evidence — never "no index", never "agrees".
 *
 * Sonnet's fixture: the record says v4.0.0 and disagrees with installs.json,
 * the current build is on disk and the running gateway proved the load. The
 * previous release read that row and warned (`conflicted-metadata`). Since one
 * bad entry makes the whole index unreadable — (i) a corrupt plugins list, or
 * (ii) a foreign plugin's record with a NUMBER for a version — the verdict
 * saw no index, so nothing disagreed, and it reported `healthy` / ok.
 *
 * Now: warn, no action, no install and no prune planned — in both index
 * layouts — and a fully readable, consistent index still reports healthy.
 * Everything runs in a temp HOME; nothing can launch a process.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { expectNoLaunch, installLaunchTripwire, isolateHostEnv } from './support/openclaw-host-isolation.js';

const tripwire = installLaunchTripwire();
const { gatherReconcileInput, planReconcileActions, reconcilePluginState } = await import('../integrations/openclaw-plugin-index.js');
const { checkOpenClawPluginLoadState, renderPluginLoadVerdict } = await import('../cli/doctor.js');

const PLUGIN = 'shieldcortex-realtime';
const PKG = '@drakon-systems/shieldcortex-realtime';
const EXPECTED = '5.22.1';

let home: string;
let restoreEnv: () => void;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-260-unknown-index-'));
  restoreEnv = isolateHostEnv(home);
  tripwire.reset();
});
afterEach(() => {
  try {
    expectNoLaunch(tripwire);
  } finally {
    restoreEnv();
    fs.rmSync(home, { recursive: true, force: true });
  }
});

type Fault = 'corrupt-plugins-list' | 'numeric-foreign-version' | 'none';

/** A real build at EXPECTED in a managed project; returns the plugin dir. */
function build(project: string): string {
  const dir = path.join(home, '.openclaw', 'npm', 'projects', project, 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
  fs.mkdirSync(path.join(dir, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version: EXPECTED, main: './dist/index.js' }));
  fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: EXPECTED }));
  fs.writeFileSync(path.join(dir, 'dist', 'index.js'), '');
  return dir;
}

function fixture(layout: 'legacy' | 'new', fault: Fault, recordVersion: string, extraProject = false): void {
  const oc = path.join(home, '.openclaw');
  const dir = build('drakon-systems-shieldcortex-realtime-aaa');
  if (extraProject) build('drakon-systems-shieldcortex-realtime-bbb');
  fs.writeFileSync(path.join(oc, 'openclaw.json'), JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } }, allow: [PLUGIN] } }));
  fs.mkdirSync(path.join(oc, 'plugins'), { recursive: true });
  fs.writeFileSync(path.join(oc, 'plugins', 'installs.json'), JSON.stringify({ installRecords: { [PLUGIN]: { version: EXPECTED, installPath: dir } } }));
  const records: Record<string, unknown> = { [PLUGIN]: { source: 'npm', version: recordVersion, installPath: dir } };
  if (fault === 'numeric-foreign-version') records['other-plugin'] = { source: 'npm', version: 1, installPath: path.join(home, 'elsewhere') };
  const plugins = [{ pluginId: PLUGIN, enabled: true, rootDir: dir }];
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  try {
    if (layout === 'legacy') {
      db.prepare('CREATE TABLE installed_plugin_index (index_key TEXT PRIMARY KEY, generated_at_ms INTEGER, install_records_json TEXT, plugins_json TEXT, warning TEXT)').run();
      db.prepare('INSERT INTO installed_plugin_index VALUES (?, 1, ?, ?, NULL)')
        .run('installed-plugin-index', JSON.stringify(records), fault === 'corrupt-plugins-list' ? '{not json' : JSON.stringify(plugins));
    } else {
      db.prepare('CREATE TABLE config_machine_state (state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)').run();
      const value = fault === 'corrupt-plugins-list'
        ? `{"revision":1,"index":{"generatedAtMs":1,"installRecords":${JSON.stringify(records)},"plugins":{not json}}}`
        : JSON.stringify({ revision: 1, index: { generatedAtMs: 1, installRecords: records, plugins } });
      db.prepare('INSERT INTO config_machine_state VALUES (?, ?, 1)').run('plugins.installedIndex', value);
    }
  } finally {
    db.close();
  }
}

/** Gather with the running gateway's roster proving the load. */
function judge() {
  const input = gatherReconcileInput(home, { expectedVersion: EXPECTED, readLiveRoster: () => [PLUGIN] });
  const verdict = reconcilePluginState(input);
  const plan = planReconcileActions(verdict, { pluginId: PLUGIN, packageName: PKG, expectedVersion: EXPECTED }).map((s) => s.kind);
  return { input, verdict, plan, doctor: renderPluginLoadVerdict(verdict) };
}

describe.each(['legacy', 'new'] as const)('#260 r15: an unreadable index never ends in healthy (%s layout)', (layout) => {
  it.each(['corrupt-plugins-list', 'numeric-foreign-version'] as const)(
    'Sonnet fixture (%s): record v4.0.0 vs installs.json, current build on disk, roster proven — warn like main, no replacement or prune planned',
    (fault) => {
      fixture(layout, fault, '4.0.0');

      const { input, verdict, plan, doctor } = judge();

      expect(input.indexUnreadable).toBe(true);
      // The previous release's class for this input: warn (conflicted-metadata). Never ok.
      expect(verdict.state).not.toBe('healthy');
      expect(verdict.severity).toBe('warn');
      expect(verdict.state).toBe('index-unreadable');
      expect(verdict.recommendedAction).toBe('none');
      expect(plan).toEqual(['self-check']);
      expect(doctor.status).toBe('warn');
      expect(doctor.fix ?? '').not.toMatch(/shieldcortex (openclaw )?repair/);
    },
  );

  it('an unreadable index beside two project dirs plans no prune (would be duplicate-install on a readable one)', () => {
    fixture(layout, 'numeric-foreign-version', EXPECTED, true);

    const { verdict, plan } = judge();

    expect(verdict.state).toBe('index-unreadable');
    expect(plan).toEqual(['self-check']);
  });

  it('control: a fully readable, consistent index still reports healthy', () => {
    fixture(layout, 'none', EXPECTED);

    const { input, verdict, plan, doctor } = judge();

    expect(input.indexUnreadable).toBe(false);
    expect(verdict.state).toBe('healthy');
    expect(verdict.severity).toBe('ok');
    expect(plan).toEqual(['self-check']);
    expect(doctor.status).toBe('pass');
  });

  it('control: the same readable index whose record says v4.0.0 still warns as conflicted-metadata', () => {
    fixture(layout, 'none', '4.0.0');

    const { verdict } = judge();

    expect(verdict.state).toBe('conflicted-metadata');
    expect(verdict.severity).toBe('warn');
  });
});

/**
 * #1179 (item 2): the same unreadable index, but NO build anywhere ShieldCortex
 * looks and a config that does not enable the plugin. Rule 1 used to call that
 * `not-installed` / ok — doctor's "skipped (realtime plugin not installed)" —
 * an absence read off a record nobody read. Synthetic evidence only: a temp
 * HOME holding an openclaw.json (or none) and a state DB whose index row does
 * not parse. Doctor's own check runs; the tripwire proves it launched nothing.
 */
describe.each(['legacy', 'new'] as const)('#1179: unreadable index, no build, config not enabling (%s layout)', (layout) => {
  const oc = (): string => path.join(home, '.openclaw');
  /** Only openclaw.json (or none) and, unless `index` is false, an index row that does not parse. */
  function hostWithout(config: unknown, index: boolean): void {
    fs.mkdirSync(oc(), { recursive: true });
    if (config !== undefined) fs.writeFileSync(path.join(oc(), 'openclaw.json'), JSON.stringify(config));
    if (!index) return;
    fs.mkdirSync(path.join(oc(), 'state'), { recursive: true });
    const db = new Database(path.join(oc(), 'state', 'openclaw.sqlite'));
    try {
      if (layout === 'legacy') {
        db.prepare('CREATE TABLE installed_plugin_index (index_key TEXT PRIMARY KEY, generated_at_ms INTEGER, install_records_json TEXT, plugins_json TEXT, warning TEXT)').run();
        db.prepare('INSERT INTO installed_plugin_index VALUES (?, 1, ?, ?, NULL)').run('installed-plugin-index', '{}', '{not json');
      } else {
        db.prepare('CREATE TABLE config_machine_state (state_key TEXT PRIMARY KEY, value_json TEXT, updated_at_ms INTEGER)').run();
        db.prepare('INSERT INTO config_machine_state VALUES (?, ?, 1)').run('plugins.installedIndex', '{"revision":1,"index":{not json}}');
      }
    } finally {
      db.close();
    }
  }
  const unread = () => gatherReconcileInput(home, { expectedVersion: EXPECTED, readLiveRoster: () => null });

  it.each([
    ['no stanza', { plugins: { allow: [], entries: {} } }],
    ['an explicit enabled:false', { plugins: { entries: { [PLUGIN]: { enabled: false } } } }],
    ['no openclaw.json', undefined],
  ] as const)('%s ⇒ index-unreadable / warn, and doctor WARNS — never "skipped (not installed)"', async (_label, config) => {
    hostWithout(config, true);

    const input = unread();
    const verdict = reconcilePluginState(input);
    const doctor = await checkOpenClawPluginLoadState(home, EXPECTED);

    expect(input).toMatchObject({ indexUnreadable: true, index: null, installsJson: null, onDiskVersion: null });
    expect(verdict).toMatchObject({ state: 'index-unreadable', severity: 'warn', recommendedAction: 'none', enabledInConfig: false });
    expect(planReconcileActions(verdict, { pluginId: PLUGIN, packageName: PKG, expectedVersion: EXPECTED }).map((s) => s.kind)).toEqual(['self-check']);
    expect(doctor.status).toBe('warn');
    expect(doctor.message).not.toMatch(/not installed/);
    expect(doctor.fix ?? '').not.toMatch(/plugins install/);
  });

  it.each([
    ['no stanza', { plugins: { allow: [], entries: {} } }],
    ['an explicit enabled:false', { plugins: { entries: { [PLUGIN]: { enabled: false } } } }],
  ] as const)('absent-index control (%s): NO state DB at all ⇒ still not-installed / ok, doctor info "skipped"', async (_label, config) => {
    hostWithout(config, false);

    const input = unread();
    const verdict = reconcilePluginState(input);
    const doctor = await checkOpenClawPluginLoadState(home, EXPECTED);

    expect(input.indexUnreadable).toBe(false);
    expect(verdict).toMatchObject({ state: 'not-installed', severity: 'ok' });
    expect(doctor).toMatchObject({ status: 'info', message: 'skipped (realtime plugin not installed)' });
  });

  it('disabled control: a build on disk + explicit enabled:false + the unreadable index ⇒ still disabled-by-operator / warn', async () => {
    fixture(layout, 'corrupt-plugins-list', EXPECTED);
    fs.writeFileSync(path.join(oc(), 'openclaw.json'), JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: false } } } }));

    const verdict = reconcilePluginState(unread());
    const doctor = await checkOpenClawPluginLoadState(home, EXPECTED);

    expect(verdict).toMatchObject({ state: 'disabled-by-operator', severity: 'warn', recommendedAction: 'none', indexUnreadable: true });
    expect(doctor.status).toBe('warn');
    expect(doctor.message).toMatch(/explicitly disabled/);
  });
});
