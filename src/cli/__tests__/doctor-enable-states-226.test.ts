import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { checkOpenClawPluginLoadState, doctorExitCode } from '../doctor.js';

/**
 * #226 — doctor's switch over the reconciler verdict had no case for
 * `installed-not-enabled`, so the state #222 added fell straight through to
 * `default:` and printed:
 *
 *   ✓ OpenClaw plugin loaded — realtime plugin loaded (roster-confirmed, v…)
 *
 * on a host where the gateway will boot with no memory firewall and no action
 * guard. The reconciler had been taught to see the wipe; the surface that
 * reports to the operator had not, so the fix was invisible from the outside.
 *
 * These run against a temp HOME with a real (temp) SQLite index, so they
 * exercise the whole gather → reconcile → report path rather than the pure
 * classifier alone. Nothing touches the live ~/.openclaw.
 */

const PLUGIN = 'shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');

const INDEX_DDL =
  'CREATE TABLE installed_plugin_index (' +
  'index_key TEXT NOT NULL PRIMARY KEY, version INTEGER NOT NULL, ' +
  'host_contract_version TEXT NOT NULL, compat_registry_version TEXT NOT NULL, ' +
  'migration_version INTEGER NOT NULL, policy_hash TEXT NOT NULL, ' +
  'generated_at_ms INTEGER NOT NULL, refresh_reason TEXT, ' +
  'install_records_json TEXT NOT NULL, plugins_json TEXT NOT NULL, ' +
  'diagnostics_json TEXT NOT NULL, warning TEXT, updated_at_ms INTEGER NOT NULL)';
const INDEX_INSERT =
  "INSERT INTO installed_plugin_index VALUES ('k',1,'v','x',1,'h',1,'r',@ir,@pj,'[]',NULL,1)";

let home: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-enable-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

function writeIndex(roster: Array<{ pluginId: string; enabled: boolean }>, installPath: string): void {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  db.exec(INDEX_DDL);
  db.prepare(INDEX_INSERT).run({
    ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: '4.47.35', installPath } }),
    pj: JSON.stringify(roster),
  });
  db.close();
}

/** Put the plugin package on disk, with no config written yet. */
function installOnDisk(): string {
  const oc = path.join(home, '.openclaw');
  const dirName = 'drakon-systems-shieldcortex-realtime-abc';
  const pkgDir = path.join(oc, 'npm', 'projects', dirName, PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version: '4.47.35' }));
  return pkgDir;
}

const writeConfig = (body: string): void => {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(oc, { recursive: true });
  fs.writeFileSync(path.join(oc, 'openclaw.json'), body, 'utf-8');
};

describe('#226 doctor reports the config-side states truthfully', () => {
  it('installed on disk, stanza wiped → FAIL, and the fix ENABLES rather than reinstalls', async () => {
    const pkgDir = installOnDisk();
    writeIndex([], pkgDir);
    writeConfig(JSON.stringify({ plugins: { entries: {}, allow: [] } }));

    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    // The regression: this used to be `pass` — "realtime plugin loaded".
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/NOT enabled in openclaw\.json/i);
    expect(r.message).toMatch(/no memory firewall|no action guard/i);
    expect(r.fix).toMatch(/Nothing is reinstalled/i);
    expect(r.fix).not.toMatch(/plugins install|--force/i);
  });

  it('explicitly disabled → WARN (intentional), never a green tick and never a red FAIL', async () => {
    const pkgDir = installOnDisk();
    writeIndex([], pkgDir);
    writeConfig(JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: false } }, allow: [PLUGIN] } }));

    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/explicitly disabled/i);
    // It still names what the host is running without — a warn, not a shrug.
    expect(r.message).toMatch(/WITHOUT the memory firewall/i);
    expect(r.fix).toMatch(/nothing needs reinstalling/i);
  });

  it('the WARN choice is an EXIT-CODE policy, and the policy is --strict', async () => {
    // The severity is deliberate and load-bearing, so pin what it actually
    // does rather than leaving it to a comment. An operator who typed
    // `enabled: false` gets a green run that still tells them what is off; a
    // fleet that will not accept a disabled host gets exit 1 from `--strict`.
    // Promoting the severity to `fail` would take the first away to give the
    // second something it already has.
    const pkgDir = installOnDisk();
    writeIndex([], pkgDir);
    writeConfig(JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: false } }, allow: [PLUGIN] } }));

    const r = await checkOpenClawPluginLoadState(home, '4.47.35');

    expect(doctorExitCode([r])).toBe(0);
    expect(doctorExitCode([r], { strict: true })).toBe(1);
    // …and the line itself points at the flag, so the CI route is discoverable
    // from the output rather than only from the docs.
    expect(r.fix).toMatch(/--strict/);
  });

  it('a WIPED stanza is the state that fails outright — the two are not the same', async () => {
    // The contrast is the whole reason `intentionally-disabled` can afford to
    // be a warn: the state nobody chose still exits 1 without any flag.
    const pkgDir = installOnDisk();
    writeIndex([], pkgDir);
    writeConfig(JSON.stringify({ plugins: { entries: {}, allow: [] } }));

    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('fail');
    expect(doctorExitCode([r])).toBe(1);
  });

  it('a STALE index row still saying enabled does not upgrade that to a FAIL', async () => {
    // The install index lags config by design: right after an operator writes
    // `enabled: false` and before the next refresh, this row is exactly what a
    // correct host looks like. Convicting on it turns the ordinary
    // disable-then-run-doctor sequence into a red security failure.
    const pkgDir = installOnDisk();
    writeIndex([{ pluginId: PLUGIN, enabled: true }], pkgDir);
    writeConfig(JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: false } }, allow: [PLUGIN] } }));

    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/explicitly disabled/i);
  });

  it('config enables it but nothing is installed → FAIL, not "skipped (not installed)"', async () => {
    const oc = path.join(home, '.openclaw');
    fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
    writeConfig(JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } }, allow: [PLUGIN] } }));

    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/ENABLES/i);
    expect(r.fix).toMatch(/plugins install/i);
  });

  it('nothing installed and nothing configured → info, unchanged', async () => {
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not installed/i);
  });

  it('truncated openclaw.json → WARN indeterminate, never a confident UNPROTECTED', async () => {
    const pkgDir = installOnDisk();
    writeIndex([], pkgDir);
    writeConfig('{ "plugins": { "entries": { "shieldcortex-realtime": { "enabl');

    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/INDETERMINATE/);
    expect(r.message).not.toMatch(/UNPROTECTED/);
  });
});
