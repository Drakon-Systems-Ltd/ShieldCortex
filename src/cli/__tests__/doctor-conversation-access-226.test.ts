import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { checkOpenClawConversationAccess, checkOpenClawPluginLoadState } from '../doctor.js';
import { readConversationAccessGate } from '../../integrations/openclaw-plugin-index.js';

/**
 * #226 item 6 — the conversation-hook access gate.
 *
 * Verified against the host's own loader (the installed OpenClaw 2026.5.2 at
 * ~/.npm-global/lib/node_modules/openclaw, `dist/loader-*.js`, and unchanged in
 * current published builds):
 *
 *   if (isConversationHookName(hookName)) {
 *     if (record.origin !== "bundled" && policy?.allowConversationAccess !== true) {
 *       pushDiagnostic({ level: "warn", ... }); return;   // registration DROPPED
 *     }
 *   }
 *
 * ShieldCortex is non-bundled, so without
 * `plugins.entries.<id>.hooks.allowConversationAccess === true` every hook it
 * registers on the conversation plane is discarded at load: llm_input,
 * llm_output, and on 2026.5.9+ the before_agent_run gate itself. Nothing
 * throws. The plugin loads, before_tool_call still gates, and no conversation
 * content is scanned by anything — while every ShieldCortex surface reports
 * real-time scanning as on.
 *
 * The three answers doctor must keep apart are granted / not-granted /
 * cannot-tell. Fully isolated in a temp HOME.
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
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-grant-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

/** Installed on disk, enabled in config, present on the live roster — i.e. the
 *  host that every other doctor check calls healthy. */
function healthyInstall(entry: Record<string, unknown>): void {
  const oc = path.join(home, '.openclaw');
  const dirName = 'drakon-systems-shieldcortex-realtime-abc';
  const pkgDir = path.join(oc, 'npm', 'projects', dirName, PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version: '4.47.35' }));
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  fs.writeFileSync(
    path.join(oc, 'openclaw.json'),
    JSON.stringify({ plugins: { entries: { [PLUGIN]: entry }, allow: [PLUGIN] } }),
  );
  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  db.prepare(INDEX_DDL).run();
  db.prepare(INDEX_INSERT).run({
    ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: '4.47.35', installPath: pkgDir } }),
    pj: JSON.stringify([{ pluginId: PLUGIN, enabled: true }]),
  });
  db.close();
}

describe('#226 readConversationAccessGate — strict true, and cannot-tell stays cannot-tell', () => {
  const writeRaw = (body: string): void => {
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), body, 'utf-8');
  };

  it('grants only on exactly true', () => {
    writeRaw(JSON.stringify({ plugins: { entries: { [PLUGIN]: { hooks: { allowConversationAccess: true } } } } }));
    expect(readConversationAccessGate(home, PLUGIN).granted).toBe(true);
  });

  it('a truthy-but-not-true value is a refusal, exactly as the host reads it', () => {
    for (const v of ['true', 1, {}]) {
      writeRaw(JSON.stringify({ plugins: { entries: { [PLUGIN]: { hooks: { allowConversationAccess: v } } } } }));
      const gate = readConversationAccessGate(home, PLUGIN);
      expect(gate.granted).toBe(false);
      expect(gate.detail).toMatch(/only exactly true/);
    }
  });

  it('unset is a refusal, and says so as "not set" rather than as a wrong value', () => {
    writeRaw(JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } } } }));
    const gate = readConversationAccessGate(home, PLUGIN);
    expect(gate.granted).toBe(false);
    expect(gate.detail).toMatch(/is not set/);
  });

  it('an unreadable config is null — never "not granted"', () => {
    writeRaw('{ "plugins": { "entries": { "shieldcortex-realtime": { "hooks');
    expect(readConversationAccessGate(home, PLUGIN).granted).toBeNull();
  });
});

describe('#226 doctor: OpenClaw conversation access', () => {
  it('FAILS when the grant is absent, and names what is silently not happening', async () => {
    healthyInstall({ enabled: true });
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/NOT granted/);
    expect(r.message).toMatch(/REFUSES every conversation hook/i);
    expect(r.fix).toMatch(/allowConversationAccess/);
  });

  it('PASSES when granted — but does not upgrade "accepted" into "enforcing"', async () => {
    healthyInstall({ enabled: true, hooks: { allowConversationAccess: true } });
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/Acceptance is not enforcement/i);
  });

  it('WARNS, never fails, when the config cannot be read', async () => {
    healthyInstall({ enabled: true, hooks: { allowConversationAccess: true } });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), '{ truncated', 'utf-8');
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/cannot determine/i);
  });

  it('skips when the plugin is not installed — no hooks to refuse', async () => {
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('info');
  });

  it('skips when OpenClaw is not on the box at all', async () => {
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('info');
  });
});

/**
 * The grant only decides what a LOADED plugin's conversation hooks may do. On a
 * host where the plugin is not going to load, there are no hooks for the
 * gateway to refuse — and the load-state check has already printed the state
 * and the correct repair. A second red line here would tell the operator to
 * grant a permission to a plugin that is not running: the wrong fix, printed
 * over the right one.
 */
describe('#226 the conversation-access line defers to the load-state line it does not own', () => {
  it('does not fail a deliberately disabled plugin', async () => {
    healthyInstall({ enabled: false });
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/deliberately disabled/i);

    // …and the line that DOES own the state still reports it.
    const load = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(load.status).toBe('warn');
    expect(load.message).toMatch(/explicitly disabled/i);
  });

  it('does not fail a plugin wiped out of the config (#222)', async () => {
    healthyInstall({ enabled: true });
    const cfgPath = path.join(home, '.openclaw', 'openclaw.json');
    fs.writeFileSync(cfgPath, JSON.stringify({ plugins: { entries: {}, allow: [] } }), 'utf-8');

    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not enabled in openclaw\.json/i);

    const load = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(load.status).toBe('fail');
  });

  it('does not fail an enabled-but-not-installed host', async () => {
    const oc = path.join(home, '.openclaw');
    fs.mkdirSync(oc, { recursive: true });
    fs.writeFileSync(
      path.join(oc, 'openclaw.json'),
      JSON.stringify({ plugins: { entries: { [PLUGIN]: { enabled: true } }, allow: [PLUGIN] } }),
      'utf-8',
    );

    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/not installed/i);

    const load = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(load.status).toBe('fail');
  });

  it('an unreadable config is a WARN here, never a grant verdict', async () => {
    healthyInstall({ enabled: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), '{ truncated', 'utf-8');
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/could not be read/i);
    expect(r.status).not.toBe('fail');
  });

  it('still FAILS the state it does own: installed, enabled, and no grant', async () => {
    healthyInstall({ enabled: true });
    const r = await checkOpenClawConversationAccess(home);
    expect(r.status).toBe('fail');
  });
});

describe('#226 the "plugin loaded" tick never reads as protection while the grant is absent', () => {
  it('downgrades the roster-confirmed PASS to a warn that names the gap', async () => {
    healthyInstall({ enabled: true });
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    // Loaded is still true and still said; what changes is that the line no
    // longer stops there.
    expect(r.message).toMatch(/loaded \(roster-confirmed/);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/conversation scanning is NOT/i);
  });

  it('stays a clean PASS once the grant is present', async () => {
    healthyInstall({ enabled: true, hooks: { allowConversationAccess: true } });
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('pass');
    expect(r.message).not.toMatch(/conversation scanning is NOT/i);
  });
});
