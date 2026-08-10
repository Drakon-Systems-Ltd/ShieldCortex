import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { checkOpenClawConversationScanning, checkOpenClawPluginLoadState } from '../doctor.js';

/**
 * #226 item 6 — the conversation-hook access gate, as doctor reports it.
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
 * content is scanned by anything.
 *
 * WHAT THIS FILE OWNS AFTER THE #230 MERGE. The dedicated line that reports
 * conversation-scanning state is `checkOpenClawConversationScanning` (#225
 * phase 1 + #231 capability detection), and its severity contract lives in
 * src/__tests__/conversation-access-honesty-225.test.ts: an ungranted host
 * WARNS, because withholding conversation access is a legitimate operator
 * choice. #226's earlier `checkOpenClawConversationAccess` (which failed on the
 * same fact, and read the grant through a second copy of the reader) is gone.
 *
 * What survives here is the part #230 does not cover: the "OpenClaw plugin
 * loaded" tick must not read as protection while the grant is absent. Loaded is
 * still true and still said; the line simply stops short of a green tick.
 *
 * Fully isolated in a temp HOME.
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

describe('#226 the "plugin loaded" tick never reads as protection while the grant is absent', () => {
  it('downgrades the roster-confirmed PASS to a warn that names the gap', async () => {
    healthyInstall({ enabled: true });
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    // Loaded is still true and still said; what changes is that the line no
    // longer stops there.
    expect(r.message).toMatch(/loaded \(roster-confirmed/);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/conversation scanning is NOT/i);
    expect(r.fix).toMatch(/allowConversationAccess/);
  });

  it('stays a clean PASS once the grant is present', async () => {
    healthyInstall({ enabled: true, hooks: { allowConversationAccess: true } });
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('pass');
    expect(r.message).not.toMatch(/conversation scanning is NOT/i);
  });

  it('a truthy-but-not-true grant is a refusal, exactly as the host reads it', async () => {
    // OpenClaw compares `!== true`, so this host has NO conversation plane.
    // Reporting it as granted would recreate the bug in the reporting layer.
    healthyInstall({ enabled: true, hooks: { allowConversationAccess: 'true' } });
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/conversation scanning is NOT/i);
  });

  it('does not stack the note onto a state that already failed for another reason', async () => {
    // The wipe (#222) owns its own line and its own repair. A grant note glued
    // to it would point at the wrong fix.
    healthyInstall({ enabled: true });
    fs.writeFileSync(
      path.join(home, '.openclaw', 'openclaw.json'),
      JSON.stringify({ plugins: { entries: {}, allow: [] } }),
      'utf-8',
    );
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('fail');
    expect(r.message).not.toMatch(/conversation scanning is NOT/i);
  });

  it('an unreadable config never produces a grant verdict on this line', async () => {
    // Cannot-read is not "not granted": the load-state check reports the
    // indeterminate state, and no conversation note is appended to it.
    healthyInstall({ enabled: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), '{ truncated', 'utf-8');
    const r = await checkOpenClawPluginLoadState(home, '4.47.35');
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/INDETERMINATE/);
    expect(r.message).not.toMatch(/conversation scanning is NOT/i);
  });
});

describe('#226/#230 the dedicated conversation-scanning line owns the grant itself', () => {
  it('WARNS — never fails — when the grant is absent, and names the key', async () => {
    healthyInstall({ enabled: true });
    const r = await checkOpenClawConversationScanning(home);
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/INACTIVE/);
    expect(r.fix).toMatch(/allowConversationAccess/);
  });

  it('granted is INFO and says observation-only — acceptance is not enforcement', async () => {
    healthyInstall({ enabled: true, hooks: { allowConversationAccess: true } });
    const r = await checkOpenClawConversationScanning(home);
    expect(r.status).not.toBe('fail');
    expect(r.message.toLowerCase()).toMatch(/observation only/);
    expect(r.message.toLowerCase()).not.toMatch(/\bprotected\b/);
  });

  it('skips when OpenClaw is not on the box at all', async () => {
    const r = await checkOpenClawConversationScanning(home);
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/skipped/i);
  });
});
