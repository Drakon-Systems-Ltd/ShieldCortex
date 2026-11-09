/**
 * #1014 r5 (Astra round-3 blocker) — a compound warning is classified by every
 * diagnostic fact it states, not by its one reassuring sentence.
 *
 * `checkOpenClawPluginLoadState` downgrades its pass to a WARN when
 * conversation access is withheld, and gives the row the by-design
 * conversation-access fix ("That is a valid choice."). When the running
 * gateway's boot roster could not be read, the same row also says the plugin
 * load and tool-call gating are NOT separately proven. That second fact is a
 * diagnostic gap, not an operator choice, yet the default report filed the
 * whole row under EXPECTED ON THIS HOST as "Conversation scanning off" and the
 * unproven tool gate vanished.
 *
 * The producer now marks that row `observationIncomplete`, from the same
 * `loadedInLiveRoster !== true` test that writes the "NOT separately proven"
 * words, and a marked row is TO FIX with its full message and its own fix
 * prose: the withheld access stays a valid choice, and nothing tells the
 * operator to grant access, restart the gateway, run the consent-gated live
 * canary or change the Guard.
 *
 * Every row here comes from the real checks over a temp HOME. Under Jest the
 * live-roster read is guarded to null, so the unproven case is the default;
 * the proven-loaded control injects the roster through the existing
 * `readLiveRoster` seam of `gatherReconcileInput`.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import {
  checkOpenClawConversationScanning,
  checkOpenClawPluginLoadState,
  type CheckResult,
} from '../doctor.js';
import {
  formatDoctorReport,
  groupItems,
  sanitiseDoctorRowsForDisplay,
  type DoctorReportItem,
} from '../doctor-report.js';
import { formatDoctorExplain, warnTier } from '../doctor-plain.js';

const PLUGIN = 'shieldcortex-realtime';
const VERSION = '4.47.35';
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

const PLAIN = { bold: '', reset: '', green: '', yellow: '', red: '', cyan: '', dim: '' };

let home: string;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-roster-1014-'));
});
afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

/** Installed, enabled, indexed: every layer doctor reads off disk agrees. */
function healthyInstall(entry: Record<string, unknown>): void {
  const oc = path.join(home, '.openclaw');
  const pkgDir = path.join(oc, 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-abc', PKG_SUBPATH);
  fs.mkdirSync(pkgDir, { recursive: true });
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify({ version: VERSION }));
  fs.mkdirSync(path.join(oc, 'state'), { recursive: true });
  fs.writeFileSync(
    path.join(oc, 'openclaw.json'),
    JSON.stringify({ plugins: { entries: { [PLUGIN]: entry }, allow: [PLUGIN] } }),
  );
  const db = new Database(path.join(oc, 'state', 'openclaw.sqlite'));
  db.prepare(INDEX_DDL).run();
  db.prepare(INDEX_INSERT).run({
    ir: JSON.stringify({ [PLUGIN]: { source: 'npm', version: VERSION, installPath: pkgDir } }),
    pj: JSON.stringify([{ pluginId: PLUGIN, enabled: true }]),
  });
  db.close();
}

const WITHHELD = { enabled: true };
const GRANTED = { enabled: true, hooks: { allowConversationAccess: true } };

/** What runDoctor hands the renderer: the display copy of the rows. */
function report(rows: CheckResult[], opts: { verbose?: boolean; width?: number } = {}): string {
  const display = sanitiseDoctorRowsForDisplay(rows as DoctorReportItem[]);
  return formatDoctorReport(display, { width: opts.width ?? 100, color: false, verbose: opts.verbose }).join('\n');
}
const flat = (text: string): string => text.replace(/\s+/g, ' ');
/** The default report's sections, by heading. */
function section(text: string, heading: 'TO FIX' | 'EXPECTED ON THIS HOST'): string {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.startsWith(heading));
  if (start < 0) return '';
  const end = lines.findIndex((l, i) => i > start && l.trim() === '');
  return lines.slice(start, end < 0 ? undefined : end).join('\n');
}
const dollarLines = (text: string): string[] => text.split('\n').filter((l) => /^\s+\$ /.test(l)).map((l) => l.trim());

/** The default report keeps every diagnostic fact of the unproven-load row, and prescribes nothing unsafe. */
function expectUnprovenLoadToFix(text: string): void {
  const toFix = flat(section(text, 'TO FIX'));
  expect(toFix).toMatch(/boot roster could not be read/);
  expect(toFix).toMatch(/load is NOT separately proven/);
  expect(toFix).toMatch(/tool-call gating is NOT separately proven/);
  expect(toFix).toMatch(/\[openclaw-plugin-loaded\]/);
  // The withheld access stays a choice, in the row's own words.
  expect(toFix).toMatch(/That is a valid choice\./);
  expect(toFix).toMatch(/Do not grant conversation access or restart the gateway from this warning\./);
  // No grant, restart, canary or guard-changing command anywhere in the default report.
  expect(dollarLines(text)).toEqual([]);
  expect(text).not.toMatch(/SHIELDCORTEX_ALLOW_GATEWAY_CANARY|gateway canary|openclaw status/i);
  expect(text).not.toMatch(/gateway restart|allow-conversation-access|action-guard-(?:enable|enforce)/i);
  expect(flat(section(text, 'EXPECTED ON THIS HOST'))).not.toMatch(/roster|NOT separately proven/);
}

describe('#1014 r5 — an unreadable live roster is not folded into "Conversation scanning off"', () => {
  it('the real check marks the compound warning, from the same test that writes "NOT separately proven"', async () => {
    healthyInstall(WITHHELD);
    const load = await checkOpenClawPluginLoadState(home, VERSION);
    // The path under test was reached: the roster read is null under Jest.
    expect(load.status).toBe('warn');
    expect(load.message).toMatch(/boot roster could not be read/);
    expect(load.message).toMatch(/tool-call gating is NOT separately proven/);
    expect(load.fix).toMatch(/That is a valid choice\./);
    expect(load.observationIncomplete).toBe(true);
    // Severity and message are the producer's, unchanged by the marker.
    expect(load.message).not.toMatch(/tool-call gating is live/);
  });

  it('liveRoster=null + withheld access, alone: TO FIX with every fact, not EXPECTED', async () => {
    healthyInstall(WITHHELD);
    const load = await checkOpenClawPluginLoadState(home, VERSION);
    const [group] = groupItems([load], true);
    expect(warnTier(group!)).toBe('fix');

    const text = report([load]);
    expect(text).toMatch(/Healthy \| 1 thing to fix/);
    expect(text).not.toMatch(/EXPECTED ON THIS HOST/);
    expectUnprovenLoadToFix(text);
    // 40 columns: wrapped, never ellipsized.
    const narrow = report([load], { width: 40 });
    expect(narrow).not.toMatch(/…/);
    expectUnprovenLoadToFix(narrow);
  });

  it('liveRoster=null + withheld access beside the dedicated Conversation scanning row: the two stay separate', async () => {
    healthyInstall(WITHHELD);
    const load = await checkOpenClawPluginLoadState(home, VERSION);
    const scan = await checkOpenClawConversationScanning(home);
    expect(scan.status).toBe('warn');
    expect(scan.fix).toMatch(/That is a valid choice\./);

    for (const rows of [[load, scan], [scan, load]]) {
      const groups = groupItems(rows.filter((r) => r.status === 'warn') as DoctorReportItem[], true);
      expect(groups).toHaveLength(2);
      const tiers = Object.fromEntries(groups.map((g) => [g.labels.join('+'), warnTier(g)]));
      expect(tiers).toEqual({ 'OpenClaw plugin loaded': 'fix', 'Conversation scanning': 'expected' });

      const text = report(rows);
      expect(text).toMatch(/Healthy \| 1 thing to fix/);
      expectUnprovenLoadToFix(text);
      // The withheld access is still reported as the operator's choice.
      expect(flat(section(text, 'EXPECTED ON THIS HOST'))).toMatch(/Conversation scanning off/);
    }
  });

  it('--explain expected does not list the unproven-load row; --verbose and --explain print it in full', async () => {
    healthyInstall(WITHHELD);
    const load = await checkOpenClawPluginLoadState(home, VERSION);
    const scan = await checkOpenClawConversationScanning(home);
    const display = sanitiseDoctorRowsForDisplay([load, scan] as DoctorReportItem[]);

    const expected = flat(formatDoctorExplain(display, 'expected', { width: 100, style: PLAIN }).join('\n'));
    expect(expected).toMatch(/Conversation scanning/);
    expect(expected).not.toMatch(/OpenClaw plugin loaded/);

    const one = flat(formatDoctorExplain(display, 'openclaw-plugin-loaded', { width: 100, style: PLAIN }).join('\n'));
    expect(one).toMatch(/boot roster could not be read/);
    expect(one).toMatch(/tool-call gating is NOT separately proven/);

    const verbose = flat(report([load, scan], { verbose: true }));
    expect(verbose).toMatch(/boot roster could not be read/);
    expect(verbose).toMatch(/tool-call gating is NOT separately proven/);
  });
});

describe('#1014 r5 controls — a proven load with withheld access is still wholly by design', () => {
  const provenRoster = { readLiveRoster: () => [PLUGIN] };

  it('roster-proven + withheld access: no marker, EXPECTED "Conversation scanning off", nothing to fix', async () => {
    healthyInstall(WITHHELD);
    const load = await checkOpenClawPluginLoadState(home, VERSION, provenRoster);
    expect(load.status).toBe('warn');
    expect(load.message).toMatch(/tool-call gating is live/);
    expect(load.message).not.toMatch(/NOT separately proven/);
    expect(load.observationIncomplete).toBeUndefined();

    const scan = await checkOpenClawConversationScanning(home);
    for (const rows of [[load], [load, scan]]) {
      const groups = groupItems(rows as DoctorReportItem[], true);
      expect(groups.map((g) => warnTier(g))).toEqual(['expected']);
      const text = report(rows);
      expect(text).toMatch(/Healthy \| nothing to fix/);
      expect(text).not.toMatch(/TO FIX/);
      expect(flat(section(text, 'EXPECTED ON THIS HOST'))).toMatch(/Conversation scanning off/);
      expect(dollarLines(text)).toEqual([]);
    }
  });

  it('access granted: the load row stays a pass and carries no marker, roster proven or not', async () => {
    healthyInstall(GRANTED);
    const unproven = await checkOpenClawPluginLoadState(home, VERSION);
    expect(unproven.status).toBe('pass');
    expect(unproven.observationIncomplete).toBeUndefined();
    const proven = await checkOpenClawPluginLoadState(home, VERSION, provenRoster);
    expect(proven.status).toBe('pass');
    expect(proven.observationIncomplete).toBeUndefined();
  });
});
