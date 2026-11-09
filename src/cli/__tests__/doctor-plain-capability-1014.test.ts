/**
 * #1014 r6 (Astra round-4 blocker): a KNOWN unsupported capability is a fact
 * of its own, and it is not folded into "Conversation scanning off".
 *
 * `checkOpenClawConversationScanning` states two independent facts in one
 * WARN: conversation access is withheld (fix: "That is a valid choice."), and,
 * on an OpenClaw older than 2026.5.12, conversation enforcement is UNAVAILABLE
 * so detections can never be more than advisory. The default report filed the
 * whole row under EXPECTED ON THIS HOST by its by-design fix, and the version
 * limit vanished; origin/main printed it.
 *
 * The producer now carries the limit as a structured `unsupportedCapability`
 * (an observed incompatibility, not an unread observation, so it is NOT
 * `observationIncomplete`). The default report keeps the access choice under
 * EXPECTED and prints the limit as its own TO FIX item, as prose: nothing
 * tells the operator to grant access, restart the gateway, run the canary or
 * upgrade unconditionally.
 *
 * Every row comes from the real checks over a temp HOME with a managed
 * OpenClaw package.json, and PATH points at an empty directory so an OpenClaw
 * installed on the machine running the suite cannot decide the version.
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
const OLD_OPENCLAW = '2026.5.7';
const FLOOR = '2026.5.12';
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
let savedPath: string | undefined;
beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-capability-1014-'));
  savedPath = process.env.PATH;
  const emptyBin = path.join(home, 'empty-bin');
  fs.mkdirSync(emptyBin);
  process.env.PATH = emptyBin;
});
afterEach(() => {
  if (savedPath === undefined) delete process.env.PATH;
  else process.env.PATH = savedPath;
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

/** The managed OpenClaw runtime's own package.json, which decides the host version. */
function openclawHost(version: string): void {
  const dir = path.join(home, '.openclaw', 'tools', 'node-v24.15.0', 'lib', 'node_modules', 'openclaw');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'openclaw', version }));
}

/** Every form of "not granted" the access reader sees: absent, false, and a truthy non-boolean. */
const WITHHELD_FORMS: Array<[string, Record<string, unknown>]> = [
  ['absent', { enabled: true }],
  ['false', { enabled: true, hooks: { allowConversationAccess: false } }],
  ['the string "true"', { enabled: true, hooks: { allowConversationAccess: 'true' } }],
];
const WITHHELD = WITHHELD_FORMS[0][1];
const GRANTED = { enabled: true, hooks: { allowConversationAccess: true } };
const PROVEN_ROSTER = { readLiveRoster: () => [PLUGIN] };

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

/** The version limit is under TO FIX, every part of it, and nothing unsafe is prescribed. */
function expectLimitToFix(text: string): void {
  const toFix = flat(section(text, 'TO FIX'));
  expect(toFix).toMatch(/conversation enforcement UNAVAILABLE/);
  expect(toFix).toContain(`OpenClaw ${OLD_OPENCLAW} predates ${FLOOR}`);
  expect(toFix).toMatch(/before_agent_run/);
  expect(toFix).toMatch(/can never be more than advisory/);
  expect(toFix).toMatch(/\[conversation-scanning\]/);
  // The upgrade is conditional prose, never a command.
  expect(toFix).toMatch(new RegExp(`OpenClaw ${FLOOR.replace(/\./g, '\\.')} or later`));
  expect(toFix).toMatch(/only if you want/i);
  expect(dollarLines(text)).toEqual([]);
  expect(text).not.toMatch(/npm (?:i|install)\b[^\n]*openclaw|openclaw (?:update|upgrade)\b/i);
  expect(text).not.toMatch(/SHIELDCORTEX_ALLOW_GATEWAY_CANARY|gateway canary|openclaw status/i);
  expect(text).not.toMatch(/gateway restart|allow-conversation-access|action-guard-(?:enable|enforce)/i);
  // The limit is not filed as a choice.
  expect(flat(section(text, 'EXPECTED ON THIS HOST'))).not.toMatch(/UNAVAILABLE|predates|advisory/);
}

/** The withheld access is still the operator's choice, in one EXPECTED phrase. */
function expectAccessChoiceExpected(text: string): void {
  expect(flat(section(text, 'EXPECTED ON THIS HOST'))).toMatch(/Conversation scanning off/);
}

describe('#1014 r6 — the producer carries a known unsupported capability as its own fact', () => {
  it.each(WITHHELD_FORMS)('withheld access (%s) + OpenClaw 2026.5.7: WARN, by-design fix, structured limit', async (_name, entry) => {
    healthyInstall(entry);
    openclawHost(OLD_OPENCLAW);
    const scan = await checkOpenClawConversationScanning(home);
    expect(scan.status).toBe('warn');
    expect(scan.message).toMatch(/conversation scanning INACTIVE/);
    expect(scan.message).toMatch(/conversation enforcement UNAVAILABLE/);
    expect(scan.fix).toMatch(/That is a valid choice\./);
    // An observed incompatibility, not an unread observation.
    expect(scan.observationIncomplete).toBeUndefined();
    expect(scan.unsupportedCapability).toBeDefined();
    const lim = scan.unsupportedCapability!;
    expect(lim.capability).toBe('Conversation enforcement');
    // The structured fact is the very clause the message states.
    expect(scan.message).toContain(lim.fact);
    expect(lim.fact).toContain(`OpenClaw ${OLD_OPENCLAW} predates ${FLOOR}`);
    expect(lim.fix).toContain(`OpenClaw ${FLOOR} or later`);
  });

  it('no marker when the version supports enforcement, or when it could not be read', async () => {
    healthyInstall(WITHHELD);
    openclawHost(FLOOR);
    const supported = await checkOpenClawConversationScanning(home);
    expect(supported.message).toMatch(/conversation enforcement AVAILABLE/);
    expect(supported.unsupportedCapability).toBeUndefined();

    fs.rmSync(path.join(home, '.openclaw', 'tools'), { recursive: true, force: true });
    const unknown = await checkOpenClawConversationScanning(home);
    expect(unknown.message).toMatch(/conversation enforcement support UNKNOWN/);
    expect(unknown.unsupportedCapability).toBeUndefined();
  });
});

describe('#1014 r6 — withheld access + unsupported OpenClaw: the choice is EXPECTED, the limit is TO FIX', () => {
  it.each(WITHHELD_FORMS)('alone (%s): 1 thing to fix, the limit in full, scanning off as the choice', async (_name, entry) => {
    healthyInstall(entry);
    openclawHost(OLD_OPENCLAW);
    const scan = await checkOpenClawConversationScanning(home);
    const [group] = groupItems([scan], true);
    // The row's own tier is still the access choice.
    expect(warnTier(group!)).toBe('expected');

    const text = report([scan]);
    expect(text).toMatch(/Healthy \| 1 thing to fix/);
    expectLimitToFix(text);
    expectAccessChoiceExpected(text);
    // 40 columns: wrapped, never ellipsized.
    const narrow = report([scan], { width: 40 });
    expect(narrow).not.toMatch(/…/);
    expectLimitToFix(narrow);
    expectAccessChoiceExpected(narrow);
  });

  it('beside a roster-proven load row, both orders: the merged scanning group keeps the limit', async () => {
    healthyInstall(WITHHELD);
    openclawHost(OLD_OPENCLAW);
    const load = await checkOpenClawPluginLoadState(home, VERSION, PROVEN_ROSTER);
    expect(load.status).toBe('warn');
    expect(load.message).toMatch(/tool-call gating is live/);
    expect(load.observationIncomplete).toBeUndefined();
    const scan = await checkOpenClawConversationScanning(home);

    for (const rows of [[load, scan], [scan, load]]) {
      const groups = groupItems(rows as DoctorReportItem[], true);
      // One operator decision, one group, still expected.
      expect(groups).toHaveLength(1);
      expect(warnTier(groups[0]!)).toBe('expected');
      expect(groups[0]!.unsupportedCapabilities).toHaveLength(1);

      const text = report(rows);
      expect(text).toMatch(/Healthy \| 1 thing to fix/);
      expectLimitToFix(text);
      expectAccessChoiceExpected(text);
    }
  });

  it('beside a null-roster (marked) load row, both orders: the unproven load AND the limit are TO FIX', async () => {
    healthyInstall(WITHHELD);
    openclawHost(OLD_OPENCLAW);
    const load = await checkOpenClawPluginLoadState(home, VERSION);
    expect(load.observationIncomplete).toBe(true);
    const scan = await checkOpenClawConversationScanning(home);

    for (const rows of [[load, scan], [scan, load]]) {
      const text = report(rows);
      expect(text).toMatch(/Healthy \| 2 things to fix/);
      expectLimitToFix(text);
      const toFix = flat(section(text, 'TO FIX'));
      expect(toFix).toMatch(/boot roster could not be read/);
      expect(toFix).toMatch(/tool-call gating is NOT separately proven/);
      expectAccessChoiceExpected(text);
    }
  });

  it('--explain expected and --verbose still print the scanning row in full, limit included', async () => {
    healthyInstall(WITHHELD);
    openclawHost(OLD_OPENCLAW);
    const scan = await checkOpenClawConversationScanning(home);
    const display = sanitiseDoctorRowsForDisplay([scan] as DoctorReportItem[]);

    // The row's access choice is still expected, and listed there in full.
    const expected = flat(formatDoctorExplain(display, 'expected', { width: 100, style: PLAIN }).join('\n'));
    expect(expected).toMatch(/Conversation scanning/);
    expect(expected).toMatch(/conversation enforcement UNAVAILABLE/);

    const one = flat(formatDoctorExplain(display, 'conversation-scanning', { width: 100, style: PLAIN }).join('\n'));
    expect(one).toMatch(/conversation enforcement UNAVAILABLE/);
    expect(one).toMatch(/That is a valid choice\./);

    const verbose = flat(report([scan], { verbose: true }));
    expect(verbose).toMatch(/conversation enforcement UNAVAILABLE/);
  });

  it('a host-written version string is display-sanitised in the limit item', async () => {
    healthyInstall(WITHHELD);
    openclawHost(`${OLD_OPENCLAW}\u001b[31m\u202e`);
    const scan = await checkOpenClawConversationScanning(home);
    expect(scan.unsupportedCapability?.fact).toContain('\u001b[31m');
    const text = report([scan]);
    expect(text).not.toMatch(/[\u001b\u202e]/);
    expect(flat(section(text, 'TO FIX'))).toMatch(/conversation enforcement UNAVAILABLE/);
  });
});

describe('#1014 r6 controls', () => {
  it('supported version + withheld access: wholly by design, EXPECTED only, nothing to fix', async () => {
    healthyInstall(WITHHELD);
    openclawHost(FLOOR);
    const scan = await checkOpenClawConversationScanning(home);
    const load = await checkOpenClawPluginLoadState(home, VERSION, PROVEN_ROSTER);
    for (const rows of [[scan], [load, scan], [scan, load]]) {
      const text = report(rows);
      expect(text).toMatch(/Healthy \| nothing to fix/);
      expect(text).not.toMatch(/TO FIX/);
      expect(text).not.toMatch(/UNAVAILABLE/);
      expectAccessChoiceExpected(text);
      expect(dollarLines(text)).toEqual([]);
    }
  });

  it('granted access + unsupported version: still a TO FIX item, said once, with conditional upgrade prose', async () => {
    healthyInstall(GRANTED);
    openclawHost(OLD_OPENCLAW);
    const scan = await checkOpenClawConversationScanning(home);
    expect(scan.status).toBe('warn');
    expect(scan.fix).toMatch(/if you want conversation enforcement to become possible/);
    const load = await checkOpenClawPluginLoadState(home, VERSION, PROVEN_ROSTER);
    expect(load.status).toBe('pass');

    for (const rows of [[scan], [load, scan]]) {
      const text = report(rows);
      expect(text).toMatch(/Healthy \| 1 thing to fix/);
      expect(text).not.toMatch(/EXPECTED ON THIS HOST/);
      const toFix = flat(section(text, 'TO FIX'));
      expect(toFix).toMatch(/conversation enforcement UNAVAILABLE/);
      expect(toFix).toContain(`OpenClaw ${OLD_OPENCLAW} predates ${FLOOR}`);
      expect(toFix).toMatch(/Upgrade OpenClaw to 2026\.5\.12 or later if you want conversation enforcement to become possible/);
      // One item: the row itself, not the row plus a copy of its limit.
      expect(toFix.match(/conversation enforcement UNAVAILABLE/g)).toHaveLength(1);
      expect(dollarLines(text)).toEqual([]);
    }
  });
});
