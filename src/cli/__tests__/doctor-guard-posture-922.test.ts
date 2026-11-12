/**
 * #922 slice 1 (PR-A): doctor's single `Action guard posture` row and the
 * HOSTS header, read from fixture files through the real readers.
 *
 * Isolation: per-test SHIELDCORTEX_CONFIG_DIR, SHIELDCORTEX_PROTECTED_ROOT,
 * OPENCLAW_HOME and a mocked os.homedir() (jest's in-process homedir ignores
 * process.env.HOME), all under one temp dir. Nothing outside it is read or written.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { LIVE, NOW, hermesPluginArtefacts, reportBody, snapshot, writeReport } from '../../posture/__tests__/self-report-fixture.js';

type Doctor = typeof import('../doctor.js');
type Config = typeof import('../../cloud/config.js');
type HostTable = typeof import('../../setup/host-table.js');
type Report = typeof import('../doctor-report.js');

let doctor: Doctor;
let config: Config;
let hostTable: HostTable;
let report: Report;
let PROTECTED_ROOT_ENV: string;

beforeAll(async () => {
  ({ PROTECTED_ROOT_ENV } = await import('../../defence/iron-dome/protected-root.js'));
  config = await import('../../cloud/config.js');
  doctor = await import('../doctor.js');
  hostTable = await import('../../setup/host-table.js');
  report = await import('../doctor-report.js');
});

let tmp: string;
let home: string;
let configDir: string;
let saved: Record<string, string | undefined>;

const ENABLING = /`[^`]*(guard posture (advisory|enforce)|--action-guard-(enable|enforce))[^`]*`/;

function signed(actionGuard: Record<string, unknown>): void {
  // Unsigned on purpose: integrity `unsigned` is a known posture, and no
  // signing path (which also mirrors into openclaw.json) runs.
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard }));
  // A `.config-sig` left by an earlier read's adoption would make this read as tampered.
  fs.rmSync(path.join(configDir, '.config-sig'), { force: true });
  config.clearCloudConfigCache();
}

function openclawEntry(entry: Record<string, unknown>): void {
  fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
  fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({
    plugins: { entries: { 'shieldcortex-realtime': entry } },
  }));
}

function claudeHookWired(): void {
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({
    hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'npx shieldcortex hook pre-tool-use' }] }] },
  }));
}

function header(): string {
  const table = hostTable.scanHostTable(home, { openclawBinaryPresent: () => true });
  return hostTable.formatHostTable(table, '0.0.0', doctor.readHostGatePlanesWithPosture(home))[0];
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-922-doc-'));
  home = path.join(tmp, 'home');
  configDir = path.join(tmp, 'cfg');
  fs.mkdirSync(home);
  fs.mkdirSync(configDir);
  fs.mkdirSync(path.join(tmp, 'root'));
  saved = {
    SHIELDCORTEX_CONFIG_DIR: process.env.SHIELDCORTEX_CONFIG_DIR,
    [PROTECTED_ROOT_ENV]: process.env[PROTECTED_ROOT_ENV],
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
  };
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env[PROTECTED_ROOT_ENV] = path.join(tmp, 'root');
  process.env.OPENCLAW_HOME = home;
  jest.spyOn(os, 'homedir').mockReturnValue(home);
  config.clearCloudConfigCache();
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  config.clearCloudConfigCache();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe('#922 doctor — one Action guard posture row', () => {
  it('checkActionGuard emits exactly one posture row and no `Action guard config` row', async () => {
    signed({ enabled: false });
    claudeHookWired();
    const results = await doctor.checkActionGuard();
    expect(results.filter((r) => r.label === 'Action guard posture')).toHaveLength(1);
    expect(results.find((r) => r.label === 'Action guard config')).toBeUndefined();
  });

  it('fresh install: off on every present plane, warn with the default-off text, and nothing is written', () => {
    claudeHookWired();
    const before = snapshot(tmp);
    const row = doctor.checkGuardPosture();
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/^off on the one compared plane \(Claude Code hook\)/);
    expect(row.fix).toMatch(/That is the default\. Do not enable Action Guard from this warning/);
    expect(row.fix ?? '').not.toMatch(ENABLING);
    expect(snapshot(tmp)).toEqual(before);
    expect(fs.existsSync(path.join(configDir, 'config.json'))).toBe(false);
  });

  it('advisory agreeing on hook and plugin warns; enforce agreeing passes', () => {
    claudeHookWired();
    openclawEntry({ enabled: true, config: {} });
    signed({ enabled: true, enforce: false });
    const adv = doctor.checkGuardPosture();
    expect(adv.status).toBe('warn');
    expect(adv.message).toMatch(/^advisory on all 2 compared planes \(Claude Code hook, OpenClaw plugin\)/);
    expect(adv.fix ?? '').not.toMatch(ENABLING);
    signed({ enabled: true, enforce: true });
    const on = doctor.checkGuardPosture();
    expect(on.status).toBe('pass');
    expect(on.message).toMatch(/^enforce on all 2 compared planes/);
  });

  it('#634: signed enforce + plugin entry enforce:false FAILs, names the key, and offers no enabling command', () => {
    claudeHookWired();
    signed({ enabled: true, enforce: true });
    openclawEntry({ enabled: true, config: { actionGuard: { enforce: false } } });
    const row = doctor.checkGuardPosture();
    expect(row.status).toBe('fail');
    expect(row.message).toMatch(/OpenClaw plugin advisory \(openclaw\.json plugin entry actionGuard\.enforce=false overrides signed\)/);
    expect(row.fix ?? '').not.toMatch(ENABLING);
    expect(row.fix).toMatch(/`shieldcortex guard posture --help`/);
    expect(doctor.doctorExitCode([row])).not.toBe(0);
  });

  it('#1037: signed off + plugin entry enabled:true FAILs and does not suggest turning Guard off', () => {
    claudeHookWired();
    signed({ enabled: false });
    openclawEntry({ enabled: true, config: { actionGuard: { enabled: true } } });
    const row = doctor.checkGuardPosture();
    expect(row.status).toBe('fail');
    expect(row.fix).toMatch(/would turn Action Guard off on that plane/);
    expect(row.fix).toMatch(/names no command/);
    expect(row.fix ?? '').not.toMatch(/--action-guard-disable/);
    expect(row.fix ?? '').not.toMatch(/`[^`]*(--action-guard-(disable|advisory)|guard posture (off|advisory))[^`]*`/);
  });

  it('Hermes self-report looser than the hook FAILs; tighter on a default box warns (Q4 pending)', () => {
    claudeHookWired();
    hermesPluginArtefacts(home);
    const read = { home, collect: { nowMs: NOW, deps: LIVE } };

    signed({ enabled: true, enforce: true });
    writeReport(configDir, reportBody({ configured_posture: 'advisory' }));
    const looser = doctor.checkGuardPosture({ read });
    expect(looser.status).toBe('fail');
    expect(looser.message).toMatch(/Hermes advisory \(self-report\)/);
    expect(looser.fix).toMatch(/SHIELDCORTEX_ENFORCE/);

    signed({ enabled: false });
    writeReport(configDir, reportBody({ configured_posture: 'enforce' }));
    const tighter = doctor.checkGuardPosture({ read });
    expect(tighter.status).toBe('warn');
    expect(tighter.message).toMatch(/Hermes enforce \(self-report\) is tighter than the other planes/);
  });

  it('Hermes installed with no current self-report is listed as unknown and not compared', () => {
    claudeHookWired();
    hermesPluginArtefacts(home);
    signed({ enabled: true, enforce: true });
    const row = doctor.checkGuardPosture({ read: { home, collect: { nowMs: NOW, deps: LIVE } } });
    expect(row.status).toBe('pass');
    expect(row.message).toMatch(/not compared: Hermes unknown \(no current #613 self-report/);
  });
});

describe('#922 doctor — header says Guard mixed iff the posture row FAILs', () => {
  const cases: Array<[string, () => void]> = [
    ['#634 shape', () => { claudeHookWired(); signed({ enabled: true, enforce: true }); openclawEntry({ enabled: true, config: { actionGuard: { enforce: false } } }); }],
    ['plugin entry disabled under signed enforce', () => { claudeHookWired(); signed({ enabled: true, enforce: true }); openclawEntry({ enabled: true, config: { actionGuard: { enabled: false } } }); }],
    ['signed off, plugin entry enabling', () => { claudeHookWired(); signed({ enabled: false }); openclawEntry({ enabled: true, config: { actionGuard: { enabled: true } } }); }],
    ['signed advisory, plugin silent', () => { claudeHookWired(); signed({ enabled: true, enforce: false }); openclawEntry({ enabled: true, config: {} }); }],
    ['signed enforce, plugin silent', () => { claudeHookWired(); signed({ enabled: true, enforce: true }); openclawEntry({ enabled: true, config: {} }); }],
    ['fresh install', () => { claudeHookWired(); }],
    ['plugin only, entry enforce:false', () => { signed({ enabled: false }); openclawEntry({ enabled: true, config: { actionGuard: { enabled: true, enforce: false } } }); }],
  ];
  it.each(cases)('%s', (_name, arrange) => {
    arrange();
    const fails = doctor.checkGuardPosture().status === 'fail';
    expect(header().includes('Guard mixed')).toBe(fails);
  });

  it('the #634 shape is mixed (a FAIL), and the agreeing advisory box is not', () => {
    claudeHookWired();
    signed({ enabled: true, enforce: true });
    openclawEntry({ enabled: true, config: { actionGuard: { enforce: false } } });
    expect(header()).toContain('Guard mixed');
    signed({ enabled: true, enforce: false });
    openclawEntry({ enabled: true, config: {} });
    expect(header()).toContain('Guard advisory');
  });
});

/**
 * #1037: the row must name both consequences where the operator reads it, and
 * nothing doctor prints — the human report or the --ai section — may prescribe
 * a command that changes a plane's posture. Asserting on `row.fix` alone does
 * not prove this: the report renders a fix with a backticked command as the
 * command only unless the row keeps its prose.
 */
describe('#1037 doctor — the posture mismatch as the operator sees it', () => {
  const POSTURE_SETTER = /--action-guard-[a-z]|guard posture (off|advisory|enforce)|SHIELDCORTEX_ENFORCE\s*=/;

  const mismatches: Array<[string, () => void, RegExp]> = [
    ['signed off, plugin entry enabling', () => {
      claudeHookWired();
      signed({ enabled: false });
      openclawEntry({ enabled: true, config: { actionGuard: { enabled: true } } });
    }, /would turn Action Guard off on that plane/],
    ['signed advisory, plugin entry enforcing', () => {
      claudeHookWired();
      signed({ enabled: true, enforce: false });
      openclawEntry({ enabled: true, config: { actionGuard: { enforce: true } } });
    }, /would drop that plane to advisory/],
  ];

  function rendered(verbose: boolean): string {
    const display = report.sanitiseDoctorRowsForDisplay([doctor.checkGuardPosture()]);
    return report.formatDoctorReport(display, {
      verbose,
      width: 80,
      nextCommand: report.nextCommandForFailures(display),
    }).join('\n');
  }

  describe.each([false, true])('formatDoctorReport (verbose=%s)', (verbose) => {
    it.each(mismatches)('%s: both consequences survive rendering and no posture command is prescribed', (_name, arrange, down) => {
      arrange();
      expect(doctor.checkGuardPosture().status).toBe('fail');
      const text = rendered(verbose);
      const flat = text.replace(/\s+/g, ' ');
      expect(flat).toMatch(down);
      expect(flat).toMatch(/Matching the signed setting up to the stricter plane would turn a plane up/);
      expect(flat).toMatch(/This row names no command/);
      const commands = text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('$ '));
      // The row's inspection step, then NEXT. Both read-only.
      expect(commands).toEqual(['$ shieldcortex guard posture --help', '$ shieldcortex doctor --verbose']);
      expect(text).not.toMatch(POSTURE_SETTER);
    });
  });

  const reply = (suggestedCommand: string, hypothesis = 'The OpenClaw plugin entry overrides the signed setting.') =>
    JSON.stringify({ hypothesis, citedLabels: ['Action guard posture'], suggestedCommand, confidence: 'high' });

  it.each(mismatches)('%s: --ai never prints a posture-changing suggestion', async (_name, arrange) => {
    arrange();
    const row = doctor.checkGuardPosture();
    expect(row.status).toBe('fail');
    for (const unsafe of [
      'shieldcortex config --action-guard-disable',
      'shieldcortex config --action-guard-advisory',
      'shieldcortex config --action-guard-enforce',
      'npx shieldcortex config --ACTION-GUARD-DISABLE',
      'openclaw config set plugins.entries.shieldcortex-realtime.config.actionGuard.enabled false',
      'openclaw plugins disable shieldcortex-realtime',
      'SHIELDCORTEX_ENFORCE=0 hermes gateway restart',
    ]) {
      const invoke = jest.fn(async () => reply(unsafe));
      const { lines, outcome } = await doctor.runDoctorAiSection([row], { invoke });
      expect(invoke).toHaveBeenCalledTimes(1);
      const text = lines.join('\n');
      expect(text).not.toContain(unsafe);
      expect(text).not.toMatch(POSTURE_SETTER);
      expect(outcome.result?.suggestedCommand).toBe('shieldcortex doctor --verbose');
      expect(text).toContain('suggested next command:');
      expect(text).toContain('shieldcortex doctor --verbose');
    }
  });

  it('--ai drops a hypothesis that itself prescribes a posture setter', async () => {
    mismatches[0][1]();
    const row = doctor.checkGuardPosture();
    const invoke = jest.fn(async () => reply('shieldcortex guard posture', 'Run shieldcortex config --action-guard-disable to make the planes agree.'));
    const { lines, outcome } = await doctor.runDoctorAiSection([row], { invoke });
    expect(outcome.result).toBeNull();
    expect(lines.join('\n')).not.toMatch(POSTURE_SETTER);
  });

  it.each([
    'shieldcortex guard posture',
    'shieldcortex guard posture --json',
    'shieldcortex doctor --verbose',
  ])('--ai still prints read-only inspection guidance: %s', async (safe) => {
    mismatches[0][1]();
    const row = doctor.checkGuardPosture();
    const invoke = jest.fn(async () => reply(safe));
    const { lines, outcome } = await doctor.runDoctorAiSection([row], { invoke });
    expect(outcome.result?.suggestedCommand).toBe(safe);
    expect(lines.join('\n')).toContain('suggested next command:');
    expect(lines.join('\n')).toContain(safe);
  });
});
