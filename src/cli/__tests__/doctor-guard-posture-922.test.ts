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
import {
  AI_POSTURE_READ_ONLY_COMMANDS,
  AI_POSTURE_SAFE_COMMAND,
  AI_POSTURE_SAFE_HYPOTHESIS,
} from '../../defence/iron-dome/doctor-explainer.js';
import type { CheckResult } from '../doctor.js';

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

  it.each([
    'shieldcortex guard posture',
    'shieldcortex guard posture --json',
    'shieldcortex doctor',
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

  /*
   * #1037 r2 (Astra B2): for a posture finding the printed next step comes
   * from a closed set of read-only inspection commands. Each command below
   * reached the operator verbatim through the old denylist. Several of them
   * match no denylist spelling at all, so only the closed set stops them.
   */
  it.each([
    'hermes plugins disable shieldcortex',
    'openclaw plugins "disable" shieldcortex-realtime',
    'openclaw config set plugins.enabled false',
    'openclaw --profile work plugins disable shieldcortex-realtime',
    "openclaw plugins 'disable' shieldcortex-realtime",
    'openclaw plugins dis\\able shieldcortex-realtime',
    'shieldcortex guard posture; shieldcortex config --action-guard-disable',
    'shieldcortex guard posture && hermes plugins disable shieldcortex',
    'shieldcortex doctor --verbose | sh',
    'shieldcortex guard posture $(hermes plugins disable shieldcortex)',
    'env SHIELDCORTEX_ENFORCE=0 hermes gateway restart',
    'sed -i s/true/false/ ~/.openclaw/openclaw.json',
    'shieldcortex repair',
  ])('--ai replaces any command outside the read-only set: %s', async (unsafe) => {
    for (const [, arrange] of mismatches) {
      arrange();
      const row = doctor.checkGuardPosture();
      expect(row.status).toBe('fail');
      const invoke = jest.fn(async () => reply(unsafe));
      const { lines, outcome } = await doctor.runDoctorAiSection([row], { invoke });
      expect(invoke).toHaveBeenCalledTimes(1);
      const text = lines.join('\n');
      expect(text).not.toContain(unsafe);
      expect(text).not.toMatch(/plugins? +["']?dis|config set|SHIELDCORTEX_ENFORCE=|--action-guard-/);
      expect(outcome.result?.suggestedCommand).toBe(AI_POSTURE_SAFE_COMMAND);
      expect(text).toContain('suggested next command:');
      expect(text).toContain(AI_POSTURE_SAFE_COMMAND);
      // The model's hypothesis is never shown on a posture-governed result,
      // however descriptive it is.
      expect(outcome.result?.hypothesis).toBe(AI_POSTURE_SAFE_HYPOTHESIS);
    }
  });

  it('--ai normalises whitespace before matching the read-only set', async () => {
    mismatches[0][1]();
    const row = doctor.checkGuardPosture();
    const invoke = jest.fn(async () => reply('  shieldcortex   guard\tposture  '));
    const { lines, outcome } = await doctor.runDoctorAiSection([row], { invoke });
    expect(outcome.result?.suggestedCommand).toBe('shieldcortex guard posture');
    expect(lines.join('\n')).toContain('suggested next command:');
  });

  /*
   * #1037 r2 (Astra B2), the hypothesis channel: with a safe command, a
   * hypothesis that prescribes a posture change in prose is replaced with a
   * fixed sentence. The citations and confidence stay; the prescription does not.
   * Since the adjudicated fix every hypothesis is replaced on a posture-governed
   * result, not only a prescriptive one (see the never-prints test below).
   */
  const ZWSP = String.fromCharCode(0x200b);
  const CYRILLIC_I = String.fromCharCode(0x456);
  it.each([
    'Run hermes plugins disable shieldcortex to align the planes.',
    'Run `shieldcortex config --action-guard-disable` to make the planes agree.',
    'The fix is openclaw plugins "disable" shieldcortex-realtime.',
    'Disable the Hermes plugin so the planes agree.',
    'Disabling the ShieldCortex plugin in Hermes would make the planes agree.',
    'Removing shieldcortex-realtime from the OpenClaw plugins list would align them.',
    'Turn the OpenClaw plugin entry off to match the signed setting.',
    'Switch the Claude Code hook to advisory so it matches the plugin.',
    'Setting SHIELDCORTEX_ENFORCE=0 in the Hermes gateway environment would align it.',
    'Set enforce false on the plugin entry.',
    'Uninstall the OpenClaw plugin.',
    'Stop the OpenClaw plugin from gating.',
    'Use openclaw config set plugins.enabled false and restart.',
    `Dis${ZWSP}able the Hermes plugin so the planes agree.`,
    `D${CYRILLIC_I}sable the Hermes plugin so the planes agree.`,
  ])('--ai replaces a hypothesis that prescribes a posture change: %s', async (hypothesis) => {
    mismatches[0][1]();
    const row = doctor.checkGuardPosture();
    const invoke = jest.fn(async () => reply('shieldcortex guard posture', hypothesis));
    const { lines, outcome } = await doctor.runDoctorAiSection([row], { invoke });
    expect(invoke).toHaveBeenCalledTimes(1);
    const text = lines.join('\n');
    expect(outcome.result?.hypothesis).toBe(AI_POSTURE_SAFE_HYPOTHESIS);
    expect(outcome.result?.suggestedCommand).toBe('shieldcortex guard posture');
    expect(outcome.result?.citedLabels).toEqual(['Action guard posture']);
    expect(outcome.result?.confidence).toBe('high');
    expect(text).not.toContain(hypothesis);
    expect(text).toContain(AI_POSTURE_SAFE_HYPOTHESIS);
    expect(text).not.toMatch(POSTURE_SETTER);
    expect(text).not.toMatch(/disable|uninstall|remov|turn .*off|SHIELDCORTEX_ENFORCE/i);
  });

  it('the fixed posture hypothesis itself prescribes nothing', () => {
    expect(AI_POSTURE_SAFE_HYPOTHESIS).not.toMatch(/`|--|\brun\b|disable|uninstall|remov|turn|off\b|advisory|SHIELDCORTEX_ENFORCE/i);
  });

  /*
   * #1037 adjudication: a denylist cannot tell a prescription from a
   * description ("align the plugin with the signed setting" turns it off when
   * the signed setting is off), so while the posture row fails the model's
   * hypothesis is never printed, whatever it says. The line under the
   * `Hypothesis (` header is the fixed sentence and the command is from the
   * closed read-only set. Each prescriptive sentence below printed verbatim
   * before this fix; the last three are descriptive and were kept verbatim.
   */
  const COMBINING_LOW_LINE = String.fromCharCode(0x332);
  const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');
  function printedHypothesisLine(lines: string[]): string | undefined {
    const printed = strip(lines.join('\n')).split('\n');
    const header = printed.findIndex((l) => l.trim().startsWith('Hypothesis ('));
    return header === -1 ? undefined : printed[header + 1]?.trim();
  }
  it.each([
    'For the OpenClaw plugin, use advisory instead of enforcement.',
    'Ensure the Hermes ShieldCortex plugin is disabled so the planes agree.',
    'The Hermes plugin should be disabled to align the planes.',
    'The OpenClaw plugin should be disabled so the planes agree.',
    'The hook should be turned off.',
    'The hook should be switched to advisory.',
    'The OpenClaw plugin should be off.',
    'The hook ought to be advisory.',
    'Advisory on the Claude Code hook would make the planes agree.',
    'SHIELDCORTEX_ENFORCE should be 0 so Hermes matches the signed setting.',
    'Opt Hermes out of enforcement so the planes agree.',
    'Shut the OpenClaw plugin down so the planes agree.',
    'Align the OpenClaw plugin with the signed setting so the planes agree.',
    `Dis${COMBINING_LOW_LINE}able the Hermes plugin so the planes agree.`,
    'The OpenClaw plugin entry overrides the signed setting.',
    'The OpenClaw plugin entry is stricter than the signed config, so the two planes disagree.',
    'Hermes reads its posture from the gateway environment, not from config.json, so it can differ from the hook.',
  ])("--ai never prints the model's hypothesis for a failing posture row: %s", async (hypothesis) => {
    for (const [, arrange] of mismatches) {
      arrange();
      const row = doctor.checkGuardPosture();
      expect(row.status).toBe('fail');
      const invoke = jest.fn(async () => reply('shieldcortex guard posture', hypothesis));
      const { lines, outcome } = await doctor.runDoctorAiSection([row], { invoke });
      expect(invoke).toHaveBeenCalledTimes(1);
      expect(outcome.result?.hypothesis).toBe(AI_POSTURE_SAFE_HYPOTHESIS);
      expect(printedHypothesisLine(lines)).toBe(AI_POSTURE_SAFE_HYPOTHESIS);
      expect(strip(lines.join('\n'))).not.toContain(hypothesis);
      expect(AI_POSTURE_READ_ONLY_COMMANDS).toContain(outcome.result?.suggestedCommand);
      expect(outcome.result?.citedLabels).toEqual(['Action guard posture']);
      expect(outcome.result?.confidence).toBe('high');
    }
  });

  /*
   * Which results the read-only set governs: the posture row is failing
   * (whatever the model cites), or the model cites the posture row (whatever
   * its status). A default-off box shows the posture row as a warn beside
   * every unrelated failure, so a warn the model does not cite leaves
   * unrelated advice alone — the denylist still applies there.
   */
  const dbFail: CheckResult = { label: 'Database', status: 'fail', message: 'schema is behind by 2 migrations' };
  const citing = (labels: string[], suggestedCommand: string, hypothesis = 'The database schema is behind.') =>
    JSON.stringify({ hypothesis, citedLabels: labels, suggestedCommand, confidence: 'medium' });

  it('a failing posture row governs the result even when the model cites only another finding', async () => {
    for (const [, arrange] of mismatches) {
      arrange();
      const row = doctor.checkGuardPosture();
      expect(row.status).toBe('fail');
      const invoke = jest.fn(async () => citing(['Database'], 'hermes plugins "disable" shieldcortex', 'Run hermes plugins disable shieldcortex first.'));
      const { lines, outcome } = await doctor.runDoctorAiSection([row, dbFail], { invoke });
      expect(outcome.result?.citedLabels).toEqual(['Database']);
      expect(outcome.result?.suggestedCommand).toBe(AI_POSTURE_SAFE_COMMAND);
      expect(AI_POSTURE_READ_ONLY_COMMANDS).toContain(outcome.result?.suggestedCommand);
      expect(outcome.result?.hypothesis).toBe(AI_POSTURE_SAFE_HYPOTHESIS);
      expect(printedHypothesisLine(lines)).toBe(AI_POSTURE_SAFE_HYPOTHESIS);
      expect(lines.join('\n')).not.toMatch(/hermes plugins/);
    }
  });

  it('a warn posture row the model cites governs the result too', async () => {
    claudeHookWired();
    const row = doctor.checkGuardPosture();
    expect(row.status).toBe('warn');
    const invoke = jest.fn(async () => citing(['Action guard posture', 'Database'], 'hermes plugins disable shieldcortex'));
    const { outcome } = await doctor.runDoctorAiSection([row, dbFail], { invoke });
    expect(outcome.result?.suggestedCommand).toBe(AI_POSTURE_SAFE_COMMAND);
  });

  it('a default-off warn posture row the model does not cite leaves unrelated advice alone', async () => {
    claudeHookWired();
    const row = doctor.checkGuardPosture();
    expect(row.status).toBe('warn');
    const invoke = jest.fn(async () => citing(['Database'], 'shieldcortex repair'));
    const { outcome } = await doctor.runDoctorAiSection([row, dbFail], { invoke });
    expect(outcome.result?.suggestedCommand).toBe('shieldcortex repair');
    expect(outcome.result?.hypothesis).toBe('The database schema is behind.');
  });

  it.each([
    'hermes plugins disable shieldcortex',
    'openclaw plugins "disable" shieldcortex-realtime',
    'openclaw config set plugins.enabled false',
    'openclaw --profile work plugins disable shieldcortex-realtime',
  ])('outside the read-only set the denylist still replaces a plane-changing command: %s', async (unsafe) => {
    claudeHookWired();
    const row = doctor.checkGuardPosture();
    const invoke = jest.fn(async () => citing(['Database'], unsafe));
    const { lines, outcome } = await doctor.runDoctorAiSection([row, dbFail], { invoke });
    expect(outcome.result?.suggestedCommand).toBe(AI_POSTURE_SAFE_COMMAND);
    expect(lines.join('\n')).not.toContain(unsafe);
  });

  it('outside the read-only set a hypothesis naming a plane-changing command is not shown', async () => {
    claudeHookWired();
    const row = doctor.checkGuardPosture();
    const invoke = jest.fn(async () => citing(['Database'], 'shieldcortex repair', 'Run hermes plugins "disable" shieldcortex first.'));
    const { lines, outcome } = await doctor.runDoctorAiSection([row, dbFail], { invoke });
    expect(outcome.result).toBeNull();
    expect(lines.join('\n')).not.toMatch(/hermes plugins/);
  });
});

/**
 * #1063: signed advisory with one plane above it (the OpenClaw plugin entry
 * enforcing) and one below it (Hermes reporting intentionally off), read from
 * fixture files through the real readers. The human report must state both
 * consequences — matching the stricter plane down, and putting the looser plane
 * on the signed setting — and still prescribe no posture-changing command.
 */
describe('#1063 doctor — mixed stricter and looser planes, as the operator sees it', () => {
  const POSTURE_SETTER = /--action-guard-[a-z]|guard posture (off|advisory|enforce)|SHIELDCORTEX_ENFORCE\s*=/;

  function arrangeMixed(): CheckResult {
    claudeHookWired();
    hermesPluginArtefacts(home);
    signed({ enabled: true, enforce: false });
    openclawEntry({ enabled: true, config: { actionGuard: { enforce: true } } });
    writeReport(configDir, reportBody({ configured_posture: 'intentionally-off' }));
    return doctor.checkGuardPosture({ read: { home, collect: { nowMs: NOW, deps: LIVE } } });
  }

  it.each([false, true])('verbose=%s: both directions survive rendering and no posture command is prescribed', (verbose) => {
    const row = arrangeMixed();
    expect(row.status).toBe('fail');
    expect(row.message).toMatch(/Claude Code hook advisory/);
    expect(row.message).toMatch(/OpenClaw plugin enforce/);
    expect(row.message).toMatch(/Hermes off \(self-report\)/);
    const display = report.sanitiseDoctorRowsForDisplay([row]);
    const text = report.formatDoctorReport(display, {
      verbose,
      width: 80,
      nextCommand: report.nextCommandForFailures(display),
    }).join('\n');
    const flat = text.replace(/\s+/g, ' ');
    expect(flat).toMatch(/Matching the stricter plane down to the signed setting would drop that plane to advisory/);
    expect(flat).toMatch(/Putting a looser plane on the signed setting would turn that plane up/);
    expect(flat).toMatch(/Matching the signed setting up to the stricter plane would turn a plane up/);
    expect(flat).toMatch(/This row names no command/);
    const commands = text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('$ '));
    expect(commands).toEqual(['$ shieldcortex guard posture --help', '$ shieldcortex doctor --verbose']);
    expect(text).not.toMatch(POSTURE_SETTER);
  });
});

/**
 * #1063 r1: signed enforce-when-ready. The hook holds the signed value and the
 * plugin's readiness gate comes from the signed file, so the only plane that
 * can sit above it is Hermes, which has no enforce-when-ready posture. The
 * rendered row must say that, keep the looser-plugin and signed-setting-up
 * directions, and never promise Hermes a readiness-gated shadow.
 */
describe('#1063 doctor — signed enforce-when-ready with Hermes the stricter plane', () => {
  const POSTURE_SETTER = /--action-guard-[a-z]|guard posture (off|advisory|enforce)|SHIELDCORTEX_ENFORCE\s*=/;
  const HERMES_NO_GATE =
    'Hermes cannot be matched down to the signed setting: it has no enforce-when-ready posture. ' +
    'It enforces, or an explicit SHIELDCORTEX_ENFORCE opt-out makes it advisory.';
  const REST =
    'Putting a looser plane on the signed setting would turn that plane up. ' +
    'Matching the signed setting up to the stricter plane would turn a plane up. ' +
    'This row names no command.';
  const HERMES_NOTE =
    'Hermes takes its posture from SHIELDCORTEX_ENFORCE in the Hermes gateway environment, not from config.json; ' +
    'no ShieldCortex command changes it today.';

  function arrangeWhenReady(): CheckResult {
    claudeHookWired();
    hermesPluginArtefacts(home);
    signed({ enabled: true, readinessGate: true });
    openclawEntry({ enabled: true, config: { actionGuard: { enforce: false } } });
    writeReport(configDir, reportBody({ configured_posture: 'enforce' }));
    return doctor.checkGuardPosture({ read: { home, collect: { nowMs: NOW, deps: LIVE } } });
  }

  it.each([false, true])('verbose=%s: the Hermes limitation is rendered in full and no posture command is prescribed', (verbose) => {
    const row = arrangeWhenReady();
    expect(row.status).toBe('fail');
    expect(row.message).toMatch(/Claude Code hook enforce-when-ready/);
    expect(row.message).toMatch(/OpenClaw plugin advisory/);
    expect(row.message).toMatch(/Hermes enforce \(self-report\)/);
    const display = report.sanitiseDoctorRowsForDisplay([row]);
    const text = report.formatDoctorReport(display, {
      verbose,
      width: 80,
      nextCommand: report.nextCommandForFailures(display),
    }).join('\n');
    const flat = text.replace(/\s+/g, ' ');
    expect(flat).toContain(`${HERMES_NO_GATE} ${REST}`);
    expect(flat).toContain(HERMES_NOTE);
    expect(flat).not.toMatch(/drop that plane to enforce-when-ready|readiness conditions|stays in shadow/);
    const commands = text.split('\n').map((l) => l.trim()).filter((l) => l.startsWith('$ '));
    expect(commands).toEqual(['$ shieldcortex guard posture --help', '$ shieldcortex doctor --verbose']);
    expect(text).not.toMatch(POSTURE_SETTER);
  });
});
