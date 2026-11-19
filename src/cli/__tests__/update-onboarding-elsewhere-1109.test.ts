import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * #1109 round 5 (Astra B5) — after npm updated a DIFFERENT ShieldCortex
 * install (A runs `update`, npm advances B), `runUpdate` refused the plugin
 * step and the protection reconcile, but still offered to wire present,
 * unwired hosts. Accepting at a terminal ran A's own OpenClaw installer
 * (`wireHost('openclaw')` → `handleOpenClawCommand('install')`), pinning the
 * realtime plugin to A's old version.
 *
 * The chain here is the one `runUpdate` runs from the hand-off on: the real
 * hand-off answer, the real classification, the real plugin step, the real
 * host scan and offer with a TTY and every prompt accepted, and the real exit
 * decision. Only the installer entry the offer would call is replaced, so a
 * reached install is recorded instead of touching this machine's OpenClaw.
 * The control case (`updated`) proves the same harness does reach it.
 */

const questions: string[] = [];
jest.unstable_mockModule('readline/promises', () => {
  const createInterface = () => ({
    question: async (q: string) => { questions.push(q); return 'y'; },
    close: () => {},
  });
  return { default: { createInterface }, createInterface };
});

// No child process of any kind may start from A in the cross-root state.
const childCalls: unknown[][] = [];
const recordChild = (name: string) => (...args: unknown[]) => {
  childCalls.push([name, ...args]);
  throw new Error(`child_process.${name} must not be reached`);
};
const childProcess = {
  execFileSync: recordChild('execFileSync'),
  execSync: recordChild('execSync'),
  spawnSync: recordChild('spawnSync'),
  spawn: recordChild('spawn'),
  execFile: recordChild('execFile'),
  exec: recordChild('exec'),
};
jest.unstable_mockModule('child_process', () => ({ ...childProcess, default: childProcess }));

const actualOpenClaw = await import('../../setup/openclaw.js');
const installerCalls: unknown[][] = [];
jest.unstable_mockModule('../../setup/openclaw.js', () => ({
  ...actualOpenClaw,
  handleOpenClawCommand: async (...args: unknown[]) => { installerCalls.push(args); },
}));

const {
  coreUpdateOutcome,
  reexecUpdatedCli,
  stepOfferUnwiredHosts,
  stepOpenClawPlugin,
  updateVerdict,
} = await import('../update.js');

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const A = '5.20.2';
const B = '5.21.0';
const PLUGIN = 'shieldcortex-realtime';

let home: string;
let stdout: string[];
let logs: string[];
const savedOpenClawHome = process.env.OPENCLAW_HOME;
const ttyDescriptors = {
  stdin: Object.getOwnPropertyDescriptor(process.stdin, 'isTTY'),
  stdout: Object.getOwnPropertyDescriptor(process.stdout, 'isTTY'),
};

function writeOpenClawHost(plugin: 'missing' | 'disabled'): string {
  const oc = path.join(home, '.openclaw');
  fs.mkdirSync(oc, { recursive: true });
  // OpenClaw is present: a config and a binary in a probed location.
  const bin = path.join(home, '.npm-global', 'bin');
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, 'openclaw'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const enabled = plugin === 'missing';
  fs.writeFileSync(path.join(oc, 'openclaw.json'), JSON.stringify({
    plugins: { allow: [PLUGIN], entries: { [PLUGIN]: { enabled } } },
  }));
  if (plugin === 'disabled') {
    // Bytes present, entry disabled: still unwired.
    const ext = path.join(oc, 'extensions', PLUGIN);
    fs.mkdirSync(ext, { recursive: true });
    fs.writeFileSync(path.join(ext, 'index.js'), 'export default {};\n');
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: '5.17.3' }));
  }
  return oc;
}

function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else out[path.relative(dir, p)] = fs.readFileSync(p, 'utf8');
    }
  };
  walk(dir);
  return out;
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc1109-onboard-'));
  delete process.env.OPENCLAW_HOME;
  questions.length = 0;
  childCalls.length = 0;
  installerCalls.length = 0;
  stdout = [];
  logs = [];
  Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
  Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
  jest.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    stdout.push(String(chunk));
    return true;
  }) as typeof process.stdout.write);
  jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { logs.push(a.join(' ')); });
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const [stream, d] of [[process.stdin, ttyDescriptors.stdin], [process.stdout, ttyDescriptors.stdout]] as const) {
    if (d) Object.defineProperty(stream, 'isTTY', d);
    else delete (stream as { isTTY?: boolean }).isTTY;
  }
  if (savedOpenClawHome === undefined) delete process.env.OPENCLAW_HOME;
  else process.env.OPENCLAW_HOME = savedOpenClawHome;
  fs.rmSync(home, { recursive: true, force: true });
});

describe('#1109 round 5 (Astra B5) — no host onboarding from A when npm updated B', () => {
  it.each(['missing', 'disabled'] as const)(
    'plugin %s, TTY, every prompt accepted: no realtime install from A, recovery named',
    async (plugin) => {
      const oc = writeOpenClawHost(plugin);
      const before = snapshot(oc);

      // The hand-off: npm said it installed B, A's package.json still reads A.
      const launch = jest.fn(async () => 0);
      const handoff = await reexecUpdatedCli(A, { readVersion: () => A, env: {}, launch });
      expect(launch).not.toHaveBeenCalled();
      const coreUpdate = coreUpdateOutcome({
        mainUpdated: true, npmStatus: 'ok', reexeced: false, latestVersion: B, currentVersion: A, handoff,
      });
      expect(coreUpdate).toBe('elsewhere');

      const runs: unknown[] = [];
      const pluginResult = await stepOpenClawPlugin(home, {
        coreUpdate,
        readCliVersion: () => A,
        run: (async (...args: unknown[]) => { runs.push(args); return { stdout: '', stderr: '' }; }) as never,
      });

      stdout.length = 0;
      await stepOfferUnwiredHosts(home, { currentVersion: A, coreUpdate });

      // No install of any kind from A: not the installer the offer calls, not
      // a command from the plugin step, not any child process.
      expect(installerCalls).toEqual([]);
      expect(runs).toEqual([]);
      expect(childCalls).toEqual([]);
      expect(questions).toEqual([]);
      expect(snapshot(oc)).toEqual(before);

      const out = stdout.join('');
      expect(out).toContain('host setup not offered');
      expect(out).toContain('npm updated a different ShieldCortex install than the one running this update');
      expect(out).toContain('run `shieldcortex update` with the shieldcortex npm just updated first on PATH');
      expect(out).not.toContain(`v${A}`);
      expect(logs.join('\n')).not.toMatch(/does not silently wire|Present but not wired/);

      if (plugin === 'disabled') {
        // Plugin bytes on disk: the plugin step's incomplete result and its
        // recovery still reach the exit decision.
        expect(pluginResult.unfinished).toBe(true);
        expect(pluginResult.recovery?.command).toBe('shieldcortex update');
        expect(updateVerdict({ failed: false, attention: true, unfinished: pluginResult.unfinished === true }))
          .toEqual({ exitCode: 1, verdict: 'INCOMPLETE' });
      } else {
        // Never installed: the plugin step has nothing to refresh, as before.
        expect(pluginResult).toMatchObject({ status: 'skip', summary: 'not installed' });
      }
    },
  );

  it.each(['missing', 'disabled'] as const)(
    'control — plugin %s, same install updated: the same harness does reach the OpenClaw installer',
    async (plugin) => {
      writeOpenClawHost(plugin);

      await stepOfferUnwiredHosts(home, { currentVersion: B, coreUpdate: 'updated' });

      expect(questions).toEqual([
        'Wire the unwired hosts? [Y/n] ',
        'Install ShieldCortex for OpenClaw? [Y/n] ',
      ]);
      expect(installerCalls).toEqual([['install']]);
      expect(stdout.join('')).not.toContain('host setup not offered');
    },
  );

  it('runUpdate hands its own classification to the onboarding step, and has no other offer', () => {
    const src = fs.readFileSync(path.join(root, 'src/cli/update.ts'), 'utf8');
    const body = src.slice(src.indexOf('export async function runUpdate'));
    expect(body).toMatch(/const coreUpdate: CoreUpdateOutcome = coreUpdateOutcome\(/);
    expect(body).toContain('await stepOfferUnwiredHosts(home, { currentVersion, coreUpdate });');
    expect(body).not.toContain('offerUnwiredHosts(');
    expect(body.indexOf('await stepOfferUnwiredHosts')).toBeGreaterThan(body.indexOf('const coreUpdate'));
  });
});
