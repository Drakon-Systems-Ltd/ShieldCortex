/**
 * The realtime plugin's install spec (OpenClaw 2026.11.5 ClawHub default).
 *
 * Measured 19 Nov 2026: on OpenClaw 2026.11.5 an unprefixed
 * `@drakon-systems/shieldcortex-realtime@latest` resolved on ClawHub and
 * installed a stale 5.17.3 under a 5.20.2 CLI; `npm:…@5.20.2` fixed it. Every
 * install ShieldCortex runs, and every command it prints, must be the `npm:`
 * form pinned to the expected version. A host that predates `npm:` (OpenClaw
 * <= 2026.4.25 rejects any `:` with "unsupported npm spec: protocol specs are
 * not allowed") gets ONE bare retry — and only that refusal does.
 */
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  REALTIME_PLUGIN_PACKAGE,
  bareFallbackArgs,
  realtimePluginInstallArgs,
  realtimePluginInstallCommand,
  realtimePluginInstallSpec,
  rejectsNpmSourcePrefix,
  runWithNpmSourceFallbackSync,
} from '../openclaw-plugin-spec.js';
import { stepOpenClawPlugin } from '../../cli/update.js';
import { planReconcileActions, type ReconcileVerdict } from '../../integrations/openclaw-plugin-index.js';
import { summariseRepair } from '../repair-verdict.js';
import type { CapturedError } from '../../integrations/child-output.js';

/** OpenClaw <= 2026.4.25, src/infra/npm-registry-spec.ts, for any spec containing `:`. */
const PRE_NPM_PREFIX_REFUSAL = 'unsupported npm spec: protocol specs are not allowed';

/** Failures that must surface as they are — never a bare (or ClawHub) retry. */
const OTHER_FAILURES: Array<[string, string]> = [
  ['non-ClawHub consent', 'WARNING - Installing plugin from npm registry: npm:@drakon-systems/shieldcortex-realtime@5.20.2\nInstall cancelled; rerun with --force after reviewing the source.'],
  ['integrity', 'npm error code EINTEGRITY\nnpm error sha512-abc integrity checksum failed'],
  ['install policy', 'Plugin install blocked by security.installPolicy: package not allowed'],
  ['trust', 'plugin trust provenance-invalid: refusing to install'],
  ['network', 'npm error code ENOTFOUND\nnpm error network request to https://registry.npmjs.org failed'],
  ['package not found', 'npm error 404 Not Found - GET https://registry.npmjs.org/@drakon-systems%2fshieldcortex-realtime - Not found'],
  ['config invalid', 'OpenClaw config is invalid: /home/x/.openclaw/openclaw.json'],
];

describe('realtime plugin install spec — the one source of truth', () => {
  it('builds `npm:<package>@<exact version>`', () => {
    expect(REALTIME_PLUGIN_PACKAGE).toBe('@drakon-systems/shieldcortex-realtime');
    expect(realtimePluginInstallSpec('5.20.2')).toBe('npm:@drakon-systems/shieldcortex-realtime@5.20.2');
    expect(realtimePluginInstallArgs('5.20.2')).toEqual(
      ['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@5.20.2'],
    );
    expect(realtimePluginInstallCommand('5.20.2')).toBe(
      'openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@5.20.2',
    );
  });

  it('falls back to npm `@latest` — still npm, never bare — when the version is unknown or not semver', () => {
    for (const v of [null, undefined, '', 'unknown', 'latest', '5.20', '>=5.0.0', '5.20.2 ; rm -rf ~']) {
      expect(realtimePluginInstallSpec(v)).toBe('npm:@drakon-systems/shieldcortex-realtime@latest');
    }
  });

  it('keeps prereleases exact', () => {
    expect(realtimePluginInstallSpec('5.21.0-beta.1')).toBe('npm:@drakon-systems/shieldcortex-realtime@5.21.0-beta.1');
  });

  it('the bare form keeps the exact pin and drops only the prefix', () => {
    expect(realtimePluginInstallSpec('5.20.2', 'bare')).toBe('@drakon-systems/shieldcortex-realtime@5.20.2');
    expect(bareFallbackArgs(realtimePluginInstallArgs('5.20.2'))).toEqual(
      ['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@5.20.2'],
    );
    expect(bareFallbackArgs(['plugins', 'update', REALTIME_PLUGIN_PACKAGE])).toBeNull();
    expect(bareFallbackArgs(['plugins', 'install', '--force', 'npm:@other/pkg@1.0.0'])).toBeNull();
  });

  it('never produces a `clawhub:` spec', () => {
    for (const v of ['5.20.2', null]) {
      for (const src of ['npm', 'bare'] as const) {
        expect(realtimePluginInstallCommand(v, src)).not.toMatch(/clawhub:/i);
      }
    }
  });
});

describe('rejectsNpmSourcePrefix — the ONLY refusal that earns a bare retry', () => {
  it('matches the pre-`npm:` OpenClaw refusal, also inside the hook-pack fallback wrapper', () => {
    expect(rejectsNpmSourcePrefix(PRE_NPM_PREFIX_REFUSAL)).toBe(true);
    expect(rejectsNpmSourcePrefix(`Error: ${PRE_NPM_PREFIX_REFUSAL}\nAlso not a valid hook pack: ${PRE_NPM_PREFIX_REFUSAL}`)).toBe(true);
  });

  it.each(OTHER_FAILURES)('does not match a %s failure', (_label, said) => {
    expect(rejectsNpmSourcePrefix(said)).toBe(false);
  });
});

describe('runWithNpmSourceFallbackSync', () => {
  type R = { status: number; out: string };
  const outputOf = (r: R) => (r.status === 0 ? null : r.out);

  it('runs the npm: spec once when it succeeds', () => {
    const calls: string[][] = [];
    const res = runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), (a) => { calls.push(a); return { status: 0, out: '' }; }, outputOf);
    expect(calls).toEqual([realtimePluginInstallArgs('5.20.2')]);
    expect(res.fellBack).toBe(false);
  });

  it('retries ONCE with the bare exact spec when the host rejects `npm:`', () => {
    const calls: string[][] = [];
    const res = runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), (a) => {
      calls.push(a);
      return { status: 1, out: PRE_NPM_PREFIX_REFUSAL };
    }, outputOf);
    expect(calls).toEqual([
      ['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@5.20.2'],
      ['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@5.20.2'],
    ]);
    expect(res.fellBack).toBe(true);
    expect(res.args).toEqual(calls[1]);
    expect(res.result.status).toBe(1);
  });

  it.each(OTHER_FAILURES)('does NOT retry on a %s failure', (_label, said) => {
    const calls: string[][] = [];
    const res = runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), (a) => { calls.push(a); return { status: 1, out: said }; }, outputOf);
    expect(calls).toHaveLength(1);
    expect(res.fellBack).toBe(false);
  });

  it('does not retry a command that carries no npm: realtime spec', () => {
    const calls: string[][] = [];
    runWithNpmSourceFallbackSync(['plugins', 'update', REALTIME_PLUGIN_PACKAGE], (a) => { calls.push(a); return { status: 1, out: PRE_NPM_PREFIX_REFUSAL }; }, outputOf);
    expect(calls).toHaveLength(1);
  });
});

describe('remediation commands use the npm: pinned spec', () => {
  const verdict = (recommendedAction: ReconcileVerdict['recommendedAction']) =>
    ({ recommendedAction, expectedVersion: '5.20.2' }) as unknown as ReconcileVerdict;
  const plan = (action: ReconcileVerdict['recommendedAction']) => planReconcileActions(verdict(action), {
    pluginId: 'shieldcortex-realtime', packageName: REALTIME_PLUGIN_PACKAGE, expectedVersion: '5.20.2',
  });

  it.each(['reinstall-pinned', 'install'] as const)('%s runs `plugins install --force npm:…@<expected>`', (action) => {
    const commands = plan(action).filter((s) => s.command).map((s) => s.command);
    expect(commands).toEqual([realtimePluginInstallArgs('5.20.2')]);
  });

  it('the repair verdict names the npm: command pinned to the expected version', () => {
    const v = summariseRepair({
      applied: true,
      canaryConsented: false,
      expectedVersion: '5.20.2',
      selfCheck: { ok: false, rosterState: 'unproven', canaryProof: false, versionProof: false },
    } as Parameters<typeof summariseRepair>[0]);
    expect(v.nextCommand).toBe('openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@5.20.2');
  });
});

describe('`shieldcortex update` plugin step', () => {
  const CLI = '5.20.2';
  const NPM_ARGS = realtimePluginInstallArgs(CLI);
  const BARE_ARGS = realtimePluginInstallArgs(CLI, 'bare');
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-npm-pin-'));
    mkdirSync(join(home, '.openclaw', 'plugins'), { recursive: true });
    writeFileSync(join(home, '.openclaw', 'plugins', 'installs.json'),
      JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }));
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  type Call = { cmd: string; args: string[] };
  const refusal = (stderr: string) => Object.assign(new Error('exit 1: openclaw plugins install'), {
    exitCode: 1, command: 'openclaw plugins install', stdout: '', stderr,
  }) as CapturedError;

  /** Each install call takes the next scripted ending: `null` succeeds, a string is that refusal. */
  function scripted(endings: Array<string | null>) {
    const calls: Call[] = [];
    let i = 0;
    const run = (cmd: string, args: string[]) => {
      calls.push({ cmd, args });
      if (args[1] === 'list') return Promise.reject(refusal('no list'));
      const ending = endings[Math.min(i++, endings.length - 1)];
      return ending === null ? Promise.resolve({ stdout: '', stderr: '' }) : Promise.reject(refusal(ending));
    };
    return { run: run as never, calls, installs: () => calls.filter((c) => c.args[1] === 'install').map((c) => c.args) };
  }

  /** before, then after — what the on-disk read returns on successive calls. */
  const versions = (...seq: string[]) => {
    let i = 0;
    return () => seq[Math.min(i++, seq.length - 1)];
  };

  it('installs `npm:…@<expected>` — the version on disk now (readCliVersion), never `@latest`', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.17.3', CLI), readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS]);
    expect(f.installs().flat().join(' ')).not.toMatch(/@latest|clawhub:/);
    expect(r.status).toBe('ok');
  });

  it('a host that predates `npm:` gets ONE bare exact retry, and it lands', async () => {
    const f = scripted([PRE_NPM_PREFIX_REFUSAL, null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.20.1', CLI), readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS, BARE_ARGS]);
    expect(r.status).toBe('ok');
  });

  it('on that host the re-run command it prints is the bare form (the one the host accepts)', async () => {
    const f = scripted([PRE_NPM_PREFIX_REFUSAL, 'OpenClaw config is invalid: /x/openclaw.json']);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS, BARE_ARGS]);
    expect(r.status).toBe('warn');
    expect(r.rerun).toBe(`openclaw ${BARE_ARGS.join(' ')}`);
  });

  it.each(OTHER_FAILURES)('a %s failure is surfaced with no bare retry', async (_label, said) => {
    const f = scripted([said]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS]);
    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBe(realtimePluginInstallCommand(CLI));
  });

  it('an install that exits 0 but leaves the stale ClawHub 5.17.3 is plugin lag with the npm: command, not "up to date"', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.17.3', readCliVersion: () => CLI });
    expect(r.status).toBe('warn');
    expect(r.summary).toBe(`still v5.17.3 — CLI is v${CLI}`);
    expect(r.summary).not.toMatch(/up to date/);
    expect(r.rerun).toBe('openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@5.20.2');
  });

  it('a pinned install that lands any other version is not success either', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.20.1', '5.21.0'), readCliVersion: () => CLI });
    expect(r.status).toBe('warn');
    expect(r.summary).toBe(`5.20.1 → 5.21.0; v5.21.0 installed — CLI is v${CLI}`);
    expect(r.rerun).toBe(realtimePluginInstallCommand(CLI));
  });

  it('an unreadable CLI version still installs from npm (`@latest`), never bare', async () => {
    const f = scripted([null]);
    await stepOpenClawPlugin(home, {
      run: f.run,
      readPluginVersion: () => '5.20.1',
      readCliVersion: () => { throw new Error('ENOENT package.json'); },
    }).catch(() => undefined);
    expect(f.installs()[0]).toEqual(['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@latest']);
  });
});
