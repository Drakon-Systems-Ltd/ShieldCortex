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
import { existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  BareRetryBudget,
  LEGACY_NPM_PROTOCOL_REFUSAL,
  REALTIME_PLUGIN_PACKAGE,
  assessRealtimeReplacement,
  bareFallbackArgs,
  exactPluginPin,
  isLegacyNpmProtocolRefusal,
  landedVersionVerdict,
  readLinkedRealtimeInstall,
  realtimePluginInstallArgs,
  realtimePluginInstallCommand,
  realtimePluginInstallSpec,
  runWithNpmSourceFallbackSync,
} from '../openclaw-plugin-spec.js';
import { stepOpenClawPlugin, updateVerdict, type PluginPublishCheck } from '../../cli/update.js';
import { planReconcileActions, type ReconcileVerdict } from '../../integrations/openclaw-plugin-index.js';
import { summariseRepair } from '../repair-verdict.js';
import type { CapturedError } from '../../integrations/child-output.js';

/** OpenClaw <= 2026.4.25, src/infra/npm-registry-spec.ts, for any spec containing `:`. */
const PRE_NPM_PREFIX_REFUSAL = 'unsupported npm spec: protocol specs are not allowed';
/** What OpenClaw <= 2026.4.25 really prints on stderr: the plugin refusal, then the hook-pack fallback's echo. */
const PRE_NPM_PREFIX_STDERR = `${PRE_NPM_PREFIX_REFUSAL}\nAlso not a valid hook pack: ${PRE_NPM_PREFIX_REFUSAL}`;

/** Failures that must surface as they are — never a bare (or ClawHub) retry. */
const OTHER_FAILURES: Array<[string, string]> = [
  ['non-ClawHub consent', 'WARNING - Installing plugin from npm registry: npm:@drakon-systems/shieldcortex-realtime@5.20.2\nInstall cancelled; rerun with --force after reviewing the source.'],
  ['integrity', 'npm error code EINTEGRITY\nnpm error sha512-abc integrity checksum failed'],
  ['install policy', 'Plugin install blocked by security.installPolicy: package not allowed'],
  ['trust', 'plugin trust provenance-invalid: refusing to install'],
  ['secret-ref', 'gateway.auth.token is configured as a secret reference but is unavailable in this command path.'],
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

  it('an automated install REFUSES anything but an exact version — no floating install, npm or bare', () => {
    for (const v of ['', 'unknown', 'latest', '5.20', '>=5.0.0', '^5.20.2', '5.20.2 ; rm -rf ~']) {
      expect(exactPluginPin(v)).toBeNull();
      expect(() => realtimePluginInstallArgs(v)).toThrow(/exact version/);
      expect(() => realtimePluginInstallArgs(v, 'bare')).toThrow(/exact version/);
    }
  });

  it('only a printed hint for a human may say `@latest`, and only when the version is unknown — still npm', () => {
    for (const v of [null, undefined, '', 'unknown', '5.20']) {
      expect(realtimePluginInstallCommand(v)).toBe('openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@latest');
    }
  });

  it('keeps prereleases exact', () => {
    expect(realtimePluginInstallSpec('5.21.0-beta.1')).toBe('npm:@drakon-systems/shieldcortex-realtime@5.21.0-beta.1');
  });

  it('the bare form keeps the exact pin and drops only the prefix; nothing floating is ever made bare', () => {
    expect(realtimePluginInstallSpec('5.20.2', 'bare')).toBe('@drakon-systems/shieldcortex-realtime@5.20.2');
    expect(bareFallbackArgs(realtimePluginInstallArgs('5.20.2'))).toEqual(
      ['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@5.20.2'],
    );
    expect(bareFallbackArgs(['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@latest'])).toBeNull();
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

describe('isLegacyNpmProtocolRefusal — the ONLY output that earns a bare retry', () => {
  it('matches the pre-`npm:` refusal as an anchored stderr line, with or without the hook-pack echo', () => {
    expect(LEGACY_NPM_PROTOCOL_REFUSAL).toBe(PRE_NPM_PREFIX_REFUSAL);
    expect(isLegacyNpmProtocolRefusal({ stderr: PRE_NPM_PREFIX_REFUSAL })).toBe(true);
    expect(isLegacyNpmProtocolRefusal({ stderr: PRE_NPM_PREFIX_STDERR, stdout: '' })).toBe(true);
    expect(isLegacyNpmProtocolRefusal({ stderr: `Error: ${PRE_NPM_PREFIX_REFUSAL}\n` })).toBe(true);
    expect(isLegacyNpmProtocolRefusal({ stderr: `\u001b[31m${PRE_NPM_PREFIX_REFUSAL}\u001b[39m` })).toBe(true);
  });

  it('NOT when the phrase is on stdout only', () => {
    expect(isLegacyNpmProtocolRefusal({ stderr: '', stdout: PRE_NPM_PREFIX_REFUSAL })).toBe(false);
    expect(isLegacyNpmProtocolRefusal({ stderr: 'exit 1', stdout: PRE_NPM_PREFIX_STDERR })).toBe(false);
  });

  it('NOT when the phrase is quoted inside a longer stderr line', () => {
    expect(isLegacyNpmProtocolRefusal({ stderr: `plugin said: "${PRE_NPM_PREFIX_REFUSAL}"` })).toBe(false);
    expect(isLegacyNpmProtocolRefusal({ stderr: `warning: earlier run hit ${PRE_NPM_PREFIX_REFUSAL}` })).toBe(false);
  });

  it.each(OTHER_FAILURES)('NOT when the refusal line comes with a %s failure (on stderr)', (_label, said) => {
    expect(isLegacyNpmProtocolRefusal({ stderr: said })).toBe(false);
    expect(isLegacyNpmProtocolRefusal({ stderr: `${PRE_NPM_PREFIX_REFUSAL}\n${said}` })).toBe(false);
    expect(isLegacyNpmProtocolRefusal({ stderr: `${said}\n${PRE_NPM_PREFIX_STDERR}` })).toBe(false);
  });

  it.each(OTHER_FAILURES)('NOT when the refusal line comes with a %s failure (on stdout)', (_label, said) => {
    expect(isLegacyNpmProtocolRefusal({ stderr: PRE_NPM_PREFIX_STDERR, stdout: said })).toBe(false);
  });

  it('NOT when a different `unsupported npm spec` reason is in the output too', () => {
    expect(isLegacyNpmProtocolRefusal({
      stderr: `${PRE_NPM_PREFIX_REFUSAL}\nunsupported npm spec: use an exact version or dist-tag (ranges are not allowed)`,
    })).toBe(false);
  });
});

describe('runWithNpmSourceFallbackSync + BareRetryBudget', () => {
  type R = { status: number; stderr: string; stdout?: string };
  const failureOf = (r: R) => (r.status === 0 ? null : { stderr: r.stderr, stdout: r.stdout ?? '' });

  it('runs the npm: spec once when it succeeds', () => {
    const calls: string[][] = [];
    const budget = new BareRetryBudget();
    const res = runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), (a) => { calls.push(a); return { status: 0, stderr: '' }; }, failureOf, budget);
    expect(calls).toEqual([realtimePluginInstallArgs('5.20.2')]);
    expect(res.fellBack).toBe(false);
    expect(budget.spent).toBe(false);
  });

  it('retries ONCE with the bare exact spec when the host rejects `npm:`', () => {
    const calls: string[][] = [];
    const res = runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), (a) => {
      calls.push(a);
      return { status: 1, stderr: PRE_NPM_PREFIX_STDERR };
    }, failureOf, new BareRetryBudget());
    expect(calls).toEqual([
      ['plugins', 'install', '--force', 'npm:@drakon-systems/shieldcortex-realtime@5.20.2'],
      ['plugins', 'install', '--force', '@drakon-systems/shieldcortex-realtime@5.20.2'],
    ]);
    expect(res.fellBack).toBe(true);
    expect(res.args).toEqual(calls[1]);
    expect(res.result.status).toBe(1);
  });

  it('the budget is per OPERATION: a second install in the same operation gets no second bare run', () => {
    const calls: string[][] = [];
    const budget = new BareRetryBudget();
    const run = (a: string[]) => { calls.push(a); return { status: 1, stderr: PRE_NPM_PREFIX_STDERR }; };
    runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), run, failureOf, budget);
    const second = runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), run, failureOf, budget);
    expect(second.fellBack).toBe(false);
    expect(calls.filter((a) => !a[3].startsWith('npm:'))).toHaveLength(1);
    expect(calls).toHaveLength(3);
  });

  it.each(OTHER_FAILURES)('does NOT retry on a %s failure, even when the refusal line is there too', (_label, said) => {
    for (const stderr of [said, `${PRE_NPM_PREFIX_STDERR}\n${said}`]) {
      const calls: string[][] = [];
      const budget = new BareRetryBudget();
      const res = runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), (a) => { calls.push(a); return { status: 1, stderr }; }, failureOf, budget);
      expect(calls).toHaveLength(1);
      expect(res.fellBack).toBe(false);
      expect(budget.spent).toBe(false);
    }
  });

  it('does NOT retry when the refusal phrase is only on stdout', () => {
    const calls: string[][] = [];
    runWithNpmSourceFallbackSync(realtimePluginInstallArgs('5.20.2'), (a) => { calls.push(a); return { status: 1, stderr: 'exit 1', stdout: PRE_NPM_PREFIX_REFUSAL }; }, failureOf, new BareRetryBudget());
    expect(calls).toHaveLength(1);
  });

  it('does not retry a command that carries no exact npm: realtime spec', () => {
    const calls: string[][] = [];
    runWithNpmSourceFallbackSync(['plugins', 'update', REALTIME_PLUGIN_PACKAGE], (a) => { calls.push(a); return { status: 1, stderr: PRE_NPM_PREFIX_REFUSAL }; }, failureOf, new BareRetryBudget());
    expect(calls).toHaveLength(1);
  });
});

describe('never clobber a deliberate or newer install', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-npm-keep-'));
    mkdirSync(join(home, '.openclaw', 'plugins'), { recursive: true });
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));
  const writeJson = (rel: string, v: unknown) => writeFileSync(join(home, '.openclaw', rel), JSON.stringify(v));

  it('a plugins.load.paths entry is a linked install', () => {
    writeJson('openclaw.json', { plugins: { load: { paths: ['/src/ShieldCortex/plugins/openclaw/shieldcortex-realtime'] } } });
    expect(readLinkedRealtimeInstall(home)).toBe('/src/ShieldCortex/plugins/openclaw/shieldcortex-realtime');
  });

  it('a `source: "path"` install record (installs.json or openclaw.json) is a linked install', () => {
    writeJson('plugins/installs.json', { installRecords: { 'shieldcortex-realtime': { source: 'path', sourcePath: '/dev/sc-plugin' } } });
    expect(readLinkedRealtimeInstall(home)).toBe('/dev/sc-plugin');
    rmSync(join(home, '.openclaw', 'plugins', 'installs.json'));
    writeJson('openclaw.json', { plugins: { installs: { 'shieldcortex-realtime': { source: 'path', installPath: '/dev/other' } } } });
    expect(readLinkedRealtimeInstall(home)).toBe('/dev/other');
  });

  it.each(['npm', 'clawhub', undefined])('a `%s` install record is not linked — it is replaceable', (source) => {
    writeJson('plugins/installs.json', { installRecords: { 'shieldcortex-realtime': { source, installPath: '/x' } } });
    expect(readLinkedRealtimeInstall(home)).toBeNull();
  });

  it('keeps linked and newer installs, replaces equal, older and absent ones', () => {
    expect(assessRealtimeReplacement({ version: '5.20.2', linkedAt: '/dev/sc' }, '5.20.2')).toMatchObject({ replace: false, why: 'linked' });
    expect(assessRealtimeReplacement({ version: '5.21.0', linkedAt: null }, '5.20.2')).toMatchObject({ replace: false, why: 'newer' });
    expect(assessRealtimeReplacement({ version: '5.20.2', linkedAt: null }, '5.20.2')).toEqual({ replace: true });
    expect(assessRealtimeReplacement({ version: '5.17.3', linkedAt: null }, '5.20.2')).toEqual({ replace: true });
    expect(assessRealtimeReplacement({ version: null, linkedAt: null }, '5.20.2')).toEqual({ replace: true });
  });
});

describe('landedVersionVerdict — only the pin is success', () => {
  it('equal is ok; older, newer and unreadable are not', () => {
    expect(landedVersionVerdict('5.20.2', '5.20.2')).toEqual({ ok: true, version: '5.20.2' });
    expect(landedVersionVerdict('5.17.3', '5.20.2')).toMatchObject({ ok: false, version: '5.17.3', summary: 'the plugin is on v5.17.3, CLI is v5.20.2' });
    expect(landedVersionVerdict('5.21.0', '5.20.2')).toMatchObject({ ok: false, version: '5.21.0' });
    expect(landedVersionVerdict(null, '5.20.2')).toMatchObject({ ok: false, version: null });
  });
});

describe('remediation commands use the npm: pinned spec', () => {
  const verdict = (recommendedAction: ReconcileVerdict['recommendedAction']) =>
    ({ recommendedAction, expectedVersion: '5.20.2' }) as unknown as ReconcileVerdict;
  const plan = (action: ReconcileVerdict['recommendedAction'], expectedVersion = '5.20.2') => planReconcileActions(verdict(action), {
    pluginId: 'shieldcortex-realtime', packageName: REALTIME_PLUGIN_PACKAGE, expectedVersion,
  });

  it.each(['reinstall-pinned', 'install', 'update-openclaw-tracked', 'dedupe-and-reload'] as const)(
    '%s runs `plugins install --force npm:…@<expected>` — never `plugins update`, which follows a ClawHub record',
    (action) => {
      const commands = plan(action).filter((s) => s.command).map((s) => s.command);
      expect(commands).toEqual([realtimePluginInstallArgs('5.20.2')]);
      expect(commands.flat()).not.toContain('update');
    },
  );

  it('a non-exact expected version plans NO install command (the executor reports it refused)', () => {
    for (const action of ['reinstall-pinned', 'install', 'update-openclaw-tracked'] as const) {
      const steps = plan(action, 'unknown').filter((s) => s.kind.startsWith('openclaw-'));
      expect(steps.map((s) => s.command)).toEqual([[]]);
    }
  });

  it('another package keeps `plugins update`', () => {
    const steps = planReconcileActions(verdict('update-openclaw-tracked'), { pluginId: 'other', packageName: '@x/other', expectedVersion: '1.0.0' });
    expect(steps.find((s) => s.command)?.command).toEqual(['plugins', 'update', '@x/other']);
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
  const NPM_CMD = realtimePluginInstallCommand(CLI);
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-npm-pin-'));
    mkdirSync(join(home, '.openclaw', 'plugins'), { recursive: true });
    writeFileSync(join(home, '.openclaw', 'plugins', 'installs.json'),
      JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }));
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  type Call = { cmd: string; args: string[] };
  const childFailure = (stderr: string, over: Partial<CapturedError> = {}) => Object.assign(new Error('exit 1: openclaw plugins install'), {
    exitCode: 1, command: 'openclaw plugins install', stdout: '', stderr, ...over,
  }) as CapturedError;

  type Ending = null | string | { stderr: string; stdout?: string };
  /**
   * Each install call takes the next scripted ending: `null` succeeds, a
   * string is that stderr, an object sets both streams. `npm view` answers
   * with `published` (default: the pin it was asked about).
   */
  function scripted(endings: Ending[], opts: { published?: string | null; listed?: string } = {}) {
    const calls: Call[] = [];
    let i = 0;
    const run = (cmd: string, args: string[]) => {
      calls.push({ cmd, args });
      if (cmd === 'npm') {
        const asked = args[1].slice(args[1].lastIndexOf('@') + 1);
        const published = opts.published === undefined ? asked : opts.published;
        return published === null ? Promise.reject(childFailure('npm error code E404')) : Promise.resolve({ stdout: `${published}\n`, stderr: '' });
      }
      if (args[1] === 'list') {
        return opts.listed
          ? Promise.resolve({ stdout: JSON.stringify({ plugins: [{ id: 'shieldcortex-realtime', version: opts.listed }] }), stderr: '' })
          : Promise.reject(childFailure('no list'));
      }
      const ending = endings[Math.min(i++, endings.length - 1)];
      if (ending === null) return Promise.resolve({ stdout: '', stderr: '' });
      return Promise.reject(typeof ending === 'string' ? childFailure(ending) : childFailure(ending.stderr, { stdout: ending.stdout ?? '' }));
    };
    return {
      run: run as never,
      calls,
      installs: () => calls.filter((c) => c.cmd === 'openclaw' && c.args[1] === 'install').map((c) => c.args),
    };
  }

  /** before, then after — what the on-disk read returns on successive calls. */
  const versions = (...seq: string[]) => {
    let i = 0;
    return () => seq[Math.min(i++, seq.length - 1)];
  };

  const exitCodeOf = (r: { unfinished?: boolean; status: string }) =>
    updateVerdict({ failed: false, attention: r.status === 'warn', unfinished: r.unfinished === true }).exitCode;

  it('installs `npm:…@<expected>` — the version on disk now (readCliVersion), never `@latest`', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.17.3', CLI), readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS]);
    expect(f.installs().flat().join(' ')).not.toMatch(/@latest|clawhub:/);
    expect(r.status).toBe('ok');
    expect(exitCodeOf(r)).toBe(0);
  });

  it('asks npm for EXACTLY the pin before anything destructive', async () => {
    const f = scripted([null]);
    await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.17.3', CLI), readCliVersion: () => CLI });
    expect(f.calls[0]).toEqual({ cmd: 'npm', args: ['view', `${REALTIME_PLUGIN_PACKAGE}@${CLI}`, 'version'] });
  });

  it('a host that predates `npm:` gets ONE bare exact retry, and it lands', async () => {
    const f = scripted([PRE_NPM_PREFIX_STDERR, null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.20.1', CLI), readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS, BARE_ARGS]);
    expect(r.status).toBe('ok');
  });

  it('on that host the re-run command it prints is the bare form (the one the host accepts)', async () => {
    const f = scripted([PRE_NPM_PREFIX_STDERR, 'OpenClaw config is invalid: /x/openclaw.json']);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS, BARE_ARGS]);
    expect(r.status).toBe('warn');
    expect(r.rerun).toBe(`openclaw ${BARE_ARGS.join(' ')}`);
  });

  it.each(OTHER_FAILURES)('a %s failure is surfaced with no bare retry', async (_label, said) => {
    const f = scripted([said]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()[0]).toEqual(NPM_ARGS);
    expect(f.installs().filter((a) => !a[3].startsWith('npm:'))).toEqual([]);
    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
  });

  it.each(OTHER_FAILURES.filter(([l]) => l !== 'secret-ref'))('mixed output — the refusal line AND a %s failure — gets no bare retry', async (_label, said) => {
    const f = scripted([`${PRE_NPM_PREFIX_STDERR}\n${said}`]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS]);
    expect(r.unfinished).toBe(true);
  });

  it('the refusal phrase quoted on stdout (stderr says something else) gets no bare retry', async () => {
    const f = scripted([{ stderr: 'openclaw: install failed', stdout: PRE_NPM_PREFIX_REFUSAL }]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS]);
    expect(r.unfinished).toBe(true);
  });

  it('protocol fallback + secret-ref refusal on the bare run: no SECOND bare run (one per update)', async () => {
    const SECRET = 'gateway.auth.token is configured as a secret reference but is unavailable in this command path.';
    const f = scripted([PRE_NPM_PREFIX_STDERR, SECRET, null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS, BARE_ARGS]);
    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.recovery?.command).toBe(`openclaw ${BARE_ARGS.join(' ')}`);
    expect((r.detail ?? []).join('\n')).toMatch(/not retried/);
  });

  it('an install that exits 0 but leaves the stale ClawHub 5.17.3 is unfinished (exit 1), with the npm: command', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.17.3', readCliVersion: () => CLI });
    expect(r.status).toBe('warn');
    expect(r.summary).toBe(`the plugin is on v5.17.3, CLI is v${CLI}`);
    expect(r.summary).not.toMatch(/up to date|FAILED|unprotected/i);
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBe(NPM_CMD);
    expect(exitCodeOf(r)).toBe(1);
  });

  it('an exit-0 install that lands a NEWER version is unfinished too', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.20.1', '5.21.0'), readCliVersion: () => CLI });
    expect(r.status).toBe('warn');
    expect(r.summary).toBe(`5.20.1 → 5.21.0; the plugin is on v5.21.0, CLI is v${CLI}`);
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBe(NPM_CMD);
    expect(exitCodeOf(r)).toBe(1);
  });

  it('an exit-0 install whose landed version is unreadable is unfinished', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.20.1', null as unknown as string), readCliVersion: () => CLI });
    expect(r.unfinished).toBe(true);
    expect(exitCodeOf(r)).toBe(1);
  });

  it('a mismatch after a legacy-copy purge failure is still unfinished', async () => {
    mkdirSync(join(home, '.openclaw', 'extensions', 'shieldcortex-realtime'), { recursive: true });
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, {
      run: f.run,
      rm: (() => { throw new Error('EACCES: permission denied'); }) as never,
      readPluginVersion: () => '5.17.3',
      readCliVersion: () => CLI,
    });
    expect(r.summary).toMatch(/legacy copy left behind/);
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBe(NPM_CMD);
    expect(exitCodeOf(r)).toBe(1);
  });

  it('#604 path: a non-zero install that left a NEWER version is not "the target version is in place"', async () => {
    // Before: older than the pin (so the install runs). After: OpenClaw's own
    // list says a NEWER build landed.
    const f = scripted(['exit 1 for some reason'], { listed: '5.21.0' });
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.20.1', '5.21.0'), readCliVersion: () => CLI });
    expect(f.installs()).toEqual([NPM_ARGS]);
    expect(r.status).toBe('warn');
    expect((r.detail ?? []).join('\n')).toContain(`installed is v5.21.0, target v${CLI}`);
    expect(r.summary).not.toMatch(/in place/);
    expect(r.unfinished).toBe(true);
    expect(exitCodeOf(r)).toBe(1);
  });

  it('#604 path: a timed-out install that left exactly the pin is ok', async () => {
    const f = scripted([{ stderr: '' }], { listed: CLI });
    const run = ((cmd: string, args: string[], o: unknown) => (cmd === 'openclaw' && args[1] === 'install'
      ? Promise.reject(childFailure('', { timedOut: true, exitCode: null }))
      : (f.run as unknown as (c: string, a: string[], o: unknown) => Promise<unknown>)(cmd, args, o))) as never;
    const r = await stepOpenClawPlugin(home, { run, readPluginVersion: () => CLI, readCliVersion: () => CLI });
    expect(r.status).toBe('ok');
  });

  it('an unreadable CLI version installs NOTHING, deletes nothing, and exits non-zero with the command', async () => {
    const legacy = join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
    mkdirSync(legacy, { recursive: true });
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, {
      run: f.run,
      readPluginVersion: () => '5.20.1',
      readCliVersion: () => { throw new Error('ENOENT package.json'); },
    });
    expect(f.calls).toEqual([]);
    expect(existsSync(legacy)).toBe(true);
    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBe('openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@latest');
    expect(exitCodeOf(r)).toBe(1);
  });

  it('unknown version + a host that would refuse `npm:`: still no install at all, so no bare @latest', async () => {
    const f = scripted([PRE_NPM_PREFIX_STDERR, null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => 'not-a-version' });
    expect(f.installs()).toEqual([]);
    expect(r.unfinished).toBe(true);
  });

  it.each([
    ['not on npm yet', '' as string | null],
    ['npm view fails', null],
  ])('an unpublished pin (%s): nothing deleted or installed, unfinished, the command printed', async (_label, published) => {
    const legacy = join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
    mkdirSync(legacy, { recursive: true });
    const f = scripted([null], { published });
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([]);
    expect(existsSync(legacy)).toBe(true);
    expect(r.summary).toMatch(/^not updated — /);
    expect(r.summary).toMatch(/still on v5\.20\.1/);
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBe(NPM_CMD);
    expect(exitCodeOf(r)).toBe(1);
  });

  it('a linked install is preserved: no install runs, the command is printed', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, {
      run: f.run,
      readPluginVersion: () => '5.20.1',
      readCliVersion: () => CLI,
      readLinkedInstall: () => '/src/ShieldCortex/plugins/openclaw',
    });
    expect(f.calls).toEqual([]);
    expect(r.summary).toMatch(/left alone — the plugin is a linked install/);
    expect((r.detail ?? []).join('\n')).toContain(NPM_CMD);
    expect(r.unfinished).toBe(true);
  });

  it('a linked install AT the pin is ok, and still not replaced', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => CLI, readCliVersion: () => CLI, readLinkedInstall: () => '/dev/sc' });
    expect(f.calls).toEqual([]);
    expect(r.status).toBe('ok');
    expect(r.unfinished).toBeUndefined();
  });

  it('a linked install found from OpenClaw\'s own files (plugins.load.paths) is preserved by default', async () => {
    writeFileSync(join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { load: { paths: ['/dev/shieldcortex-realtime'] } } }));
    const f = scripted([null]);
    await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI });
    expect(f.installs()).toEqual([]);
  });

  it('a NEWER plugin is never downgraded — e.g. when the core npm step failed and the pin is the old CLI', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, {
      run: f.run,
      readPluginVersion: () => '5.21.0',
      readCliVersion: () => CLI,
      coreUpdate: 'failed',
    });
    expect(f.installs()).toEqual([]);
    expect(r.summary).toBe(`left alone — the plugin is on v5.21.0, newer than this CLI (v${CLI})`);
    expect((r.detail ?? []).join('\n')).toMatch(/CLI itself was not updated/);
    expect(r.unfinished).toBe(true);
  });

  it('a core npm step that failed is said out loud on an otherwise good plugin step', async () => {
    const f = scripted([null]);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: versions('5.17.3', CLI), readCliVersion: () => CLI, coreUpdate: 'failed' });
    expect(r.status).toBe('ok');
    expect((r.detail ?? []).join('\n')).toMatch(/CLI itself was not updated .*v5\.20\.2/);
  });

  it('confirmPublished is injectable and its refusal reason is shown', async () => {
    const f = scripted([null]);
    const confirmPublished = async (): Promise<PluginPublishCheck> => ({ published: false, reason: 'npm has no @drakon-systems/shieldcortex-realtime@5.20.2 yet' });
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.20.1', readCliVersion: () => CLI, confirmPublished });
    expect(f.installs()).toEqual([]);
    expect(r.summary).toBe('not updated — npm has no @drakon-systems/shieldcortex-realtime@5.20.2 yet; still on v5.20.1');
  });
});
