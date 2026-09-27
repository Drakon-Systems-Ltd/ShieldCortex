import { mkdtempSync, mkdirSync, writeFileSync, rmSync, utimesSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  stepOpenClawPlugin,
  stepOpenClawSkill,
  footer,
  openClawStepTimeoutMs,
  parsePluginListVersion,
  DEFAULT_OPENCLAW_STEP_TIMEOUT_MS,
} from '../update.js';
import type { CapturedError } from '../../integrations/child-output.js';

/**
 * #604 — `update` reported "OpenClaw plugin update failed — timed out" at
 * 120.1 s for an install that completed at 126.6 s (plugin 5.2.1 loaded),
 * reported the skill as timed out (that one really had not landed), and still
 * closed on a plain "✓ done".
 *
 * Every child here is a scripted fake: HOME and PATH point at a temp dir, and
 * no test reaches a real `openclaw` or `shieldcortex` binary.
 */

const PKG = '5.2.1';
const PLUGIN_RERUN = 'openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest';
const SKILL_ARGS = ['skills', 'install', 'shieldcortex', '--force', '--acknowledge-install-policy-warning'];
const SKILL_RERUN = `openclaw ${SKILL_ARGS.join(' ')}`;

type Call = { cmd: string; args: string[]; opts: { timeout?: number } };

let home: string;
let skillDir: string;
const saved = { HOME: process.env.HOME, PATH: process.env.PATH, T: process.env.SHIELDCORTEX_UPDATE_OPENCLAW_TIMEOUT_MS };

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-604-home-'));
  process.env.HOME = home;
  process.env.PATH = join(home, 'bin');
  delete process.env.SHIELDCORTEX_UPDATE_OPENCLAW_TIMEOUT_MS;
  // Registered plugin, so the plugin step reaches the install.
  mkdirSync(join(home, '.openclaw', 'plugins'), { recursive: true });
  writeFileSync(
    join(home, '.openclaw', 'plugins', 'installs.json'),
    JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }),
  );
  // An older installed skill copy, last written an hour ago.
  skillDir = join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex');
  writeSkill(skillDir, '5.2.0');
  const past = new Date(Date.now() - 3600_000);
  utimesSync(join(skillDir, 'SKILL.md'), past, past);
});

afterEach(() => {
  for (const [k, v] of Object.entries({ HOME: saved.HOME, PATH: saved.PATH, SHIELDCORTEX_UPDATE_OPENCLAW_TIMEOUT_MS: saved.T })) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  rmSync(home, { recursive: true, force: true });
});

function writeSkill(dir: string, version: string | null): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'SKILL.md'), `---\nname: shieldcortex\n${version ? `version: ${version}\n` : ''}---\n# ShieldCortex\n`);
}

function childError(over: Partial<CapturedError>): CapturedError {
  return Object.assign(new Error('child failed'), { stdout: '', stderr: '', exitCode: null, ...over }) as CapturedError;
}

const timedOut = (cmd: string) => childError({ timedOut: true, exitCode: null, command: cmd, message: `timeout: ${cmd}` });

function pluginList(version: string): string {
  return JSON.stringify({ plugins: [{ id: 'a2a', version: '2026.9.6' }, { id: 'shieldcortex-realtime', version, status: 'loaded' }] });
}

/** A scripted `openclaw`: `install` and `list` behave as the test says; every call is recorded. */
function fakeOpenClaw(script: { install: () => Promise<{ stdout: string; stderr: string }>; list?: () => Promise<{ stdout: string; stderr: string }> }) {
  const calls: Call[] = [];
  const run = (cmd: string, args: string[], opts: { timeout?: number } = {}) => {
    calls.push({ cmd, args, opts });
    if (args[0] === 'plugins' && args[1] === 'list') {
      return script.list ? script.list() : Promise.reject(childError({ spawnFailed: true, code: 'ENOENT' } as never));
    }
    return script.install();
  };
  return { run: run as never, calls };
}

function plugin(run: never, installedOnDisk: string | null) {
  return stepOpenClawPlugin(home, { run, readPluginVersion: () => installedOnDisk, readCliVersion: () => PKG });
}

function skill(run: never) {
  return stepOpenClawSkill(home, {
    run,
    resolveBin: () => join(home, 'bin', 'openclaw'),
    resolveArgs: () => SKILL_ARGS,
    readCliVersion: () => PKG,
  });
}

describe('#604 — timeout budget', () => {
  it('defaults to 300 s and honours SHIELDCORTEX_UPDATE_OPENCLAW_TIMEOUT_MS', () => {
    expect(DEFAULT_OPENCLAW_STEP_TIMEOUT_MS).toBe(300_000);
    expect(openClawStepTimeoutMs({})).toBe(300_000);
    expect(openClawStepTimeoutMs({ SHIELDCORTEX_UPDATE_OPENCLAW_TIMEOUT_MS: '450000' })).toBe(450_000);
  });

  it('ignores a value that would disable or corrupt the timeout', () => {
    for (const bad of ['0', '-5', 'abc', '1e9', '', '  ']) {
      expect(openClawStepTimeoutMs({ SHIELDCORTEX_UPDATE_OPENCLAW_TIMEOUT_MS: bad })).toBe(300_000);
    }
  });

  it('hands the budget to both install children', async () => {
    process.env.SHIELDCORTEX_UPDATE_OPENCLAW_TIMEOUT_MS = '450000';
    const ok = fakeOpenClaw({ install: async () => ({ stdout: '', stderr: '' }) });
    await plugin(ok.run, PKG);
    await skill(ok.run);
    const installs = ok.calls.filter((c) => c.args[1] === 'install');
    expect(installs).toHaveLength(2);
    for (const c of installs) expect(c.opts.timeout).toBe(450_000);
  });
});

describe('#604 — plugin step reads the end state after a timeout or non-zero exit', () => {
  it('timeout but landed: reports installed (slow), not failed', async () => {
    const f = fakeOpenClaw({
      install: () => Promise.reject(timedOut(PLUGIN_RERUN)),
      list: async () => ({ stdout: pluginList(PKG), stderr: '' }),
    });
    const r = await plugin(f.run, '5.2.0');
    expect(r.status).toBe('ok');
    expect(r.summary).toContain(`v${PKG} installed (slow`);
    expect(r.summary).not.toContain('failed');
    expect(r.rerun).toBeUndefined();
    expect(f.calls.some((c) => c.args.join(' ') === 'plugins list --json')).toBe(true);
  });

  it('non-zero exit but landed: the target version is in place', async () => {
    const f = fakeOpenClaw({
      install: () => Promise.reject(childError({ exitCode: 1, command: PLUGIN_RERUN, stderr: 'warning: gateway reload failed' })),
      list: async () => ({ stdout: pluginList(PKG), stderr: '' }),
    });
    const r = await plugin(f.run, '5.2.0');
    expect(r.status).toBe('ok');
    expect(r.summary).toContain('target version is in place');
    expect(r.rerun).toBeUndefined();
  });

  it('timeout and not landed: warns with the installed and target versions and the exact re-run', async () => {
    const f = fakeOpenClaw({
      install: () => Promise.reject(timedOut(PLUGIN_RERUN)),
      list: async () => ({ stdout: pluginList('5.2.0'), stderr: '' }),
    });
    const r = await plugin(f.run, '5.2.0');
    expect(r.status).toBe('warn');
    expect(r.summary).toContain('update failed');
    expect(r.detail?.join('\n')).toContain(`installed is v5.2.0, target v${PKG} — re-run: ${PLUGIN_RERUN}`);
    expect(r.rerun).toBe(PLUGIN_RERUN);
  });

  it('end state unreadable: says unknown with the exact re-run, never guesses', async () => {
    const f = fakeOpenClaw({ install: () => Promise.reject(timedOut(PLUGIN_RERUN)) });
    const r = await plugin(f.run, null);
    expect(r.status).toBe('warn');
    expect(r.detail?.join('\n')).toMatch(new RegExp(`end state unknown .* — re-run: ${PLUGIN_RERUN.replace(/[.@/]/g, '\\$&')}`));
    expect(r.summary).not.toContain('installed');
    expect(r.rerun).toBe(PLUGIN_RERUN);
  });

  it('#606 r1 (3): child exited 0 but the installed version is unreadable — unresolved, with the re-run', async () => {
    const f = fakeOpenClaw({ install: async () => ({ stdout: '', stderr: '' }) });
    const r = await plugin(f.run, null);
    expect(r.status).toBe('warn');
    expect(r.summary).toContain('installed version unreadable');
    expect(r.rerun).toBe(PLUGIN_RERUN);
  });

  it('#606 r1 (3): child exited 0 but the plugin is still behind the CLI — unresolved, with the re-run', async () => {
    const f = fakeOpenClaw({ install: async () => ({ stdout: '', stderr: '' }) });
    const r = await plugin(f.run, '5.1.0');
    expect(r.status).toBe('warn');
    expect(r.summary).toContain(`still v5.1.0 — CLI is v${PKG}`);
    expect(r.rerun).toBe(PLUGIN_RERUN);
  });

  it('parses the plugin list past leading log lines and ignores a non-semver version', () => {
    expect(parsePluginListVersion(`[plugins] loading…\n${pluginList('5.2.1')}`)).toBe('5.2.1');
    expect(parsePluginListVersion(pluginList('garbage'))).toBeNull();
    expect(parsePluginListVersion('not json')).toBeNull();
    expect(parsePluginListVersion(JSON.stringify({ plugins: [{ id: 'other', version: '1.0.0' }] }))).toBeNull();
  });
});

describe('#604 — skill step reads the end state after a timeout or non-zero exit', () => {
  it('all clean: reports the installed version', async () => {
    const f = fakeOpenClaw({ install: async () => { writeSkill(skillDir, PKG); return { stdout: '', stderr: '' }; } });
    const r = await skill(f.run);
    expect(r.status).toBe('ok');
    expect(r.summary).toBe(`v${PKG} installed`);
    expect(r.rerun).toBeUndefined();
  });

  it('timeout but landed: reports installed (slow), not failed', async () => {
    const f = fakeOpenClaw({ install: () => { writeSkill(skillDir, PKG); return Promise.reject(timedOut(SKILL_RERUN)); } });
    const r = await skill(f.run);
    expect(r.status).toBe('ok');
    expect(r.summary).toContain(`v${PKG} installed (slow`);
    expect(r.rerun).toBeUndefined();
  });

  it('timeout and not landed: warns with the exact re-run command', async () => {
    const f = fakeOpenClaw({ install: () => Promise.reject(timedOut(SKILL_RERUN)) });
    const r = await skill(f.run);
    expect(r.status).toBe('warn');
    expect(r.summary).toContain('reinstall failed');
    expect(r.detail?.join('\n')).toContain(`installed is still v5.2.0, target v${PKG} — re-run: ${SKILL_RERUN}`);
    expect(r.rerun).toBe(SKILL_RERUN);
  });

  it('end state unreadable: says unknown with the exact re-run', async () => {
    const f = fakeOpenClaw({ install: () => { writeSkill(skillDir, null); return Promise.reject(timedOut(SKILL_RERUN)); } });
    const r = await skill(f.run);
    expect(r.status).toBe('warn');
    expect(r.detail?.join('\n')).toContain(`end state unknown (SKILL.md version unreadable`);
    expect(r.detail?.join('\n')).toContain(`— re-run: ${SKILL_RERUN}`);
    expect(r.rerun).toBe(SKILL_RERUN);
  });

  it('skill older than package after a forced @latest install: names ClawHub lag, not a failure', async () => {
    const f = fakeOpenClaw({ install: async () => { writeSkill(skillDir, '5.2.0'); return { stdout: '', stderr: '' }; } });
    const r = await skill(f.run);
    expect(r.status).toBe('ok');
    expect(r.summary).toContain('v5.2.0 installed');
    expect(r.summary).toContain(`behind package v${PKG}`);
    expect(r.summary).toContain('ClawHub lags npm');
    expect(r.rerun).toBeUndefined();
  });

  it('prefers the skill directory the install command reported', async () => {
    const other = join(home, 'elsewhere', 'skills', 'shieldcortex');
    const f = fakeOpenClaw({
      install: async () => { writeSkill(other, PKG); return { stdout: `Installed shieldcortex → ${other}\n`, stderr: '' }; },
    });
    const r = await skill(f.run);
    expect(r.summary).toBe(`v${PKG} installed`);
  });

  it('#606 r1 (1): two copies, exit 1 naming the other copy, nothing changed — warn + re-run, never "verified"', async () => {
    // A second, older copy that a failing child merely mentions in its output.
    const other = join(home, '.openclaw', 'skills', 'shieldcortex');
    writeSkill(other, '5.1.0');
    const past = new Date(Date.now() - 3600_000);
    utimesSync(join(other, 'SKILL.md'), past, past);
    const f = fakeOpenClaw({
      install: () => Promise.reject(childError({ exitCode: 1, stdout: `checked ${other}\n`, stderr: 'install failed', command: SKILL_RERUN })),
    });
    const r = await skill(f.run);
    expect(r.status).toBe('warn');
    expect(r.summary).toContain('reinstall failed');
    expect(r.summary).not.toContain('verified');
    expect(r.summary).not.toContain('ClawHub');
    expect(r.detail?.join('\n')).toContain(`installed is still v5.2.0, target v${PKG} — re-run: ${SKILL_RERUN}`);
    expect(r.rerun).toBe(SKILL_RERUN);
  });

  it('#606 r1 (2): old copy rewritten during the run, then EACCES — a changed file is not a completed install', async () => {
    const f = fakeOpenClaw({
      install: () => { writeSkill(skillDir, '5.1.0'); return Promise.reject(childError({ exitCode: 1, stderr: 'EACCES: permission denied', command: SKILL_RERUN })); },
    });
    const r = await skill(f.run);
    expect(r.status).toBe('warn');
    expect(r.summary).toContain('reinstall failed');
    expect(r.summary).not.toContain('verified');
    expect(r.summary).not.toContain('ClawHub');
    expect(r.detail?.join('\n')).toContain(`installed is still v5.1.0, target v${PKG} — re-run: ${SKILL_RERUN}`);
    expect(r.rerun).toBe(SKILL_RERUN);
  });

  it('#606 r1 (1): after a failure the end state is read at the measured directory, not one the child named', async () => {
    const other = join(home, 'elsewhere', 'skills', 'shieldcortex');
    const f = fakeOpenClaw({
      install: () => { writeSkill(other, PKG); return Promise.reject(timedOut(SKILL_RERUN)); },
    });
    const r = await skill(f.run);
    // The target landed somewhere else; the copy this box is measured on is still 5.2.0.
    expect(r.status).toBe('warn');
    expect(r.detail?.join('\n')).toContain(`installed is still v5.2.0, target v${PKG}`);
    expect(r.rerun).toBe(SKILL_RERUN);
  });

  it('#606 r1 (3): child exited 0 but the version is unreadable — unresolved, with the re-run', async () => {
    const f = fakeOpenClaw({ install: async () => { writeSkill(skillDir, null); return { stdout: '', stderr: '' }; } });
    const r = await skill(f.run);
    expect(r.status).toBe('warn');
    expect(r.summary).toContain('installed but version unreadable');
    expect(r.rerun).toBe(SKILL_RERUN);
  });
});

describe('#604 — footer never closes on a bare "✓ done" with a step unresolved', () => {
  function runFooter(unresolved: Array<{ label: string; rerun: string }>): string {
    const calls: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = (chunk: any) => { calls.push(String(chunk)); return true; };
    try {
      footer(1234, true, { version: PKG }, unresolved);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stdout as any).write = original;
    }
    // eslint-disable-next-line no-control-regex
    return calls.join('').replace(/\x1b\[[0-9;]*m/g, '');
  }

  it('lists each unresolved step with its exact re-run command', () => {
    const out = runFooter([
      { label: 'OpenClaw plugin', rerun: PLUGIN_RERUN },
      { label: 'OpenClaw skill', rerun: SKILL_RERUN },
    ]);
    expect(out).not.toContain('✓');
    expect(out).toContain('2 steps unresolved');
    expect(out).toContain(`OpenClaw plugin: re-run ${PLUGIN_RERUN}`);
    expect(out).toContain(`OpenClaw skill: re-run ${SKILL_RERUN}`);
  });

  it('still closes on "✓ done" when every step resolved', () => {
    const out = runFooter([]);
    expect(out).toMatch(/✓\s+done/);
    expect(out).not.toContain('unresolved');
  });
});

/** `runUpdate` spawns npm and re-execs the CLI, so its wiring is pinned at the source. */
describe('#604 — runUpdate hands the unresolved steps to the footer and the panel', () => {
  it('passes plugin and skill re-run commands through', () => {
    const src = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', 'update.ts'), 'utf-8');
    expect(src).toContain("{ label: 'OpenClaw plugin', result: pluginResult }");
    expect(src).toContain("{ label: 'OpenClaw skill', result: skillResult }");
    expect(src).toContain('footer(Date.now() - flowStart, mainUpdated, latest, unresolved);');
    expect(src).toContain('for (const u of unresolved) if (!next.includes(u.rerun)) next.push(u.rerun);');
    expect(src).not.toMatch(/timeout: 120000/);
  });
});
