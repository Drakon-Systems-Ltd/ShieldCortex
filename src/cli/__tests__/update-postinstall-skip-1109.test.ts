/**
 * #1109 round 2 (Astra P2) — one `shieldcortex update` is one operation.
 *
 * `update`'s core step runs `npm install -g shieldcortex@latest` with scripts
 * on. On an OpenClaw host the new package's postinstall used to run
 * `shieldcortex openclaw install` — its own realtime-plugin install, with its
 * own bare-spec retry budget — before `update` reached its plugin step and
 * created another. Now the core npm child carries
 * `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` (the long-standing postinstall switch),
 * scoped to that child only, and `update` refreshes the plugin itself.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { coreInstallRunOpts, stepNpmPackage, type RunOpts } from '../update.js';

const REPO_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..');

afterEach(() => { jest.restoreAllMocks(); });

describe('the core npm install child skips the postinstall OpenClaw refresh', () => {
  it('coreInstallRunOpts sets the flag on a COPY of the env — process.env is untouched', () => {
    const before = process.env.SHIELDCORTEX_SKIP_AUTO_OPENCLAW;
    const opts = coreInstallRunOpts({ PATH: '/bin', KEEP: 'me' });
    expect(opts.env).toEqual({ PATH: '/bin', KEEP: 'me', SHIELDCORTEX_SKIP_AUTO_OPENCLAW: '1' });
    expect(opts.timeout).toBe(180000);
    coreInstallRunOpts();
    expect(process.env.SHIELDCORTEX_SKIP_AUTO_OPENCLAW).toBe(before);
  });

  it.each([
    ['an update to a newer version', '5.99.0', false],
    ['a --force reinstall of the same version', '5.20.2', true],
  ])('%s: the npm child runs with SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1', async (_label, latest, force) => {
    jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const calls: Array<{ cmd: string; args: string[]; opts?: RunOpts }> = [];
    const run = async (cmd: string, args: string[], opts?: RunOpts) => {
      calls.push({ cmd, args, opts });
      return { stdout: '', stderr: '' };
    };
    const r = await stepNpmPackage('5.20.2', { version: latest } as never, force, run as never);
    expect(r.updated).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toBe('npm');
    expect(calls[0].args.slice(0, 3)).toEqual(['install', '-g', 'shieldcortex@latest']);
    expect(calls[0].opts?.env?.SHIELDCORTEX_SKIP_AUTO_OPENCLAW).toBe('1');
    expect(process.env.SHIELDCORTEX_SKIP_AUTO_OPENCLAW).not.toBe('1');
  });
});

describe('the postinstall honours that flag', () => {
  let home: string | null = null;
  afterEach(() => {
    if (home) fs.rmSync(home, { recursive: true, force: true });
    home = null;
  });

  it('source contract: every OpenClaw refresh in postinstall sits behind the flag', () => {
    const src = fs.readFileSync(path.join(REPO_ROOT, 'scripts', 'postinstall.mjs'), 'utf-8');
    expect(src).toContain("const skipAutoOpenClaw = process.env.SHIELDCORTEX_SKIP_AUTO_OPENCLAW === '1';");
    const gate = src.indexOf('if (!skipAutoOpenClaw && state.openclawInstalled)');
    expect(gate).toBeGreaterThan(0);
    // Every call site of the refresh / plugin copy comes after (inside) that gate.
    for (const call of ['refreshOpenClawInstall(cliPath)', 'autoCopyPlugin(state.pluginDir']) {
      let at = src.indexOf(call);
      expect(at).toBeGreaterThan(0);
      while (at >= 0) {
        // The definition (`function refreshOpenClawInstall(cliPath)`) is not a call.
        if (!src.slice(Math.max(0, at - 9), at).endsWith('function ')) expect(at).toBeGreaterThan(gate);
        at = src.indexOf(call, at + 1);
      }
    }
  });

  it('a global install on a host with the hook AND plugin installed, flag set: no OpenClaw refresh runs', () => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1109-postinstall-'));
    fs.mkdirSync(path.join(home, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
    fs.mkdirSync(path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime'), { recursive: true });
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      HOME: home,
      npm_config_global: 'true',
      SHIELDCORTEX_SKIP_AUTO_OPENCLAW: '1',
    };
    const r = spawnSync(process.execPath, [path.join(REPO_ROOT, 'scripts', 'postinstall.mjs')], {
      env, encoding: 'utf-8', timeout: 60000, cwd: home,
    });
    expect(r.status).toBe(0);
    const out = `${r.stdout}${r.stderr}`;
    expect(out).toContain('ShieldCortex installed!');
    expect(out).not.toMatch(/Refreshing OpenClaw|Copying updated plugin files|auto-refresh/);
    // The plugin dir is exactly as it was: nothing copied in.
    expect(fs.readdirSync(path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime'))).toEqual([]);
  });
});
