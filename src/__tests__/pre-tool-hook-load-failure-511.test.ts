import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as launcher from '../setup/hooks.js';

const root = resolve(fileURLToPath(new URL('../../', import.meta.url)));
const hook = join(root, 'scripts/pre-tool-hook.mjs');
const catastrophic = ['rm', '-rf', '/'].join(' ');

function decision(stdout: string): string | undefined {
  try { return JSON.parse(stdout).hookSpecificOutput?.permissionDecision; }
  catch { return undefined; }
}

describe('issue #511 PreToolUse failure posture', () => {
  let temp: string;
  let home: string;
  beforeEach(() => {
    temp = mkdtempSync(join(tmpdir(), 'sc-hook-511-'));
    home = join(temp, 'home');
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    writeFileSync(join(home, '.shieldcortex/config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  });
  afterEach(() => rmSync(temp, { recursive: true, force: true }));

  function run(script: string, input: string) {
    const result = spawnSync(process.execPath, [script], {
      input, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex') },
    });
    expect(result.status).not.toBeNull();
    return result;
  }

  // A throwaway install (dist + scripts + package.json, node_modules linked) so
  // the real launcher resolves the hook relative to its own dist, with no
  // production env seam that could redirect the hook path.
  function installCopy(): string {
    const install = join(temp, 'install');
    mkdirSync(install);
    cpSync(join(root, 'dist'), join(install, 'dist'), { recursive: true });
    cpSync(join(root, 'scripts'), join(install, 'scripts'), { recursive: true });
    cpSync(join(root, 'package.json'), join(install, 'package.json'));
    symlinkSync(join(root, 'node_modules'), join(install, 'node_modules'), 'dir');
    return install;
  }

  function hostEffectWitness(install: string, input: string, sentinel: string) {
    const result = spawnSync(process.execPath, [join(install, 'dist/index.js'), 'hook', 'pre-tool'], {
      input, encoding: 'utf8', timeout: 30_000,
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex') },
    });
    expect(result.status).not.toBeNull();
    // Claude Code blocks a deny JSON or exit 2; other non-zero exits proceed.
    if (decision(result.stdout) !== 'deny' && result.status !== 2) writeFileSync(sentinel, 'tool ran');
    return result;
  }

  for (const failure of ['syntax error', 'missing static import']) {
    it(`blocks the host effect when the hook has a ${failure}`, () => {
      const install = installCopy();
      if (failure === 'syntax error') writeFileSync(join(install, 'scripts/pre-tool-hook.mjs'), 'this is not JavaScript !');
      else unlinkSync(join(install, 'scripts/lib/state-perms.mjs'));
      const payload = (command: string) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
      const blocked = join(temp, 'catastrophic-sentinel');
      const catastrophicResult = hostEffectWitness(install, payload(catastrophic), blocked);
      expect(catastrophicResult.status).toBe(0);
      expect(decision(catastrophicResult.stdout)).toBe('deny');
      expect(existsSync(blocked)).toBe(false);
      const benign = join(temp, 'benign-sentinel');
      hostEffectWitness(install, payload('ls'), benign);
      expect(existsSync(benign)).toBe(true);
    });
  }

  it('a healthy install still passes the real hook decision through the launcher', () => {
    const install = installCopy();
    const payload = (command: string) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, permission_mode: 'default' });
    const blocked = join(temp, 'healthy-catastrophic-sentinel');
    const denied = hostEffectWitness(install, payload(catastrophic), blocked);
    expect(decision(denied.stdout)).toBe('deny');
    expect(existsSync(blocked)).toBe(false);
    const benign = join(temp, 'healthy-benign-sentinel');
    const allowed = hostEffectWitness(install, payload('ls'), benign);
    expect(allowed.status).toBe(0);
    expect(decision(allowed.stdout)).toBeUndefined();
    expect(existsSync(benign)).toBe(true);
  });

  it.each([
    ['empty', '', false],
    ['malformed catastrophic', `{"tool_name":"Bash","tool_input":{"command":"${catastrophic}"`, true],
    ['malformed benign', '{"tool_name":"Bash","tool_input":{"command":"ls"', false],
    ['null catastrophic', JSON.stringify({ tool_name: 'Bash', tool_input: null, note: catastrophic }), true],
    ['null benign', JSON.stringify({ tool_name: 'Bash', tool_input: null, note: 'ls' }), false],
    ['missing catastrophic', JSON.stringify({ tool_name: 'Bash', note: catastrophic }), true],
    ['missing benign', JSON.stringify({ tool_name: 'Bash', note: 'ls' }), false],
  ])('%s input uses only the catastrophic raw fallback', (_name, input, blocked) => {
    const result = run(hook, input);
    expect(result.status).toBe(0);
    expect(decision(result.stdout)).toBe(blocked ? 'deny' : undefined);
    expect(existsSync(join(home, '.shieldcortex/approvals'))).toBe(false);
    expect(existsSync(join(home, '.shieldcortex/leases'))).toBe(false);
  });

  it('keeps the launcher catastrophic patterns in parity with the hook', () => {
    const source = readFileSync(hook, 'utf8');
    const block = source.match(/const FALLBACK_CATASTROPHIC_PATTERNS = \[([\s\S]*?)\n\];/)?.[1];
    expect(block).toBeDefined();
    const literals = block!.split('\n').map((line) => line.trim()).filter((line) => line.startsWith('/') && !line.startsWith('//'))
      .map((line) => line.replace(/,$/, ''));
    const patterns = (launcher as unknown as { LAUNCHER_CATASTROPHIC_PATTERNS?: RegExp[] }).LAUNCHER_CATASTROPHIC_PATTERNS;
    expect(patterns?.map((pattern) => pattern.toString())).toEqual(literals);
  });

  it('scans adversarial 4096-character input in under 50 ms', () => {
    const match = (launcher as unknown as { launcherCatastrophicMatch?: (input: string) => boolean }).launcherCatastrophicMatch;
    expect(match).toBeDefined();
    const paddings = [
      'curl ' + 'x|'.repeat(2044),
      'rm ' + '-x '.repeat(1364),
      'rm ' + 'a'.repeat(4093),
      'curl ' + '| '.repeat(2045),
      ['ch', 'mod -R '].join('') + 'a '.repeat(2044),
      'dd ' + 'x'.repeat(4093),
    ];
    for (const padding of paddings) {
      const start = performance.now();
      match!(padding);
      expect(performance.now() - start).toBeLessThan(50);
    }
    // Past the cap the catastrophic tail is out of scope by design (FALLBACK_SCAN_CAP).
    expect(match!('ls ' + catastrophic)).toBe(true);
  });
});
