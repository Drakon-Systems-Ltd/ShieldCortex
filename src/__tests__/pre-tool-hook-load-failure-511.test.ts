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
const splitFlags = ['rm', '-r', '-f', '/'].join(' ');
const recursivePermissions = ['chmod', '-R', '777', '/'].join(' ');
const payload = (command: string | string[]) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });

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
      for (const [index, command] of [catastrophic, splitFlags, recursivePermissions].entries()) {
        const blocked = join(temp, `catastrophic-sentinel-${index}`);
        const catastrophicResult = hostEffectWitness(install, payload(command), blocked);
        expect(catastrophicResult.status).toBe(0);
        expect(decision(catastrophicResult.stdout)).toBe('deny');
        expect(existsSync(blocked)).toBe(false);
      }
      const benign = join(temp, 'benign-sentinel');
      hostEffectWitness(install, payload('ls'), benign);
      expect(existsSync(benign)).toBe(true);
    });
  }

  it('a healthy install still passes the real hook decision through the launcher', () => {
    const install = installCopy();
    const healthyPayload = (command: string) => JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, permission_mode: 'default' });
    for (const [index, command] of [catastrophic, splitFlags, recursivePermissions].entries()) {
      const blocked = join(temp, `healthy-catastrophic-sentinel-${index}`);
      const denied = hostEffectWitness(install, healthyPayload(command), blocked);
      expect(decision(denied.stdout)).toBe('deny');
      expect(existsSync(blocked)).toBe(false);
    }
    const benign = join(temp, 'healthy-benign-sentinel');
    const allowed = hostEffectWitness(install, healthyPayload('ls'), benign);
    expect(allowed.status).toBe(0);
    expect(decision(allowed.stdout)).toBeUndefined();
    expect(existsSync(benign)).toBe(true);
  });

  it('does not treat load-error text on stderr as a failed hook when exit is zero', () => {
    const install = installCopy();
    writeFileSync(join(install, 'scripts/pre-tool-hook.mjs'), "process.stderr.write('SyntaxError: diagnostic text\\n');\n");
    const sentinel = join(temp, 'successful-stderr-sentinel');
    const result = hostEffectWitness(install, payload(catastrophic), sentinel);
    expect(result.status).toBe(0);
    expect(result.stderr).toContain('SyntaxError: diagnostic text');
    expect(decision(result.stdout)).toBeUndefined();
    expect(existsSync(sentinel)).toBe(true);
  });

  it.each([
    ['empty', '', false],
    ['malformed catastrophic', `{"tool_name":"Bash","tool_input":{"command":"${catastrophic}"`, true],
    ['malformed quoted r-f', `{"tool_name":"Bash","tool_input":{"command":"${splitFlags}"`, true],
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

  it('keeps the launcher surface keys in parity with the hook', () => {
    const source = readFileSync(hook, 'utf8');
    const block = source.match(/const FALLBACK_SURFACE_KEYS = \[([\s\S]*?)\n\];/)?.[1];
    expect(block).toBeDefined();
    const keys = [...block!.matchAll(/'([^']+)'/g)].map((match) => match[1]);
    expect(launcher.LAUNCHER_SURFACE_KEYS).toEqual(keys);
  });

  it.each([
    [['rm', '-r', '-f', '/'].join(' '), true],
    [['rm', '-R', '-f', '/'].join(' '), true],
    [['rm', '-r', '-f', '~'].join(' '), true],
    [['chmod', '-R', '777', '/'].join(' '), true],
    [['chown', '-R', 'root', '/'].join(' '), true],
    ['ls', false],
    [['rm', '-r', 'build'].join(' '), false],
  ])('matches the launcher surface for %s', (command, expected) => {
    expect(launcher.launcherCatastrophicMatch(payload(command))).toBe(expected);
  });

  it.each(['data', 'text', 'literal'])('matches the OpenClaw typed-shell %s field on the parsed surface', (key) => {
    const input = JSON.stringify({ tool_name: 'process', tool_input: { [key]: catastrophic } });
    expect(launcher.launcherCatastrophicMatch(input)).toBe(true);
    const benign = JSON.stringify({ tool_name: 'process', tool_input: { [key]: 'ls' } });
    expect(launcher.launcherCatastrophicMatch(benign)).toBe(false);
  });

  it('matches argv arrays and truncated quoted input', () => {
    expect(launcher.launcherCatastrophicMatch(payload(['rm', '-r', '-f', '/']))).toBe(true);
    expect(launcher.launcherCatastrophicMatch(`{"tool_name":"Bash","tool_input":{"command":"${splitFlags}"`)).toBe(true);
  });

  // Budget rationale (measured, not guessed). The `rm` rows are quadratic in
  // the scanned length, and only FALLBACK_SCAN_CAP bounds them. At the 4096
  // cap the worst padding (`rm -x -x ...`) costs ~13 ms locally. On a contended
  // CI runner (the full suite in parallel), the warmed minimum reached 118 ms.
  // Uncapped, the same padding costs ~190 ms at 16 KB, ~750 ms at 32 KB and
  // seconds at 100 KB. 300 ms (the guard-bypasses-4475 precedent) is far above
  // the capped regime and far below the uncapped one. The 100 KB rows below are
  // the real regression check: they pass only if every path enforces the cap.
  const SCAN_BUDGET_MS = 300;

  it(`scans adversarial input in under ${SCAN_BUDGET_MS} ms at the cap and at 25x the cap`, () => {
    const match = (launcher as unknown as { launcherCatastrophicMatch?: (input: string) => boolean }).launcherCatastrophicMatch;
    expect(match).toBeDefined();
    const paddings = (n: number) => [
      'curl ' + 'x|'.repeat(n / 2 - 4),
      'rm ' + '-x '.repeat(Math.floor(n / 3) - 1),
      'rm ' + 'a'.repeat(n - 3),
      'curl ' + '| '.repeat(n / 2 - 3),
      ['ch', 'mod -R '].join('') + 'a '.repeat(n / 2 - 4),
      'dd ' + 'x'.repeat(n - 3),
    ];
    for (const padding of [...paddings(4096), ...paddings(102_400)]) {
      const wrapped = payload(padding);
      // Raw text, the parsed-JSON surface, and the raw fallback for a malformed payload.
      for (const input of [padding, wrapped, wrapped + '"']) {
        match!(input);
        // A cold run or scheduler pause can spike, but the warmed minimum still
        // catches a row that is consistently slow.
        const durations = Array.from({ length: 5 }, () => {
          const start = performance.now();
          match!(input);
          return performance.now() - start;
        });
        expect(Math.min(...durations)).toBeLessThan(SCAN_BUDGET_MS);
      }
    }
    // Past the cap the catastrophic tail is out of scope by design (FALLBACK_SCAN_CAP).
    expect(match!('ls ' + catastrophic)).toBe(true);
  });
});
