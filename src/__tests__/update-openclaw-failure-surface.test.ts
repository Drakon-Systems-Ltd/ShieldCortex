import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { stepOpenClawPlugin } from '../cli/update.js';
import type { CapturedError } from '../integrations/child-output.js';

/**
 * #221 — `update` must surface what the child said, not restate the command.
 *
 * The reported behaviour: `stepOpenClawPlugin` caught the failure and returned
 * "update failed — run `openclaw plugins install --force …`" — the very command
 * that had just failed. `runQuiet` had already captured OpenClaw's message,
 * which names the offending config key and the repair, and the bare `catch {}`
 * discarded it.
 */

/** What OpenClaw really writes when its config is invalid. */
const INVALID_CONFIG_STDERR = [
  'OpenClaw config is invalid: /home/x/.openclaw/openclaw.json',
  '  × plugins: plugin manifest not found: ~/.openclaw/extensions/ekho-adapter/openclaw.plugin.json',
  '',
  'Run `openclaw doctor --fix` to repair, or fix the keys above manually.',
  'Audit, status, health, logs, tasks list/audit, and doctor commands still run with invalid config.',
].join('\n');

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-221-home-'));
  // Make the step believe the plugin is installed, so it reaches the spawn.
  mkdirSync(join(home, '.openclaw', 'plugins'), { recursive: true });
  writeFileSync(
    join(home, '.openclaw', 'plugins', 'installs.json'),
    JSON.stringify({ installRecords: { 'shieldcortex-realtime': {} } }),
  );
});

afterEach(() => rmSync(home, { recursive: true, force: true }));

function rejectWith(over: Partial<CapturedError>) {
  return () => Promise.reject(Object.assign(new Error('exit 1: openclaw plugins install'), {
    exitCode: 1,
    command: 'openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest',
    stdout: '',
    stderr: '',
    ...over,
  }) as CapturedError);
}

describe('#221 — the reason reaches the operator', () => {
  it('reports the config error, not the command that just failed', async () => {
    const r = await stepOpenClawPlugin(home, {
      run: rejectWith({ stderr: INVALID_CONFIG_STDERR }) as never,
    });

    expect(r.status).toBe('warn');
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');

    expect(shown).toContain('OpenClaw config is invalid');
    expect(shown).toContain('plugin manifest not found');
    // The old behaviour, and the whole of the field report.
    expect(r.summary).not.toContain('plugins install --force');
  });

  it('does not present OpenClaw\'s reassurance as the reason', async () => {
    // The last line says audit/status/health/doctor still work. A `slice(-1)`
    // reads exactly that and drops the cause above it.
    const r = await stepOpenClawPlugin(home, {
      run: rejectWith({ stderr: INVALID_CONFIG_STDERR }) as never,
    });

    expect(r.summary).not.toContain('still run with invalid config');
  });

  it('still says something useful when the child produced no output', async () => {
    const r = await stepOpenClawPlugin(home, { run: rejectWith({}) as never });

    expect(r.status).toBe('warn');
    expect(r.summary).toContain('exited 1');
    // Naming the command is right HERE — it is all we have — but as the
    // fallback, not as the standard answer.
    expect(r.summary).toContain('openclaw plugins install');
  });

  it('distinguishes a missing binary from a rejected command', async () => {
    const r = await stepOpenClawPlugin(home, {
      run: rejectWith({ spawnFailed: true, exitCode: null, code: 'ENOENT' }) as never,
    });

    expect(r.summary).toContain('command not found');
  });
});

/**
 * A source rail for the sibling site. `stepOpenClawSkill` has the same defect
 * and the same fix, but its early-return path makes a behavioural test cost
 * more than it proves — so the wiring is pinned directly.
 */
describe('#221 — no swallow is left behind in the OpenClaw steps', () => {
  it('neither OpenClaw step restates its own command as the failure reason', () => {
    const src = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), '..', 'cli', 'update.ts'),
      'utf-8',
    );

    expect(src).not.toContain("summary: 'update failed — run `openclaw plugins install");
    expect(src).not.toContain("summary: 'reinstall failed — run `shieldcortex openclaw skill install`'");
    // Both catches must go through the shared reporter.
    expect((src.match(/describeRunFailure\(err\)/g) ?? []).length).toBeGreaterThanOrEqual(2);
  });
});
