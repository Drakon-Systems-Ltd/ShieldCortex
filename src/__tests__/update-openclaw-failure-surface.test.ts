import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { classifyOpenClawInstallEnding, collectUnresolved, footer, stepOpenClawPlugin, updateVerdict } from '../cli/update.js';
import { buildUpdateSummary } from '../cli/update-summary.js';
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

/**
 * #952 — two OpenClaw install endings are not a finished plugin swap, and the
 * `#604` "the target version landed, so it is ok" branch must never see them.
 *
 *  1. Secret-ref: OpenClaw refuses because `gateway.auth.token` is a secret
 *     reference this command path cannot resolve. The step used to answer with
 *     the very `openclaw plugins install --force …` that fails the same way.
 *  2. Drain: OpenClaw saves the files and then refuses the swap ("admitted work
 *     did not settle"; "the previous plugin generation stays active"). The
 *     on-disk version already equals the CLI, so `#604` reported **ok** while
 *     the running gateway still had the old plugin.
 */
describe('#952 — secret-ref and drain endings are not a finished swap', () => {
  const CLI = '5.15.2';
  const FORCE_INSTALL = 'openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest';

  /** OpenClaw's exact refusal: gateway/credentials.ts, `GatewaySecretRefUnavailableError`. Its own `Fix:` lines come with it. */
  const SECRET_REF_STDERR = [
    'gateway.auth.token is configured as a secret reference but is unavailable in this command path.',
    'Fix: set OPENCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_PASSWORD, pass explicit --token/--password,',
    'or run a gateway command path that resolves secret references before credential selection.',
  ].join('\n');

  /**
   * OpenClaw's exact refusal: gateway/server-plugin-reload-cleanup.ts,
   * `PluginAdmittedWorkTimeoutError`. It names its own recovery — and the line
   * is longer than the 160 chars a detail line keeps, so that tail is cut off
   * by the time an operator sees it. The step has to name the command itself.
   */
  const DRAIN_STDERR =
    'plugin shieldcortex-realtime admitted work did not settle within 60s; the previous plugin generation stays active. Use `openclaw plugins reload shieldcortex-realtime --wait` to wait until it finishes.';
  const RELOAD_WAIT = 'openclaw plugins reload shieldcortex-realtime --wait';

  type Call = { cmd: string; args: string[] };

  /** A scripted `openclaw`: the install ends as told; `plugins list --json` answers with `listed`; every spawn is recorded. */
  function scripted(install: Partial<CapturedError>, listed: string | null = null) {
    const calls: Call[] = [];
    const run = (cmd: string, args: string[]) => {
      calls.push({ cmd, args });
      if (args[0] === 'plugins' && args[1] === 'list') {
        return listed
          ? Promise.resolve({ stdout: JSON.stringify({ plugins: [{ id: 'shieldcortex-realtime', version: listed }] }), stderr: '' })
          : Promise.reject(Object.assign(new Error('no list'), { exitCode: 1, stdout: '', stderr: '' }));
      }
      return rejectWith(install)();
    };
    return { run: run as never, calls };
  }

  it.each([
    ['the full OpenClaw line', SECRET_REF_STDERR],
    ['the bare refusal wording', 'config value is configured as a secret reference but is unavailable'],
  ])('secret-ref (%s): warns, unfinished, and never names the force install as the answer', async (_label, stderr) => {
    const f = scripted({ stderr }, CLI);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.15.1', readCliVersion: () => CLI });

    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBeUndefined();
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).not.toContain('plugins install --force');
    expect(shown).toMatch(/secret reference/);
    expect(shown).toMatch(/shieldcortex update/);
    // The prerequisite is the one OpenClaw's own resolver has: the reference must
    // resolve in the environment the command runs in. "A login shell" is one way
    // to get that environment, not the requirement — a login shell without the
    // variable fails the same way.
    expect(shown).toMatch(/environment resolves that reference/);
    expect(shown).not.toMatch(/login shell/);
    // No credential code: nothing but the one install was spawned — no secrets
    // helper, no end-state read that pretends the install may have landed.
    expect(f.calls.map((c) => c.args.join(' '))).toEqual([FORCE_INSTALL.replace(/^openclaw /, '')]);
  });

  it('secret-ref: OpenClaw\'s own `Fix:` lines reach the operator alongside the step\'s advice', async () => {
    const f = scripted({ stderr: SECRET_REF_STDERR }, CLI);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.15.1', readCliVersion: () => CLI });

    const detail = (r.detail ?? []).join('\n');
    expect(detail).toContain('Fix: set OPENCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_PASSWORD');
    expect(detail).toContain('resolves secret references before credential selection');
  });

  it('drain: files saved but the old generation stays active — not ok even when the on-disk version already matches the CLI', async () => {
    // Both end-state sources say "landed": OpenClaw's own list and the package on disk.
    const f = scripted({ stderr: DRAIN_STDERR }, CLI);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => CLI, readCliVersion: () => CLI });

    expect(r.status).toBe('warn');
    expect(r.status).not.toBe('ok');
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBeUndefined();
    expect(r.summary).toMatch(/files saved/);
    expect(r.summary).toMatch(/previous plugin generation stays active/);
    expect(r.summary).not.toContain('plugins install --force');
    const detail = (r.detail ?? []).join('\n');
    expect(detail).toMatch(/do not re-run `openclaw plugins install --force`/);
    // The recovery OpenClaw's refusal names, in full — its own line is cut at
    // 160 chars before the command. The OpenClaw plugins *tool* has no such
    // action (its enum is `reload`), so the advice must be the CLI command.
    expect(detail).toContain(RELOAD_WAIT);
    expect(detail).not.toMatch(/reloadAndResume|plugins tool/);
    expect(r.summary).not.toMatch(/current (agent )?turn/);
  });

  it('a bare "did not settle" about something other than admitted plugin work is an ordinary failure, not a drain', async () => {
    // OpenClaw says "did not settle" about an unsettled gateway start too. Without
    // the admitted-work wording this is a plain non-zero exit: #604 reads the end
    // state (still the old version here) and names the force install as the re-run.
    const f = scripted({ stderr: 'Gateway did not settle; startup phase: starting' }, '5.15.1');
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.15.1', readCliVersion: () => CLI });

    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.summary).not.toMatch(/files saved/);
    expect(r.rerun).toBe(FORCE_INSTALL);
  });

  it('drain: the exact OpenClaw wording on its own is enough', async () => {
    const f = scripted({ stderr: 'the previous plugin generation stays active' }, CLI);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => CLI, readCliVersion: () => CLI });
    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBeUndefined();
  });

  it.each([
    ['the secret-ref refusal', 'gateway.auth.token is configured as a secret reference but is unavailable in this command path.', 'secret-ref'],
    ['the drain refusal', 'plugin shieldcortex-realtime admitted work did not settle within 60s; the previous plugin generation stays active.', 'drain'],
    ['a secret reference that is mentioned, not refused', 'gateway.auth.token is configured as a secret reference (env OPENCLAW_GATEWAY_TOKEN)', null],
    ['an unsettled gateway start', 'Gateway did not settle; startup phase: starting', null],
    ['an invalid config', INVALID_CONFIG_STDERR, null],
  ] as const)('classifier: %s', (_label, text, want) => {
    expect(classifyOpenClawInstallEnding(text)).toBe(want);
  });

  /**
   * Release review r1 (B1/N1): neither ending sets `rerun`, and the footer's
   * unresolved list used to be built from `rerun` alone — so a run whose only
   * open step was one of these closed on a green "✓ done", and the calm summary
   * fell back to `shieldcortex update` (the force install again) for a drain.
   * Each ending now carries its own `recovery`, which the footer lists and the
   * summary offers as the fix, without bringing back the force install.
   */
  describe('the unfinished step reaches the footer and the closing summary', () => {
    function captureFooter(mainUpdated: boolean, unresolved: ReturnType<typeof collectUnresolved>): string {
      const calls: string[] = [];
      const original = process.stdout.write.bind(process.stdout);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stdout as any).write = (chunk: any) => { calls.push(String(chunk)); return true; };
      try {
        footer(1000, mainUpdated, { version: CLI }, unresolved);
      } finally {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (process.stdout as any).write = original;
      }
      // eslint-disable-next-line no-control-regex
      return calls.join('').replace(/\x1b\[[0-9;]*m/g, '');
    }

    const ENDINGS = [
      {
        name: 'secret-ref',
        stderr: SECRET_REF_STDERR,
        command: 'shieldcortex update',
        note: /environment resolves the gateway secret reference/,
      },
      { name: 'drain', stderr: DRAIN_STDERR, command: RELOAD_WAIT, note: null },
    ] as const;

    describe.each(ENDINGS)('$name', ({ stderr, command, note }) => {
      async function plugin() {
        // The plugin on disk already matches the CLI — the case that used to read as finished.
        const f = scripted({ stderr }, CLI);
        return stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => CLI, readCliVersion: () => CLI });
      }

      it('is collected as unresolved with its own recovery, never the force install', async () => {
        const r = await plugin();
        const unresolved = collectUnresolved([
          { label: 'OpenClaw plugin', result: r },
          { label: 'OpenClaw skill', result: { status: 'ok', summary: 'v5.15.2 installed' } },
        ]);
        expect(unresolved).toHaveLength(1);
        expect(unresolved[0]).toMatchObject({ label: 'OpenClaw plugin', rerun: command, verb: 'run' });
        expect(unresolved[0].rerun).not.toContain('plugins install --force');
        // The verdict is untouched: still non-zero, still a step-level warning.
        expect(r.status).toBe('warn');
        expect(updateVerdict({ failed: false, attention: true, unfinished: r.unfinished === true }).exitCode).toBe(1);
      });

      it.each([
        ['already on the latest package', false],
        ['a newly updated package', true],
      ])('the footer names it instead of a bare "✓ done" (%s)', async (_label, mainUpdated) => {
        const r = await plugin();
        const out = captureFooter(mainUpdated, collectUnresolved([
          { label: 'OpenClaw plugin', result: r },
          { label: 'OpenClaw skill', result: { status: 'ok', summary: 'v5.15.2 installed' } },
        ]));
        expect(out).not.toContain('✓');
        expect(out).not.toContain('already on latest');
        expect(out).toContain('1 step unresolved');
        expect(out).toContain(`OpenClaw plugin: run ${command}`);
        expect(out).not.toContain('re-run');
        expect(out).not.toContain('plugins install --force');
        if (note) expect(out).toMatch(note);
      });

      it.each([['current'], ['updated']] as const)('the closing summary offers the same recovery (package %s)', async (packageState) => {
        const r = await plugin();
        const summary = buildUpdateSummary({
          fromVersion: '5.15.1',
          toVersion: CLI,
          packageState,
          engine: { ok: true },
          plugin: { status: r.status, rerun: r.rerun, recovery: r.recovery },
          skill: { status: 'ok' },
          guardOn: false,
          protection: { status: 'ok', loaded: 'yes', versionOk: true, pluginVersion: CLI },
        });
        const row = summary.rows.find((x) => x.label === 'OpenClaw');
        expect(row).toMatchObject({ mark: 'check', text: 'plugin couldn\'t be updated', command, commandLabel: 'Fix' });
        if (note) expect(row?.commandNote).toMatch(note);
        else expect(row?.commandNote).toBeUndefined();
      });
    });

    it('an ordinary re-run is still listed as a re-run', () => {
      const out = captureFooter(false, collectUnresolved([
        { label: 'OpenClaw plugin', result: { status: 'warn', summary: 'update failed', rerun: FORCE_INSTALL, unfinished: true } },
      ]));
      expect(out).toContain(`OpenClaw plugin: re-run ${FORCE_INSTALL}`);
    });
  });

  it('#604 still holds: an ordinary timeout whose target version landed is reported installed', async () => {
    const f = scripted({ timedOut: true, exitCode: null, stderr: '' }, CLI);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.15.1', readCliVersion: () => CLI });

    expect(r.status).toBe('ok');
    expect(r.summary).toContain(`v${CLI} installed (slow`);
    expect(r.unfinished).toBeUndefined();
    expect(r.rerun).toBeUndefined();
  });

  it('#221 still holds: an ordinary invalid-config exit reports the config error and keeps the re-run', async () => {
    const f = scripted({ stderr: INVALID_CONFIG_STDERR });
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.15.1', readCliVersion: () => CLI });

    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).toContain('OpenClaw config is invalid');
    expect(shown).toContain('plugin manifest not found');
    expect(r.summary).not.toContain('plugins install --force');
    expect(r.rerun).toBe(FORCE_INSTALL);
  });
});
