import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { classifyOpenClawInstallEnding, collectUnresolved, footer, stepOpenClawPlugin, updateVerdict } from '../cli/update.js';
import { buildUpdateSummary, renderUpdateSummary, type UpdateSummaryInput } from '../cli/update-summary.js';
import { NO_STYLE } from '../cli/term-ui.js';
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
 *     reference it could not resolve for the install child. #1071 replaced
 *     #952's answer (`shieldcortex update`, which only repeats the refused
 *     install) with one retry and, failing that, the force install itself run
 *     where `openclaw` resolves the reference — see the #1071 block below.
 *  2. Drain: OpenClaw saves the files and then refuses the swap ("admitted work
 *     did not settle"; "the previous plugin generation stays active"). The
 *     on-disk version already equals the CLI, so `#604` reported **ok** while
 *     the running gateway still had the old plugin.
 */
describe('#952 — secret-ref and drain endings are not a finished swap', () => {
  const CLI = '5.15.2';
  const FORCE_INSTALL = 'openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest';
  /** Where the #1071 retry finds `openclaw` — injected so no test shells out to `which`. */
  const RESOLVED_BIN = '/opt/openclaw/bin/openclaw';
  const resolveBin = () => RESOLVED_BIN;

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
  ])('secret-ref refused twice (%s): warns, unfinished, and names the force install — never `shieldcortex update`', async (_label, stderr) => {
    const f = scripted({ stderr }, CLI);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.15.1', readCliVersion: () => CLI, resolveBin });

    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.rerun).toBeUndefined();
    // #1071: the command that finishes the step is the force install, run where
    // `openclaw` resolves the reference — not the update that was just refused.
    expect(r.recovery?.command).toBe(FORCE_INSTALL);
    expect(r.recovery?.note).toMatch(/where openclaw resolves the gateway secret reference/);
    const shown = [r.summary ?? '', ...(r.detail ?? [])].join('\n');
    expect(shown).toMatch(/secret reference/);
    expect(shown).toMatch(/refused twice/);
    expect(shown).toContain(`run \`${FORCE_INSTALL}\` from the shell where \`openclaw\` resolves that reference`);
    // `shieldcortex update` appears only as what NOT to do, never as the fix.
    expect(shown).not.toMatch(/run `shieldcortex update`/);
    expect(shown).not.toMatch(/login shell/);
    // No credential code: the install and its one retry were all that was
    // spawned — no secrets helper, no --token/--password, no end-state read
    // that pretends the refused install may have landed.
    expect(f.calls).toEqual([
      { cmd: 'openclaw', args: FORCE_INSTALL.split(' ').slice(1) },
      { cmd: RESOLVED_BIN, args: FORCE_INSTALL.split(' ').slice(1) },
    ]);
  });

  it('secret-ref: OpenClaw\'s own `Fix:` lines reach the operator alongside the step\'s advice', async () => {
    const f = scripted({ stderr: SECRET_REF_STDERR }, CLI);
    const r = await stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => '5.15.1', readCliVersion: () => CLI, resolveBin });

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

    // `never`: the command this ending must not be answered with. A drain is not
    // finished by the force install (#952); a secret-ref is not finished by the
    // update that just ran that same install and was refused (#1071).
    const ENDINGS = [
      {
        name: 'secret-ref',
        stderr: SECRET_REF_STDERR,
        command: FORCE_INSTALL,
        note: /where openclaw resolves the gateway secret reference/,
        never: 'shieldcortex update',
      },
      { name: 'drain', stderr: DRAIN_STDERR, command: RELOAD_WAIT, note: null, never: 'plugins install --force' },
    ] as const;

    describe.each(ENDINGS)('$name', ({ stderr, command, note, never }) => {
      async function plugin() {
        // The plugin on disk already matches the CLI — the case that used to read as finished.
        const f = scripted({ stderr }, CLI);
        return stepOpenClawPlugin(home, { run: f.run, readPluginVersion: () => CLI, readCliVersion: () => CLI, resolveBin });
      }

      it('is collected as unresolved with its own recovery, never the command that cannot finish it', async () => {
        const r = await plugin();
        const unresolved = collectUnresolved([
          { label: 'OpenClaw plugin', result: r },
          { label: 'OpenClaw skill', result: { status: 'ok', summary: 'v5.15.2 installed' } },
        ]);
        expect(unresolved).toHaveLength(1);
        expect(unresolved[0]).toMatchObject({ label: 'OpenClaw plugin', rerun: command, verb: 'run' });
        expect(unresolved[0].rerun).not.toContain(never);
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
        expect(out).not.toContain(never);
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

/**
 * #1071 — `update` skipped the OpenClaw plugin on a host whose
 * `gateway.auth.token` is a secret reference, then told the operator to fix it
 * with `shieldcortex update`: the very run that had just been refused. The
 * Guard row on the same screen gave a different command, the one that worked
 * (`openclaw plugins install --force …@latest`, verified from the same shell).
 *
 * Now a secret-ref refusal is retried once through the resolved `openclaw`
 * binary; if that is refused too, every row names that one working command.
 */
describe('#1071 — a gateway secret reference does not end the plugin step', () => {
  const CLI = '5.20.0';
  const BEFORE = '5.19.0';
  const FORCE_INSTALL = 'openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest';
  const INSTALL_ARGS = FORCE_INSTALL.split(' ').slice(1);
  const RESOLVED_BIN = '/opt/openclaw/bin/openclaw';
  const RELOAD_WAIT = 'openclaw plugins reload shieldcortex-realtime --wait';
  /** OpenClaw 2026.11.3's exact refusal (`GatewaySecretRefUnavailableError`, dist/credentials-*.mjs). */
  const SECRET_REF_STDERR = [
    'gateway.auth.token is configured as a secret reference but is unavailable in this command path.',
    'Fix: set OPENCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_PASSWORD, pass explicit --token/--password,',
    'or run a gateway command path that resolves secret references before credential selection.',
  ].join('\n');
  const DRAIN_STDERR =
    'plugin shieldcortex-realtime admitted work did not settle within 60s; the previous plugin generation stays active.';
  const CREDENTIAL_ENV = ['OPENCLAW_GATEWAY_TOKEN', 'OPENCLAW_GATEWAY_PASSWORD', 'OPENCLAW_HOME'] as const;

  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    // The reporter's host: the token is a secret reference in OpenClaw's own
    // config, and no gateway credential is in this process's environment.
    writeFileSync(join(home, '.openclaw', 'openclaw.json'), JSON.stringify({
      gateway: { mode: 'local', auth: { mode: 'token', token: { source: 'exec', provider: 'vault', id: 'gateway/token' } } },
    }));
    saved = {};
    for (const k of CREDENTIAL_ENV) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
  });

  afterEach(() => {
    for (const k of CREDENTIAL_ENV) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  type Call = { cmd: string; args: string[]; env: NodeJS.ProcessEnv };

  /**
   * A fake `openclaw`. It reads the gateway config under the HOME it was handed
   * and, when `gateway.auth.token` is a secret reference, refuses exactly as
   * OpenClaw does unless `resolves(cmd)` says this binary resolves it. Anything
   * it installs lands at the CLI's version. `retryEnding` scripts a different
   * failure for the second install.
   */
  function fakeOpenClaw(resolves: (cmd: string) => boolean, retryEnding?: string) {
    const calls: Call[] = [];
    let onDisk = BEFORE;
    const run = (cmd: string, args: string[], opts: { env?: NodeJS.ProcessEnv } = {}) => {
      const env = opts.env ?? process.env;
      calls.push({ cmd, args, env });
      if (args[0] === 'plugins' && args[1] === 'list') {
        return Promise.resolve({ stdout: JSON.stringify({ plugins: [{ id: 'shieldcortex-realtime', version: onDisk }] }), stderr: '' });
      }
      const installs = calls.filter((c) => c.args[1] === 'install').length;
      if (installs > 1 && retryEnding) return rejectWith({ stderr: retryEnding })();
      const cfg = JSON.parse(readFileSync(join(String(env.HOME), '.openclaw', 'openclaw.json'), 'utf-8'));
      const tokenIsRef = typeof cfg?.gateway?.auth?.token === 'object';
      const hasExplicit = Boolean(env.OPENCLAW_GATEWAY_TOKEN || env.OPENCLAW_GATEWAY_PASSWORD)
        || args.includes('--token') || args.includes('--password');
      if (tokenIsRef && !hasExplicit && !resolves(cmd)) return rejectWith({ stderr: SECRET_REF_STDERR })();
      onDisk = CLI;
      return Promise.resolve({ stdout: 'Installed shieldcortex-realtime', stderr: '' });
    };
    return { run: run as never, calls, readPluginVersion: () => onDisk };
  }

  function step(f: ReturnType<typeof fakeOpenClaw>) {
    return stepOpenClawPlugin(home, {
      run: f.run,
      readPluginVersion: f.readPluginVersion,
      readCliVersion: () => CLI,
      resolveBin: () => RESOLVED_BIN,
    });
  }

  function captureFooter(unresolved: ReturnType<typeof collectUnresolved>): string {
    const calls: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = (chunk: any) => { calls.push(String(chunk)); return true; };
    try {
      footer(1000, true, { version: CLI }, unresolved);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stdout as any).write = original;
    }
    // eslint-disable-next-line no-control-regex
    return calls.join('').replace(/\x1b\[[0-9;]*m/g, '');
  }

  it('refused through `openclaw` on PATH, the retry through the resolved binary installs — the step is ok', async () => {
    const f = fakeOpenClaw((cmd) => cmd === RESOLVED_BIN);
    const r = await step(f);

    expect(r.status).toBe('ok');
    expect(r.summary).toBe(`${BEFORE} → ${CLI}`);
    expect(r.unfinished).toBeUndefined();
    expect(r.rerun).toBeUndefined();
    expect(r.recovery).toBeUndefined();
    expect(r.detail?.[0]).toBe(
      `first install refused: gateway.auth.token is a gateway secret reference OpenClaw could not resolve for it; retried through \`${RESOLVED_BIN} plugins install --force\``,
    );
    expect(collectUnresolved([{ label: 'OpenClaw plugin', result: r }])).toEqual([]);

    // Exactly the install and one retry of the same command — no secrets helper,
    // no explicit credential, no token in either child's environment.
    expect(f.calls.map(({ cmd, args }) => ({ cmd, args }))).toEqual([
      { cmd: 'openclaw', args: INSTALL_ARGS },
      { cmd: RESOLVED_BIN, args: INSTALL_ARGS },
    ]);
    for (const c of f.calls) {
      expect(c.env.HOME).toBe(home);
      expect(c.env.OPENCLAW_GATEWAY_TOKEN).toBeUndefined();
      expect(c.env.OPENCLAW_GATEWAY_PASSWORD).toBeUndefined();
      expect(c.args).not.toContain('--token');
      expect(c.args).not.toContain('--password');
    }
  });

  it('an OPENCLAW_HOME the operator set reaches the retry untouched, as it does the first install', async () => {
    process.env.OPENCLAW_HOME = '/srv/openclaw-profile';
    const f = fakeOpenClaw((cmd) => cmd === RESOLVED_BIN);
    await step(f);

    expect(f.calls).toHaveLength(2);
    for (const c of f.calls) expect(c.env.OPENCLAW_HOME).toBe('/srv/openclaw-profile');
  });

  it('an ordinary failure is not retried', async () => {
    const f = fakeOpenClaw(() => true);
    const r = await stepOpenClawPlugin(home, {
      run: ((cmd: string, args: string[]) => {
        f.calls.push({ cmd, args, env: {} });
        return rejectWith({ stderr: 'OpenClaw config is invalid: ~/.openclaw/openclaw.json' })();
      }) as never,
      readPluginVersion: () => BEFORE,
      readCliVersion: () => CLI,
      resolveBin: () => RESOLVED_BIN,
    });

    expect(r.status).toBe('warn');
    expect(f.calls.filter((c) => c.args[1] === 'install')).toHaveLength(1);
    expect(f.calls.some((c) => c.cmd === RESOLVED_BIN)).toBe(false);
  });

  it('the retry goes through the same ending checks: a drain on the retry gets the drain recovery', async () => {
    const f = fakeOpenClaw(() => false, DRAIN_STDERR);
    const r = await step(f);

    expect(r.status).toBe('warn');
    expect(r.unfinished).toBe(true);
    expect(r.recovery?.command).toBe(RELOAD_WAIT);
    // The first refusal is not lost behind the retry's own ending.
    expect(r.detail?.[0]).toMatch(/^first install refused: gateway\.auth\.token is a gateway secret reference/);
  });

  describe('refused by the retry too', () => {
    async function refusedTwice() {
      const f = fakeOpenClaw(() => false);
      return { r: await step(f), f };
    }

    it('the step names the force install as its one fix, never `shieldcortex update`', async () => {
      const { r, f } = await refusedTwice();

      expect(f.calls.filter((c) => c.args[1] === 'install')).toHaveLength(2);
      expect(r.status).toBe('warn');
      expect(r.unfinished).toBe(true);
      expect(r.recovery?.command).toBe(FORCE_INSTALL);
      expect(r.recovery?.command).not.toContain('shieldcortex update');
      expect(r.summary).toMatch(/refused twice: gateway\.auth\.token is a gateway secret reference/);

      const out = captureFooter(collectUnresolved([{ label: 'OpenClaw plugin', result: r }]));
      expect(out).toContain(`OpenClaw plugin: run ${FORCE_INSTALL}`);
      expect(out).not.toContain('shieldcortex update');
    });

    /**
     * The closing screen of the operator report: Guard on, and the end-of-run
     * plugin check saw the plugin behind the CLI and suggested the force install.
     * Plus two shapes where the check suggested something else entirely.
     */
    const PROTECTION: Array<[string, UpdateSummaryInput['protection']]> = [
      ['plugin behind, check suggests the force install (the report)', {
        status: 'unproven', loaded: 'unknown', versionOk: false, pluginVersion: BEFORE, expectedVersion: CLI,
        gatewayReloaded: false, nextCommand: FORCE_INSTALL,
      }],
      ['plugin behind, check suggests `shieldcortex repair`', {
        status: 'unproven', loaded: 'unknown', versionOk: false, pluginVersion: BEFORE, expectedVersion: CLI,
        gatewayReloaded: false, nextCommand: 'shieldcortex repair',
      }],
      ['enforcement not confirmed, check suggests doctor', {
        status: 'unproven', loaded: 'unknown', pluginVersion: BEFORE, gatewayReloaded: false,
        nextCommand: 'shieldcortex doctor --ai',
      }],
    ];

    it.each(PROTECTION)('every OpenClaw and Guard row gives the same single working command (%s)', async (_label, protection) => {
      const { r } = await refusedTwice();
      const input: UpdateSummaryInput = {
        fromVersion: BEFORE,
        toVersion: CLI,
        packageState: 'updated',
        engine: { ok: true },
        plugin: { status: r.status, rerun: r.rerun, recovery: r.recovery },
        skill: { status: 'ok' },
        guardOn: true,
        protection,
      };
      const summary = buildUpdateSummary(input);
      const openclaw = summary.rows.find((x) => x.label === 'OpenClaw');
      const guard = summary.rows.find((x) => x.label === 'Guard');

      expect(openclaw).toMatchObject({ mark: 'check', command: FORCE_INSTALL, commandLabel: 'Fix' });
      expect(guard).toMatchObject({ mark: 'check', command: FORCE_INSTALL, commandLabel: 'Fix' });
      expect(guard?.commandNote).toBe(openclaw?.commandNote);
      expect(summary.rows.map((x) => x.command)).not.toContain('shieldcortex update');
      // The renderer wraps a long command onto a continuation line; read it flat.
      const screen = renderUpdateSummary(summary, input, { width: 100, style: NO_STYLE, ascii: true })
        .join('\n').replace(/\s+/g, ' ');
      expect(screen).not.toContain('shieldcortex update');
      expect(screen.split(FORCE_INSTALL)).toHaveLength(3);
    });
  });

  it.each([
    ['plugin behind', { versionOk: false, nextCommand: FORCE_INSTALL }],
    ['enforcement not confirmed', { nextCommand: 'shieldcortex doctor --ai' }],
  ] as const)('a drain recovery is the Guard row\'s command too, not the force install (%s)', (_label, over) => {
    const summary = buildUpdateSummary({
      fromVersion: BEFORE,
      toVersion: CLI,
      packageState: 'updated',
      engine: { ok: true },
      plugin: { status: 'warn', recovery: { command: RELOAD_WAIT } },
      skill: { status: 'ok' },
      guardOn: true,
      protection: { status: 'unproven', loaded: 'unknown', pluginVersion: BEFORE, gatewayReloaded: false, ...over },
    });
    expect(summary.rows.find((x) => x.label === 'OpenClaw')?.command).toBe(RELOAD_WAIT);
    expect(summary.rows.find((x) => x.label === 'Guard')?.command).toBe(RELOAD_WAIT);
  });
});
