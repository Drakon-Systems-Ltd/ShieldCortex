import { describe, it, expect } from '@jest/globals';
import {
  applyOpenClawCliGate,
  checkOpenClawConfigValid,
  OPENCLAW_CONFIG_LABEL,
} from '../cli/doctor.js';
import type { CheckResult } from '../cli/doctor.js';
import type { SpawnOutcome, ValidateDeps } from '../integrations/openclaw-config-validate.js';

/**
 * #221 — doctor must not recommend commands that cannot run.
 *
 * An operator followed three suggested fixes for five days while OpenClaw
 * refused every one of them, reporting only "Unknown command". Advice that
 * cannot be followed is worse than no advice: it consumes the operator's
 * attention and hides the real cause.
 *
 * The two risks pulled in opposite directions, so both are pinned here:
 * remedies that genuinely cannot run must be withdrawn, and remedies that
 * still work must survive untouched — including one that reads
 * "shieldcortex repair" and is the ONLY fix for an unprotected host.
 */

const HOME = '/home/tester';

function deps(run: () => SpawnOutcome): ValidateDeps {
  return {
    exists: () => true,
    configPath: () => `${HOME}/.openclaw/openclaw.json`,
    resolveBin: () => '/opt/homebrew/bin/openclaw',
    run,
  };
}

const INVALID_CONFIG = deps(() => ({
  status: 1,
  stdout: '',
  stderr: 'OpenClaw config is invalid: /home/tester/.openclaw/openclaw.json\n  × plugins: plugin manifest not found: ~/.openclaw/extensions/ekho-adapter/openclaw.plugin.json',
}));

/** The blocking row the gate keys on, as the real check would produce it. */
async function blockingRow(): Promise<CheckResult> {
  return await checkOpenClawConfigValid(HOME, INVALID_CONFIG);
}

describe('#221 — the config check itself', () => {
  it('fails, quotes what OpenClaw said, and names the unblocking command', async () => {
    const r = await checkOpenClawConfigValid(HOME, INVALID_CONFIG);

    expect(r.status).toBe('fail');
    expect(r.label).toBe(OPENCLAW_CONFIG_LABEL);
    expect(r.message).toContain('plugin manifest not found');
    // The operator's whole problem was not knowing WHY commands no-opped.
    expect(r.message).toContain('Unknown command');
    expect(r.fix).toContain('openclaw doctor --fix');
  });

  it('passes on a config that merely has warnings', async () => {
    const r = await checkOpenClawConfigValid(HOME, deps(() => ({
      status: 0,
      stdout: 'Config valid: ~/.openclaw/openclaw.json\n1 warning(s):\n  ! plugins.entries.ekho-adapter: duplicate plugin id detected',
      stderr: '',
    })));

    expect(r.status).toBe('pass');
  });

  it('is info, never fail, when the verdict could not be established', async () => {
    const r = await checkOpenClawConfigValid(HOME, { ...INVALID_CONFIG, resolveBin: () => null });
    expect(r.status).toBe('info');
  });

  it('returns rather than throws — a crash would render with no fix at all', async () => {
    const r = await checkOpenClawConfigValid(HOME, deps(() => { throw new Error('boom'); }));
    expect(r.status).toBe('info');
  });
});

describe('#221 — the gate withdraws advice that cannot run', () => {
  it('strips a fix whose only route is an OpenClaw subcommand', async () => {
    const results: CheckResult[] = [
      await blockingRow(),
      {
        label: 'OpenClaw plugin loaded',
        status: 'fail',
        message: 'realtime plugin regressed to v4.47.33',
        fix: 'Run `openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest`',
        needsOpenClawCli: { subcommand: 'plugins' },
      },
    ];

    const gated = applyOpenClawCliGate(results);

    expect(gated[1].fix).toBeUndefined();
    expect(gated[1].message).toContain('remedy blocked');
  });

  it('swaps in the working half when a site has one', async () => {
    const results: CheckResult[] = [
      await blockingRow(),
      {
        label: 'OpenClaw residue',
        status: 'warn',
        message: 'legacy install found',
        fix: 'Run `shieldcortex uninstall --deep --confirm` to purge, or reinstall with `shieldcortex openclaw install`',
        needsOpenClawCli: { subcommand: 'plugins', fallbackFix: 'Run `shieldcortex uninstall --deep --confirm` to purge the residue (pure filesystem).' },
      },
    ];

    const gated = applyOpenClawCliGate(results);

    expect(gated[1].fix).toBe('Run `shieldcortex uninstall --deep --confirm` to purge the residue (pure filesystem).');
    expect(gated[1].fix).not.toContain('openclaw install');
  });

  it('annotates a site whose remediation lives in `message`, not `fix`', async () => {
    // The optional-skill notice. A gate that only rewrote `fix` would leave
    // this as the one piece of unfollowable advice still on the page.
    const results: CheckResult[] = [
      await blockingRow(),
      {
        label: 'OpenClaw skill',
        status: 'info',
        message: 'skill not installed (optional) — `shieldcortex openclaw skill install` adds it',
        needsOpenClawCli: { subcommand: 'skills' },
      },
    ];

    const gated = applyOpenClawCliGate(results);
    expect(gated[1].message).toContain('remedy blocked');
  });
});

describe('#221 — the gate must not over-reach', () => {
  /**
   * THE MOST DANGEROUS OVER-REACH. `installed-not-enabled` recommends
   * "shieldcortex repair", but that routes to restore-registration — a pure
   * JSON write with no spawn — and it is the only working remedy for an
   * UNPROTECTED host. Any suppression keyed on the substring "shieldcortex
   * repair" would delete precisely the advice that still helps.
   */
  it('keeps an untagged `shieldcortex repair` fix even though the text matches', async () => {
    const stillWorks = 'Restore the registration for the EXISTING install: `shieldcortex repair` (writes plugins.allow …). Nothing is reinstalled.';
    const results: CheckResult[] = [
      await blockingRow(),
      { label: 'OpenClaw plugin loaded', status: 'fail', message: 'UNPROTECTED', fix: stillWorks },
    ];

    const gated = applyOpenClawCliGate(results);

    expect(gated[1].fix).toBe(stillWorks);
    expect(gated[1].message).not.toContain('remedy blocked');
  });

  it('leaves every fix alone when the config is merely indeterminate', () => {
    // Fail-open: hiding working advice because we could not reach `openclaw`
    // would be a worse bug than the one being fixed.
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'info', message: 'not checked — openclaw binary not found' },
      {
        label: 'OpenClaw plugin loaded',
        status: 'fail',
        message: 'regressed',
        fix: 'Run `openclaw plugins install --force …`',
        needsOpenClawCli: { subcommand: 'plugins' },
      },
    ];

    expect(applyOpenClawCliGate(results)).toEqual(results);
  });

  it('leaves every fix alone when the config is valid', () => {
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'pass', message: 'validates' },
      {
        label: 'OpenClaw plugin loaded',
        status: 'fail',
        message: 'regressed',
        fix: 'Run `openclaw plugins install --force …`',
        needsOpenClawCli: { subcommand: 'plugins' },
      },
    ];

    expect(applyOpenClawCliGate(results)).toEqual(results);
  });

  /**
   * The gate keys on `openClawCliBlocked`, never on `status === 'fail'`.
   * Keying on severity would mean any later adjustment to this check's status
   * silently switches the whole suppression feature off with no test failing —
   * the coupling that produced #222 and #103.
   */
  it('still suppresses when the config row is a warn, not a fail', () => {
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'warn', message: 'invalid', openClawCliBlocked: true },
      { label: 'A', status: 'fail', message: 'm', fix: 'f', needsOpenClawCli: { subcommand: 'plugins' } },
    ];

    expect(applyOpenClawCliGate(results)[1].fix).toBeUndefined();
  });

  it('does not suppress on a fail row that lacks the marker', () => {
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'fail', message: 'some other failure' },
      { label: 'A', status: 'fail', message: 'm', fix: 'f', needsOpenClawCli: { subcommand: 'plugins' } },
    ];

    expect(applyOpenClawCliGate(results)[1].fix).toBe('f');
  });

  /**
   * `doctor` exits 1 on any fail with no --strict opt-in, and the enforcement
   * contract reserves that for states ShieldCortex owns. A host using
   * ShieldCortex purely as MCP memory, whose OpenClaw has some third-party
   * plugin's dangling entry, must not start failing its pipeline over it.
   */
  /**
   * A TAG IS NOT A FAULT.
   *
   * `checkOpenClawSkillVersion` returns this exact tagged `info` row whenever
   * the skill is not installed — the DEFAULT for every host not using the
   * OpenClaw integration. Counting tags rather than faults kept the config row
   * at `fail`, so `shieldcortex doctor` exited 1 on hosts with nothing wrong,
   * over a third party's config. The row must still be annotated: it does not
   * vote on severity, but it is still advice that cannot be followed.
   */
  it('an optional info row does not make doctor fail, but is still annotated', () => {
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'fail', message: 'invalid', openClawCliBlocked: true },
      {
        label: 'OpenClaw skill version',
        status: 'info',
        message: 'skill not installed (optional) — `shieldcortex openclaw skill install` adds it',
        needsOpenClawCli: { subcommand: 'skills' },
      },
    ];

    const gated = applyOpenClawCliGate(results);

    expect(gated[0].status).toBe('warn');
    expect(gated[1].message).toContain('remedy blocked');
  });

  it('a real fault alongside an info row still fails', () => {
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'fail', message: 'invalid', openClawCliBlocked: true },
      { label: 'OpenClaw skill version', status: 'info', message: 'optional', needsOpenClawCli: { subcommand: 'skills' } },
      { label: 'OpenClaw plugin loaded', status: 'fail', message: 'UNPROTECTED', fix: 'f', needsOpenClawCli: { subcommand: 'plugins' } },
    ];

    const gated = applyOpenClawCliGate(results);

    expect(gated[0].status).toBe('fail');
    expect(gated[2].fix).toBeUndefined();
  });

  it('downgrades to warn when no remedy of ours is actually blocked', () => {
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'fail', message: 'invalid', openClawCliBlocked: true },
      { label: 'Database', status: 'pass', message: 'healthy' },
    ];

    const gated = applyOpenClawCliGate(results);

    expect(gated[0].status).toBe('warn');
    expect(gated[0].message).toContain('no ShieldCortex remedy');
  });

  it('keeps the fail when something of ours IS blocked', () => {
    const results: CheckResult[] = [
      { label: OPENCLAW_CONFIG_LABEL, status: 'fail', message: 'invalid', openClawCliBlocked: true },
      { label: 'A', status: 'fail', message: 'm', fix: 'f', needsOpenClawCli: { subcommand: 'plugins' } },
    ];

    expect(applyOpenClawCliGate(results)[0].status).toBe('fail');
  });

  it('never changes severity of any OTHER check', async () => {
    const results: CheckResult[] = [
      await blockingRow(),
      { label: 'A', status: 'fail', message: 'm', fix: 'f', needsOpenClawCli: { subcommand: 'plugins' } },
      { label: 'B', status: 'warn', message: 'm', fix: 'f', needsOpenClawCli: { subcommand: 'skills' } },
      { label: 'C', status: 'pass', message: 'm' },
    ];

    const gated = applyOpenClawCliGate(results);

    // Counts and doctor's exit code derive from these — a gate that softened a
    // failure would make a blocked host look healthier than it is.
    expect(gated.map(r => r.status)).toEqual(results.map(r => r.status));
    expect(gated).toHaveLength(results.length);
  });
});
