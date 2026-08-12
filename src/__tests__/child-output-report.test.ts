import { describe, it, expect } from '@jest/globals';
import { summariseCommandOutput, describeRunFailure } from '../integrations/child-output.js';
import type { CapturedError } from '../integrations/child-output.js';

/**
 * #221 — a failed child process must yield the CAUSE, not a restatement of the
 * command that failed.
 *
 * The two properties that are easy to get wrong and are the reason this module
 * exists are pinned first: signal-first line selection (a tail returns
 * OpenClaw's reassuring sign-off and discards its diagnosis) and redaction of
 * env values we ourselves handed to the child.
 */

/** The real shape, captured from OpenClaw 2026.7.1-2 with a dangling plugin path. */
const OPENCLAW_INVALID_STDERR = [
  'OpenClaw config is invalid: /Users/x/.openclaw/openclaw.json',
  '  × plugins.load.paths: plugin: plugin path not found: /tmp/definitely-does-not-exist/plugin',
  '',
  'Run `openclaw doctor --fix` to repair, or fix the keys above manually.',
  'Inspect with openclaw config validate.',
  'Audit, status, health, logs, tasks list/audit, and doctor commands still run with invalid config.',
].join('\n');

describe('#221 — signal-first selection, because a tail loses the cause', () => {
  it('keeps OpenClaw\'s diagnosis and drops its reassuring sign-off', () => {
    const { lines } = summariseCommandOutput(OPENCLAW_INVALID_STDERR, { maxLines: 3 });

    expect(lines.join('\n')).toContain('plugin path not found');
    // The last line is the trap: `slice(-N)` returns THIS and nothing useful.
    expect(lines.join('\n')).not.toContain('still run with invalid config');
  });

  it('falls back to the tail when no line carries signal', () => {
    const { lines } = summariseCommandOutput('alpha\nbravo\ncharlie\ndelta', { maxLines: 2 });
    expect(lines).toEqual(['charlie', 'delta']);
  });
});

describe('#221 — output is destined for a pasted report, so it is redacted', () => {
  it('redacts an env value we handed the child, even in an unrecognised shape', () => {
    // `runQuiet` passes {...process.env}; npm echoes the token back in the 401
    // body. Deliberately not a shape our credential patterns recognise — this
    // layer must not depend on the detector knowing the token's format.
    const env = { NPM_TOKEN: 'totally-not-a-known-token-shape-1234567890' };
    const body = `npm error 401 Unauthorized - PUT https://registry.npmjs.org/x - token ${env.NPM_TOKEN} is not valid`;

    const { lines } = summariseCommandOutput(body, { env, maxLines: 4 });

    const text = lines.join('\n');
    expect(text).not.toContain(env.NPM_TOKEN);
    expect(text).toContain('[redacted:$NPM_TOKEN]');
  });

  it('leaves short env values alone — they would redact ordinary prose', () => {
    const env = { API_KEY: 'dev' };
    const { lines } = summariseCommandOutput('error: the device failed to start', { env });
    expect(lines.join('\n')).toBe('error: the device failed to start');
  });

  it('does not shred npm integrity hashes into noise', () => {
    const line = 'npm error sha512-Kn6y87SxfnGb0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA== integrity check failed';
    const { lines } = summariseCommandOutput(line, { env: {} });
    expect(lines.join('\n')).toContain('integrity check failed');
  });
});

describe('#221 — the strongest cause wins, not the earliest line', () => {
  /**
   * Measured on a real fleet host: `openclaw <unknown-command>` emits two
   * `[plugins] codex failed during register …: TypeError …` lines from an
   * unrelated third-party plugin BEFORE OpenClaw's own reason. Both match on
   * the word "failed", so taking the first signal line reported someone else's
   * TypeError as the cause — one misleading headline swapped for another.
   */
  it('drops other plugins\' registration chatter and leads with the real reason', () => {
    const real = [
      "[plugins] codex failed during register from /x/dist/index.js: TypeError: Cannot read properties of undefined (reading 'openSyncKeyedStore')",
      '[plugins] codex failed during register from /x/dist/index.js: TypeError: Cannot read properties of undefined',
      '[openclaw] Could not start the CLI.',
      '[openclaw] Reason: Unknown command: openclaw plugins install.',
    ].join('\n');

    const { lines } = summariseCommandOutput(real, { maxLines: 3, env: {} });

    expect(lines.join('\n')).not.toContain('codex failed');
    expect(lines[0]).toContain('Unknown command');
  });

  /**
   * The char-fit loop used to `shift()` unconditionally. On the signal path the
   * list is ranked most-important-first, so shifting deleted the line naming
   * WHICH config file was invalid and promoted a sibling issue to `reason`.
   */
  it('trims from the end when lines are ranked, keeping the header', () => {
    const long = '/Users/x/.openclaw/npm/projects/some-quite-long-vendor-plugin-directory-name/node_modules';
    const out = [
      'OpenClaw config is invalid: /Users/x/.openclaw/openclaw.json',
      `  × plugins.load.paths[0]: plugin path not found: ${long}-alpha`,
      `  × plugins.load.paths[1]: plugin path not found: ${long}-bravo`,
      `  × plugins.entries.foo.path: plugin path not found: ${long}-charlie`,
    ].join('\n');

    const { lines, truncated } = summariseCommandOutput(out, { maxLines: 4, maxChars: 400, env: {} });

    expect(lines[0]).toContain('OpenClaw config is invalid');
    expect(truncated).toBe(true);
  });

  it('keeps the head when output exceeds the input cap', () => {
    // The cap used to take the tail, discarding a diagnosis printed first
    // before the signal filter could ever see it.
    const out = 'OpenClaw config is invalid: /Users/x/.openclaw/openclaw.json\n' + 'filler line\n'.repeat(6000);

    const { lines, truncated } = summariseCommandOutput(out, { maxLines: 2, env: {} });

    expect(lines.join('\n')).toContain('OpenClaw config is invalid');
    expect(truncated).toBe(true);
  });
});

describe('#221 — the operator\'s identity does not travel with the report', () => {
  it('abbreviates the home directory, as every other doctor path site does', () => {
    const home = '/Users/somebody';
    const { lines } = summariseCommandOutput(
      `error: plugin path not found: ${home}/.openclaw/npm/projects/acme-client-plugin/dist/index.js`,
      { home, env: {} },
    );

    const text = lines.join('\n');
    expect(text).not.toContain(home);
    expect(text).toContain('~/.openclaw');
  });

  it('redacts the longer of two secrets that share a prefix', () => {
    // Visiting the shorter first left the tail of the longer one in cleartext,
    // and the second pass then found nothing intact to replace.
    const env = { MY_TOKEN: 'abcdefgh', MY_TOKEN_LONG: 'abcdefghIJKLMNOP' };
    const { lines } = summariseCommandOutput('error: rejected token abcdefghIJKLMNOP', { env, home: '/nowhere' });

    expect(lines.join('\n')).not.toContain('IJKLMNOP');
  });
});

describe('#221 — the empty-output ladder never yields a bare "failed"', () => {
  const err = (over: Partial<CapturedError>): CapturedError =>
    Object.assign(new Error('exit 1: openclaw plugins install'), over) as CapturedError;

  it('names the command when the child produced no output at all', () => {
    const r = describeRunFailure(err({ exitCode: 1, command: 'openclaw plugins install', stdout: '', stderr: '' }));
    expect(r.reason).toContain('exited 1');
    expect(r.reason).toContain('openclaw plugins install');
    expect(r.detail).toEqual([]);
  });

  it('reports a timeout as a timeout, not as an exit code', () => {
    const r = describeRunFailure(err({ exitCode: null, timedOut: true, command: 'openclaw plugins install' }));
    expect(r.timedOut).toBe(true);
    expect(r.reason).toContain('timed out');
  });

  /**
   * How the process ENDED outranks whatever it managed to print. A step killed
   * at the 120s wall usually has a plausible network line in its buffer;
   * reporting that alone tells the operator to retry a transient blip when the
   * real fact is a SIGTERM mid-flight and a possibly half-applied install.
   */
  it('a killed process is not reported as whatever it last printed', () => {
    const r = describeRunFailure(err({
      timedOut: true,
      exitCode: null,
      command: 'openclaw plugins install',
      stderr: 'npm error network request to https://registry.npmjs.org/x failed, reason: socket hang up',
    }));

    expect(r.reason).toContain('timed out');
    // The partial output is still available, just not masquerading as the cause.
    expect(r.detail.join('\n')).toContain('socket hang up');
  });

  it('reports a missing binary distinctly from a non-zero exit', () => {
    const r = describeRunFailure(err({ code: 'ENOENT', exitCode: null, command: 'openclaw' }));
    expect(r.spawnFailed).toBe(true);
    expect(r.reason).toContain('command not found');
  });

  it('prefers the stream carrying signal rather than concatenating both', () => {
    // The valid path writes to stdout, the invalid path to stderr — a blind
    // `stderr + stdout` join buries one inside the other.
    const r = describeRunFailure(err({
      exitCode: 1,
      stdout: 'Config valid: ~/.openclaw/openclaw.json',
      stderr: OPENCLAW_INVALID_STDERR,
    }));
    expect(r.reason).toContain('OpenClaw config is invalid');
    expect(r.detail.join('\n')).not.toContain('Config valid');
  });

  it('keeps the reason to a single line — step() pads it on one row', () => {
    const r = describeRunFailure(err({ exitCode: 1, stderr: 'error: ' + 'x'.repeat(500) }));
    expect(r.reason).not.toContain('\n');
    expect(r.reason.length).toBeLessThanOrEqual(120);
  });
});
