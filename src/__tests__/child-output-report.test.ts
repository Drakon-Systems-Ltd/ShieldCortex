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
