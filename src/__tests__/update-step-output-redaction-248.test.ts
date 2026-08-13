import { describe, it, expect, afterEach } from '@jest/globals';
import { step } from '../cli/update.js';
import type { CapturedError } from '../integrations/child-output.js';

/**
 * #248 item 1 — `step()`'s catch block wrote `(e.stderr || '') + (e.stdout || '')`
 * straight to `process.stderr` with nothing between the child and the
 * terminal. `runQuiet` hands the child `{...process.env}`, so `NPM_TOKEN` /
 * `CLAWHUB_TOKEN` are values WE supplied — and npm echoes them back verbatim
 * in a 401 body. Update output is routinely pasted into issues and support
 * threads, so this dumped a live credential straight into whatever channel
 * that output landed in.
 *
 * The fix routes the same captured output through `describeRunFailure`
 * (`summariseCommandOutput` underneath), the exact module #221 built to
 * redact env-supplied secrets before anything reaches a terminal.
 */

const ORIGINAL_NPM_TOKEN = process.env.NPM_TOKEN;
const TOKEN = 'SEKRET-npm-token-abc123456789';

afterEach(() => {
  if (ORIGINAL_NPM_TOKEN === undefined) delete process.env.NPM_TOKEN;
  else process.env.NPM_TOKEN = ORIGINAL_NPM_TOKEN;
});

function captureWrites(stream: NodeJS.WriteStream): { calls: string[]; restore: () => void } {
  const calls: string[] = [];
  const original = stream.write.bind(stream);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (stream as any).write = (chunk: any, ...rest: any[]) => {
    calls.push(typeof chunk === 'string' ? chunk : String(chunk));
    return true;
  };
  return { calls, restore: () => { (stream as any).write = original; } };
}

describe('#248 — step() redacts child output before it reaches the terminal', () => {
  it('never writes a raw NPM_TOKEN value that the child echoed back', async () => {
    process.env.NPM_TOKEN = TOKEN;
    const stderr = captureWrites(process.stderr);
    const stdout = captureWrites(process.stdout);

    const err = Object.assign(new Error('exit 1: npm install -g shieldcortex@latest'), {
      exitCode: 1,
      command: 'npm install -g shieldcortex@latest',
      stdout: '',
      stderr: `npm error code E401\nnpm error 401 Unauthorized - GET https://registry.npmjs.org/shieldcortex - auth token=${TOKEN} rejected\n`,
    } satisfies Partial<CapturedError>);

    try {
      await expect(step('npm package', async () => { throw err; })).rejects.toThrow();
    } finally {
      stderr.restore();
      stdout.restore();
    }

    const allOutput = [...stderr.calls, ...stdout.calls].join('');
    expect(allOutput).not.toContain(TOKEN);
  });

  it('still surfaces a redacted summary of what the child said, not a blank block', async () => {
    process.env.NPM_TOKEN = TOKEN;
    const stderr = captureWrites(process.stderr);
    const stdout = captureWrites(process.stdout);

    const err = Object.assign(new Error('exit 1: npm install -g shieldcortex@latest'), {
      exitCode: 1,
      command: 'npm install -g shieldcortex@latest',
      stdout: '',
      stderr: `npm error code E401\nnpm error 401 Unauthorized - GET https://registry.npmjs.org/shieldcortex - auth token=${TOKEN} rejected\n`,
    } satisfies Partial<CapturedError>);

    try {
      await expect(step('npm package', async () => { throw err; })).rejects.toThrow();
    } finally {
      stderr.restore();
      stdout.restore();
    }

    const stderrText = stderr.calls.join('');
    expect(stderrText).toMatch(/E401/);
    expect(stderrText.toLowerCase()).toContain('redacted');
  });
});
