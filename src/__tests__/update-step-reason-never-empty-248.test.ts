import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from '@jest/globals';
import { step } from '../cli/update.js';
import type { CapturedError } from '../integrations/child-output.js';

/**
 * #248 (review round 2) — `step()`'s catch block computed `report.reason` via
 * `describeRunFailure` and then threw it away, printing only `report.detail`
 * — and `neverEmpty` was never passed. `detail` is `[]` in exactly the cases
 * that matter most:
 *
 *   - output entirely of noise-class lines (`npm warn …`, `added 3 packages`)
 *   - a spawn ENOENT (binary not found)
 *   - a timeout with nothing captured
 *
 * In each, the operator saw `✗  npm package: failed (12.3s)` and nothing
 * else — the exact defect class #248 was filed to remove, reopened inside
 * the function #248 names. The noise case is also a regression against
 * `main`, which printed the raw captured lines unconditionally.
 */

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

async function runFailingStep(err: CapturedError): Promise<string> {
  const stderr = captureWrites(process.stderr);
  const stdout = captureWrites(process.stdout);
  try {
    await expect(step('npm package', async () => { throw err; })).rejects.toThrow();
  } finally {
    stderr.restore();
    stdout.restore();
  }
  return stderr.calls.join('');
}

describe('#248 — step() never renders a blank failure block', () => {
  it('shows a reason when the captured output was entirely noise-class lines', async () => {
    const err = Object.assign(new Error('exit 1: npm install -g shieldcortex@latest'), {
      exitCode: 1,
      command: 'npm install -g shieldcortex@latest',
      stdout: 'added 3 packages in 2s\nfound 0 vulnerabilities\n',
      stderr: '',
    } satisfies Partial<CapturedError>);

    const stderrText = await runFailingStep(err);

    // Not silence beyond "failed (Xs)" — the block prints, with content.
    expect(stderrText).toMatch(/── output/);
    expect(stderrText).toMatch(/added 3 packages/);
  });

  it('shows "command not found" as the reason on a spawn ENOENT, where detail is empty', async () => {
    const err = Object.assign(new Error('spawn npm ENOENT'), {
      spawnFailed: true,
      exitCode: null,
      code: 'ENOENT',
      command: 'npm install -g shieldcortex@latest',
    } satisfies Partial<CapturedError>);

    const stderrText = await runFailingStep(err);

    expect(stderrText).toMatch(/command not found/);
  });

  it('shows "timed out" as the reason on a timeout with nothing captured', async () => {
    const err = Object.assign(new Error('timeout: npm install -g shieldcortex@latest'), {
      timedOut: true,
      exitCode: null,
      command: 'npm install -g shieldcortex@latest',
      stdout: '',
      stderr: '',
    } satisfies Partial<CapturedError>);

    const stderrText = await runFailingStep(err);

    expect(stderrText).toMatch(/timed out/);
  });
});

describe('#248 — step() is wired through the never-empty guarantee', () => {
  it('calls describeRunFailure with { neverEmpty: true }', () => {
    const src = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), '..', 'cli', 'update.ts'),
      'utf-8',
    );
    expect(src).toMatch(/describeRunFailure\(err,\s*\{\s*neverEmpty:\s*true\s*\}\)/);
  });
});
