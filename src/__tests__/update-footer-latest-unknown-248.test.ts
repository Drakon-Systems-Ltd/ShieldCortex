import { describe, it, expect } from '@jest/globals';
import { footer } from '../cli/update.js';

/**
 * #248 (review round 2) — `footer()` printed "already on latest" whenever
 * `mainUpdated` was false, which is also true when the registry lookup
 * never resolved (E401, ENOTFOUND, timeout). An E401/ENOTFOUND run closed
 * with the same reassuring last line as a real "you're current" check.
 * `header()` already told the two cases apart; `footer()` needed the same
 * treatment.
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

function runFooter(mainUpdated: boolean, latest: { version: string | null; reason?: string }): string {
  const stdout = captureWrites(process.stdout);
  try {
    footer(1234, mainUpdated, latest);
  } finally {
    stdout.restore();
  }
  return stdout.calls.join('');
}

describe('#248 — footer() does not claim "already on latest" when resolution failed', () => {
  it('does not print "already on latest" when the registry lookup never resolved', () => {
    const out = runFooter(false, { version: null, reason: 'registry returned E401 (auth rejected)' });
    expect(out).not.toMatch(/already on latest/);
  });

  it('surfaces the failure reason instead', () => {
    const out = runFooter(false, { version: null, reason: 'registry returned E401 (auth rejected)' });
    expect(out).toMatch(/latest version unknown/i);
    expect(out).toContain('registry returned E401 (auth rejected)');
  });

  it('still prints "already on latest" when the lookup genuinely succeeded and matched', () => {
    const out = runFooter(false, { version: '4.48.0' });
    expect(out).toMatch(/already on latest/);
  });

  it('prints the restart hint, not "already on latest", when the package WAS updated', () => {
    const out = runFooter(true, { version: '4.49.0' });
    expect(out).not.toMatch(/already on latest/);
    expect(out).toMatch(/restart/i);
  });
});
