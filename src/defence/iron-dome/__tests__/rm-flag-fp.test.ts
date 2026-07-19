import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * Catastrophic-tier false positive (reported from the field): the
 * recursive-force-delete pattern `-\w*r\w*f\w*` matched any hyphenated
 * FILENAME token that happens to carry an 'r' before an 'f' — `-verify`,
 * `-perf`, `-refactor` — so a plain single-file `rm` was hard-blocked as
 * "catastrophic" with no override (the catastrophic tier ignores
 * `enforce:false`). e.g. `rm …/.write-verify-test.txt.verified`.
 *
 * Fix: the `-rf`/`-fr` flag cluster must begin at an argv boundary (preceded by
 * whitespace / start / a command separator), not be embedded inside a filename
 * token. `rm -rf /` still blocks; `rm file-verify.txt` does not.
 */

const v = (command: string) => evaluateToolCall('Bash', { command });

describe('catastrophic rm FP — a hyphenated filename is not an -rf flag', () => {
  const notCatastrophic: Array<[string, string]> = [
    ['the reported case', 'rm /home/mike/.openclaw/workspace/.write-verify-test.txt.verified'],
    ['-verify suffix', 'rm notes-verify.txt'],
    ['-perf token', 'rm my-perf-report.txt'],
    ['-refactor token', 'rm old-refactor-draft.md'],
    ['dashed dir, single file', 'rm ./build-final/report.txt'],
  ];
  it.each(notCatastrophic)('is NOT catastrophic: %s', (_name, command) => {
    const r = v(command);
    expect(r.severity).not.toBe('catastrophic');
    expect(r.decision).not.toBe('block');
    // it IS still a delete → dangerous tier (gated), just not a hard block
    expect(r.signals).toContain('file-delete');
  });
});

describe('catastrophic rm — real recursive-force deletes still hard-block (regression)', () => {
  const stillCatastrophic = [
    'rm -rf /',
    'rm -fr /tmp/x',
    'rm -Rf ~/',
    'rm -rf --no-preserve-root /',
    'rm --recursive --force /home',
    'rm -r -f --force /', // combined + root
  ];
  it.each(stillCatastrophic)('still blocks: %s', (command) => {
    const r = v(command);
    expect(r.severity).toBe('catastrophic');
    expect(r.decision).toBe('block');
  });
});
