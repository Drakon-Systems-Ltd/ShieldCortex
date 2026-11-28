/**
 * #1109 round 2 (nit): runQuiet's signal handling, proved with a REAL child.
 *
 * This suite launches `node` (process.execPath) on purpose, and nothing else,
 * so it has no launch tripwire. It was split out of
 * openclaw-repair-preflight-1109.test.ts (#1179 r1), whose repair cases run
 * behind the tripwire, which this case would trip.
 */
import { describe, expect, it } from '@jest/globals';
import { __runQuietForTest } from '../../cli/update.js';

describe('runQuiet — a signal-killed child is not a success (nit)', () => {
  it('runQuiet REJECTS a child killed by a signal (it used to resolve like exit 0)', async () => {
    await expect(__runQuietForTest(process.execPath, ['-e', 'process.kill(process.pid, "SIGTERM")'], { timeout: 20000 }))
      .rejects.toMatchObject({ exitCode: null, signal: 'SIGTERM' });
    await expect(__runQuietForTest(process.execPath, ['-e', 'process.stdout.write("ok")'], { timeout: 20000 }))
      .resolves.toEqual({ stdout: 'ok', stderr: '' });
  });
});
