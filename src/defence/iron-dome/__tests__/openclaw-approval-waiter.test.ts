/**
 * Adversarial spec for openclaw-approval-waiter.ts (#143) — the courier that
 * turns an authenticated card tap into a #118 store write. The property under
 * test: the ONLY two responses that move the store are the two decisions the
 * card offered; everything else — timeout (decision:null), errors, junk,
 * even 'allow-always' — ends the waiter with the store untouched.
 */
import { parseWaiterArgs, runWaiter } from '../openclaw-approval-waiter.js';

const ARGS = { id: 'plugin:abc', hash: 'f'.repeat(64), openclawBin: '/usr/bin/openclaw' };

type ExecCb = (err: Error | null, stdout: string) => void;
function fakeExec(respond: { err?: Error; stdout?: string }) {
  const impl = ((_f: string, _a: string[], _o: unknown, cb: ExecCb) => {
    setImmediate(() => cb(respond.err ?? null, respond.stdout ?? ''));
  }) as never;
  return impl;
}

function spies() {
  const approved: string[] = [];
  const denied: string[] = [];
  return {
    approved,
    denied,
    approveImpl: ((h: string) => {
      approved.push(h);
      return { ok: true, record: {} };
    }) as never,
    denyImpl: ((h: string) => {
      denied.push(h);
      return { ok: true, record: {} };
    }) as never,
  };
}

describe('runWaiter — strict, total decision mapping', () => {
  test("'allow-once' → approveRequest on exactly the card's hash", async () => {
    const s = spies();
    const outcome = await runWaiter(ARGS, {
      execFileImpl: fakeExec({ stdout: JSON.stringify({ id: ARGS.id, decision: 'allow-once' }) }),
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome).toEqual({ acted: 'approved', ok: true });
    expect(s.approved).toEqual([ARGS.hash]);
    expect(s.denied).toEqual([]);
  });

  test("'deny' → denyRequest, nothing approved", async () => {
    const s = spies();
    const outcome = await runWaiter(ARGS, {
      execFileImpl: fakeExec({ stdout: JSON.stringify({ decision: 'deny' }) }),
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome).toEqual({ acted: 'denied', ok: true });
    expect(s.denied).toEqual([ARGS.hash]);
    expect(s.approved).toEqual([]);
  });

  test('timeout (decision:null) touches NOTHING — silence is not a no', async () => {
    const s = spies();
    const outcome = await runWaiter(ARGS, {
      execFileImpl: fakeExec({ stdout: JSON.stringify({ decision: null }) }),
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome.acted).toBe('nothing');
    expect(s.approved).toEqual([]);
    expect(s.denied).toEqual([]);
  });

  test("'allow-always' was never offered and is NOT honoured — unknown means untouched", async () => {
    const s = spies();
    const outcome = await runWaiter(ARGS, {
      execFileImpl: fakeExec({ stdout: JSON.stringify({ decision: 'allow-always' }) }),
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome.acted).toBe('nothing');
    expect(s.approved).toEqual([]);
  });

  test('gateway error / junk / injection-shaped responses all end with the store untouched', async () => {
    for (const respond of [
      { err: new Error('gateway gone') },
      { stdout: 'not json' },
      { stdout: JSON.stringify({ decision: 'ALLOW-ONCE' }) },              // case matters
      { stdout: JSON.stringify({ decision: { toString: () => 'allow-once' } }) },
      { stdout: JSON.stringify({ approved: true }) },                     // no decision field
    ]) {
      const s = spies();
      const outcome = await runWaiter(ARGS, {
        execFileImpl: fakeExec(respond),
        approveImpl: s.approveImpl,
        denyImpl: s.denyImpl,
      });
      expect(outcome.acted).toBe('nothing');
      expect(s.approved).toEqual([]);
      expect(s.denied).toEqual([]);
    }
  });
});

describe('parseWaiterArgs — refuses to forward surprises', () => {
  test('round-trips the flags the channel passes', () => {
    expect(
      parseWaiterArgs(['--id', ARGS.id, '--hash', ARGS.hash, '--openclaw-bin', ARGS.openclawBin]),
    ).toEqual(ARGS);
  });

  test('missing flags or a non-hash hash → null (waiter exits without acting)', () => {
    expect(parseWaiterArgs([])).toBeNull();
    expect(parseWaiterArgs(['--id', 'x', '--hash', 'not-a-hash', '--openclaw-bin', '/x'])).toBeNull();
    expect(parseWaiterArgs(['--id', 'x', '--openclaw-bin', '/x'])).toBeNull();
  });
});
