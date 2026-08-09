/**
 * Adversarial spec for openclaw-approval-waiter.ts (#143) — the process that
 * owns the card and turns an authenticated tap into a #118 store write. The
 * property under test: the ONLY two responses that move the store are the
 * two decisions the card offered; everything else — timeout (decision:null),
 * errors, junk, even 'allow-always' — ends the waiter with the store
 * untouched. Receipt behaviour is covered as the channel's only window in.
 */
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseWaiterArgs, runWaiter, type WaiterArgs } from '../openclaw-approval-waiter.js';

const PARAMS_B64 = Buffer.from(JSON.stringify({ title: 't', description: 'd' }), 'utf8').toString('base64');

type ExecCb = (err: Error | null, stdout: string) => void;
function fakeExec(respond: { err?: Error; stdout?: string }) {
  const calls: Array<{ file: string; args: string[] }> = [];
  const impl = ((file: string, args: string[], _o: unknown, cb: ExecCb) => {
    calls.push({ file, args });
    setImmediate(() => cb(respond.err ?? null, respond.stdout ?? ''));
  }) as never;
  return { impl, calls };
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
  let dir: string;
  let args: WaiterArgs;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-waiter-'));
    args = {
      paramsB64: PARAMS_B64,
      hash: 'f'.repeat(64),
      openclawBin: '/usr/bin/openclaw',
      receiptPath: join(dir, 'receipt.json'),
    };
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test("'allow-once' → approveRequest on exactly the card's hash; receipt cleaned up", async () => {
    const s = spies();
    const exec = fakeExec({ stdout: JSON.stringify({ id: 'plugin:x', decision: 'allow-once' }) });
    const outcome = await runWaiter(args, {
      execFileImpl: exec.impl,
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome).toEqual({ acted: 'approved', ok: true });
    expect(s.approved).toEqual([args.hash]);
    expect(s.denied).toEqual([]);
    expect(existsSync(args.receiptPath)).toBe(false);
    // The one long-lived call is request-with-final — request and wait share
    // one connection, which is the whole topology lesson.
    expect(exec.calls[0].args).toEqual(
      expect.arrayContaining(['plugin.approval.request', '--expect-final']),
    );
  });

  test("'deny' → denyRequest, nothing approved", async () => {
    const s = spies();
    const outcome = await runWaiter(args, {
      execFileImpl: fakeExec({ stdout: JSON.stringify({ decision: 'deny' }) }).impl,
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome).toEqual({ acted: 'denied', ok: true });
    expect(s.denied).toEqual([args.hash]);
    expect(s.approved).toEqual([]);
  });

  test('timeout (decision:null) touches NOTHING — silence is not a no', async () => {
    const s = spies();
    const outcome = await runWaiter(args, {
      execFileImpl: fakeExec({ stdout: JSON.stringify({ decision: null }) }).impl,
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome.acted).toBe('nothing');
    expect(s.approved).toEqual([]);
    expect(s.denied).toEqual([]);
  });

  test("'allow-always' was never offered and is NOT honoured — unknown means untouched", async () => {
    const s = spies();
    const outcome = await runWaiter(args, {
      execFileImpl: fakeExec({ stdout: JSON.stringify({ decision: 'allow-always' }) }).impl,
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome.acted).toBe('nothing');
    expect(s.approved).toEqual([]);
  });

  test('gateway error → failed receipt LEFT for the channel to read, store untouched', async () => {
    const s = spies();
    const outcome = await runWaiter(args, {
      execFileImpl: fakeExec({ err: new Error('connect ECONNREFUSED') }).impl,
      approveImpl: s.approveImpl,
      denyImpl: s.denyImpl,
    });
    expect(outcome.acted).toBe('nothing');
    expect(s.approved).toEqual([]);
    const receipt = JSON.parse(readFileSync(args.receiptPath, 'utf8'));
    expect(receipt.phase).toBe('failed');
    expect(receipt.reason).toContain('ECONNREFUSED');
  });

  test('junk / injection-shaped responses all end with the store untouched', async () => {
    for (const respond of [
      { stdout: 'not json' },
      { stdout: JSON.stringify({ decision: 'ALLOW-ONCE' }) },              // case matters
      { stdout: JSON.stringify({ decision: { toString: () => 'allow-once' } }) },
      { stdout: JSON.stringify({ approved: true }) },                     // no decision field
    ]) {
      const s = spies();
      const outcome = await runWaiter(args, {
        execFileImpl: fakeExec(respond).impl,
        approveImpl: s.approveImpl,
        denyImpl: s.denyImpl,
      });
      expect(outcome.acted).toBe('nothing');
      expect(s.approved).toEqual([]);
      expect(s.denied).toEqual([]);
    }
  });

  test('unparseable params never dial the gateway at all', async () => {
    const s = spies();
    const exec = fakeExec({ stdout: '{}' });
    const outcome = await runWaiter(
      { ...args, paramsB64: '!!!not-base64-json!!!' },
      { execFileImpl: exec.impl, approveImpl: s.approveImpl, denyImpl: s.denyImpl },
    );
    expect(outcome.acted).toBe('nothing');
    expect(exec.calls).toHaveLength(0);
  });
});

describe('parseWaiterArgs — refuses to forward surprises', () => {
  const full = [
    '--params-b64', PARAMS_B64,
    '--hash', 'f'.repeat(64),
    '--openclaw-bin', '/usr/bin/openclaw',
    '--receipt', '/tmp/r.json',
  ];

  test('round-trips the flags the channel passes', () => {
    expect(parseWaiterArgs(full)).toEqual({
      paramsB64: PARAMS_B64,
      hash: 'f'.repeat(64),
      openclawBin: '/usr/bin/openclaw',
      receiptPath: '/tmp/r.json',
    });
  });

  test('missing flags or a non-hash hash → null (waiter exits without acting)', () => {
    expect(parseWaiterArgs([])).toBeNull();
    expect(parseWaiterArgs(full.slice(0, 6))).toBeNull();
    const bad = [...full];
    bad[3] = 'not-a-hash';
    expect(parseWaiterArgs(bad)).toBeNull();
  });
});
