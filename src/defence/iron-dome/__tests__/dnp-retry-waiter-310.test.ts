/**
 * #310 — the DNP retry waiter's decision mapping.
 *
 * The waiter is the only thing that turns a chat tap into store state, so the
 * mapping is pinned exhaustively here: allow-once grants, deny suppresses,
 * and EVERYTHING else — a timeout, a dead gateway, an unparseable body, an
 * unknown decision string — does nothing at all.
 *
 * Two properties get their own tests because they are the ones an
 * implementation drifts away from: the waiter never reaches for
 * `approveRequest` (the #118 live-hold store has no business here), and the
 * operator is never told "granted" before the store said ok (R3 rule 8).
 */
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { existsSync, mkdtempSync, openSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  parseRetryWaiterArgs,
  readNonceFromFd,
  runRetryWaiter,
  type RetryWaiterArgs,
} from '../dnp-retry-waiter.js';
import {
  canonicaliseCwd,
  claimCardLaunch,
  consumeRetryGrant,
  fingerprintId,
  getRetryRow,
  hashToolCall,
  isDenySuppressed,
  recordDenialFingerprint,
} from '../retry-control.js';

const HASH = hashToolCall('Bash', { command: 'sudo modprobe softdog' });
const CARD_PARAMS_B64 = Buffer.from(JSON.stringify({ pluginId: 'shieldcortex' }), 'utf8').toString('base64');

/** A stand-in for `execFile` that answers with one canned gateway response. */
function gatewayReturning(body: string | Error) {
  return ((_bin: unknown, _args: unknown, _opts: unknown, cb: unknown) => {
    const done = cb as (err: Error | null, out: string) => void;
    if (body instanceof Error) done(body, '');
    else done(null, body);
    return undefined as never;
  }) as never;
}

describe('#310 — the DNP retry waiter', () => {
  let home: string;
  let cwd: string;
  let receiptPath: string;
  let t0: number;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-retry-waiter-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-retry-job-'));
    receiptPath = join(home, 'receipt.json');
    t0 = 1_760_000_000_000;
  });

  afterEach(() => {
    for (const dir of [home, cwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function seedClaim(): { id: string; nonce: string } {
    recordDenialFingerprint(
      {
        hash: HASH,
        tool: 'Bash',
        actionId: 'act-00000000000000aa',
        signals: ['privilege-escalation'],
        redactedSurface: 'Bash: [redacted action surface] fields=command',
        cwd,
      },
      { home, now: t0 },
    );
    const claim = claimCardLaunch(
      { id: fingerprintId(HASH, canonicaliseCwd(cwd)) },
      { home, now: t0, windowStartMs: t0, windowMs: 900_000, actionId: 'act-00000000000000aa' },
    );
    if (!claim.ok) throw new Error(`claim failed: ${claim.reason}`);
    return { id: claim.id, nonce: claim.nonce };
  }

  function args(over: Partial<RetryWaiterArgs> = {}): RetryWaiterArgs {
    return {
      paramsB64: CARD_PARAMS_B64,
      fingerprint: fingerprintId(HASH, canonicaliseCwd(cwd)),
      actionId: 'act-00000000000000aa',
      openclawBin: '/usr/local/bin/openclaw',
      receiptPath,
      ttlMs: 600_000,
      suppressionMs: 900_000,
      ...over,
    };
  }

  function receipt(): Record<string, unknown> | null {
    return existsSync(receiptPath) ? JSON.parse(readFileSync(receiptPath, 'utf8')) : null;
  }

  // ── The mapping ────────────────────────────────────────────────────────

  it('allow-once → a scoped, one-shot grant (never approveRequest)', async () => {
    const { nonce } = seedClaim();
    const out = await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'allow-once' })),
      home,
      now: t0 + 1_000,
    });

    expect(out.acted).toBe('granted');
    const grant = getRetryRow({ hash: HASH, cwd }, { home })?.grant;
    expect(grant?.grantKind).toBe('retry');
    expect(grant?.approvedAt).toBe(t0 + 1_000);
    expect(grant?.via).toBe('card');
    expect(grant?.origin.cwd).toBe(canonicaliseCwd(cwd));
    // The #118 live-hold store is untouched — not "not called", not present.
    expect(existsSync(join(home, '.shieldcortex', 'approvals', 'approvals.json'))).toBe(false);
    // And the retry actually spends, once.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 })).not.toBeNull();
  });

  it('deny → windowed suppression, and an unspent grant revoked with it', async () => {
    const { nonce } = seedClaim();
    await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'allow-once' })),
      home,
      now: t0 + 1_000,
    });
    // Same card, operator changes their mind before the retry runs.
    const { nonce: nonce2 } = (() => {
      // A second card is impossible while the grant is live; the deny path
      // does not need one — it is the SAME waiter answering late.
      return { nonce: nonce };
    })();
    const out = await runRetryWaiter(args({ nonce: nonce2 }), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'deny' })),
      home,
      now: t0 + 2_000,
    });

    expect(out.acted).toBe('denied');
    expect(isDenySuppressed({ hash: HASH, cwd }, { home, now: t0 + 3_000 }).suppressed).toBe(true);
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 3_000 })).toBeNull();
  });

  it.each([
    ['a timed-out card', JSON.stringify({ decision: null })],
    ['an unknown decision', JSON.stringify({ decision: 'allow-always' })],
    ['a decision-less body', JSON.stringify({ ok: true })],
    ['an unparseable body', 'not json at all'],
  ])('%s does NOTHING — silence is not consent, and it is not a no either', async (_label, body) => {
    const { nonce } = seedClaim();
    const out = await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(body),
      home,
      now: t0 + 1_000,
    });

    expect(out.acted).toBe('nothing');
    const row = getRetryRow({ hash: HASH, cwd }, { home })!;
    expect(row.grant).toBeUndefined();
    expect(row.suppression).toBeUndefined();
  });

  it('a dead gateway leaves a failure receipt and touches no state', async () => {
    const { nonce } = seedClaim();
    const out = await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(new Error('connect ECONNREFUSED')),
      home,
      now: t0 + 1_000,
    });

    expect(out.acted).toBe('nothing');
    expect(receipt()?.phase).toBe('failed');
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  // ── Ack follows the store (R3 rule 8) ──────────────────────────────────

  it('acks only after grantRetry returns ok', async () => {
    const { nonce } = seedClaim();
    const rows: Array<Record<string, unknown>> = [];
    await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'allow-once' })),
      appendOutcomeImpl: ((row: Record<string, unknown>) => { rows.push(row); return true; }) as never,
      home,
      now: t0 + 1_000,
    });

    expect(receipt()?.phase).toBe('granted');
    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe('retry_granted');
  });

  it('a FAILED grant is never acked — the operator is pointed at --denial instead', async () => {
    const { nonce } = seedClaim();
    const rows: Array<Record<string, unknown>> = [];
    const out = await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'allow-once' })),
      grantImpl: (() => ({ ok: false, reason: 'suppressed' })) as never,
      appendOutcomeImpl: ((row: Record<string, unknown>) => { rows.push(row); return true; }) as never,
      home,
      now: t0 + 1_000,
    });

    expect(out.acted).toBe('nothing');
    expect(receipt()?.phase).toBe('grant_failed');
    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe('retry_grant_failed');
    expect(String(rows[0].nextStep)).toContain('shieldcortex approve --denial act-00000000000000aa');
  });

  // ── The nonce ──────────────────────────────────────────────────────────

  it('reads the claim nonce off the inherited fd and never needs it on argv', () => {
    const { nonce } = seedClaim();
    const noncePath = join(home, 'nonce');
    writeFileSync(noncePath, nonce, { mode: 0o600 });
    const fd = openSync(noncePath, 'r');
    unlinkSync(noncePath); // exactly what the hook does — the fd is the last handle
    expect(readNonceFromFd(fd)).toBe(nonce);
  });

  it('refuses to raise a card it could never honour (no nonce by either route)', () => {
    const argv = [
      '--params-b64', CARD_PARAMS_B64,
      '--fingerprint', 'a'.repeat(32),
      '--openclaw-bin', '/usr/local/bin/openclaw',
      '--receipt', receiptPath,
    ];
    expect(parseRetryWaiterArgs(argv)).toBeNull();
    expect(parseRetryWaiterArgs([...argv, '--nonce-fd', '3'])).not.toBeNull();
    expect(parseRetryWaiterArgs([...argv, '--nonce', 'f'.repeat(64)])).not.toBeNull();
    // A malformed nonce is no nonce.
    expect(parseRetryWaiterArgs([...argv, '--nonce', 'short'])).toBeNull();
    // A fingerprint that is not one is refused rather than forwarded.
    expect(parseRetryWaiterArgs([
      '--params-b64', CARD_PARAMS_B64, '--fingerprint', '../../etc/passwd',
      '--openclaw-bin', '/x', '--receipt', receiptPath, '--nonce-fd', '3',
    ])).toBeNull();
  });

  it('never dials the gateway when the nonce cannot be read', async () => {
    seedClaim();
    const execFileImpl = jest.fn();
    const out = await runRetryWaiter(args({ nonceFd: 9 }), {
      execFileImpl: execFileImpl as never,
      readNonceImpl: () => null,
      home,
      now: t0,
    });

    expect(out).toEqual({ acted: 'nothing', reason: 'no claim nonce' });
    expect(execFileImpl).not.toHaveBeenCalled();
    expect(receipt()?.phase).toBe('failed');
  });

  it('a stale nonce cannot grant after the operator already denied', async () => {
    const { nonce } = seedClaim();
    await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'deny' })),
      home,
      now: t0 + 1_000,
    });
    // The same card, tapped Approve after the Deny landed.
    const late = await runRetryWaiter(args({ nonce }), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'allow-once' })),
      home,
      now: t0 + 2_000,
    });

    expect(late.acted).toBe('nothing');
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });
});
