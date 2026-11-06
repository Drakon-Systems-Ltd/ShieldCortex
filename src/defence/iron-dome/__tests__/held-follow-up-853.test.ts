/**
 * #853 — a held (Plane A) retry card that ends WITHOUT an Approve is reported
 * as "nothing ran": one terminal row in denials.jsonl, one no-button
 * follow-up. Pinned here at the waiter seam and at the follow-up sender.
 *
 * What must hold:
 *   - expired / denied / transport-failed / unreadable / unknown answers each
 *     write exactly one row under their own outcome name, with the follow-up
 *     status on it;
 *   - an Approve sends no "nothing ran" follow-up (it did not end that way);
 *   - a transport failure AFTER `requesting` marks its receipt `requested`, so
 *     the hook never re-labels that denial as card-less;
 *   - the follow-up goes to the denial webhook when one is configured, and is
 *     queued in the retry store otherwise — never lost, never with buttons.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runRetryWaiter, type RetryWaiterArgs } from '../dnp-retry-waiter.js';
import { buildHeldFollowUpNotification, deliverHeldFollowUp } from '../held-follow-up.js';
import {
  canonicaliseCwd,
  claimCardLaunch,
  drainHeldFollowUps,
  fingerprintId,
  formatHeldFollowUpNotice,
  hashToolCall,
  listHeldFollowUps,
  queueHeldFollowUp,
  recordDenialFingerprint,
  restoreHeldFollowUps,
  type HeldFollowUp,
} from '../retry-control.js';

const HASH = hashToolCall('Bash', { command: 'sudo modprobe softdog' });
const ACTION_ID = 'act-00000000000000aa';
const CARD_PARAMS_B64 = Buffer.from(JSON.stringify({ pluginId: 'shieldcortex' }), 'utf8').toString('base64');

function gatewayReturning(body: string | Error) {
  return ((_bin: unknown, _args: unknown, _opts: unknown, cb: unknown) => {
    const done = cb as (err: Error | null, out: string) => void;
    if (body instanceof Error) done(body, '');
    else done(null, body);
    return undefined as never;
  }) as never;
}

describe('#853 — held card follow-ups from the retry waiter', () => {
  let home: string;
  let cwd: string;
  let receiptPath: string;
  const t0 = 1_760_000_000_000;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-held-followup-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-held-job-'));
    receiptPath = join(home, 'receipt.json');
  });

  afterEach(() => {
    for (const dir of [home, cwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function seedClaim(): string {
    recordDenialFingerprint(
      { hash: HASH, tool: 'Bash', actionId: ACTION_ID, signals: ['privilege-escalation'], redactedSurface: 'Bash: [redacted]', cwd },
      { home, now: t0 },
    );
    const claim = claimCardLaunch(
      { id: fingerprintId(HASH, canonicaliseCwd(cwd)) },
      { home, now: t0, windowStartMs: t0, windowMs: 900_000, actionId: ACTION_ID },
    );
    if (!claim.ok) throw new Error(`claim failed: ${claim.reason}`);
    return claim.nonce;
  }

  function args(nonce: string): RetryWaiterArgs {
    return {
      paramsB64: CARD_PARAMS_B64,
      fingerprint: fingerprintId(HASH, canonicaliseCwd(cwd)),
      actionId: ACTION_ID,
      tool: 'Bash',
      openclawBin: '/usr/local/bin/openclaw',
      receiptPath,
      nonce,
      ttlMs: 600_000,
      suppressionMs: 900_000,
    };
  }

  function rows(): Array<Record<string, unknown>> {
    const file = join(home, '.shieldcortex', 'denials.jsonl');
    return existsSync(file)
      ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
      : [];
  }

  function recorder() {
    const sent: HeldFollowUp[] = [];
    const impl = (async (item: HeldFollowUp) => { sent.push(item); return 'delivered' as const; }) as typeof deliverHeldFollowUp;
    return { sent, impl };
  }

  for (const [label, gateway, kind, outcome] of [
    ['expired unanswered (decision null)', JSON.stringify({ decision: null }), 'expired', 'retry_card_expired'],
    ['an unknown decision string', JSON.stringify({ decision: 'allow-always' }), 'failed', 'retry_card_failed'],
    ['an unreadable answer', 'not json', 'failed', 'retry_card_failed'],
    ['a transport failure after requesting', new Error('gateway closed'), 'failed', 'retry_card_failed'],
  ] as const) {
    it(`${label} → one ${outcome} row and one "${kind}" follow-up; nothing granted`, async () => {
      const nonce = seedClaim();
      const { sent, impl } = recorder();
      const out = await runRetryWaiter(args(nonce), {
        execFileImpl: gatewayReturning(gateway as string | Error),
        followUpImpl: impl,
        home,
        now: t0 + 1_000,
      });
      expect(out.acted).toBe('nothing');
      expect(sent).toEqual([{ kind, tool: 'Bash', at: t0 + 1_000, actionId: ACTION_ID }]);
      const written = rows();
      expect(written).toHaveLength(1);
      expect(written[0]).toMatchObject({ event: 'action_guard_denial', outcome, actionId: ACTION_ID, tool: 'Bash', followUp: 'delivered' });
      expect(String(written[0].reason)).toContain('nothing ran');
      if (kind === 'failed') expect(written[0].nextStep).toBe(`shieldcortex approve --denial ${ACTION_ID}`);
      // No nonce, hash or command on the operator row.
      const text = JSON.stringify(written);
      expect(text).not.toContain(nonce);
      expect(text).not.toContain(HASH);
      expect(text).not.toContain('modprobe');
    });
  }

  it('a transport failure after requesting leaves a receipt marked `requested`', async () => {
    const nonce = seedClaim();
    await runRetryWaiter(args(nonce), {
      execFileImpl: gatewayReturning(new Error('gateway closed')),
      followUpImpl: recorder().impl,
      home,
    });
    expect(JSON.parse(readFileSync(receiptPath, 'utf8'))).toMatchObject({ phase: 'failed', requested: true });
  });

  it('a Deny writes retry_denied with "nothing ran" and sends a denied follow-up', async () => {
    const nonce = seedClaim();
    const { sent, impl } = recorder();
    const out = await runRetryWaiter(args(nonce), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'deny' })),
      followUpImpl: impl,
      home,
      now: t0 + 1_000,
    });
    expect(out.acted).toBe('denied');
    expect(sent.map((s) => s.kind)).toEqual(['denied']);
    const written = rows();
    expect(written).toHaveLength(1);
    expect(written[0]).toMatchObject({ outcome: 'retry_denied', followUp: 'delivered', actionId: ACTION_ID });
    expect(String(written[0].reason)).toContain('nothing ran');
  });

  it('an Approve sends NO "nothing ran" follow-up', async () => {
    const nonce = seedClaim();
    const { sent, impl } = recorder();
    const out = await runRetryWaiter(args(nonce), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'allow-once' })),
      followUpImpl: impl,
      home,
      now: t0 + 1_000,
    });
    expect(out.acted).toBe('granted');
    expect(sent).toHaveLength(0);
    expect(rows().map((r) => r.outcome)).toEqual(['retry_granted']);
  });

  it('a failure BEFORE requesting sends nothing — no card was ever shown', async () => {
    const { sent, impl } = recorder();
    const out = await runRetryWaiter(
      { ...args('0'.repeat(64)), paramsB64: Buffer.from('{not json', 'utf8').toString('base64') },
      { execFileImpl: gatewayReturning(JSON.stringify({ decision: null })), followUpImpl: impl, home },
    );
    expect(out.acted).toBe('nothing');
    expect(sent).toHaveLength(0);
    expect(rows()).toHaveLength(0);
    expect(JSON.parse(readFileSync(receiptPath, 'utf8')).requested).toBeUndefined();
  });

  it('a follow-up sender that throws still leaves the row, marked dropped', async () => {
    const nonce = seedClaim();
    await runRetryWaiter(args(nonce), {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: null })),
      followUpImpl: (async () => { throw new Error('boom'); }) as never,
      home,
    });
    expect(rows()).toEqual([expect.objectContaining({ outcome: 'retry_card_expired', followUp: 'dropped' })]);
  });
});

describe('#853 — deliverHeldFollowUp', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-held-deliver-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  });

  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  const item: HeldFollowUp = { kind: 'expired', tool: 'Bash', actionId: 'act-0123456789abcdef', at: 1_760_000_000_000 };

  function writeNotify(notify: Record<string, unknown>): void {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { notify } }));
  }

  it('posts to the denial webhook when one is configured — a no-button outcome alert', async () => {
    writeNotify({ enabled: true, webhookUrl: 'https://hooks.example.test/sc' });
    const bodies: string[] = [];
    const fetchImpl = (async (_url: unknown, init?: { body?: unknown }) => {
      bodies.push(String(init?.body ?? ''));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;
    const status = await deliverHeldFollowUp(item, { home, fetchImpl });
    expect(status).toBe('delivered');
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toContain('retry_card_expired');
    expect(bodies[0]).toContain('act-0123456789abcdef');
    expect(bodies[0]).not.toMatch(/allow-once|approve once/i);
    expect(listHeldFollowUps({ home })).toHaveLength(0);
  });

  it('queues in the retry store when no webhook is configured', async () => {
    expect(await deliverHeldFollowUp(item, { home })).toBe('queued');
    expect(listHeldFollowUps({ home })).toEqual([item]);
  });

  it('queues when the webhook send fails', async () => {
    writeNotify({ enabled: true, webhookUrl: 'https://hooks.example.test/sc' });
    const fetchImpl = (async () => new Response('nope', { status: 500 })) as typeof fetch;
    expect(await deliverHeldFollowUp(item, { home, fetchImpl })).toBe('queued');
    expect(listHeldFollowUps({ home })).toHaveLength(1);
  });

  it('the alert body says nothing ran and carries no command', () => {
    const n = buildHeldFollowUpNotification(item);
    expect(n.outcome).toBe('retry_card_expired');
    expect(n.digestText).toBe('ShieldCortex: card for Bash (act-0123456789abcdef) expired unanswered. Nothing ran.');
    expect(JSON.stringify(n)).not.toMatch(/approve --denial act-0123456789abcdef --ttl|allow-once/);
  });
});

describe('#853 — the follow-up queue', () => {
  let home: string;

  beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'sc-held-queue-')); });
  afterEach(() => { try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ } });

  it('dedupes by (kind, actionId), drains once, and restores after a failed send', () => {
    const a: HeldFollowUp = { kind: 'expired', tool: 'Bash', actionId: 'act-000000000000000a', at: 1 };
    const b: HeldFollowUp = { kind: 'failed', tool: 'Write', actionId: 'act-000000000000000b', at: 2 };
    expect(queueHeldFollowUp(a, { home })).toBe(true);
    expect(queueHeldFollowUp(a, { home })).toBe(true);
    expect(queueHeldFollowUp(b, { home })).toBe(true);
    expect(listHeldFollowUps({ home })).toHaveLength(2);

    const drained = drainHeldFollowUps({ home });
    expect(drained).toHaveLength(2);
    expect(drainHeldFollowUps({ home })).toHaveLength(0);

    restoreHeldFollowUps(drained, { home });
    expect(listHeldFollowUps({ home })).toHaveLength(2);

    const text = formatHeldFollowUpNotice(drained);
    expect(text).toContain('card for Bash (act-000000000000000a) expired unanswered. Nothing ran.');
    expect(text).toContain('shieldcortex approve --denial act-000000000000000b');
  });

  it('refuses a malformed follow-up (bad actionId shape)', () => {
    expect(queueHeldFollowUp({ kind: 'expired', tool: 'Bash', actionId: 'act-NOPE', at: 1 }, { home })).toBe(false);
    expect(listHeldFollowUps({ home })).toHaveLength(0);
  });
});
