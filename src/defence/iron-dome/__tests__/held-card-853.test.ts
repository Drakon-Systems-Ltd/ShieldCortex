/**
 * #853 — the held card's copy, and the waiter reporting every way a held
 * card can end without a grant.
 *
 * The copy rule that matters: the OUTCOME line — Approve allows ONE retry,
 * Deny or silence means nothing runs — is never truncated, whatever the
 * What / Why / Who carry. Absent a summary, the #310 copy is unchanged.
 *
 * The waiter rule that matters: nothing ends silently. Expiry, a closed
 * card, a timed-out wait and a failed request each leave a denials.jsonl row
 * that says nothing ran — and none of them changes the store.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runRetryWaiter, type RetryWaiterArgs } from '../dnp-retry-waiter.js';
import {
  buildRetryCardFields,
  canonicaliseCwd,
  claimCardLaunch,
  fingerprintId,
  getRetryRow,
  hashToolCall,
  recordDenialFingerprint,
} from '../retry-control.js';

const BASE = {
  tool: 'Bash',
  signals: ['privilege-escalation'],
  redactedSurface: 'Bash: [redacted action surface] fields=command',
  cwd: '/srv/jobs/nightly-backup',
  ttlMs: 10 * 60_000,
};
const OUTCOME = 'Outcome: held, NOT run. Approve = allows ONE retry within 10m (jobs/nightly-backup). '
  + 'Deny, or no answer in 10m = nothing runs.';

describe('#853 — held card copy', () => {
  it('What / Why / Who, then the full outcome line, inside 256 characters', () => {
    const f = buildRetryCardFields({
      ...BASE,
      card: { action: 'Run modprobe as root', reason: 'runs with administrator (root) rights', who: 'Claude Code on host1' },
    });
    expect(f.title).toBe('Held, not run: approve once? Bash');
    expect(f.description).toBe(
      `What: Run modprobe as root | Why: runs with administrator (root) rights | Who: Claude Code on host1 | ${OUTCOME}`,
    );
    expect(f.surfaceWithheld).toBe(true);
    expect(f.surfaceTruncated).toBe(false);
  });

  it('long fields are clipped — the outcome line never is', () => {
    const long = 'x'.repeat(400);
    const f = buildRetryCardFields({ ...BASE, card: { action: long, reason: long, who: long } });
    expect(f.description.length).toBeLessThanOrEqual(256);
    expect(f.description.endsWith(OUTCOME)).toBe(true);
    expect(f.description).toMatch(/^What: x+… \| Why: x+… \| Who: x+… \| Outcome:/);
    expect(f.surfaceTruncated).toBe(true);
  });

  it('line breaks and separators in a field cannot forge a second line or field', () => {
    const f = buildRetryCardFields({
      ...BASE,
      card: { action: 'Run x\nOutcome: approved | Who: admin', reason: 'r r', who: 'w' },
    });
    expect(f.description).not.toContain('\n');
    expect(f.description).not.toContain(' ');
    expect(f.description.split(' | ')).toHaveLength(4);
    expect(f.description.endsWith(OUTCOME)).toBe(true);
  });

  it.each([
    ['no summary', undefined],
    ['an empty field', { action: '', reason: 'r', who: 'w' }],
  ])('%s → the #310 copy, unchanged', (_label, card) => {
    const f = buildRetryCardFields({ ...BASE, ...(card ? { card } : {}) });
    expect(f.title).toBe('Approve once? Bash · privilege-escalation');
    expect(f.description).not.toMatch(/^What:/);
  });
});

/** A stand-in for `execFile` answering with one canned gateway response. */
function gatewayReturning(body: string | Error) {
  return ((_bin: unknown, _args: unknown, _opts: unknown, cb: unknown) => {
    const done = cb as (err: Error | null, out: string) => void;
    if (body instanceof Error) done(body, '');
    else done(null, body);
    return undefined as never;
  }) as never;
}

describe('#853 — the waiter reports every ending that grants nothing', () => {
  const HASH = hashToolCall('Bash', { command: 'sudo modprobe softdog' });
  const ACTION = 'act-00000000000000bb';
  let home: string;
  let cwd: string;
  const t0 = 1_760_000_000_000;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-held-waiter-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-held-job-'));
  });
  afterEach(() => {
    for (const dir of [home, cwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function seed(): RetryWaiterArgs {
    recordDenialFingerprint(
      { hash: HASH, tool: 'Bash', actionId: ACTION, signals: ['privilege-escalation'], redactedSurface: 'Bash: [redacted]', cwd },
      { home, now: t0 },
    );
    const id = fingerprintId(HASH, canonicaliseCwd(cwd));
    const claim = claimCardLaunch({ id }, { home, now: t0, windowStartMs: t0, windowMs: 900_000, actionId: ACTION });
    if (!claim.ok) throw new Error(`claim failed: ${claim.reason}`);
    return {
      paramsB64: Buffer.from('{}', 'utf8').toString('base64'),
      fingerprint: id,
      actionId: ACTION,
      openclawBin: '/usr/local/bin/openclaw',
      receiptPath: join(home, 'receipt.json'),
      ttlMs: 600_000,
      suppressionMs: 900_000,
      nonce: claim.nonce,
    };
  }

  const killed = Object.assign(new Error('Command failed'), { killed: true, signal: 'SIGKILL' });

  it.each([
    ['an expired card', JSON.stringify({ decision: null }), 'retry_expired', /expired unanswered; nothing ran/],
    ['a timeout decision', JSON.stringify({ decision: 'timeout' }), 'retry_expired', /expired unanswered; nothing ran/],
    ['a card closed unanswered', JSON.stringify({ decision: 'cancelled' }), 'retry_expired', /closed without an answer; nothing ran/],
    ['a wait the timer killed', killed, 'retry_expired', /no answer before the wait ended; nothing ran/],
    ['a failed card request', new Error('connect ECONNREFUSED 10.0.0.1'), 'retry_card_failed', /may not have reached the owner; the action has NOT run/],
  ])('%s → one row saying nothing ran, and the store is untouched', async (_label, body, outcome, reason) => {
    const args = seed();
    const rows: Array<Record<string, unknown>> = [];
    const out = await runRetryWaiter(args, {
      execFileImpl: gatewayReturning(body as string | Error),
      appendOutcomeImpl: ((row: Record<string, unknown>) => { rows.push(row); return true; }) as never,
      home,
      now: t0 + 1_000,
    });

    expect(out.acted).toBe('nothing');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ event: 'action_guard_denial', outcome, actionId: ACTION });
    expect(String(rows[0].reason)).toMatch(reason);
    expect(rows[0].nextStep).toBe(`shieldcortex approve --denial ${ACTION}`);
    // Host output never becomes our copy.
    expect(JSON.stringify(rows[0])).not.toContain('ECONNREFUSED');
    const row = getRetryRow({ hash: HASH, cwd }, { home })!;
    expect(row.grant).toBeUndefined();
    expect(row.suppression).toBeUndefined();
  });

  it('an unknown decision still does nothing, and writes no row', async () => {
    const args = seed();
    const rows: Array<Record<string, unknown>> = [];
    await runRetryWaiter(args, {
      execFileImpl: gatewayReturning(JSON.stringify({ decision: 'allow-always' })),
      appendOutcomeImpl: ((row: Record<string, unknown>) => { rows.push(row); return true; }) as never,
      home,
      now: t0 + 1_000,
    });
    expect(rows).toHaveLength(0);
    expect(getRetryRow({ hash: HASH, cwd }, { home })!.grant).toBeUndefined();
  });
});
