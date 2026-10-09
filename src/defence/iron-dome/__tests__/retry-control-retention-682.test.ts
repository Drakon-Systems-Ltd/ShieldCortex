/**
 * #682 — pending denial identities are kept for a 48h operator review window,
 * in a bounded store that says truthfully what it dropped and why.
 *
 * What must NOT move is pinned beside what does: an identity is still nothing
 * spendable, a grant is still one-shot and counted from the approval (default
 * 10m, max 60m), a card still lives 10m, spend still AND-matches hash + tool +
 * cwd, and a retirement receipt is unreachable from every grant, claim, consume
 * and deny path. Injected home + injected clock only; no real host state.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  DEFAULT_RETRY_GRANT_TTL_MS,
  MAX_RETIRED_IDENTITIES,
  MAX_RETRY_GRANT_TTL_MS,
  MAX_RETRY_ROWS,
  RETIRED_IDENTITY_MAX_AGE_MS,
  RETRY_CARD_LIFETIME_MS,
  RETRY_FINGERPRINT_RETENTION_MS,
  RETRY_GRANT_AUDIT_TAIL_MS,
  RETRY_PENDING_REVIEW_WINDOW_MS,
  canonicaliseCwd,
  claimCardLaunch,
  consumeRetryGrant,
  findRetiredIdentity,
  fingerprintId,
  getRetryRow,
  grantRetry,
  hashToolCall,
  isDenySuppressed,
  listRetryRows,
  lookupRetryRow,
  pruneRetryControl,
  recordDenialFingerprint,
  recordDenySuppression,
  retryControlPath,
  retryStoreCapacity,
} from '../retry-control.js';

const HASH = hashToolCall('Bash', { command: 'sudo systemctl restart backup-daily' });
const ACTION_ID = 'act-00000000000068aa';
const MIN = 60_000;
const HOUR = 60 * MIN;
const WINDOW = RETRY_PENDING_REVIEW_WINDOW_MS;

function jobHash(i: number): string {
  return hashToolCall('Bash', { command: `nightly-job --slot ${i}` });
}
function jobActionId(i: number): string {
  return `act-${(0x6820_0000 + i).toString(16).padStart(16, '0')}`;
}

describe('#682 — 48h review window for pending denial identities', () => {
  let home: string;
  let cwd: string;
  let otherCwd: string;
  let t0: number;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-retain-682-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    cwd = mkdtempSync(join(tmpdir(), 'sc-retain-job-'));
    otherCwd = mkdtempSync(join(tmpdir(), 'sc-retain-other-'));
    t0 = 1_760_000_000_000;
  });

  afterEach(() => {
    for (const dir of [home, cwd, otherCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function denial(opts: { now?: number; hash?: string; actionId?: string; cwd?: string } = {}) {
    return recordDenialFingerprint(
      {
        hash: opts.hash ?? HASH,
        tool: 'Bash',
        actionId: opts.actionId ?? ACTION_ID,
        signals: ['privilege-escalation'],
        redactedSurface: 'Bash: [redacted action surface] fields=command',
        cwd: opts.cwd ?? cwd,
        sessionKey: 'sc-bbbbbbbbbbbbbbbb',
      },
      { home, now: opts.now ?? t0 },
    );
  }

  function fill(count: number, start = 0, now = (i: number) => t0 + i) {
    for (let i = start; i < start + count; i += 1) {
      const r = denial({ hash: jobHash(i), actionId: jobActionId(i), now: now(i) });
      expect(r.ok).toBe(true);
    }
  }

  function rawStore(): Record<string, unknown> {
    return JSON.parse(readFileSync(retryControlPath(home), 'utf8')) as Record<string, unknown>;
  }

  const id = () => fingerprintId(HASH, canonicaliseCwd(cwd));

  // ── Clocks ──────────────────────────────────────────────────────────────

  it('splits the review window from every spend clock', () => {
    expect(WINDOW).toBe(48 * HOUR);
    // The pre-#682 name is an alias of the clock that now applies.
    expect(RETRY_FINGERPRINT_RETENTION_MS).toBe(WINDOW);
    // Unchanged: grant default/max, card lifetime, audit tail.
    expect(DEFAULT_RETRY_GRANT_TTL_MS).toBe(10 * MIN);
    expect(MAX_RETRY_GRANT_TTL_MS).toBe(60 * MIN);
    expect(RETRY_CARD_LIFETIME_MS).toBe(10 * MIN);
    expect(RETRY_GRANT_AUDIT_TAIL_MS).toBe(24 * HOUR);
  });

  // ── The boundaries ──────────────────────────────────────────────────────

  it.each([
    ['61 minutes', 61 * MIN],
    ['24 hours', 24 * HOUR],
    ['48h - 1ms', WINDOW - 1],
  ])('at %s the identity is listed, nothing is spendable, and a TTY approval mints a fresh 10m one-shot', (_label, offset) => {
    denial();
    const at = t0 + offset;
    pruneRetryControl({ home, now: at });

    expect(listRetryRows({ home, now: at }).map((r) => r.id)).toEqual([id()]);
    expect(lookupRetryRow({ actionId: ACTION_ID }, { home, now: at })?.id).toBe(id());
    // Retention alone authorises nothing.
    expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: at })).toBeNull();

    const g = grantRetry({ id: id() }, { isInteractive: true }, { home, now: at });
    expect(g.ok).toBe(true);
    if (!g.ok) return;
    expect(g.grant.approvedAt).toBe(at);
    expect(g.grant.ttlMs).toBe(DEFAULT_RETRY_GRANT_TTL_MS);
    expect(g.grant.via).toBe('tty');
    expect(g.grant.origin).toEqual({ cwd: canonicaliseCwd(cwd), tool: 'Bash' });
  });

  it.each([
    ['exactly 48h', WINDOW],
    ['48h + 1ms', WINDOW + 1],
  ])('at %s the identity has expired: unlisted, ungrantable, and a receipt says so', (_label, offset) => {
    denial();
    const at = t0 + offset;
    // Unlisted even before any prune runs (the list and the prune share one predicate).
    expect(listRetryRows({ home, now: at })).toEqual([]);

    pruneRetryControl({ home, now: at });
    expect(getRetryRow({ id: id() }, { home })).toBeUndefined();
    expect(grantRetry({ id: id(), actionId: ACTION_ID }, { isInteractive: true }, { home, now: at }))
      .toEqual({ ok: false, reason: 'not-found' });

    const gone = findRetiredIdentity({ actionId: ACTION_ID }, { home, now: at });
    expect(gone).toEqual({
      id: id(),
      actionIds: [ACTION_ID],
      tool: 'Bash',
      reason: 'expired',
      lastDeniedAt: t0,
      retiredAt: at,
    });
  });

  it('the window rolls from the LAST denial (a remint refreshes it, not the epoch)', () => {
    denial({ now: t0 });
    const again = denial({ now: t0 + 30 * HOUR, actionId: 'act-00000000000068ab' });
    expect(again.row?.denyEpoch).toBe(0);
    pruneRetryControl({ home, now: t0 + WINDOW + HOUR });
    expect(lookupRetryRow({ actionId: 'act-00000000000068ab' }, { home, now: t0 + WINDOW + HOUR })).toBeDefined();
    pruneRetryControl({ home, now: t0 + 30 * HOUR + WINDOW });
    expect(getRetryRow({ id: id() }, { home })).toBeUndefined();
  });

  // ── A fresh grant from an old identity is the SAME short one-shot ──────

  it('a grant minted 47h after the denial runs from the approval, for its TTL only', () => {
    denial();
    const at = t0 + 47 * HOUR;
    expect(grantRetry({ id: id() }, { isInteractive: true }, { home, now: at }).ok).toBe(true);

    // Exact TTL boundary: approvedAt + ttl is already expired (strict <).
    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash' } },
      { home, now: at + DEFAULT_RETRY_GRANT_TTL_MS },
    )).toBeNull();
    // And the row is not a standing grant: re-denied tomorrow, it is a pending
    // identity again, with nothing spendable until a human acts.
    const tomorrow = at + 24 * HOUR;
    denial({ now: tomorrow });
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: tomorrow + 1 })).toBeNull();
  });

  it('…and inside its TTL it is spent exactly once', () => {
    denial();
    const at = t0 + 47 * HOUR;
    expect(grantRetry({ id: id() }, { isInteractive: true }, { home, now: at }).ok).toBe(true);
    const spent = consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash' } },
      { home, now: at + DEFAULT_RETRY_GRANT_TTL_MS - 1 },
    );
    expect(spent?.approvedAt).toBe(at);
    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash' } },
      { home, now: at + DEFAULT_RETRY_GRANT_TTL_MS - 1 },
    )).toBeNull();
  });

  it('an old identity\'s grant still AND-matches hash, tool and cwd', () => {
    denial();
    const at = t0 + 40 * HOUR;
    expect(grantRetry({ id: id() }, { isInteractive: true }, { home, now: at }).ok).toBe(true);
    const later = at + MIN;
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd: otherCwd, tool: 'Bash' } }, { home, now: later })).toBeNull();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Write' } }, { home, now: later })).toBeNull();
    expect(consumeRetryGrant(
      { hash: hashToolCall('Bash', { command: 'sudo systemctl restart backup-daily; id' }), origin: { cwd, tool: 'Bash' } },
      { home, now: later },
    )).toBeNull();
    // Still unspent after three misses: the right call can have it.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: later })).not.toBeNull();
  });

  it('a TTY grant still caps --ttl at 60m and still needs isInteractive', () => {
    denial();
    const at = t0 + 30 * HOUR;
    expect(grantRetry({ id: id() }, {}, { home, now: at })).toEqual({ ok: false, reason: 'not-authenticated' });
    expect(grantRetry({ id: id() }, { isInteractive: false }, { home, now: at }))
      .toEqual({ ok: false, reason: 'not-authenticated' });
    const g = grantRetry({ id: id() }, { isInteractive: true }, { home, now: at, ttlMs: 24 * HOUR });
    // Out of bounds falls back to the default — it never becomes a day.
    expect(g.ok && g.grant.ttlMs).toBe(DEFAULT_RETRY_GRANT_TTL_MS);
  });

  // ── Cards, nonces and epochs keep their own short lifetimes ────────────

  it('a card is still dead after 10m, even though its identity is kept for 48h', () => {
    denial();
    const c = claimCardLaunch({ id: id() }, { home, now: t0, windowStartMs: t0, windowMs: 15 * MIN });
    expect(c.ok).toBe(true);
    const nonce = c.ok ? c.nonce : '';
    const epoch = c.ok ? c.epoch : -1;

    for (const late of [t0 + RETRY_CARD_LIFETIME_MS, t0 + 11 * MIN, t0 + 24 * HOUR, t0 + WINDOW - 1]) {
      const tap = grantRetry({ id: id() }, { nonce }, { home, now: late });
      expect(tap.ok).toBe(false);
      expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
    }
    // The unanswered claim's expiry advanced the epoch exactly once.
    expect(getRetryRow({ id: id() }, { home })?.denyEpoch).toBe(epoch + 1);
  });

  it('a nonce from a retired identity buys nothing on its re-created row', () => {
    denial();
    const c = claimCardLaunch({ id: id() }, { home, now: t0, windowStartMs: t0, windowMs: 15 * MIN });
    const nonce = c.ok ? c.nonce : '';
    pruneRetryControl({ home, now: t0 + WINDOW });
    const back = denial({ now: t0 + WINDOW + 1 });
    expect(back.row?.denyEpoch).toBe(0);
    expect(back.row?.claim).toBeUndefined();
    expect(grantRetry({ id: id() }, { nonce }, { home, now: t0 + WINDOW + 2 }))
      .toEqual({ ok: false, reason: 'claim-missing' });
  });

  // ── D1: the OR — a spent grant's tail never cuts short a newer denial ──

  it('spent grant at t0, new denial at t0+20h: kept past the old tail, until 48h after the new denial', () => {
    denial();
    expect(grantRetry({ id: id() }, { isInteractive: true }, { home, now: t0 }).ok).toBe(true);
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 1 })).not.toBeNull();
    const reminted = t0 + 20 * HOUR;
    denial({ now: reminted, actionId: 'act-00000000000068ac' });

    const pastOldTail = t0 + DEFAULT_RETRY_GRANT_TTL_MS + RETRY_GRANT_AUDIT_TAIL_MS + 10 * MIN;
    pruneRetryControl({ home, now: pastOldTail });
    expect(listRetryRows({ home, now: pastOldTail }).map((r) => r.id)).toEqual([id()]);
    // Still spent, still unspendable.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: pastOldTail })).toBeNull();
    // The operator can authorise a NEW one-shot for the new denial.
    const fresh = grantRetry({ actionId: 'act-00000000000068ac' }, { isInteractive: true }, { home, now: pastOldTail });
    expect(fresh.ok && fresh.grant.approvedAt).toBe(pastOldTail);
  });

  it('the D1 row still leaves at 48h after its newest denial', () => {
    denial();
    grantRetry({ id: id() }, { isInteractive: true }, { home, now: t0 });
    consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 1 });
    const reminted = t0 + 20 * HOUR;
    denial({ now: reminted });

    pruneRetryControl({ home, now: reminted + WINDOW - 1 });
    expect(getRetryRow({ id: id() }, { home })).toBeDefined();
    pruneRetryControl({ home, now: reminted + WINDOW });
    expect(getRetryRow({ id: id() }, { home })).toBeUndefined();
    expect(findRetiredIdentity({ id: id() }, { home })?.lastDeniedAt).toBe(reminted);
  });

  it('D2: what the prune keeps, the list shows (terminal grant in its tail, denial older than 48h)', () => {
    denial();
    const grantAt = t0 + 47 * HOUR;
    grantRetry({ id: id() }, { isInteractive: true }, { home, now: grantAt });
    consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: grantAt + 1 });
    const at = t0 + WINDOW + HOUR;
    pruneRetryControl({ home, now: at });
    expect(getRetryRow({ id: id() }, { home })).toBeDefined();
    expect(listRetryRows({ home, now: at }).map((r) => r.id)).toEqual([id()]);
  });

  // ── Receipts are unreachable from every spend/grant/claim/deny path ────

  it('a retired identity cannot be granted, claimed, consumed, denied or found as a row', () => {
    denial();
    const at = t0 + WINDOW;
    pruneRetryControl({ home, now: at });
    expect(findRetiredIdentity({ id: id() }, { home })).toBeDefined();

    for (const ref of [{ id: id() }, { actionId: ACTION_ID }, { actionId: ACTION_ID.toUpperCase() }, { hash: HASH, cwd }]) {
      expect(getRetryRow(ref, { home })).toBeUndefined();
      expect(lookupRetryRow(ref, { home, now: at })).toBeUndefined();
      expect(grantRetry(ref, { isInteractive: true, anyOrigin: true, overrideDeny: true }, { home, now: at }))
        .toEqual({ ok: false, reason: 'not-found' });
      expect(claimCardLaunch(ref, { home, now: at, windowStartMs: at, windowMs: 15 * MIN }))
        .toEqual({ ok: false, reason: 'not-found' });
      expect(recordDenySuppression(ref, { home, now: at })).toEqual({ ok: false, reason: 'not-found' });
      expect(isDenySuppressed(ref, { home, now: at }).suppressed).toBe(false);
    }
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: at })).toBeNull();
  });

  it('a receipt carries no hash, origin, surface, signals, claim or grant material', () => {
    denial();
    const c = claimCardLaunch({ id: id() }, { home, now: t0, windowStartMs: t0, windowMs: 15 * MIN });
    expect(c.ok).toBe(true);
    pruneRetryControl({ home, now: t0 + WINDOW });

    const raw = readFileSync(retryControlPath(home), 'utf8');
    const store = JSON.parse(raw) as { rows: unknown[]; retired: Array<Record<string, unknown>> };
    expect(store.rows).toEqual([]);
    expect(store.retired).toHaveLength(1);
    expect(Object.keys(store.retired[0]).sort()).toEqual(
      ['actionIds', 'id', 'lastDeniedAt', 'reason', 'retiredAt', 'tool'],
    );
    expect(raw).not.toContain(HASH);
    expect(raw).not.toContain('redacted action surface');
    expect(raw).not.toContain('privilege-escalation');
    expect(raw).not.toContain('nonceHmac');
    expect(raw).not.toContain(canonicaliseCwd(cwd) as string);
    expect(raw).not.toContain('sc-bbbbbbbbbbbbbbbb');
  });

  it('a re-denied retired identity is a NEW row (epoch 0, nothing carried) and its receipt goes', () => {
    denial();
    grantRetry({ id: id() }, { isInteractive: true }, { home, now: t0 + HOUR });
    recordDenySuppression({ id: id() }, { home, now: t0 + 2 * HOUR });
    const gone = t0 + 2 * HOUR + WINDOW;
    pruneRetryControl({ home, now: gone });
    expect(findRetiredIdentity({ id: id() }, { home })).toBeDefined();

    const back = denial({ now: gone + 1 });
    expect(back.row?.denyEpoch).toBe(0);
    expect(back.row?.deniedAt).toBe(gone + 1);
    expect(back.row?.grant).toBeUndefined();
    expect(back.row?.suppression).toBeUndefined();
    expect(findRetiredIdentity({ id: id() }, { home })).toBeUndefined();
    expect(rawStore()).not.toHaveProperty('retired');
  });

  // ── Capacity ────────────────────────────────────────────────────────────

  it('enforces MAX_RETRY_ROWS by retiring the oldest-denied identity for capacity', () => {
    fill(MAX_RETRY_ROWS);
    expect(retryStoreCapacity({ home, now: t0 + MAX_RETRY_ROWS })).toMatchObject({
      rows: MAX_RETRY_ROWS, cap: MAX_RETRY_ROWS, overCap: false, retiredForCapacity: 0,
    });

    const at = t0 + 10 * MIN;
    fill(1, MAX_RETRY_ROWS, () => at);
    const rows = listRetryRows({ home, now: at });
    expect(rows).toHaveLength(MAX_RETRY_ROWS);
    expect(rows.some((r) => r.actionIds.includes(jobActionId(0)))).toBe(false);
    expect(rows[0].actionIds).toEqual([jobActionId(MAX_RETRY_ROWS)]);

    expect(findRetiredIdentity({ actionId: jobActionId(0) }, { home })).toMatchObject({
      reason: 'capacity', lastDeniedAt: t0, retiredAt: at,
    });
    expect(retryStoreCapacity({ home, now: at })).toMatchObject({
      rows: MAX_RETRY_ROWS, overCap: false, retiredForCapacity: 1, lastCapacityRetiredAt: at,
    });
    // Evicted means gone from every path, same as expired.
    expect(grantRetry({ actionId: jobActionId(0) }, { isInteractive: true }, { home, now: at }))
      .toEqual({ ok: false, reason: 'not-found' });
  }, 60_000);

  it('never evicts a protected row; the oldest UNPROTECTED one goes instead', () => {
    fill(MAX_RETRY_ROWS);
    const at = t0 + 5 * MIN;
    // Oldest: live suppression. Second: live unspent grant. Third: live card.
    recordDenySuppression({ actionId: jobActionId(0) }, { home, now: at });
    grantRetry({ actionId: jobActionId(1) }, { isInteractive: true }, { home, now: at });
    const card = claimCardLaunch({ actionId: jobActionId(2) }, { home, now: at, windowStartMs: at, windowMs: 15 * MIN });
    expect(card.ok).toBe(true);

    fill(1, MAX_RETRY_ROWS, () => at + 1);
    expect(isDenySuppressed({ actionId: jobActionId(0) }, { home, now: at + 1 }).suppressed).toBe(true);
    expect(getRetryRow({ actionId: jobActionId(1) }, { home })?.grant).toBeDefined();
    expect(getRetryRow({ actionId: jobActionId(2) }, { home })?.claim).toBeDefined();
    expect(getRetryRow({ actionId: jobActionId(3) }, { home })).toBeUndefined();
    expect(findRetiredIdentity({ actionId: jobActionId(3) }, { home })?.reason).toBe('capacity');
  }, 60_000);

  it('protected rows exactly AT the cap: a new unprotected denial is kept at insert, then the next prune drops it for space', () => {
    fill(MAX_RETRY_ROWS);
    const at = t0 + MIN;
    for (let i = 0; i < MAX_RETRY_ROWS; i += 1) {
      expect(recordDenySuppression({ actionId: jobActionId(i) }, { home, now: at }).ok).toBe(true);
    }
    fill(1, MAX_RETRY_ROWS, () => at + 1);

    // Straight after the insert (read-only, nothing has pruned yet): the newest
    // denial was kept too (it is never its own victim), so the store is one over.
    const cap = retryStoreCapacity({ home, now: at + 1 });
    expect(cap).toMatchObject({
      rows: MAX_RETRY_ROWS + 1, cap: MAX_RETRY_ROWS, protectedRows: MAX_RETRY_ROWS, overCap: true, retiredForCapacity: 0,
    });
    expect(lookupRetryRow({ actionId: jobActionId(MAX_RETRY_ROWS) }, { home, now: at + 1 })).toBeDefined();
    for (let i = 0; i < MAX_RETRY_ROWS; i += 1) {
      expect(isDenySuppressed({ actionId: jobActionId(i) }, { home, now: at + 1 }).suppressed).toBe(true);
    }

    // Protected rows alone do NOT exceed the cap here, so the next prune brings
    // the store back inside it: the one unprotected row goes, for capacity.
    expect(pruneRetryControl({ home, now: at + 2 }).ok).toBe(true);
    expect(retryStoreCapacity({ home, now: at + 2 })).toMatchObject({
      rows: MAX_RETRY_ROWS, protectedRows: MAX_RETRY_ROWS, overCap: false, retiredForCapacity: 1, lastCapacityRetiredAt: at + 2,
    });
    expect(lookupRetryRow({ actionId: jobActionId(MAX_RETRY_ROWS) }, { home, now: at + 2 })).toBeUndefined();
    expect(findRetiredIdentity({ actionId: jobActionId(MAX_RETRY_ROWS) }, { home })?.reason).toBe('capacity');
    for (let i = 0; i < MAX_RETRY_ROWS; i += 1) {
      expect(isDenySuppressed({ actionId: jobActionId(i) }, { home, now: at + 2 }).suppressed).toBe(true);
    }
  }, 60_000);

  it('when protected rows alone exceed the cap, the store keeps them and SAYS it is over cap', () => {
    // A persisted store with every one of MAX_RETRY_ROWS + 1 rows protected by
    // a live Deny. Real writes, then the last row's suppression on disk: every
    // locked call prunes first, and that prune drops an unprotected extra row
    // before any public call could protect it.
    fill(MAX_RETRY_ROWS);
    const at = t0 + MIN;
    for (let i = 0; i < MAX_RETRY_ROWS; i += 1) {
      expect(recordDenySuppression({ actionId: jobActionId(i) }, { home, now: at }).ok).toBe(true);
    }
    fill(1, MAX_RETRY_ROWS, () => at + 1);
    const raw = rawStore() as {
      rows: Array<{ actionIds: string[]; denyEpoch: number; suppression?: { at: number; until: number; via: string } }>;
    };
    expect(raw.rows).toHaveLength(MAX_RETRY_ROWS + 1);
    const template = raw.rows.find((r) => r.suppression)!.suppression!;
    const last = raw.rows.find((r) => r.actionIds.includes(jobActionId(MAX_RETRY_ROWS)))!;
    expect(last.suppression).toBeUndefined();
    last.denyEpoch += 1;
    last.suppression = { at: at + 1, until: at + 1 + (template.until - template.at), via: 'card' };
    writeFileSync(retryControlPath(home), JSON.stringify(raw));

    const expected = {
      rows: MAX_RETRY_ROWS + 1, cap: MAX_RETRY_ROWS, protectedRows: MAX_RETRY_ROWS + 1, overCap: true, retiredForCapacity: 0,
    };
    expect(retryStoreCapacity({ home, now: at + 1 })).toMatchObject(expected);

    // A prune cannot bring it back inside the cap without dropping a Deny, so
    // it drops nothing.
    expect(pruneRetryControl({ home, now: at + 2 }).ok).toBe(true);
    expect(retryStoreCapacity({ home, now: at + 2 })).toMatchObject(expected);
    expect((rawStore().rows as unknown[])).toHaveLength(MAX_RETRY_ROWS + 1);
    for (let i = 0; i <= MAX_RETRY_ROWS; i += 1) {
      expect(isDenySuppressed({ actionId: jobActionId(i) }, { home, now: at + 2 }).suppressed).toBe(true);
      expect(findRetiredIdentity({ actionId: jobActionId(i) }, { home })).toBeUndefined();
    }
  }, 60_000);

  it('a capacity eviction between lookup and grant leaves the grant refused, not adjacent', () => {
    fill(MAX_RETRY_ROWS);
    const at = t0 + MIN;
    const looked = lookupRetryRow({ actionId: jobActionId(0) }, { home, now: at });
    expect(looked).toBeDefined();
    // Another writer records a new denial in between.
    fill(1, MAX_RETRY_ROWS, () => at);
    const g = grantRetry({ id: looked!.id, actionId: jobActionId(0) }, { isInteractive: true }, { home, now: at });
    expect(g).toEqual({ ok: false, reason: 'not-found' });
    expect(listRetryRows({ home, now: at }).some((r) => r.grant)).toBe(false);
    expect(findRetiredIdentity({ actionId: jobActionId(0) }, { home })?.reason).toBe('capacity');
  }, 60_000);

  // ── Receipt bounds ──────────────────────────────────────────────────────

  it('keeps at most MAX_RETIRED_IDENTITIES receipts, newest first out of the door last', () => {
    const n = MAX_RETIRED_IDENTITIES + 6;
    fill(n);
    pruneRetryControl({ home, now: t0 + WINDOW + n });
    const store = rawStore() as { retired: Array<{ id: string }> };
    expect(store.retired).toHaveLength(MAX_RETIRED_IDENTITIES);
    expect(findRetiredIdentity({ actionId: jobActionId(0) }, { home })).toBeUndefined();
    expect(findRetiredIdentity({ actionId: jobActionId(5) }, { home })).toBeUndefined();
    expect(findRetiredIdentity({ actionId: jobActionId(6) }, { home })?.reason).toBe('expired');
    expect(findRetiredIdentity({ actionId: jobActionId(n - 1) }, { home })?.reason).toBe('expired');
  }, 60_000);

  it('an insert that evicts for capacity writes at most MAX_RETIRED_IDENTITIES receipts to disk', () => {
    // MAX_RETIRED_IDENTITIES expiry receipts on file...
    fill(MAX_RETIRED_IDENTITIES);
    const expiredAt = t0 + WINDOW + MAX_RETIRED_IDENTITIES;
    pruneRetryControl({ home, now: expiredAt });
    // ...then a full store of fresh, unprotected rows.
    const base = expiredAt + MIN;
    fill(MAX_RETRY_ROWS, MAX_RETIRED_IDENTITIES, (i) => base + i);
    type RawReceipt = { id: string; reason: string; retiredAt: number; actionIds: string[] } & Record<string, unknown>;
    type RawRow = { id: string; grant?: unknown; claim?: unknown; suppression?: unknown };
    const before = rawStore() as { rows: RawRow[]; retired: RawReceipt[] };
    expect(before.rows).toHaveLength(MAX_RETRY_ROWS);
    expect(before.retired).toHaveLength(MAX_RETIRED_IDENTITIES);
    expect(before.retired.every((e) => e.reason === 'expired')).toBe(true);

    // A distinct new denial: the insert evicts the oldest row for capacity.
    const fresh = MAX_RETIRED_IDENTITIES + MAX_RETRY_ROWS;
    const at = base + 10 * MIN;
    const r = denial({ hash: jobHash(fresh), actionId: jobActionId(fresh), now: at });
    expect(r.ok).toBe(true);
    expect(r.row?.denyEpoch).toBe(0);
    expect(r.row?.grant).toBeUndefined();

    // The raw file, straight after the insert: readFileSync + JSON.parse only.
    // No API reader and no prune has run since, so parseRetired's read-time
    // slice cannot be what hides an extra receipt.
    const victim = MAX_RETIRED_IDENTITIES;
    const victimId = fingerprintId(jobHash(victim), canonicaliseCwd(cwd));
    const raw = readFileSync(retryControlPath(home), 'utf8');
    const after = JSON.parse(raw) as { rows: RawRow[]; retired: RawReceipt[] };
    expect(after.retired).toHaveLength(MAX_RETIRED_IDENTITIES);
    expect(new Set(after.retired.map((e) => e.id)).size).toBe(MAX_RETIRED_IDENTITIES);
    // The newest receipt is the victim's; the oldest expiry receipt made room.
    const newest = after.retired[after.retired.length - 1];
    expect(newest).toEqual({
      id: victimId, actionIds: [jobActionId(victim)], tool: 'Bash', reason: 'capacity', lastDeniedAt: base + victim, retiredAt: at,
    });
    expect(after.retired.map((e) => e.id)).not.toContain(fingerprintId(jobHash(0), canonicaliseCwd(cwd)));
    expect(after.retired.map((e) => e.id)).toContain(fingerprintId(jobHash(1), canonicaliseCwd(cwd)));
    for (const e of after.retired) {
      expect(Object.keys(e).sort()).toEqual(['actionIds', 'id', 'lastDeniedAt', 'reason', 'retiredAt', 'tool']);
    }
    expect(raw).not.toContain(jobHash(victim));
    expect(raw).not.toContain('nonceHmac');

    // Rows: still at the cap, the newcomer kept, the victim gone, nothing
    // granted, claimed or suppressed by the bounding.
    expect(after.rows).toHaveLength(MAX_RETRY_ROWS);
    expect(after.rows.map((row) => row.id)).toContain(fingerprintId(jobHash(fresh), canonicaliseCwd(cwd)));
    expect(after.rows.map((row) => row.id)).not.toContain(victimId);
    expect(after.rows.some((row) => row.grant || row.claim || row.suppression)).toBe(false);
    expect(grantRetry({ id: victimId }, { isInteractive: true }, { home, now: at })).toEqual({ ok: false, reason: 'not-found' });
  }, 60_000);

  it('receipts age out after RETIRED_IDENTITY_MAX_AGE_MS', () => {
    denial();
    const at = t0 + WINDOW;
    pruneRetryControl({ home, now: at });
    pruneRetryControl({ home, now: at + RETIRED_IDENTITY_MAX_AGE_MS - 1 });
    expect(findRetiredIdentity({ id: id() }, { home })).toBeDefined();
    pruneRetryControl({ home, now: at + RETIRED_IDENTITY_MAX_AGE_MS });
    expect(findRetiredIdentity({ id: id() }, { home })).toBeUndefined();
    expect(rawStore()).not.toHaveProperty('retired');
  });

  // ── Aliases ─────────────────────────────────────────────────────────────

  it('the lookup matches aliases case-insensitively, like the store, and caps them at 10', () => {
    for (let i = 0; i < 12; i += 1) {
      denial({ now: t0 + i, actionId: `act-${(0x68f0 + i).toString(16).padStart(16, '0')}` });
    }
    const row = getRetryRow({ id: id() }, { home })!;
    expect(row.actionIds).toHaveLength(10);
    const newest = row.actionIds[9];
    expect(lookupRetryRow({ actionId: newest.toUpperCase() }, { home, now: t0 + HOUR })?.id).toBe(id());
    expect(lookupRetryRow({ actionId: ` ${newest} ` }, { home, now: t0 + HOUR })?.id).toBe(id());

    pruneRetryControl({ home, now: t0 + 11 + WINDOW });
    const gone = findRetiredIdentity({ actionId: newest.toUpperCase() }, { home });
    expect(gone?.actionIds).toEqual(row.actionIds);
    // An alias that had already rotated out of the index is not on the receipt.
    expect(findRetiredIdentity({ actionId: 'act-00000000000068f0' }, { home })).toBeUndefined();
  });

  // ── Hostile / malformed / old persisted data ────────────────────────────

  it('a store from before #682 (no `retired`) reads, and gains the 48h window for rows still on disk', () => {
    const cwdCanon = canonicaliseCwd(cwd)!;
    mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
    writeFileSync(retryControlPath(home), JSON.stringify({
      version: 1,
      budget: null,
      rows: [{
        id: id(), hash: HASH, tool: 'Bash', denyEpoch: 2, deniedAt: t0, lastDeniedAt: t0,
        originScope: { cwd: cwdCanon }, signals: [], redactedSurface: '', actionIds: [ACTION_ID],
      }],
    }));
    const at = t0 + 2 * HOUR;
    expect(lookupRetryRow({ actionId: ACTION_ID }, { home, now: at })?.denyEpoch).toBe(2);
    pruneRetryControl({ home, now: at });
    // Nothing retired, so nothing new is written into the shape.
    expect(rawStore()).not.toHaveProperty('retired');
    expect(retryStoreCapacity({ home, now: at })).toMatchObject({ rows: 1, retiredOnRecord: 0 });
  });

  it('an identity the old 60m rule already erased is not revived', () => {
    mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
    writeFileSync(retryControlPath(home), JSON.stringify({ version: 1, budget: null, rows: [] }));
    const at = t0 + 2 * HOUR;
    expect(lookupRetryRow({ actionId: ACTION_ID }, { home, now: at })).toBeUndefined();
    expect(findRetiredIdentity({ actionId: ACTION_ID }, { home, now: at })).toBeUndefined();
    expect(grantRetry({ actionId: ACTION_ID }, { isInteractive: true }, { home, now: at }))
      .toEqual({ ok: false, reason: 'not-found' });
  });

  it.each([
    ['a string', 'junk'],
    ['an object', { id: 'x' }],
    ['null', null],
  ])('a `retired` field that is %s reads as no receipts and leaves rows alone', (_label, retired) => {
    denial();
    const store = rawStore();
    writeFileSync(retryControlPath(home), JSON.stringify({ ...store, retired }));
    expect(lookupRetryRow({ actionId: ACTION_ID }, { home, now: t0 })?.id).toBe(id());
    expect(retryStoreCapacity({ home, now: t0 }).retiredOnRecord).toBe(0);
    expect(pruneRetryControl({ home, now: t0 + 1 }).ok).toBe(true);
    expect(rawStore()).not.toHaveProperty('retired');
  });

  it('hostile receipt entries are dropped or sanitised, and an oversized array is bounded', () => {
    denial();
    const good = { id: 'a'.repeat(32), actionIds: ['act-00000000000068ff'], tool: 'Bash', reason: 'expired', lastDeniedAt: t0, retiredAt: t0 + 1 };
    const hostile = [
      // Padding first: only the newest slice is parsed, and the hostile
      // entries below sit inside it.
      ...Array.from({ length: 1000 }, (_, i) => ({ ...good, id: i.toString(16).padStart(32, '0') })),
      { ...good, id: 'not-a-row-id' },
      { ...good, id: 'b'.repeat(32), reason: 'granted' },
      { ...good, id: 'c'.repeat(32), lastDeniedAt: '1760000000000' },
      { ...good, id: 'd'.repeat(32), retiredAt: null },
      { ...good, id: 'e'.repeat(32), hash: HASH, grant: { approvedAt: t0 }, tool: '\u001b[31mBash\u0007', actionIds: ['act-ok', '\u001b]8;;x\u0007', 42, 'act-ok'] },
      'string-entry',
      null,
      [],
      good,
    ];
    writeFileSync(retryControlPath(home), JSON.stringify({ ...rawStore(), retired: hostile }));

    for (const junk of ['b', 'c', 'd']) {
      expect(findRetiredIdentity({ id: junk.repeat(32) }, { home })).toBeUndefined();
    }
    expect(findRetiredIdentity({ id: 'a'.repeat(32) }, { home })?.reason).toBe('expired');
    expect(findRetiredIdentity({ id: 'e'.repeat(32) }, { home })).toMatchObject({ tool: 'tool', actionIds: ['act-ok'] });
    pruneRetryControl({ home, now: t0 + 2 });
    const after = rawStore() as { retired: Array<Record<string, unknown>> };
    expect(after.retired.length).toBeLessThanOrEqual(MAX_RETIRED_IDENTITIES);
    for (const e of after.retired) {
      expect(Object.keys(e).sort()).toEqual(['actionIds', 'id', 'lastDeniedAt', 'reason', 'retiredAt', 'tool']);
      expect(JSON.stringify(e)).not.toMatch(/[\u0000-\u001f\u007f]/);
    }
    // The live row is untouched by any of it.
    expect(lookupRetryRow({ actionId: ACTION_ID }, { home, now: t0 + 2 })?.id).toBe(id());
  });

  it('a hostile entry that survives parsing is sanitised (escape-laden tool and aliases)', () => {
    mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
    writeFileSync(retryControlPath(home), JSON.stringify({
      version: 1, budget: null, rows: [],
      retired: [{
        id: 'e'.repeat(32), hash: HASH, grant: { approvedAt: t0 }, tool: '\u001b[31mBash\u0007',
        actionIds: ['act-ok', '\u001b]8;;x\u0007', 42, 'act-ok'], reason: 'capacity', lastDeniedAt: t0, retiredAt: t0 + 1,
      }],
    }));
    expect(findRetiredIdentity({ actionId: 'ACT-OK' }, { home })).toEqual({
      id: 'e'.repeat(32), actionIds: ['act-ok'], tool: 'tool', reason: 'capacity', lastDeniedAt: t0, retiredAt: t0 + 1,
    });
  });

  it('a row with a non-string alias does not break the lookup', () => {
    denial();
    const store = rawStore() as { rows: Array<{ actionIds: unknown[] }> };
    store.rows[0].actionIds = [42, null, ACTION_ID];
    writeFileSync(retryControlPath(home), JSON.stringify(store));
    expect(lookupRetryRow({ actionId: ACTION_ID }, { home, now: t0 })?.id).toBe(id());
  });

  it('an install that only ever consumes keeps an untouched store shape', () => {
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 })).toBeNull();
    expect(existsSync(retryControlPath(home))).toBe(false);
  });

  it('never touches the #118 approvals store', () => {
    denial();
    fill(3);
    grantRetry({ id: id() }, { isInteractive: true }, { home, now: t0 + 30 * HOUR });
    pruneRetryControl({ home, now: t0 + WINDOW + 30 * HOUR });
    findRetiredIdentity({ id: id() }, { home });
    retryStoreCapacity({ home, now: t0 + WINDOW + 30 * HOUR });
    expect(existsSync(join(home, '.shieldcortex', 'approvals', 'approvals.json'))).toBe(false);
  });
});
