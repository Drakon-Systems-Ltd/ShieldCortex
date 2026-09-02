/**
 * #310 — the operator retry-control store.
 *
 * Every case named in the design's Test plan (docs/design/2026-08-19-310-
 * retry-control.md) that lives at the STORE layer, plus the ten binding R3
 * rules. The hook wiring, the waiter's decision mapping and the CLI surface
 * have their own files; what is pinned here is the thing all three depend on:
 * that nothing spendable exists before an operator acts, that a deny always
 * beats an unspent approve, and that a card can never be replayed.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  CARD_BUDGET_PER_WINDOW,
  DEFAULT_RETRY_GRANT_TTL_MS,
  RETRY_CARD_LIFETIME_MS,
  RETRY_FINGERPRINT_RETENTION_MS,
  RETRY_GRANT_AUDIT_TAIL_MS,
  buildRetryCardFields,
  buildRetryCardParams,
  canonicaliseCwd,
  claimCardLaunch,
  consumeRetryGrant,
  drainLostActionIds,
  restoreLostActionIds,
  fingerprintId,
  formatBudgetExhaustedNotice,
  formatUnspentExpiryNotice,
  getRetryRow,
  grantRetry,
  hashToolCall,
  isDenySuppressed,
  listRetryRows,
  normaliseRetryControlConfig,
  pruneRetryControl,
  recordDenialFingerprint,
  recordDenySuppression,
  releaseCardLaunch,
  retryControlPath,
} from '../retry-control.js';

const HASH = hashToolCall('Bash', { command: 'sudo modprobe softdog' });
const OTHER_HASH = hashToolCall('Bash', { command: 'systemctl restart nginx' });

describe('#310 retry control — the one lock plane', () => {
  let home: string;
  let cwd: string;
  let otherCwd: string;
  let t0: number;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-retry-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    // Real directories: cwd canonicalisation calls realpath, and a path that
    // does not exist would silently take the resolve() fallback instead.
    cwd = mkdtempSync(join(tmpdir(), 'sc-job-'));
    otherCwd = mkdtempSync(join(tmpdir(), 'sc-other-'));
    t0 = 1_760_000_000_000;
  });

  afterEach(() => {
    for (const dir of [home, cwd, otherCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function denial(opts: { now?: number; hash?: string; cwd?: string | null; actionId?: string; signals?: string[] } = {}) {
    return recordDenialFingerprint(
      {
        hash: opts.hash ?? HASH,
        tool: 'Bash',
        actionId: opts.actionId ?? 'act-000000000000000a',
        signals: opts.signals ?? ['privilege-escalation'],
        redactedSurface: 'Bash: [redacted action surface] fields=command',
        cwd: opts.cwd === undefined ? cwd : (opts.cwd ?? undefined),
        sessionKey: 'sc-aaaaaaaaaaaaaaaa',
      },
      { home, now: opts.now ?? t0 },
    );
  }

  function claim(opts: { now?: number; id?: string; actionId?: string } = {}) {
    return claimCardLaunch(
      { id: opts.id ?? fingerprintId(HASH, canonicaliseCwd(cwd)) },
      {
        home,
        now: opts.now ?? t0,
        windowStartMs: t0,
        windowMs: 900_000,
        actionId: opts.actionId ?? 'act-000000000000000a',
      },
    );
  }

  // ── Nothing spendable before an operator acts ───────────────────────────

  it('a denial mints a fingerprint and NOTHING spendable', () => {
    const r = denial();
    expect(r.ok).toBe(true);
    expect(r.row?.grant).toBeUndefined();
    expect(r.row?.claim).toBeUndefined();
    expect(r.suppressed).toBe(false);

    // No grant means nothing to consume, no matter who asks.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 })).toBeNull();
  });

  it('refuses to grant without either a claimNonce or a TTY (a library import buys nothing)', () => {
    denial();
    const out = grantRetry({ id: fingerprintId(HASH, canonicaliseCwd(cwd)) }, {}, { home, now: t0 });
    expect(out).toEqual({ ok: false, reason: 'not-authenticated' });
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('never writes a retry grant without approvedAt — grant is ONE locked write', () => {
    denial();
    const c = claim();
    expect(c.ok).toBe(true);
    // Mid-flight (claimed, not yet tapped) the row has a claim and no grant.
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();

    const granted = grantRetry(
      { hash: HASH, cwd },
      { nonce: c.ok ? c.nonce : 'x' },
      { home, now: t0 + 1_000 },
    );
    expect(granted.ok).toBe(true);

    const raw = JSON.parse(readFileSync(retryControlPath(home), 'utf8')) as {
      rows: Array<{ grant?: { approvedAt?: number; grantKind?: string } }>;
    };
    for (const row of raw.rows) {
      if (!row.grant) continue;
      expect(row.grant.grantKind).toBe('retry');
      expect(typeof row.grant.approvedAt).toBe('number');
    }
  });

  // ── claimNonce: required, HMAC at rest (R3 rule 4) ──────────────────────

  it('stores only the HMAC of the claim nonce — the raw nonce never lands on disk', () => {
    denial();
    const c = claim();
    expect(c.ok).toBe(true);
    const nonce = c.ok ? c.nonce : '';
    expect(nonce).toMatch(/^[0-9a-f]{64}$/);

    const onDisk = readFileSync(retryControlPath(home), 'utf8');
    expect(onDisk).not.toContain(nonce);
    expect(onDisk).toMatch(/"nonceHmac":\s*"[0-9a-f]{64}"/);
  });

  it('refuses a wrong nonce, and refuses when no claim was ever minted', () => {
    denial();
    expect(grantRetry({ hash: HASH, cwd }, { nonce: 'f'.repeat(64) }, { home, now: t0 }))
      .toEqual({ ok: false, reason: 'claim-missing' });

    const c = claim();
    expect(c.ok).toBe(true);
    expect(grantRetry({ hash: HASH, cwd }, { nonce: 'a'.repeat(64) }, { home, now: t0 }))
      .toEqual({ ok: false, reason: 'bad-nonce' });
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('a corrupt store cannot revive a stale card — fresh store, no claim, refused', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    writeFileSync(retryControlPath(home), '{ this is not json', { mode: 0o600 });

    const out = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: t0 + 1_000 });
    expect(out.ok).toBe(false);
    // not-found (the row is gone with the corrupt file) — never a grant.
    expect(out.ok === false && out.reason).toBe('not-found');
  });

  // ── Deny epochs (B1 + R3 rule 2) ────────────────────────────────────────

  it('a remint does NOT advance the epoch — a live card survives a flapping job', () => {
    denial({ now: t0 });
    const c = claim({ now: t0 });
    expect(c.ok).toBe(true);
    const epoch = c.ok ? c.epoch : -1;

    // The cron job keeps failing, three more times, under the live claim.
    denial({ now: t0 + 30_000, actionId: 'act-000000000000000b' });
    denial({ now: t0 + 60_000, actionId: 'act-000000000000000c' });
    denial({ now: t0 + 90_000, actionId: 'act-000000000000000d' });

    const row = getRetryRow({ hash: HASH, cwd }, { home })!;
    expect(row.denyEpoch).toBe(epoch);
    expect(row.claim).toBeDefined();
    // The tap the operator makes on that same card still lands.
    const granted = grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 120_000 });
    expect(granted.ok).toBe(true);
  });

  it('remints of one identity share an epoch across their actionIds (R3 rule 2)', () => {
    denial({ now: t0, actionId: 'act-000000000000000a' });
    denial({ now: t0 + 1_000, actionId: 'act-000000000000000b' });
    const byFirst = getRetryRow({ actionId: 'act-000000000000000a' }, { home })!;
    const bySecond = getRetryRow({ actionId: 'act-000000000000000b' }, { home })!;
    expect(byFirst.id).toBe(bySecond.id);
    expect(listRetryRows({ home, now: t0 + 1_000 })).toHaveLength(1);
  });

  it('an operator deny advances the epoch and retires the live card', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    const denied = recordDenySuppression({ hash: HASH, cwd }, { home, now: t0 + 1_000, suppressionMs: 900_000 });
    expect(denied.ok).toBe(true);

    const out = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: t0 + 2_000 });
    expect(out.ok).toBe(false);
    expect(out.ok === false && out.reason).toBe('claim-missing');
  });

  it('a claim that expires unanswered advances the epoch, and its card can never be revalidated', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    const afterCard = t0 + RETRY_CARD_LIFETIME_MS + 1;

    // A fresh DNP arrives after the card died — the identity is still here.
    denial({ now: afterCard, actionId: 'act-000000000000000e' });
    const row = getRetryRow({ hash: HASH, cwd }, { home })!;
    expect(row.denyEpoch).toBe(1);
    expect(row.claim).toBeUndefined();

    const out = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: afterCard + 1_000 });
    expect(out.ok).toBe(false);
    expect(out.ok === false && out.reason).toBe('claim-missing');
  });

  // ── Suppression is first-class and ordered (B2) ─────────────────────────

  it('a deny silences the identity for the window — and says so, honestly, with an end', () => {
    denial();
    const denied = recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: 900_000, via: 'card' });
    expect(denied.ok && denied.untilMs).toBe(t0 + 900_000);

    expect(isDenySuppressed({ hash: HASH, cwd }, { home, now: t0 + 1_000 }).suppressed).toBe(true);
    // Windowed silence, not permanence.
    expect(isDenySuppressed({ hash: HASH, cwd }, { home, now: t0 + 900_001 }).suppressed).toBe(false);
  });

  it('a suppressed remint still writes its fingerprint (audit truth) and still reports suppressed', () => {
    denial();
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: 900_000 });

    const again = denial({ now: t0 + 60_000, actionId: 'act-000000000000000f' });
    expect(again.ok).toBe(true);
    expect(again.suppressed).toBe(true);
    expect(again.suppressedUntilMs).toBe(t0 + 900_000);
    expect(again.row?.actionIds).toContain('act-000000000000000f');
    expect(again.row?.lastDeniedAt).toBe(t0 + 60_000);
  });

  it('a suppressed identity never burns card budget', () => {
    denial();
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: 900_000 });
    const c = claim({ now: t0 + 1_000 });
    expect(c.ok).toBe(false);
    expect(c.ok === false && c.reason).toBe('suppressed');

    // Three other identities still get their full window budget.
    for (let i = 0; i < CARD_BUDGET_PER_WINDOW; i += 1) {
      const h = hashToolCall('Bash', { command: `systemctl restart svc-${i}` });
      denial({ now: t0 + 2_000, hash: h, actionId: `act-00000000000000${i}${i}` });
      const other = claimCardLaunch(
        { hash: h, cwd },
        { home, now: t0 + 2_000, windowStartMs: t0, windowMs: 900_000 },
      );
      expect(other.ok).toBe(true);
    }
  });

  it('deny beats an in-flight approve: a tap that outlives the deny is a no-op', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0 + 1_000, suppressionMs: 900_000 });

    const late = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: t0 + 2_000 });
    expect(late.ok).toBe(false);
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('deny revokes an UNSPENT grant in the same locked write (R3 rule 6)', () => {
    denial();
    const c = claim();
    const granted = grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 1_000 });
    expect(granted.ok).toBe(true);

    const denied = recordDenySuppression({ hash: HASH, cwd }, { home, now: t0 + 2_000, suppressionMs: 900_000, via: 'tty' });
    expect(denied.ok && denied.revokedGrant).toBe(true);
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 3_000 })).toBeNull();
  });

  it('a SPENT grant is history — a later deny does not rewrite it', () => {
    denial();
    const c = claim();
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 1_000 });
    const spent = consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 });
    expect(spent?.consumedAt).toBe(t0 + 2_000);

    const denied = recordDenySuppression({ hash: HASH, cwd }, { home, now: t0 + 3_000, suppressionMs: 900_000 });
    expect(denied.ok && denied.revokedGrant).toBe(false);
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant?.consumedAt).toBe(t0 + 2_000);
  });

  // ── Budgets (B6 + R3 rule 7) ───────────────────────────────────────────

  it('caps cards at the global window budget and names the actionIds that lost one', () => {
    const ids: string[] = [];
    for (let i = 0; i < CARD_BUDGET_PER_WINDOW; i += 1) {
      const h = hashToolCall('Bash', { command: `systemctl restart svc-${i}` });
      denial({ now: t0, hash: h, actionId: `act-10000000000000${i}${i}` });
      expect(claimCardLaunch({ hash: h, cwd }, { home, now: t0, windowStartMs: t0, windowMs: 900_000 }).ok).toBe(true);
    }
    denial({ now: t0, hash: OTHER_HASH, actionId: 'act-2000000000000000' });
    ids.push('act-2000000000000000');
    const out = claimCardLaunch(
      { hash: OTHER_HASH, cwd },
      { home, now: t0, windowStartMs: t0, windowMs: 900_000, actionId: 'act-2000000000000000' },
    );
    expect(out.ok).toBe(false);
    expect(out.ok === false && out.reason).toBe('budget-exhausted');
    expect(out.ok === false && out.lostActionIds).toEqual(ids);

    const copy = formatBudgetExhaustedNotice(out.ok === false ? out.lostActionIds ?? [] : []);
    expect(copy).toContain('budget_exhausted');
    expect(copy).toContain('act-2000000000000000');
    expect(copy).toContain('shieldcortex approve --denial');
  });

  it('the budget window resets when the caller passes a NEW digest window start', () => {
    for (let i = 0; i < CARD_BUDGET_PER_WINDOW; i += 1) {
      const h = hashToolCall('Bash', { command: `systemctl restart svc-${i}` });
      denial({ now: t0, hash: h, actionId: `act-30000000000000${i}${i}` });
      claimCardLaunch({ hash: h, cwd }, { home, now: t0, windowStartMs: t0, windowMs: 900_000 });
    }
    const nextWindow = t0 + 900_000;
    denial({ now: nextWindow, hash: OTHER_HASH, actionId: 'act-4000000000000000' });
    const out = claimCardLaunch(
      { hash: OTHER_HASH, cwd },
      { home, now: nextWindow, windowStartMs: nextWindow, windowMs: 900_000 },
    );
    expect(out.ok).toBe(true);
  });

  it('one identity gets ONE live card, and a live unspent grant blocks a second (R3 rule 5)', () => {
    denial();
    expect(claim().ok).toBe(true);
    const second = claim({ now: t0 + 1_000 });
    expect(second.ok).toBe(false);
    expect(second.ok === false && second.reason).toBe('already-claimed');

    const c = claimCardLaunch({ hash: HASH, cwd }, { home, now: t0, windowStartMs: t0, windowMs: 900_000 });
    expect(c.ok).toBe(false);

    // Now tap it, then try again: a live unspent grant also blocks a card.
    const row = getRetryRow({ hash: HASH, cwd }, { home })!;
    const nonceOk = grantRetry({ id: row.id }, { isInteractive: true }, { home, now: t0 + 2_000 });
    expect(nonceOk.ok).toBe(true);
    denial({ now: t0 + 3_000, actionId: 'act-000000000000001a' });
    const third = claim({ now: t0 + 3_000 });
    expect(third.ok).toBe(false);
    expect(third.ok === false && third.reason).toBe('grant-live');
  });

  it('a failed spawn releases the slot it debited', () => {
    denial();
    const c = claim();
    expect(c.ok).toBe(true);
    expect(releaseCardLaunch({ hash: HASH, cwd }, { home }).ok).toBe(true);
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.claim).toBeUndefined();

    // The budget slot came back: three more cards still fit in this window.
    for (let i = 0; i < CARD_BUDGET_PER_WINDOW; i += 1) {
      const h = hashToolCall('Bash', { command: `systemctl restart svc-${i}` });
      denial({ now: t0, hash: h, actionId: `act-50000000000000${i}${i}` });
      expect(claimCardLaunch({ hash: h, cwd }, { home, now: t0, windowStartMs: t0, windowMs: 900_000 }).ok).toBe(true);
    }
  });

  // ── Origin binding (B3 + R3 rule 3) ────────────────────────────────────

  it('spends only on an AND-match of {cwd, tool}', () => {
    denial();
    const c = claim();
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 1_000 });

    // Wrong cwd.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd: otherCwd, tool: 'Bash' } }, { home, now: t0 + 2_000 })).toBeNull();
    // Wrong tool.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Write' } }, { home, now: t0 + 2_000 })).toBeNull();
    // No cwd at all.
    expect(consumeRetryGrant({ hash: HASH, origin: { tool: 'Bash' } }, { home, now: t0 + 2_000 })).toBeNull();
    // Both right.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 })).not.toBeNull();
  });

  it('a fresh sessionKey never fails the spend closed — sessionKey is diagnostic only (R3 rule 3)', () => {
    recordDenialFingerprint(
      { hash: HASH, tool: 'Bash', actionId: 'act-6000000000000000', signals: ['dangerous-shell'], redactedSurface: 's', cwd, sessionKey: 'sc-1111111111111111' },
      { home, now: t0 },
    );
    const c = claim();
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 1_000 });

    // A session-aware lane cannot accidentally consume an ordinary unbound
    // cron grant.
    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash', sessionKey: 'sc-2222222222222222' } },
      { home, now: t0 + 1_500 },
    )).toBeNull();
    // The next cron tick is a NEW Claude session, but this legacy lane does not
    // put diagnostic session metadata in its predicate. Same cwd/tool spends.
    const spent = consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 });
    expect(spent).not.toBeNull();
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.originScope.sessionKey).toBe('sc-1111111111111111');
  });

  it('an explicitly session-bound fingerprint spends only in its captured session', () => {
    const sessionKey = 'hermes-task-1111';
    const actionId = 'act-6000000000000001';
    recordDenialFingerprint(
      {
        hash: HASH,
        tool: 'Bash',
        actionId,
        signals: ['privilege-escalation'],
        redactedSurface: 's',
        cwd,
        sessionKey,
        bindSession: true,
      },
      { home, now: t0 },
    );
    const granted = grantRetry(
      { actionId },
      { isInteractive: true },
      { home, now: t0 + 1_000, tool: 'Bash' },
    );
    expect(granted.ok).toBe(true);

    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash' } },
      { home, now: t0 + 1_500 },
    )).toBeNull();
    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash', sessionKey: 'hermes-task-2222' } },
      { home, now: t0 + 2_000 },
    )).toBeNull();
    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash', sessionKey } },
      { home, now: t0 + 2_100 },
    )).not.toBeNull();
  });

  it('canonicalises cwd before matching (realpath + trailing slash)', () => {
    const canon = canonicaliseCwd(cwd)!;
    expect(canonicaliseCwd(`${cwd}/`)).toBe(canon);
    expect(canonicaliseCwd(`${cwd}//`)).toBe(canon);
    expect(canonicaliseCwd('relative/path')).toBeUndefined();
    expect(canonicaliseCwd(undefined)).toBeUndefined();

    denial({ cwd: `${cwd}/` });
    // Same identity as the un-slashed form.
    expect(getRetryRow({ hash: HASH, cwd }, { home })).toBeDefined();
    const c = claim();
    grantRetry({ hash: HASH, cwd: `${cwd}//` }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 1_000 });
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd: `${cwd}/`, tool: 'Bash' } }, { home, now: t0 + 2_000 })).not.toBeNull();
  });

  it('refuses an UNSCOPEABLE identity on the card path, and on TTY without --any-origin', () => {
    denial({ cwd: null });
    const id = fingerprintId(HASH, undefined);
    const c = claimCardLaunch({ id }, { home, now: t0, windowStartMs: t0, windowMs: 900_000 });
    expect(c.ok).toBe(false);
    expect(c.ok === false && c.reason).toBe('unscopeable');

    const tty = grantRetry({ id }, { isInteractive: true }, { home, now: t0 });
    expect(tty.ok).toBe(false);
    expect(tty.ok === false && tty.reason).toBe('unscopeable');

    const anyOrigin = grantRetry({ id }, { isInteractive: true, anyOrigin: true }, { home, now: t0 });
    expect(anyOrigin.ok).toBe(true);
    expect(anyOrigin.ok && anyOrigin.grant.origin.anyOrigin).toBe(true);
    // ANY local process in ANY directory may spend it — that is what the
    // confirmation upstream is for.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd: otherCwd, tool: 'Bash' } }, { home, now: t0 + 1_000 })).not.toBeNull();
  });

  it('--any-origin and --override-deny are TTY-only — a card can never set either', () => {
    denial();
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: 900_000 });
    denial({ now: t0 + 1_000 });
    // The card path cannot even claim while suppressed, but prove the grant
    // path refuses the flags too: nonce present ⇒ card ⇒ overrides ignored.
    const out = grantRetry(
      { hash: HASH, cwd },
      { nonce: 'a'.repeat(64), anyOrigin: true, overrideDeny: true },
      { home, now: t0 + 2_000 },
    );
    expect(out.ok).toBe(false);
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('TTY --override-deny grants despite a live deny, and lifts the silence it overrode', () => {
    denial();
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: 900_000 });
    const out = grantRetry({ hash: HASH, cwd }, { isInteractive: true, overrideDeny: true }, { home, now: t0 + 1_000 });
    expect(out.ok).toBe(true);
    expect(isDenySuppressed({ hash: HASH, cwd }, { home, now: t0 + 1_000 }).suppressed).toBe(false);
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 })).not.toBeNull();
  });

  // ── One-shot, idempotent, time-boxed ───────────────────────────────────

  it('is one-shot: the second identical call finds nothing', () => {
    denial();
    const c = claim();
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 1_000 });
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 })).not.toBeNull();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_001 })).toBeNull();
  });

  it('double-tap is idempotent — the first grant stands and its TTL is not extended', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    const first = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: t0 + 1_000 });
    expect(first.ok).toBe(true);

    const second = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: t0 + 5_000 });
    expect(second.ok).toBe(true);
    expect(second.ok && second.alreadyGranted).toBe(true);
    expect(second.ok && second.grant.approvedAt).toBe(t0 + 1_000);
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant?.approvedAt).toBe(t0 + 1_000);
  });

  it('expires on the spend TTL and tells the operator exactly once', () => {
    denial();
    const c = claim();
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 });

    const tooLate = t0 + DEFAULT_RETRY_GRANT_TTL_MS + 1;
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: tooLate })).toBeNull();

    const swept = pruneRetryControl({ home, now: tooLate });
    expect(swept.expired).toHaveLength(1);
    expect(swept.expired[0].tool).toBe('Bash');
    expect(formatUnspentExpiryNotice(swept.expired)).toContain('expired UNSPENT');
    expect(formatUnspentExpiryNotice(swept.expired)).toContain('shieldcortex approve --denial');

    // Reported ONCE — the next sweep is silent.
    expect(pruneRetryControl({ home, now: tooLate + 1_000 }).expired).toHaveLength(0);
  });

  // ── Prune precedence (R3 rule 1) ───────────────────────────────────────

  it('never prunes a row with a live claim (fingerprint TTL yields to it)', () => {
    denial({ now: t0 });
    // Claimed at 55m, so the card is live at 61m — past the 60m fingerprint TTL
    // that would otherwise have dropped this identity.
    const c = claim({ now: t0 + 55 * 60_000 });
    expect(c.ok).toBe(true);

    const past = t0 + 61 * 60_000;
    pruneRetryControl({ home, now: past });
    const row = getRetryRow({ hash: HASH, cwd }, { home });
    expect(row).toBeDefined();
    expect(row?.claim).toBeDefined();
    // And the tap still lands on it.
    expect(grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: past }).ok).toBe(true);
  });

  it('never prunes a row with a live unspent grant (fingerprint TTL yields to it)', () => {
    denial({ now: t0 });
    const c = claim({ now: t0 + 55 * 60_000 });
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 56 * 60_000, ttlMs: 600_000 });

    const past = t0 + 61 * 60_000;   // past the 60m fingerprint TTL
    pruneRetryControl({ home, now: past });
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeDefined();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: past })).not.toBeNull();
  });

  it('one claim mints one grant — a tap after that grant was spent is refused', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: t0 + 1_000 });
    consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 });

    const late = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: t0 + 3_000 });
    expect(late.ok).toBe(false);
    expect(late.ok === false && late.reason).toBe('claim-spent');
  });

  it('keeps a terminal grant for the spend-TTL + 24h audit tail, then drops it', () => {
    denial();
    const c = claim();
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0, ttlMs: 600_000 });
    consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 1_000 });

    const insideTail = t0 + 600_000 + RETRY_GRANT_AUDIT_TAIL_MS - 1_000;
    pruneRetryControl({ home, now: insideTail });
    expect(getRetryRow({ hash: HASH, cwd }, { home })).toBeDefined();

    const pastTail = t0 + 600_000 + RETRY_GRANT_AUDIT_TAIL_MS + 1_000;
    pruneRetryControl({ home, now: pastTail });
    expect(getRetryRow({ hash: HASH, cwd }, { home })).toBeUndefined();
  });

  it('tap-after-prune stays refused', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    const longAfter = t0 + RETRY_FINGERPRINT_RETENTION_MS + RETRY_CARD_LIFETIME_MS + 60_000;
    pruneRetryControl({ home, now: longAfter });
    expect(getRetryRow({ hash: HASH, cwd }, { home })).toBeUndefined();

    const out = grantRetry({ hash: HASH, cwd }, { nonce }, { home, now: longAfter });
    expect(out.ok).toBe(false);
    expect(out.ok === false && out.reason).toBe('not-found');
  });

  it('a suppression outlives the fingerprint TTL that would otherwise drop the row', () => {
    denial();
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: MAX_SUPPRESSION_FOR_TEST });
    const pastFingerprintTtl = t0 + RETRY_FINGERPRINT_RETENTION_MS + 60_000;
    pruneRetryControl({ home, now: pastFingerprintTtl });
    expect(isDenySuppressed({ hash: HASH, cwd }, { home, now: pastFingerprintTtl }).suppressed).toBe(true);
  });

  // ── Store hygiene ──────────────────────────────────────────────────────

  it('writes the store and its key owner-only (0600)', () => {
    denial();
    claim();
    expect(statSync(retryControlPath(home)).mode & 0o777).toBe(0o600);
    expect(statSync(join(home, '.shieldcortex', 'approvals', 'retry-control.key')).mode & 0o777).toBe(0o600);
  });

  it('never touches the #118 approvals store', () => {
    denial();
    const c = claim();
    grantRetry({ hash: HASH, cwd }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 });
    consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 1 });
    expect(() => readFileSync(join(home, '.shieldcortex', 'approvals', 'approvals.json'), 'utf8')).toThrow();
  });

  // ── Config ─────────────────────────────────────────────────────────────

  it('is OFF unless the config says exactly true, and bounds both clocks', () => {
    expect(normaliseRetryControlConfig(undefined).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({ retryCards: 'true' }).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({ retryCards: 1 }).retryCards).toBe(false);
    expect(normaliseRetryControlConfig({ retryCards: true }).retryCards).toBe(true);

    const defaults = normaliseRetryControlConfig({ retryCards: true });
    expect(defaults.retryGrantTtlMs).toBe(DEFAULT_RETRY_GRANT_TTL_MS);
    // Deny suppression defaults to the DIGEST window, per the clocks table.
    expect(normaliseRetryControlConfig({}, { digestWindowMs: 600_000 }).denySuppressionMs).toBe(600_000);
    // Junk falls back rather than clamping to the nearest understood value.
    expect(normaliseRetryControlConfig({ retryGrantTtlMs: 5 }).retryGrantTtlMs).toBe(DEFAULT_RETRY_GRANT_TTL_MS);
    expect(normaliseRetryControlConfig({ retryGrantTtlMs: 'ten' }).retryGrantTtlMs).toBe(DEFAULT_RETRY_GRANT_TTL_MS);
    expect(normaliseRetryControlConfig({ denySuppressionMs: 120_000 }).denySuppressionMs).toBe(120_000);
  });

  // ── Card copy (256-char budget order) ──────────────────────────────────

  it('spends the description budget in order: trust copy first, surface truncates last', () => {
    const fields = buildRetryCardFields({
      tool: 'Bash',
      signals: ['privilege-escalation'],
      redactedSurface: `Bash: [redacted action surface] ${'x'.repeat(400)}`,
      cwd: '/srv/jobs/nightly-backup',
      ttlMs: 600_000,
    });
    expect(fields.title.length).toBeLessThanOrEqual(80);
    expect(fields.title).toBe('Approve once? Bash · privilege-escalation');
    expect(fields.description.length).toBeLessThanOrEqual(256);
    // The trust copy is intact and FIRST.
    expect(fields.description.startsWith('held headless — Approve = ONE retry (10m, jobs/nightly-backup)')).toBe(true);
    expect(fields.surfaceTruncated).toBe(true);
    expect(fields.description.endsWith('…')).toBe(true);
  });

  it('withholds the surface entirely for a secret-egress class', () => {
    const fields = buildRetryCardFields({
      tool: 'Bash',
      signals: ['secret-egress'],
      redactedSurface: 'Bash: [redacted action surface] fields=command',
      cwd: '/srv/jobs/nightly-backup',
      ttlMs: 600_000,
    });
    expect(fields.surfaceWithheld).toBe(true);
    expect(fields.description).not.toContain('fields=command');
    expect(fields.description).toContain('held headless');
  });

  it('says so when the schedule outruns the spend TTL, and points at --denial --ttl', () => {
    const fields = buildRetryCardFields({
      tool: 'Bash',
      signals: ['dangerous-shell'],
      redactedSurface: 'Bash: [redacted action surface] fields=command',
      cwd: '/srv/jobs/hourly',
      ttlMs: 600_000,
      cronIntervalMs: 3_600_000,
    });
    expect(fields.description).toContain('schedule is slower than this TTL');
    expect(fields.description).toContain('--denial <id> --ttl');
  });

  it('offers exactly allow-once and deny — never allow-always', () => {
    const params = buildRetryCardParams({
      tool: 'Bash', signals: ['dangerous-shell'], redactedSurface: 's', cwd: '/srv/jobs', ttlMs: 600_000,
    });
    expect(params.allowedDecisions).toEqual(['allow-once', 'deny']);
    expect(JSON.stringify(params)).not.toContain('allow-always');
    expect(params.timeoutMs).toBe(RETRY_CARD_LIFETIME_MS);
    expect(String(params.title).length).toBeLessThanOrEqual(80);
    expect(String(params.description).length).toBeLessThanOrEqual(256);
  });

  // ── Alerts never carry a spendable artifact ────────────────────────────

  it('no card copy, budget notice or expiry notice carries a nonce or a hash', () => {
    denial();
    const c = claim();
    const nonce = c.ok ? c.nonce : '';
    const params = JSON.stringify(buildRetryCardParams({
      tool: 'Bash', signals: ['dangerous-shell'], redactedSurface: 'Bash: [redacted]', cwd, ttlMs: 600_000,
    }));
    expect(params).not.toContain(nonce);
    expect(params).not.toContain(HASH);
    expect(formatBudgetExhaustedNotice(['act-0000000000000001'])).not.toContain(nonce);
  });

  // ── R-impl review fixes (Grok APPROVE_WITH_NITS / SOL REQUEST_CHANGES) ──

  it('post-spend claim does not black out the next card (SOL blocker 1)', () => {
    denial();
    const c1 = claim();
    expect(c1.ok).toBe(true);
    expect(grantRetry({ hash: HASH, cwd }, { nonce: c1.ok ? c1.nonce : 'x' }, { home, now: t0 + 1_000 }).ok).toBe(true);
    const spent = consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 });
    expect(spent?.consumedAt).toBe(t0 + 2_000);
    // grant spent -> claim is inert history; a new DNP may card again
    denial({ now: t0 + 3_000 });
    const c2 = claim({ now: t0 + 3_000 });
    expect(c2.ok).toBe(true);
  });

  it('card auth hard-drops smuggled TTY wideners (SOL blocker 2)', () => {
    denial();
    const c = claim();
    expect(c.ok).toBe(true);
    // Operator denies while the card is still up.
    const denied = recordDenySuppression({ hash: HASH, cwd }, { home, now: t0 + 500, suppressionMs: 900_000, via: 'card' });
    expect(denied.ok).toBe(true);
    // A caller presenting the card nonce PLUS smuggled TTY flags: overrideDeny
    // must be dropped — deny beats the card, wideners are TTY-only.
    const out = grantRetry(
      { hash: HASH, cwd },
      { nonce: c.ok ? c.nonce : 'x', isInteractive: true, anyOrigin: true, overrideDeny: true },
      { home, now: t0 + 1_000 },
    );
    expect(out.ok).toBe(false);
    // Deny tore the claim down, so the card path dies as claim-missing —
    // the point is it dies: wideners never resurrect it and nothing grants.
    expect(out.ok === false && ['suppressed', 'claim-missing'].includes(out.reason)).toBe(true);
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('restoreLostActionIds puts drained ids back, deduped (shared nit)', () => {
    // burn the global budget so later denials record lost ids
    const cwds = [cwd, otherCwd];
    for (let i = 0; i < CARD_BUDGET_PER_WINDOW; i++) {
      const h = hashToolCall('Bash', { command: `burn-${i}` });
      denial({ hash: h, cwd: cwds[i % cwds.length] });
      const cc = claimCardLaunch(
        { id: fingerprintId(h, canonicaliseCwd(cwds[i % cwds.length])) },
        { home, now: t0, windowStartMs: t0, windowMs: 900_000, actionId: `act-burn${String(i).padStart(11, '0')}` },
      );
      expect(cc.ok).toBe(true);
    }
    const h2 = hashToolCall('Bash', { command: 'the one that lost' });
    denial({ hash: h2, actionId: 'act-00000000lost0001' });
    const lostClaim = claimCardLaunch(
      { id: fingerprintId(h2, canonicaliseCwd(cwd)) },
      { home, now: t0 + 1, windowStartMs: t0, windowMs: 900_000, actionId: 'act-00000000lost0001' },
    );
    expect(lostClaim.ok).toBe(false);
    const drained = drainLostActionIds({ home });
    expect(drained).toContain('act-00000000lost0001');
    expect(drainLostActionIds({ home })).toEqual([]);
    restoreLostActionIds(drained, { home });
    restoreLostActionIds(drained, { home });
    const again = drainLostActionIds({ home });
    expect(again.sort()).toEqual([...new Set(drained)].sort());
  });

});

/** Long enough to outlive the fingerprint retention clock in the prune test. */
const MAX_SUPPRESSION_FOR_TEST = 2 * 60 * 60 * 1000;
