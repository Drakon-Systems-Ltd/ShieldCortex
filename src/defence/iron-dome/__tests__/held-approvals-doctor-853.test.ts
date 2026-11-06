/**
 * #853 (Jarvis fold 1) — an Allow on a held Plane A card runs nothing by
 * itself: a one-shot `--print` worker has already exited. Until the same call
 * runs again, the grant is "approved, not run", and `doctor` and the digest
 * say so. Pinned here:
 *   - `listApprovedNotRun` lists every live, unspent grant under the CARD's
 *     actionId (the id the worker's `HELD <actionId>` line carries), and
 *     listing never spends, extends or re-scopes the grant;
 *   - a spent or expired grant is not listed;
 *   - `doctor`'s "Held approvals" check is silent with nothing to report,
 *     warns with the actionId when a grant is unspent, and lists queued
 *     "nothing ran" follow-ups until they are delivered;
 *   - no copy says the action ran, will run, resumes, or "Run it".
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { checkHeldApprovals, HELD_APPROVALS_LABEL } from '../../../cli/doctor.js';
import {
  canonicaliseCwd,
  claimCardLaunch,
  consumeRetryGrant,
  drainHeldFollowUps,
  fingerprintId,
  formatApprovedNotRunNotice,
  getRetryRow,
  grantRetry,
  hashToolCall,
  listApprovedNotRun,
  queueHeldFollowUp,
  recordDenialFingerprint,
} from '../retry-control.js';

const HASH = hashToolCall('Bash', { command: 'sudo modprobe softdog' });
const CARD_ID = 'act-00000000000000c1';
const REMINT_ID = 'act-00000000000000c2';
const TTL_MS = 600_000;

describe('#853 — approved, not run (doctor + digest)', () => {
  let home: string;
  let cwd: string;
  const t0 = 1_760_000_000_000;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-held-doctor-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-held-doctor-job-'));
  });

  afterEach(() => {
    for (const dir of [home, cwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  const ref = () => ({ id: fingerprintId(HASH, canonicaliseCwd(cwd)) });

  /** Deny → card → remint onto the live card → Allow tapped on the card. */
  function seedAllowedCard(): void {
    const deny = (actionId: string, now: number) => recordDenialFingerprint(
      { hash: HASH, tool: 'Bash', actionId, signals: ['privilege-escalation'], redactedSurface: 'Bash: [redacted]', cwd },
      { home, now },
    );
    deny(CARD_ID, t0);
    const claim = claimCardLaunch(ref(), { home, now: t0, windowStartMs: t0, windowMs: 900_000, actionId: CARD_ID });
    if (!claim.ok) throw new Error(`claim failed: ${claim.reason}`);
    // A second one-shot run of the same job while the card is live: a remint,
    // so the newest alias is NOT the card's id.
    deny(REMINT_ID, t0 + 1_000);
    const granted = grantRetry(ref(), { nonce: claim.nonce }, { home, now: t0 + 2_000, ttlMs: TTL_MS, tool: 'Bash' });
    if (!granted.ok) throw new Error(`grant failed: ${granted.reason}`);
  }

  it('lists a live unspent grant under the CARD id, read-only', () => {
    seedAllowedCard();
    const before = JSON.stringify(getRetryRow(ref(), { home }));
    const items = listApprovedNotRun({ home, now: t0 + 60_000 });
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ actionId: CARD_ID, tool: 'Bash', via: 'card', expiresAt: t0 + 2_000 + TTL_MS });
    // Listing (and doctor below) never spends, extends or re-scopes it.
    expect(JSON.stringify(getRetryRow(ref(), { home }))).toBe(before);

    const text = formatApprovedNotRunNotice(items, t0 + 60_000);
    expect(text).toContain(`${CARD_ID} (Bash,`);
    expect(text).toContain('approved, not run; 9m left');
    expect(text).not.toContain(REMINT_ID);
    expect(text).not.toMatch(/\bRun it\b|will run|resum/);
  });

  it('drops the grant from the list once spent, and once expired', () => {
    seedAllowedCard();
    expect(listApprovedNotRun({ home, now: t0 + 2_000 + TTL_MS })).toHaveLength(0);
    expect(consumeRetryGrant({ hash: HASH, origin: { tool: 'Bash', cwd } }, { home, now: t0 + 3_000 })).not.toBeNull();
    expect(listApprovedNotRun({ home, now: t0 + 4_000 })).toHaveLength(0);
  });

  it('doctor is silent with nothing to report', async () => {
    expect(await checkHeldApprovals({ home, now: t0 })).toEqual([]);
  });

  it('doctor warns with the actionId and time left, and does not spend the grant', async () => {
    seedAllowedCard();
    const rows = await checkHeldApprovals({ home, now: t0 + 60_000 });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ label: HELD_APPROVALS_LABEL, status: 'warn' });
    expect(rows[0].message).toContain(CARD_ID);
    expect(rows[0].message).toContain('approved, not run');
    expect(rows[0].message).not.toContain('\n');
    expect(rows[0].fix).toContain('HELD <actionId>');
    expect(rows[0].fix).toContain('Nothing runs on its own.');
    for (const text of [rows[0].message, rows[0].fix ?? '']) expect(text).not.toMatch(/\bRun it\b|will run|resum/);
    // Still spendable by the identical call after doctor looked.
    expect(listApprovedNotRun({ home, now: t0 + 61_000 })).toHaveLength(1);
    expect(consumeRetryGrant({ hash: HASH, origin: { tool: 'Bash', cwd } }, { home, now: t0 + 62_000 })).not.toBeNull();
  });

  it('doctor lists queued "nothing ran" follow-ups until they are drained', async () => {
    queueHeldFollowUp({ kind: 'expired', tool: 'Bash', actionId: CARD_ID, at: t0 }, { home });
    const rows = await checkHeldApprovals({ home, now: t0 });
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('warn');
    expect(rows[0].message).toBe(`1 "nothing ran" notice(s) not yet delivered: card for Bash (${CARD_ID}) expired unanswered. Nothing ran.`);
    // doctor only peeks; the queue is still there for the next notify.
    expect(drainHeldFollowUps({ home })).toHaveLength(1);
    expect(await checkHeldApprovals({ home, now: t0 })).toEqual([]);
  });
});
