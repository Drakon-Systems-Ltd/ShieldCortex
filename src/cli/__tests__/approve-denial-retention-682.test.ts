/**
 * #682 — `shieldcortex approve --denial` over the 48h review window.
 *
 * The CLI is where the operator learns what happened, so these drive the
 * real `runApprove` (injected home, clock, TTY and provenance) and read what
 * it prints: a denial older than the old 60m cliff is listed and approvable,
 * one past 48h is reported as EXPIRED (not "no match"), one dropped for space
 * says so, and none of those answers ever grants anything. A grant minted
 * from an old identity is the same short one-shot as ever.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runApprove, type ApproveDeps } from '../approve.js';
import {
  DEFAULT_RETRY_GRANT_TTL_MS,
  MAX_RETRY_ROWS,
  RETRY_PENDING_REVIEW_WINDOW_MS,
  canonicaliseCwd,
  claimCardLaunch,
  consumeRetryGrant,
  findRetiredIdentity,
  fingerprintId,
  getRetryRow,
  grantRetry,
  hashToolCall,
  listRetryRows,
  pruneRetryControl,
  recordDenialFingerprint,
  recordDenySuppression,
  retryControlPath,
  retryStoreCapacity,
} from '../../defence/iron-dome/retry-control.js';

const HASH = hashToolCall('Bash', { command: 'sudo systemctl restart backup-daily' });
const ACTION_ID = 'act-00000000000068cc';
const MIN = 60_000;
const HOUR = 60 * MIN;
const WINDOW = RETRY_PENDING_REVIEW_WINDOW_MS;

function jobActionId(i: number): string {
  return `act-${(0x6830_0000 + i).toString(16).padStart(16, '0')}`;
}

describe('#682 — approve --denial across the 48h review window', () => {
  let home: string;
  let cwd: string;
  let t0: number;

  const sink = () => {
    const lines: string[] = [];
    return { lines, write: (m: string) => { lines.push(m); }, text: () => lines.join('\n') };
  };
  const human = () => ({ ok: true as const, reason: null, detail: 'ok', chain: [] as string[] });
  const agent = () => ({ ok: false as const, reason: 'agent-ancestor' as const, detail: 'x', chain: ['node', 'claude'] });

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-approve-682-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    cwd = mkdtempSync(join(tmpdir(), 'sc-approve-682-job-'));
    t0 = 1_760_000_000_000;
  });

  afterEach(() => {
    for (const dir of [home, cwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function denial(opts: { now?: number; actionId?: string; hash?: string } = {}) {
    const r = recordDenialFingerprint(
      {
        hash: opts.hash ?? HASH,
        tool: 'Bash',
        actionId: opts.actionId ?? ACTION_ID,
        signals: ['privilege-escalation'],
        redactedSurface: 'Bash: [redacted action surface] fields=command',
        cwd,
      },
      { home, now: opts.now ?? t0 },
    );
    expect(r.ok).toBe(true);
    return r;
  }

  function fill(count: number, start = 0, now = (i: number) => t0 + i) {
    for (let i = start; i < start + count; i += 1) {
      denial({ hash: hashToolCall('Bash', { command: `nightly-job --slot ${i}` }), actionId: jobActionId(i), now: now(i) });
    }
  }

  function approve(args: string[], at: number, extra: Partial<ApproveDeps> = {}) {
    const out = sink();
    const code = runApprove(args, {
      home, now: at, interactive: true, provenance: human, log: out.write, error: out.write, ...extra,
    });
    return { code, text: out.text() };
  }

  const id = () => fingerprintId(HASH, canonicaliseCwd(cwd));

  // ── Listed and approvable past the old 60m cliff ───────────────────────

  it.each([
    ['61 minutes', 61 * MIN],
    ['24 hours', 24 * HOUR],
    ['48h - 1ms', WINDOW - 1],
  ])('at %s the denial is listed with its review deadline and the slot count', (_label, offset) => {
    denial();
    const { code, text } = approve(['--denial'], t0 + offset, { interactive: false });
    expect(code).toBe(0);
    expect(text).toContain(ACTION_ID);
    expect(text).toContain('denied, no decision');
    expect(text).toContain(`reviewable until ${new Date(t0 + WINDOW).toISOString()}`);
    expect(text).toContain(`1 of ${MAX_RETRY_ROWS} denial slots in use`);
    // Looking granted nothing.
    expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
  });

  it.each([
    ['61 minutes', 61 * MIN],
    ['24 hours', 24 * HOUR],
    ['48h - 1ms', WINDOW - 1],
  ])('at %s an operator approval mints a FRESH default 10m one-shot, counted from now', (_label, offset) => {
    denial();
    const at = t0 + offset;
    const { code, text } = approve(['--denial', ACTION_ID], at);
    expect(code).toBe(0);
    expect(text).toContain('Authorised ONE retry');
    expect(text).toContain(`expires ${new Date(at + DEFAULT_RETRY_GRANT_TTL_MS).toISOString()}`);
    expect(text).toContain('It is not held for a later scheduled run');

    const grant = getRetryRow({ id: id() }, { home })!.grant!;
    expect(grant.approvedAt).toBe(at);
    expect(grant.ttlMs).toBe(DEFAULT_RETRY_GRANT_TTL_MS);
    expect(grant.via).toBe('tty');
    // One-shot, from the approval: spent once, never again; never a day later.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: at + DEFAULT_RETRY_GRANT_TTL_MS })).toBeNull();
  });

  it('the fresh grant is spent by the first matching call inside its window, and only once', () => {
    denial();
    const at = t0 + 24 * HOUR;
    expect(approve(['--denial', ACTION_ID], at).code).toBe(0);
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: at + MIN })).not.toBeNull();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: at + 2 * MIN })).toBeNull();
    // Tomorrow's tick finds nothing to spend.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: at + 24 * HOUR })).toBeNull();
  });

  it('--ttl above 60m is still refused for an old identity', () => {
    denial();
    const { code, text } = approve(['--denial', ACTION_ID, '--ttl', '1440'], t0 + 30 * HOUR);
    expect(code).toBe(1);
    expect(text).toContain('--ttl for a retry must be between');
    expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
  });

  // ── Past 48h: reported as expired, never silently absent ───────────────

  it.each([
    ['exactly 48h', WINDOW],
    ['48h + 1ms', WINDOW + 1],
  ])('at %s approve --denial reports EXPIRED with the times, and grants nothing', (_label, offset) => {
    denial();
    const at = t0 + offset;
    const { code, text } = approve(['--denial', ACTION_ID], at);
    expect(code).toBe(1);
    expect(text).toContain(`Headless denial ${ACTION_ID} (Bash) expired`);
    expect(text).toContain(`last denied at ${new Date(t0).toISOString()}`);
    expect(text).toContain(`48h review window ended at ${new Date(t0 + WINDOW).toISOString()}`);
    expect(text).toContain(`left the store at ${new Date(at).toISOString()}`);
    expect(text).toContain('Nothing was granted');
    expect(text).not.toContain('No headless denial matches');
    expect(getRetryRow({ id: id() }, { home })).toBeUndefined();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: at })).toBeNull();
  });

  it('the expiry answer matches the alias case-insensitively, and by canonical id', () => {
    denial();
    const at = t0 + WINDOW;
    expect(approve(['--denial', ACTION_ID.toUpperCase()], at).text).toContain('expired');
    expect(approve(['--denial', id()], at).text).toContain('expired');
  });

  it('after expiry the list says nothing is on file, and that a record exists', () => {
    denial();
    const { code, text } = approve(['--denial'], t0 + WINDOW, { interactive: false });
    expect(code).toBe(0);
    expect(text).toContain('No headless denials on file');
    expect(text).toContain('1 expired or dropped denial(s) on record');
  });

  it('an id with no receipt keeps the generic answer, states the window, and echoes safely', () => {
    denial();
    const { code, text } = approve(['--denial', 'act-\u001b[2Jdeadbeef'], t0);
    expect(code).toBe(1);
    expect(text).toContain('No headless denial matches "act-?[2Jdeadbeef"');
    expect(text).toContain('Denials are kept 48h from their last denial');
    expect(text).not.toContain('\u001b[2J');
  });

  it('an identity the old 60m rule already erased is not revived', () => {
    mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
    writeFileSync(retryControlPath(home), JSON.stringify({ version: 1, budget: null, rows: [] }));
    const { code, text } = approve(['--denial', ACTION_ID], t0 + 2 * HOUR);
    expect(code).toBe(1);
    expect(text).toContain('No headless denial matches');
  });

  // ── Nothing grants through any refusal path ────────────────────────────

  it('a non-interactive caller is refused for an old identity, before any lookup', () => {
    denial();
    for (const at of [t0 + 47 * HOUR, t0 + WINDOW]) {
      const { code, text } = approve(['--denial', ACTION_ID], at, { interactive: false });
      expect(code).toBe(1);
      expect(text).toMatch(/interactive terminal/i);
      expect(text).not.toContain('expired');
      expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
    }
  });

  it('a provenance failure is refused for an old identity', () => {
    denial();
    const { code } = approve(['--denial', ACTION_ID], t0 + 47 * HOUR, { provenance: agent });
    expect(code).toBe(1);
    expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
  });

  it('an expired card cannot grant, even while its identity is still on file', () => {
    denial();
    const c = claimCardLaunch({ id: id() }, { home, now: t0, windowStartMs: t0, windowMs: 15 * MIN });
    expect(c.ok).toBe(true);
    // The operator runs approve at 2h (sweeping), then the stale card is tapped.
    expect(approve(['--denial'], t0 + 2 * HOUR, { interactive: false }).text).toContain(ACTION_ID);
    const tap = grantRetry({ id: id() }, { nonce: c.ok ? c.nonce : '' }, { home, now: t0 + 2 * HOUR });
    expect(tap.ok).toBe(false);
    expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
  });

  it('a live deny suppression on an old identity still needs --override-deny', () => {
    denial();
    recordDenySuppression({ id: id() }, { home, now: t0 + 40 * HOUR, suppressionMs: HOUR, via: 'card' });
    const { code, text } = approve(['--denial', ACTION_ID], t0 + 40 * HOUR + MIN);
    expect(code).toBe(1);
    expect(text).toContain('You denied this action');
    expect(getRetryRow({ id: id() }, { home })?.grant).toBeUndefined();
  });

  // ── Spent grant + newer denial (the OR) ────────────────────────────────

  it('after a spent grant, a newer denial is still approvable once the old audit tail has lapsed', () => {
    denial();
    expect(approve(['--denial', ACTION_ID], t0).code).toBe(0);
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 1 })).not.toBeNull();
    denial({ now: t0 + 20 * HOUR, actionId: 'act-00000000000068cd' });

    const at = t0 + 24 * HOUR + 10 * MIN + 1;
    const listed = approve(['--denial'], at, { interactive: false }).text;
    expect(listed).toContain('act-00000000000068cd');
    expect(listed).toContain('denied, no decision');

    const { code } = approve(['--denial', 'act-00000000000068cd'], at);
    expect(code).toBe(0);
    expect(getRetryRow({ id: id() }, { home })!.grant!.approvedAt).toBe(at);
  });

  it('a spent grant with no newer denial is shown as spent, not as a pending decision', () => {
    denial();
    expect(approve(['--denial', ACTION_ID], t0 + HOUR).code).toBe(0);
    consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + HOUR + 1 });
    const text = approve(['--denial'], t0 + 2 * HOUR, { interactive: false }).text;
    expect(text).toContain(`retry spent at ${new Date(t0 + HOUR + 1).toISOString()}`);
    expect(text).not.toContain('denied, no decision');
  });

  // ── Capacity, reported truthfully ──────────────────────────────────────

  it('a denial dropped for space says so, names the cap, and grants nothing', () => {
    fill(MAX_RETRY_ROWS + 1);
    const at = t0 + HOUR;
    const { code, text } = approve(['--denial', jobActionId(0)], at);
    expect(code).toBe(1);
    expect(text).toContain(`Headless denial ${jobActionId(0)} (Bash) was dropped at ${new Date(t0 + MAX_RETRY_ROWS).toISOString()} to make room`);
    expect(text).toContain(`the store's normal capacity is ${MAX_RETRY_ROWS} denials`);
    expect(text).toContain('or your Deny are exempt from it');
    expect(text).not.toContain('at most');
    // Not over the cap here, so no over-cap sentence.
    expect(text).not.toContain('The store is above that now');
    expect(text).toContain('Nothing was granted');

    const list = approve(['--denial'], at, { interactive: false }).text;
    expect(list).toContain(`${MAX_RETRY_ROWS} of ${MAX_RETRY_ROWS} denial slots in use`);
    expect(list).toContain('1 older denial(s) dropped for space on record');
  }, 60_000);

  /**
   * A persisted store over the cap where EVERY row is protected (a live Deny).
   * Built from real writes, then the one row no public call can protect in
   * time is given its suppression on disk: every locked call prunes first, and
   * that prune drops an unprotected 129th row before anything could protect
   * it. This is the "arrives over the cap" store the prune and the copy
   * handle.
   */
  function allProtectedOverCap(at: number): void {
    fill(MAX_RETRY_ROWS);
    for (let i = 0; i < MAX_RETRY_ROWS; i += 1) {
      expect(recordDenySuppression({ actionId: jobActionId(i) }, { home, now: at }).ok).toBe(true);
    }
    fill(1, MAX_RETRY_ROWS, () => at + 1);
    const raw = JSON.parse(readFileSync(retryControlPath(home), 'utf8')) as {
      rows: Array<{ actionIds: string[]; denyEpoch: number; suppression?: { at: number; until: number; via: string } }>;
    };
    expect(raw.rows).toHaveLength(MAX_RETRY_ROWS + 1);
    const template = raw.rows.find((r) => r.suppression)!.suppression!;
    const last = raw.rows.find((r) => r.actionIds.includes(jobActionId(MAX_RETRY_ROWS)))!;
    expect(last.suppression).toBeUndefined();
    last.denyEpoch += 1;
    last.suppression = { at: at + 1, until: at + 1 + (template.until - template.at), via: 'card' };
    writeFileSync(retryControlPath(home), JSON.stringify(raw));
  }

  it('protected rows over the cap are listed as OVER the cap, not hidden', () => {
    const at = t0 + MIN;
    allProtectedOverCap(at);
    const list = approve(['--denial'], at + 2, { interactive: false }).text;
    expect(list).toContain(`${MAX_RETRY_ROWS + 1} of ${MAX_RETRY_ROWS} denial slots in use`);
    expect(list).toContain(`OVER the cap: ${MAX_RETRY_ROWS + 1} row(s)`);
    // The OVER line itself explains protected rows "are never dropped for
    // space"; what must be absent is the report that an eviction happened.
    expect(list).toContain('are never dropped for space');
    expect(list).not.toContain('older denial(s) dropped for space on record');
    for (let i = 0; i <= MAX_RETRY_ROWS; i += 1) expect(list).toContain(jobActionId(i));

    // The listing's own prune ran; every protected row survived it, still denied.
    const rows = listRetryRows({ home, now: at + 2 });
    expect(rows).toHaveLength(MAX_RETRY_ROWS + 1);
    for (let i = 0; i <= MAX_RETRY_ROWS; i += 1) {
      expect(getRetryRow({ actionId: jobActionId(i) }, { home })?.suppression).toBeDefined();
      expect(findRetiredIdentity({ actionId: jobActionId(i) }, { home })).toBeUndefined();
    }
    expect(rows.some((r) => r.grant)).toBe(false);
    // Nothing was retired for capacity, before or by that prune.
    const cap = retryStoreCapacity({ home, now: at + 2 });
    expect(cap).toMatchObject({
      rows: MAX_RETRY_ROWS + 1, cap: MAX_RETRY_ROWS, protectedRows: MAX_RETRY_ROWS + 1, overCap: true, retiredForCapacity: 0,
    });
    expect(cap.lastCapacityRetiredAt).toBeUndefined();
  }, 60_000);

  it('128 protected rows plus one unprotected denial: the prune drops it for space and says so', () => {
    fill(MAX_RETRY_ROWS);
    const at = t0 + MIN;
    for (let i = 0; i < MAX_RETRY_ROWS; i += 1) {
      expect(recordDenySuppression({ actionId: jobActionId(i) }, { home, now: at }).ok).toBe(true);
    }
    fill(1, MAX_RETRY_ROWS, () => at + 1);

    const list = approve(['--denial'], at + 2, { interactive: false }).text;
    expect(list).toContain(`${MAX_RETRY_ROWS} of ${MAX_RETRY_ROWS} denial slots in use`);
    expect(list).not.toContain('OVER the cap');
    expect(list).toContain(`1 older denial(s) dropped for space on record (latest ${new Date(at + 2).toISOString()})`);
    expect(list).not.toContain(jobActionId(MAX_RETRY_ROWS));
    for (let i = 0; i < MAX_RETRY_ROWS; i += 1) {
      expect(getRetryRow({ actionId: jobActionId(i) }, { home })?.suppression).toBeDefined();
    }

    const { code, text } = approve(['--denial', jobActionId(MAX_RETRY_ROWS)], at + 3);
    expect(code).toBe(1);
    expect(text).toContain(`Headless denial ${jobActionId(MAX_RETRY_ROWS)} (Bash) was dropped at ${new Date(at + 2).toISOString()} to make room`);
    expect(text).toContain('Nothing was granted');
    expect(listRetryRows({ home, now: at + 3 }).some((r) => r.grant)).toBe(false);
  }, 60_000);

  it('over the cap with protected rows, a dropped newcomer is told the cap is normal, not absolute', () => {
    const at = t0 + MIN;
    allProtectedOverCap(at);
    // A distinct newcomer with nothing protecting it. Inserting keeps it (it is
    // never its own victim); the next prune can retire only it, because every
    // other row holds a live Deny.
    const newcomer = MAX_RETRY_ROWS + 1;
    fill(1, newcomer, () => at + 2);
    expect(retryStoreCapacity({ home, now: at + 2 })).toMatchObject({
      rows: MAX_RETRY_ROWS + 2, protectedRows: MAX_RETRY_ROWS + 1, overCap: true, retiredForCapacity: 0,
    });
    expect(pruneRetryControl({ home, now: at + 3 }).ok).toBe(true);
    expect(listRetryRows({ home, now: at + 3 })).toHaveLength(MAX_RETRY_ROWS + 1);
    expect(findRetiredIdentity({ actionId: jobActionId(newcomer) }, { home })).toMatchObject({
      reason: 'capacity', retiredAt: at + 3,
    });

    const { code, text } = approve(['--denial', jobActionId(newcomer)], at + 4);
    expect(code).toBe(1);
    expect(text).toContain(`Headless denial ${jobActionId(newcomer)} (Bash) was dropped at ${new Date(at + 3).toISOString()} to make room`);
    expect(text).toContain(`the store's normal capacity is ${MAX_RETRY_ROWS} denials`);
    expect(text).toContain('or your Deny are exempt from it and never dropped for space');
    expect(text).toContain(`The store is above that now: ${MAX_RETRY_ROWS + 1} denials, ${MAX_RETRY_ROWS + 1} of them protected.`);
    expect(text).not.toContain('at most');
    expect(text).toContain('Nothing was granted');

    // No grant anywhere, and every protected row is still there and still denied.
    const rows = listRetryRows({ home, now: at + 4 });
    expect(rows).toHaveLength(MAX_RETRY_ROWS + 1);
    expect(rows.some((r) => r.grant)).toBe(false);
    for (let i = 0; i <= MAX_RETRY_ROWS; i += 1) {
      expect(getRetryRow({ actionId: jobActionId(i) }, { home })?.suppression).toBeDefined();
      expect(findRetiredIdentity({ actionId: jobActionId(i) }, { home })).toBeUndefined();
    }
    expect(getRetryRow({ actionId: jobActionId(newcomer) }, { home })).toBeUndefined();
    expect(retryStoreCapacity({ home, now: at + 4 })).toMatchObject({
      rows: MAX_RETRY_ROWS + 1, protectedRows: MAX_RETRY_ROWS + 1, overCap: true, retiredForCapacity: 1,
    });
  }, 60_000);

  it('a capacity eviction that lands between lookup and grant is reported, not granted around', () => {
    fill(MAX_RETRY_ROWS);
    const at = t0 + MIN;
    // --any-origin's confirmation runs after the lookup and before the grant:
    // another writer fills the store in exactly that gap.
    const { code, text } = approve(['--denial', jobActionId(0), '--any-origin'], at, {
      confirm: () => {
        fill(1, MAX_RETRY_ROWS, () => at);
        return true;
      },
    });
    expect(code).toBe(1);
    expect(text).toContain(`Headless denial ${jobActionId(0)} (Bash) was dropped at ${new Date(at).toISOString()} to make room`);
    expect(listRetryRows({ home, now: at }).some((r) => r.grant)).toBe(false);
  }, 60_000);

  // ── Hostile persisted receipts render safely ───────────────────────────

  it('a hostile receipt cannot inject terminal escapes into the answer', () => {
    mkdirSync(join(home, '.shieldcortex', 'approvals'), { recursive: true });
    writeFileSync(retryControlPath(home), JSON.stringify({
      version: 1, budget: null, rows: [],
      retired: [{
        id: 'f'.repeat(32), actionIds: ['act-00000000000068ce', '\u001b]8;;http://x\u0007click'],
        tool: '\u001b[2JBash', reason: 'expired', lastDeniedAt: 1e300, retiredAt: t0,
      }],
    }));
    const { code, text } = approve(['--denial', 'act-00000000000068ce'], t0 + MIN);
    expect(code).toBe(1);
    expect(text).toContain('Headless denial act-00000000000068ce (tool) expired');
    expect(text).toContain('an unknown time');
    expect(text).not.toMatch(/\u001b\]|\u001b\[2J|\u0007/);
    expect(readFileSync(retryControlPath(home), 'utf8')).not.toContain('click');
  });
});
