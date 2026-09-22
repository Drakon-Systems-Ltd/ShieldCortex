import { describe, expect, it } from '@jest/globals';
import {
  checkSessionLease,
  findFreeze,
  leasePermits,
  parseFreezeRecords,
} from '../session-lease.js';

/**
 * Every case below is a replay of something that actually happened on
 * 10 Aug 2026, or a bug found while building the guard that day. None are
 * invented scenarios.
 */

// The real ledger shape: records WRAP across lines. The first implementation
// parsed line-by-line and never saw "gateway restarts" on the continuation.
const LEDGER = `# DECISIONS.md — standing freezes and commitments

2026-08-10 12:05Z | FROZEN | npm publish, from any repo, any box | No package is
published to a public registry without the operator's explicit per-release
go-ahead in that turn. | Lift: operator only.

2026-08-10 12:05Z | FROZEN | installing/upgrading security components on ANY
box, incl. gateway restarts to activate them | Requires explicit authorisation
naming the box. | Lift: operator only.

2026-08-10 12:06Z | AUTHORISED | ShieldCortex work | Building and testing in a
worktree is in scope. | —
`;

const NOW = 1_754_000_000_000;

describe('parseFreezeRecords — wrapped records', () => {
  it('rejoins records that wrap across physical lines', () => {
    const records = parseFreezeRecords(LEDGER);
    expect(records).toHaveLength(2);
    // The continuation line is part of the record, which is the whole point:
    // "gateway restarts" lives there and was invisible line-by-line.
    expect(records[1]).toMatch(/gateway restarts to activate them/);
  });

  it('ignores non-FROZEN records — an AUTHORISED line is not a freeze', () => {
    expect(parseFreezeRecords(LEDGER).join(' ')).not.toMatch(/AUTHORISED/);
  });
});

describe('findFreeze — the exact matching bugs found on 10 Aug', () => {
  it('matches `install` against a freeze written `installing` (the guard that was silently off)', () => {
    expect(findFreeze(LEDGER, 'install')).toMatch(/installing\/upgrading/);
  });

  it('matches gateway-restart on text that only appears in the wrapped continuation', () => {
    expect(findFreeze(LEDGER, 'gateway-restart')).toMatch(/gateway restarts/);
  });

  it('does NOT fire on an unrelated scope (the `instruction`~`installing` false positive)', () => {
    expect(findFreeze(LEDGER, 'fleet-broadcast')).toBeNull();
  });
});

describe('checkSessionLease — replaying 10 Aug', () => {
  const base = { ledger: LEDGER, held: null, self: 'session-A', nowMs: NOW };

  it('11:14Z npm publish → REFUSED, quoting the freeze', () => {
    const d = checkSessionLease({ ...base, scope: 'npm-publish' });
    expect(d.verdict).toBe('frozen');
    expect(leasePermits(d)).toBe(false);
    expect(d.freeze).toMatch(/npm publish/);
    expect(d.reason).toMatch(/DECISIONS\.md/);
  });

  it('11:30Z install, 77s after the freeze → REFUSED even though no lease is held', () => {
    // The critical ordering: a freeze outranks lease availability. If an unheld
    // lease on a frozen scope were allowed, the first session after a freeze
    // would sail straight through — which is exactly what happened.
    const d = checkSessionLease({ ...base, scope: 'install', held: null });
    expect(d.verdict).toBe('frozen');
  });

  it('an unfrozen scope with a free lease is ALLOWED — the guard must not block everything', () => {
    const d = checkSessionLease({ ...base, scope: 'fleet-broadcast' });
    expect(d.verdict).toBe('allow');
    expect(leasePermits(d)).toBe(true);
  });
});

describe('checkSessionLease — mutual exclusion', () => {
  const base = { ledger: LEDGER, self: 'session-A', nowMs: NOW, scope: 'fleet-broadcast' as const };

  it('refuses when another live session holds it, naming holder, pid and age', () => {
    const d = checkSessionLease({
      ...base,
      held: { holder: 'session-B', pid: 4242, reason: 'sending the directive', acquiredAtMs: NOW - 30_000, expiresAtMs: NOW + 600_000 },
    });
    expect(d.verdict).toBe('held');
    expect(d.reason).toMatch(/session-B/);
    expect(d.reason).toMatch(/4242/);
    expect(d.reason).toMatch(/30s/);
    expect(d.reason).toMatch(/sending the directive/);
  });

  it('the holder may re-enter its own lease — a multi-step action must not deadlock on itself', () => {
    const d = checkSessionLease({
      ...base,
      held: { holder: 'session-A', pid: 1, acquiredAtMs: NOW - 5_000, expiresAtMs: NOW + 600_000 },
    });
    expect(d.verdict).toBe('allow');
  });

  it('an EXPIRED lease does not wedge the fleet — a crashed session self-heals', () => {
    const d = checkSessionLease({
      ...base,
      held: { holder: 'session-B', acquiredAtMs: NOW - 3_600_000, expiresAtMs: NOW - 1_000 },
    });
    expect(d.verdict).toBe('allow');
  });

  it('#438: a lease whose holder PID is confirmed dead does not block', () => {
    const d = checkSessionLease({
      ...base,
      held: {
        holder: 'session-B',
        pid: 160367,
        acquiredAtMs: NOW - 30_000,
        expiresAtMs: NOW + 600_000,
      },
      holderAlive: false,
    });
    expect(d.verdict).toBe('allow');
  });

  it('#438: unknown liveness still fails closed — a live-looking lease stays held', () => {
    const d = checkSessionLease({
      ...base,
      held: {
        holder: 'session-B',
        pid: 160367,
        acquiredAtMs: NOW - 30_000,
        expiresAtMs: NOW + 600_000,
      },
    });
    expect(d.verdict).toBe('held');
  });

  it('#438: a blank PID is never a skeleton key even if the caller claims dead', () => {
    const d = checkSessionLease({
      ...base,
      held: {
        holder: 'session-B',
        pid: null,
        acquiredAtMs: NOW - 30_000,
        expiresAtMs: NOW + 600_000,
      },
      holderAlive: false,
    });
    expect(d.verdict).toBe('held');
  });
});

describe('checkSessionLease — freeze outranks dead PID', () => {
  it('#438: a confirmed-dead holder on a FROZEN scope is still frozen', () => {
    const d = checkSessionLease({
      scope: 'npm-publish',
      ledger: LEDGER,
      held: {
        holder: 'session-B',
        pid: 160367,
        acquiredAtMs: NOW - 30_000,
        expiresAtMs: NOW + 600_000,
      },
      self: 'session-A',
      nowMs: NOW,
      holderAlive: false,
    });
    expect(d.verdict).toBe('frozen');
  });
});

describe('checkSessionLease — fails closed', () => {
  it('an unreadable ledger REFUSES: "cannot know" must never behave like "nothing is frozen"', () => {
    const d = checkSessionLease({ scope: 'npm-publish', ledger: null, held: null, self: 'A', nowMs: NOW });
    expect(d.verdict).toBe('unknown');
    expect(leasePermits(d)).toBe(false);
    expect(d.reason).toMatch(/cannot read|cannot know/i);
  });

  it('an empty ledger is readable and genuinely has no freezes — that is allow, not unknown', () => {
    const d = checkSessionLease({ scope: 'npm-publish', ledger: '', held: null, self: 'A', nowMs: NOW });
    expect(d.verdict).toBe('allow');
  });
});

describe('#550 — re-entry through the runtime that spawned this harness', () => {
  const held = { holder: 'openclaw-session-uuid', pid: 4242, acquiredAtMs: NOW - 1000, expiresAtMs: NOW + 60_000 };

  it('a live foreign record held by the spawning runtime, taken for this call, re-enters', () => {
    const d = checkSessionLease({ scope: 'security-config', ledger: '', held, self: 'sc-hook-hash', nowMs: NOW, holderSpawnedSelf: true, holderGatedThisCall: true });
    expect(d.verdict).toBe('allow');
    expect(d.reason).toContain('spawned this session');
    expect(d.reason).toContain('this very call');
    expect(d.reason).toContain('4242');
  });

  it('ancestry alone is not identity (#552): spawned-by but not gated-for-this-call is held', () => {
    expect(checkSessionLease({ scope: 'security-config', ledger: '', held, self: 'sc-hook-hash', nowMs: NOW, holderSpawnedSelf: true }).verdict).toBe('held');
    expect(checkSessionLease({ scope: 'security-config', ledger: '', held, self: 'sc-hook-hash', nowMs: NOW, holderSpawnedSelf: true, holderGatedThisCall: false }).verdict).toBe('held');
    // and the call key alone, from a process that did not spawn us, is held too
    expect(checkSessionLease({ scope: 'security-config', ledger: '', held, self: 'sc-hook-hash', nowMs: NOW, holderGatedThisCall: true }).verdict).toBe('held');
    expect(checkSessionLease({ scope: 'security-config', ledger: '', held, self: 'sc-hook-hash', nowMs: NOW, holderSpawnedSelf: false, holderGatedThisCall: true }).verdict).toBe('held');
  });

  it('omitted or false is the old answer: held', () => {
    expect(checkSessionLease({ scope: 'security-config', ledger: '', held, self: 'sc-hook-hash', nowMs: NOW }).verdict).toBe('held');
    expect(checkSessionLease({ scope: 'security-config', ledger: '', held, self: 'sc-hook-hash', nowMs: NOW, holderSpawnedSelf: false }).verdict).toBe('held');
  });

  it('a record without a pid never re-enters this way — no skeleton key through emptiness', () => {
    const noPid = { ...held, pid: null };
    expect(checkSessionLease({ scope: 'security-config', ledger: '', held: noPid, self: 'sc-hook-hash', nowMs: NOW, holderSpawnedSelf: true, holderGatedThisCall: true }).verdict).toBe('held');
  });

  it('a freeze still outranks the spawning runtime', () => {
    const d = checkSessionLease({ scope: 'security-config', ledger: '| FROZEN | security component edits |', held, self: 'sc-hook-hash', nowMs: NOW, holderSpawnedSelf: true, holderGatedThisCall: true });
    expect(d.verdict).toBe('frozen');
  });
});
