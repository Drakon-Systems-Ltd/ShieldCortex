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
