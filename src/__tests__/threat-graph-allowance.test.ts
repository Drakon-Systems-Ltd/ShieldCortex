/**
 * Phase C step 2 — the allowance state machine (design doc Loop 3).
 *
 * Allowance creation requires N=3 QUALIFYING approvals of a (source, pattern)
 * pair: ≥3 distinct days, materially-different content (distinct hashes),
 * individually reviewed (bulk never counts). Revocation on reject is
 * remembered — re-earning needs 2× approvals over 2× the window; a second
 * revocation disables the pair (annotation-only) forever.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  applyApproval,
  applyRejection,
  freshAllowance,
  isAllowanceActive,
  type AllowanceState,
} from '../threat-graph/allowance.js';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { canonicalDump, projectToCompletion, rebuildThreatGraph } from '../threat-graph/projector.js';

const DAY = 24 * 60 * 60 * 1000;
const T0 = Date.parse('2026-08-01T00:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();
const dayStr = (ms: number) => iso(ms).slice(0, 10);

function approve(state: ReturnType<typeof freshAllowance>, dayOffset: number, hash: string, bulk = false) {
  const ts = T0 + dayOffset * DAY;
  return applyApproval(state, { ts: iso(ts), day: dayStr(ts), hash, bulk });
}

describe('allowance creation', () => {
  it('activates after 3 non-bulk approvals on 3 distinct days with distinct hashes', () => {
    let s = freshAllowance();
    s = approve(s, 0, 'h1');
    expect(s.active).toBe(false);
    s = approve(s, 1, 'h2');
    expect(s.active).toBe(false);
    s = approve(s, 2, 'h3');
    expect(s.active).toBe(true);
    expect(s.exemplars.sort()).toEqual(['h1', 'h2', 'h3']);
    expect(isAllowanceActive(s, T0 + 3 * DAY)).toBe(true);
  });

  it('does not activate from 3 approvals on the SAME day', () => {
    let s = freshAllowance();
    s = approve(s, 0, 'h1');
    s = approve(s, 0, 'h2');
    s = approve(s, 0, 'h3');
    expect(s.active).toBe(false);
  });

  it('near-duplicate approvals (same hash) count once', () => {
    let s = freshAllowance();
    s = approve(s, 0, 'dup');
    s = approve(s, 1, 'dup');
    s = approve(s, 2, 'dup');
    expect(s.active).toBe(false); // only one distinct hash
  });

  it('bulk approvals never count toward the allowance', () => {
    let s = freshAllowance();
    s = approve(s, 0, 'h1', true);
    s = approve(s, 1, 'h2', true);
    s = approve(s, 2, 'h3', true);
    expect(s.active).toBe(false);
    expect(s.approvals).toHaveLength(0);
  });

  it('prunes approvals older than the 30-day window', () => {
    let s = freshAllowance();
    s = approve(s, 0, 'h1');
    s = approve(s, 1, 'h2');
    // 40 days later the first two are out of window; this alone can't activate.
    s = approve(s, 40, 'h3');
    expect(s.active).toBe(false);
  });

  it('expires 30 days after the qualifying approval', () => {
    let s = freshAllowance();
    s = approve(s, 0, 'h1');
    s = approve(s, 1, 'h2');
    s = approve(s, 2, 'h3');
    expect(isAllowanceActive(s, T0 + 2 * DAY + 29 * DAY)).toBe(true);
    expect(isAllowanceActive(s, T0 + 2 * DAY + 31 * DAY)).toBe(false);
  });
});

describe('revocation with memory', () => {
  function activate() {
    let s = freshAllowance();
    s = approve(s, 0, 'h1');
    s = approve(s, 1, 'h2');
    s = approve(s, 2, 'h3');
    return s;
  }

  it('one reject revokes immediately and records a strike', () => {
    let s = activate();
    expect(s.active).toBe(true);
    s = applyRejection(s, { ts: iso(T0 + 3 * DAY) });
    expect(s.active).toBe(false);
    expect(s.strikes).toBe(1);
    expect(isAllowanceActive(s, T0 + 3 * DAY)).toBe(false);
  });

  it('re-earning after one strike needs 6 approvals over 6 distinct days', () => {
    let s = applyRejection(activate(), { ts: iso(T0 + 3 * DAY) });
    // 3 fresh approvals no longer suffice.
    s = approve(s, 10, 'a'); s = approve(s, 11, 'b'); s = approve(s, 12, 'c');
    expect(s.active).toBe(false);
    s = approve(s, 13, 'd'); s = approve(s, 14, 'e'); s = approve(s, 15, 'f');
    expect(s.active).toBe(true);
  });

  it('a second revocation disables the pair permanently (annotation-only)', () => {
    let s = applyRejection(activate(), { ts: iso(T0 + 3 * DAY) });
    // re-earn (6 over 60d window)
    for (let i = 0; i < 6; i++) s = approve(s, 10 + i, 'r' + i);
    expect(s.active).toBe(true);
    s = applyRejection(s, { ts: iso(T0 + 20 * DAY) });
    expect(s.strikes).toBe(2);
    expect(s.disabled).toBe(true);
    // No amount of approvals can re-activate.
    for (let i = 0; i < 10; i++) s = approve(s, 30 + i, 'z' + i);
    expect(s.active).toBe(false);
    expect(isAllowanceActive(s, T0 + 45 * DAY)).toBe(false);
  });
});

describe('projector derives allowances from the decision ledger', () => {
  beforeEach(() => initDatabase(':memory:'));
  afterEach(() => closeDatabase());

  // Decisions are stamped wall-clock by the real review flow, so to exercise
  // the distinct-day logic we insert the ledger rows directly with crafted
  // timestamps — the shape the review flow produces.
  function decisionRow(dayOffset: number, hash: string, decision: 'approve' | 'reject', bulk = false): void {
    const ts = iso(T0 + dayOffset * DAY);
    getDatabase().prepare(`
      INSERT INTO defence_audit (project, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result, operation, anomaly_score,
        threat_indicators, blocked_patterns, reason)
      VALUES ('test', ?, 'user', 'michael', 0.9, 'INTERNAL', 'ALLOW', 'review', 0, '[]', '[]', ?)
    `).run(ts, JSON.stringify({
      kind: 'quarantine_decision', decision, source_key: 'agent:jarvis',
      patterns: ['instruction_injection'], content_hash: hash, quarantine_id: dayOffset + 1, bulk,
    }));
  }

  function allowance(): AllowanceState | null {
    const row = getDatabase().prepare(`
      SELECT e.attrs FROM threat_edges e
      JOIN threat_nodes s ON s.id = e.src
      JOIN threat_nodes p ON p.id = e.dst
      WHERE e.predicate = 'allows' AND s.key = 'agent:jarvis' AND p.key = 'instruction_injection'
    `).get() as { attrs: string } | undefined;
    return row ? JSON.parse(row.attrs) as AllowanceState : null;
  }

  it('mints an active allows edge after 3 qualifying approvals', () => {
    decisionRow(0, 'h1', 'approve');
    decisionRow(1, 'h2', 'approve');
    decisionRow(2, 'h3', 'approve');
    projectToCompletion();

    const a = allowance();
    expect(a).not.toBeNull();
    expect(a!.active).toBe(true);
    expect(a!.exemplars.sort()).toEqual(['h1', 'h2', 'h3']);
  });

  it('bulk approvals never mint an allowance', () => {
    decisionRow(0, 'h1', 'approve', true);
    decisionRow(1, 'h2', 'approve', true);
    decisionRow(2, 'h3', 'approve', true);
    projectToCompletion();
    const a = allowance();
    expect(a?.active ?? false).toBe(false);
  });

  it('a reject after activation revokes and records a strike', () => {
    decisionRow(0, 'h1', 'approve');
    decisionRow(1, 'h2', 'approve');
    decisionRow(2, 'h3', 'approve');
    decisionRow(3, 'h4', 'reject');
    projectToCompletion();
    const a = allowance()!;
    expect(a.active).toBe(false);
    expect(a.strikes).toBe(1);
  });

  it('a reject of a never-approved pair mints no phantom edge', () => {
    decisionRow(0, 'h1', 'reject');
    projectToCompletion();
    const count = (getDatabase().prepare("SELECT COUNT(*) AS c FROM threat_edges WHERE predicate = 'allows'").get() as { c: number }).c;
    expect(count).toBe(0);
    expect(allowance()).toBeNull();
  });

  it('is reproduced deterministically by a rebuild (including a reject/strike)', () => {
    decisionRow(0, 'h1', 'approve');
    decisionRow(1, 'h2', 'approve');
    decisionRow(2, 'h3', 'approve');
    decisionRow(3, 'h4', 'reject'); // revoke + strike
    projectToCompletion();
    const incremental = canonicalDump();
    rebuildThreatGraph();
    expect(canonicalDump()).toBe(incremental);
    expect(allowance()!.strikes).toBe(1);
  });
});
