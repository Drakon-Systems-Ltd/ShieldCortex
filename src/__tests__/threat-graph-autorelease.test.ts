/**
 * Phase C step 3 — auto-release consumption (design doc Loop 3).
 *
 * Auto-release admits a would-be-QUARANTINED item ONLY when: the feature is
 * on (default off), the item's every detection is an ACTIVE allowance for the
 * source, the content is a near-dup of an approved exemplar, and the source is
 * under its per-day cap. It is the loosening, so it fails CLOSED — any doubt
 * keeps the item quarantined.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { shouldAutoRelease, recordAutoRelease } from '../threat-graph/allowance.js';
import { isAutoReleaseEnabled } from '../cloud/config.js';

const NOW = Date.parse('2026-08-15T12:00:00.000Z');

/** Seed an ACTIVE allowance edge for (agent:jarvis, pattern) with an exemplar. */
function seedAllowance(pattern: string, exemplarHash: string, opts: { active?: boolean; expires?: string } = {}): void {
  const db = getDatabase();
  const src = db.prepare("INSERT INTO threat_nodes (kind, key, attrs, first_seen, last_seen) VALUES ('source', 'agent:jarvis', '{}', 'x', 'x')").run();
  const dst = db.prepare("INSERT INTO threat_nodes (kind, key, attrs, first_seen, last_seen) VALUES ('pattern', ?, '{}', 'x', 'x')").run(pattern);
  const state = {
    approvals: [], exemplars: [exemplarHash],
    active: opts.active ?? true, expires: opts.expires ?? '2026-09-01T00:00:00.000Z',
    strikes: 0, disabled: false,
  };
  db.prepare(`
    INSERT INTO threat_edges (src, predicate, dst, count, first_seen, last_seen, valid_to, writer, evidence, attrs)
    VALUES (?, 'allows', ?, 1, 'x', 'x', ?, 'operator', '[]', ?)
  `).run(Number(src.lastInsertRowid), Number(dst.lastInsertRowid), state.expires, JSON.stringify(state));
}

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

const Q = 'QUARANTINE' as const;

describe('shouldAutoRelease', () => {
  it('releases when every detection is an active allowance and content is a near-dup', () => {
    seedAllowance('instruction_injection', 'HASH_A');
    const r = shouldAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection'], contentHash: 'HASH_A', verdict: Q, nowMs: NOW });
    expect(r.release).toBe(true);
  });

  it('NEVER releases a BLOCK verdict (invariant 2)', () => {
    seedAllowance('instruction_injection', 'HASH_A');
    const r = shouldAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection'], contentHash: 'HASH_A', verdict: 'BLOCK', nowMs: NOW });
    expect(r.release).toBe(false);
    expect(r.reason).toMatch(/QUARANTINE/);
  });

  it('holds when content is NOT a near-dup of an exemplar', () => {
    seedAllowance('instruction_injection', 'HASH_A');
    const r = shouldAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection'], contentHash: 'DIFFERENT', verdict: Q, nowMs: NOW });
    expect(r.release).toBe(false);
  });

  it('holds when ANY detection (incl. an indicator-only one) lacks an active allowance', () => {
    seedAllowance('instruction_injection', 'HASH_A');
    // credential_exfil surfaces only in threat_indicators in production; it must
    // still block release when unallowed.
    const r = shouldAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection', 'credential_exfil'], contentHash: 'HASH_A', verdict: Q, nowMs: NOW });
    expect(r.release).toBe(false);
  });

  it('holds when the allowance has expired', () => {
    seedAllowance('instruction_injection', 'HASH_A', { expires: '2026-08-01T00:00:00.000Z' });
    const r = shouldAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection'], contentHash: 'HASH_A', verdict: Q, nowMs: NOW });
    expect(r.release).toBe(false);
  });

  it('holds when there is no detection at all (nothing to release against)', () => {
    seedAllowance('instruction_injection', 'HASH_A');
    const r = shouldAutoRelease({ sourceKey: 'agent:jarvis', patterns: [], contentHash: 'HASH_A', verdict: Q, nowMs: NOW });
    expect(r.release).toBe(false);
  });

  it('holds once the per-source per-day cap is reached', () => {
    seedAllowance('instruction_injection', 'HASH_A');
    for (let i = 0; i < 20; i++) recordAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection'], contentHash: 'HASH_A', nowMs: NOW });
    const r = shouldAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection'], contentHash: 'HASH_A', verdict: Q, nowMs: NOW, dailyCap: 20 });
    expect(r.release).toBe(false);
    expect(r.reason).toMatch(/cap/i);
  });

  it('each auto-release lands a reviewable audit row', () => {
    seedAllowance('instruction_injection', 'HASH_A');
    recordAutoRelease({ sourceKey: 'agent:jarvis', patterns: ['instruction_injection'], contentHash: 'HASH_A', nowMs: NOW });
    const row = getDatabase().prepare(
      "SELECT threat_indicators, reason FROM defence_audit WHERE threat_indicators LIKE '%auto_released%' ORDER BY id DESC LIMIT 1"
    ).get() as { threat_indicators: string; reason: string };
    expect(row).toBeDefined();
    expect(row.reason).toContain('instruction_injection');
  });
});

describe('config gate', () => {
  it('defaults to off', () => {
    expect(isAutoReleaseEnabled({})).toBe(false);
    expect(isAutoReleaseEnabled({ threatGraph: {} })).toBe(false);
  });
  it('on only when explicitly true', () => {
    expect(isAutoReleaseEnabled({ threatGraph: { autoRelease: true } })).toBe(true);
    expect(isAutoReleaseEnabled({ threatGraph: { autoRelease: false } })).toBe(false);
  });
});
