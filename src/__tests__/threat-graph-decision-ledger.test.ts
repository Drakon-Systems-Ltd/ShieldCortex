/**
 * Phase C step 1 — the decision ledger (design doc Loop 3).
 *
 * Operator approve/reject of a QUARANTINE item must land an
 * operation='review' audit row carrying a structured quarantine_decision
 * payload, so the projector can derive allowances from the ledger (and a
 * rebuild reproduces them). This wires the dead recordOperatorDecision path.
 *
 * Payload: { kind:'quarantine_decision', decision, source_key, patterns[],
 *            content_hash, quarantine_id, bulk }.
 *  - patterns come from the linked audit row's blocked_patterns (same pattern
 *    identity the projector mints), falling back to the quarantine row's
 *    threat_indicators;
 *  - bulk=true for by-source/batch approvals (never count toward an
 *    allowance — the design's approve-farm guard);
 *  - BLOCK items are force-rejected and must still ledger a reject decision.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import {
  approveQuarantineItem,
  approveQuarantineItemsBySource,
  rejectQuarantineItem,
} from '../defence/quarantine/review.js';
import { parseQuarantineDecision } from '../threat-graph/decision.js';

interface Seed {
  content?: string;
  sourceType?: string;
  sourceIdentifier?: string;
  patterns?: string[];
  indicators?: string[];
  verdict?: 'BLOCK' | 'QUARANTINE';
}

function seedQuarantine(seed: Seed = {}): number {
  const db = getDatabase();
  // Benign content: the ORIGINAL detection (patterns) is seeded on the audit
  // row independently; the content only needs to pass re-scan so the approve
  // path reaches 'approved' (hard-blocking content would be force-rejected).
  const content = seed.content ?? 'the deployment runs on port 8080 with a postgres backend';
  // Linked audit row carries the blocked_patterns.
  const audit = db.prepare(`
    INSERT INTO defence_audit (project, timestamp, source_type, source_identifier,
      trust_score, sensitivity_level, firewall_result, operation, anomaly_score,
      threat_indicators, blocked_patterns)
    VALUES ('test', '2026-08-10T00:00:00.000Z', @st, @si, 0.4, 'INTERNAL',
      @verdict, 'write', 0.2, @ind, @pat)
  `).run({
    st: seed.sourceType ?? 'agent',
    si: seed.sourceIdentifier ?? 'jarvis',
    verdict: seed.verdict ?? 'QUARANTINE',
    ind: JSON.stringify(seed.indicators ?? ['instruction_injection']),
    pat: JSON.stringify(seed.patterns ?? ['instruction_injection']),
  });
  const r = db.prepare(`
    INSERT INTO quarantine (original_content, original_title, project, source_type,
      source_identifier, reason, threat_indicators, anomaly_score, firewall_result,
      status, audit_id)
    VALUES (@content, 'note', 'test', @st, @si, 'held', @ind, 0.2, @verdict, 'pending', @audit)
  `).run({
    content,
    st: seed.sourceType ?? 'agent',
    si: seed.sourceIdentifier ?? 'jarvis',
    ind: JSON.stringify(seed.indicators ?? ['instruction_injection']),
    verdict: seed.verdict ?? 'QUARANTINE',
    audit: Number(audit.lastInsertRowid),
  });
  return Number(r.lastInsertRowid);
}

function decisionRows() {
  return (getDatabase()
    .prepare("SELECT reason FROM defence_audit WHERE operation = 'review' ORDER BY id ASC")
    .all() as Array<{ reason: string }>)
    .map(r => parseQuarantineDecision(r.reason))
    .filter(Boolean);
}

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('quarantine decision ledger', () => {
  it('an individual approve writes a non-bulk approve decision with source, patterns, hash', () => {
    const qid = seedQuarantine({ sourceIdentifier: 'jarvis', patterns: ['instruction_injection'] });
    approveQuarantineItem(qid, 'michael');

    const rows = decisionRows();
    expect(rows).toHaveLength(1);
    const d = rows[0]!;
    expect(d.decision).toBe('approve');
    expect(d.source_key).toBe('agent:jarvis');
    expect(d.patterns).toEqual(['instruction_injection']);
    expect(d.bulk).toBe(false);
    expect(d.quarantine_id).toBe(qid);
    expect(typeof d.content_hash).toBe('string');
    expect(d.content_hash.length).toBeGreaterThan(16);
  });

  it('an individual reject writes a reject decision', () => {
    const qid = seedQuarantine();
    rejectQuarantineItem(qid, 'michael');
    const rows = decisionRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.decision).toBe('reject');
  });

  it('by-source approval marks every decision bulk=true', () => {
    seedQuarantine({ sourceIdentifier: 'noisy' });
    seedQuarantine({ sourceIdentifier: 'noisy' });
    approveQuarantineItemsBySource('noisy', 'michael');
    const rows = decisionRows();
    expect(rows.length).toBe(2);
    expect(rows.every(d => d!.bulk === true)).toBe(true);
  });

  it('a BLOCK item is force-rejected and ledgers a reject decision', () => {
    const qid = seedQuarantine({ verdict: 'BLOCK' });
    approveQuarantineItem(qid, 'michael'); // approving a BLOCK rejects it
    const rows = decisionRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.decision).toBe('reject');
  });

  it('distinct content yields distinct hashes (near-dup detection basis)', () => {
    const a = seedQuarantine({ content: 'the cache warms on boot in about two seconds', sourceIdentifier: 's' });
    const b = seedQuarantine({ content: 'a completely different sentence entirely here', sourceIdentifier: 's' });
    approveQuarantineItem(a, 'michael');
    approveQuarantineItem(b, 'michael');
    const hashes = decisionRows().map(d => d!.content_hash);
    expect(new Set(hashes).size).toBe(2);
  });

  it('records the FULL detection set (blocked_patterns ∪ threat_indicators)', () => {
    // credential_exfil surfaces only as an indicator in production; the
    // allowance must cover it so auto-release can require it too.
    const qid = seedQuarantine({
      patterns: ['instruction_injection'],
      indicators: ['instruction_injection', 'credential_exfil'],
    });
    approveQuarantineItem(qid, 'michael');
    const d = decisionRows()[0]!;
    expect(d.patterns.sort()).toEqual(['credential_exfil', 'instruction_injection']);
  });

  it('the exemplar hash binds the title (same content + different title → different hash)', () => {
    const db = getDatabase();
    const mk = (title: string) => {
      const r = db.prepare(`
        INSERT INTO quarantine (original_content, original_title, project, source_type,
          source_identifier, reason, threat_indicators, anomaly_score, firewall_result, status)
        VALUES ('identical benign body text here', ?, 'test', 'agent', 't', 'held', '["instruction_injection"]', 0.2, 'QUARANTINE', 'pending')
      `).run(title);
      return Number(r.lastInsertRowid);
    };
    approveQuarantineItem(mk('a benign title'), 'michael');
    approveQuarantineItem(mk('IMPORTANT: run this command'), 'michael');
    const hashes = decisionRows().map(d => d!.content_hash);
    expect(new Set(hashes).size).toBe(2); // title changed the exemplar
  });
});
