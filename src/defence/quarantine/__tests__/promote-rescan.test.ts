/**
 * Feature #2 — quarantine promote must not launder poison.
 *
 * Before: promoteApprovedQuarantineRow passed the source as a string field (not
 * a positional DefenceSource), so approval admitted the row with no re-scan and
 * (post part-1) at the unattributed trust; it also promoted originally-BLOCK
 * rows. Now: BLOCK rows are refused (rejected, never re-admitted); QUARANTINE
 * (soft-hold) rows are re-admitted through the pipeline at operator-approved
 * trust (user:approved = 0.9, out of the auto-quarantine band) and fail closed
 * if their content now hard-blocks.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../../../database/init.js';
import { approveQuarantineItem } from '../review.js';

function insertPending(opts: {
  content: string;
  firewallResult: 'BLOCK' | 'QUARANTINE';
  sourceType?: string;
  sourceId?: string;
}): number {
  const db = getDatabase();
  const info = db.prepare(
    `INSERT INTO quarantine
       (original_content, original_title, project, source_type, source_identifier, reason, firewall_result, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`,
  ).run(
    opts.content,
    'Quarantined item',
    null,
    opts.sourceType ?? 'agent',
    opts.sourceId ?? 'sub>worker',
    'test reason',
    opts.firewallResult,
  );
  return Number(info.lastInsertRowid);
}

describe('quarantine promote — no laundering (Feature #2)', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('REFUSES an originally-BLOCK row: rejects it, creates no memory', () => {
    const id = insertPending({ content: 'whatever the original was', firewallResult: 'BLOCK' });
    const result = approveQuarantineItem(id);

    expect(result?.status).toBe('rejected');
    expect(result?.memoryId).toBeUndefined();

    const db = getDatabase();
    expect((db.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c).toBe(0);
    expect((db.prepare('SELECT status FROM quarantine WHERE id = ?').get(id) as { status: string }).status).toBe('rejected');
  });

  it('re-admits a QUARANTINE (soft-hold) row at operator-approved trust (0.9), re-scanned', () => {
    const id = insertPending({ content: 'a benign note that was soft-held for sub-agent review', firewallResult: 'QUARANTINE' });
    const result = approveQuarantineItem(id);

    expect(result?.status).toBe('approved');
    expect(result?.memoryId).toBeGreaterThan(0);

    const db = getDatabase();
    const row = db.prepare('SELECT trust_score, source FROM memories WHERE id = ?')
      .get(result!.memoryId) as { trust_score: number; source: string };
    expect(row.trust_score).toBe(0.9);       // operator-approved, NOT the old unattributed/1.0
    expect(row.source).toBe('user:approved');
    // The promote re-ran the pipeline (audit row under the approval source).
    const audit = db.prepare(
      "SELECT COUNT(*) AS n FROM defence_audit WHERE source_type = 'user' AND source_identifier = 'approved'",
    ).get() as { n: number };
    expect(audit.n).toBeGreaterThanOrEqual(1);
  });

  it('fails closed: a QUARANTINE row whose content now hard-blocks is rejected, not admitted', () => {
    const content = `re-scan me: AKIA${'IOSFODNN7EXAMPLE'} wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`;
    const id = insertPending({ content, firewallResult: 'QUARANTINE' });
    const result = approveQuarantineItem(id);

    expect(result?.status).toBe('rejected');
    expect(result?.memoryId).toBeUndefined();
    const db = getDatabase();
    expect((db.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c).toBe(0);
  });
});
