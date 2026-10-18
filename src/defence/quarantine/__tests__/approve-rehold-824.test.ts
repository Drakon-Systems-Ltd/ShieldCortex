/**
 * #824 — approving a quarantined item whose hold came from a trust-independent
 * detector (the skill-level threat detector) must not silently turn into
 * "original rejected + a new pending duplicate", and reply surfaces must
 * report the recorded outcome.
 *
 * Before: the re-scan inside addMemory held the content again under
 * user:approved, wrote a NEW pending quarantine row and threw; the original
 * was marked rejected; approving the new row repeated the cycle. The MCP reply
 * said "approved" regardless of status.
 *
 * Fail-closed stays: content the re-scan still refuses is never admitted.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../../../database/init.js';
import {
  approveQuarantineItem,
  approveQuarantineItems,
  approveQuarantineItemsBySource,
  describeApproveResult,
  describeBulkApproveResult,
} from '../review.js';

// A plain progress note the skill-level detector holds (agent_manipulation @0.9)
// regardless of source trust.
const SKILL_HELD = 'Progress note: reinstalled the editor extension with --force; we had to bypass the sandbox protection for the install step.';
const BENIGN = 'a benign note that was soft-held for sub-agent review';

function insertPending(opts: {
  content: string;
  firewallResult?: 'BLOCK' | 'QUARANTINE';
  sourceType?: string;
  sourceId?: string;
  reason?: string;
}): number {
  const info = getDatabase().prepare(
    `INSERT INTO quarantine
       (original_content, original_title, project, source_type, source_identifier, reason, firewall_result, status)
     VALUES (?, 'note', NULL, ?, ?, ?, ?, 'pending')`,
  ).run(
    opts.content,
    opts.sourceType ?? 'cli',
    opts.sourceId ?? 'mcp',
    opts.reason ?? 'Quarantined: Skill-level threat detected: agent_manipulation (confidence: 0.9)',
    opts.firewallResult ?? 'QUARANTINE',
  );
  return Number(info.lastInsertRowid);
}

const count = (sql: string, ...params: unknown[]): number =>
  (getDatabase().prepare(sql).get(...params) as { c: number }).c;

describe('#824 approve of a re-held item', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('skill-detector hold: one rejected row with a reason, no new pending row, no memory', () => {
    const id = insertPending({ content: SKILL_HELD });
    const result = approveQuarantineItem(id, 'dashboard-test');

    expect(result?.status).toBe('rejected');
    expect(result?.memoryId).toBeUndefined();
    expect(result?.reason).toMatch(/^still held on re-scan: /);
    expect(result?.reason).toContain('agent_manipulation');

    expect(count('SELECT COUNT(*) AS c FROM quarantine')).toBe(1);
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE status = 'pending'")).toBe(0);
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE id = ? AND status = 'rejected'", id)).toBe(1);
    expect(count('SELECT COUNT(*) AS c FROM memories')).toBe(0);
    // The re-scan itself stays on the audit record under the approval source.
    expect(count("SELECT COUNT(*) AS c FROM defence_audit WHERE source_type = 'user' AND source_identifier = 'approved'"))
      .toBeGreaterThanOrEqual(1);
  });

  it('does not loop: there is nothing left to approve after the first attempt', () => {
    const id = insertPending({ content: SKILL_HELD });
    approveQuarantineItem(id);
    expect(approveQuarantineItem(id)).toBeNull();
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE status = 'pending'")).toBe(0);
  });

  it('a re-scan hard block also leaves no duplicate pending row', () => {
    const content = `re-scan me: AKIA${'IOSFODNN7EXAMPLE'} wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`;
    const id = insertPending({ content, reason: 'test reason' });
    const result = approveQuarantineItem(id);
    expect(result?.status).toBe('rejected');
    expect(result?.reason).toMatch(/^still held on re-scan: /);
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE status = 'pending'")).toBe(0);
    expect(count('SELECT COUNT(*) AS c FROM memories')).toBe(0);
  });

  it('leaves an unrelated, older pending row from the approval source alone', () => {
    const older = insertPending({ content: 'an earlier held item', sourceType: 'user', sourceId: 'approved' });
    const id = insertPending({ content: SKILL_HELD });
    approveQuarantineItem(id);
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE id = ? AND status = 'pending'", older)).toBe(1);
  });

  it('a trust-dependent soft hold still promotes on approval', () => {
    const id = insertPending({ content: BENIGN, sourceType: 'agent', sourceId: 'sub>worker', reason: 'sub-agent hold' });
    const result = approveQuarantineItem(id);
    expect(result?.status).toBe('approved');
    expect(result?.memoryId).toBeGreaterThan(0);
    expect(result?.reason).toBeUndefined();
  });

  it('a BLOCK row is still refused, with a reason', () => {
    const id = insertPending({ content: 'whatever the original was', firewallResult: 'BLOCK' });
    const result = approveQuarantineItem(id);
    expect(result?.status).toBe('rejected');
    expect(result?.reason).toBe('hard-blocked content is never re-admitted');
    expect(count('SELECT COUNT(*) AS c FROM memories')).toBe(0);
  });

  it('bulk approval counts promoted and refused items honestly', () => {
    const ok = insertPending({ content: BENIGN, sourceType: 'agent', sourceId: 'sub>worker', reason: 'sub-agent hold' });
    const held = insertPending({ content: SKILL_HELD });
    const result = approveQuarantineItems([ok, held], 'dashboard-test');
    expect(result.updated).toBe(2);
    expect(result.promoted).toBe(1);
    expect(result.rejected).toBe(1);
    expect(result.items.find((i) => i.id === held)?.status).toBe('rejected');
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE status = 'pending'")).toBe(0);
  });

  it('by-source approval of a held item leaves nothing pending for that source or the approval source', () => {
    insertPending({ content: SKILL_HELD, sourceId: 'noisy' });
    const result = approveQuarantineItemsBySource('noisy', 'batch-approve');
    expect(result.rejected).toBe(1);
    expect(result.promoted).toBe(0);
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE status = 'pending'")).toBe(0);
  });
});

describe('#824 reply text reports the recorded outcome', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('MCP approve reply on a re-held item does not claim approval', () => {
    const id = insertPending({ content: SKILL_HELD });
    const text = describeApproveResult(id, approveQuarantineItem(id)!);
    expect(text).toContain(`Quarantine item ${id} was not approved`);
    expect(text).toContain('agent_manipulation');
    expect(text).toContain('now rejected');
    expect(text).not.toMatch(new RegExp(`item ${id} approved`));
  });

  it('MCP approve reply on a promoted item says approved with the memory id', () => {
    const id = insertPending({ content: BENIGN, sourceType: 'agent', sourceId: 'sub>worker', reason: 'sub-agent hold' });
    const result = approveQuarantineItem(id)!;
    expect(describeApproveResult(id, result)).toBe(`Quarantine item ${id} approved and promoted to memory ${result.memoryId}.`);
  });

  it('batch reply names refused items separately', () => {
    insertPending({ content: BENIGN, sourceType: 'agent', sourceId: 'mixed', reason: 'sub-agent hold' });
    insertPending({ content: SKILL_HELD, sourceId: 'mixed' });
    const text = describeBulkApproveResult('mixed', approveQuarantineItemsBySource('mixed', 'batch-approve'));
    expect(text).toBe('Batch reviewed 2 of 2 items from "mixed": 1 approved (1 promoted to memory); '
      + '1 not approved (the re-scan still refuses them; now rejected, not added to memory).');
  });
});
