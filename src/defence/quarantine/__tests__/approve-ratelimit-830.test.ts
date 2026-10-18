/**
 * #830 — the memory write rate limit refuses an approval before the admission
 * scan runs, so the rejection reason must not claim a re-scan. A refusal from
 * the scan itself keeps saying `still held on re-scan:`. Outcomes are unchanged:
 * either way the item ends rejected and nothing is added to memory.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../../../database/init.js';
import { addMemory } from '../../../memory/store.js';
import { approveQuarantineItem, describeApproveResult } from '../review.js';

const BENIGN = 'a benign note that was soft-held for sub-agent review';
const SKILL_HELD = 'Progress note: reinstalled the editor extension with --force; we had to bypass the sandbox protection for the install step.';
// The approval path admits under this code-constant source (review.ts).
const APPROVAL_SOURCE = { type: 'user', identifier: 'approved' } as const;

function insertPending(content: string, reason = 'sub-agent hold', sourceType = 'agent', sourceId = 'sub>worker'): number {
  const info = getDatabase().prepare(
    `INSERT INTO quarantine
       (original_content, original_title, project, source_type, source_identifier, reason, firewall_result, status)
     VALUES (?, 'note', NULL, ?, ?, ?, 'QUARANTINE', 'pending')`,
  ).run(content, sourceType, sourceId, reason);
  return Number(info.lastInsertRowid);
}

/** Use up the approval source's write window through the real store. */
function exhaustApprovalRateLimit(): void {
  for (let i = 0; i < 20; i++) {
    addMemory({ title: `filler ${i}`, content: `routine filler note number ${i} for the write window` }, undefined, APPROVAL_SOURCE);
  }
}

const count = (sql: string, ...params: unknown[]): number =>
  (getDatabase().prepare(sql).get(...params) as { c: number }).c;

describe('#830 approve refused by the write rate limit', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('reason names the rate limit, not a re-scan; the item still ends rejected', () => {
    const id = insertPending(BENIGN);
    exhaustApprovalRateLimit();
    const memoriesBefore = count('SELECT COUNT(*) AS c FROM memories');

    const result = approveQuarantineItem(id, 'dashboard-test');

    expect(result?.status).toBe('rejected');
    expect(result?.memoryId).toBeUndefined();
    expect(result?.reason).not.toMatch(/re-scan/);
    expect(result?.reason).toMatch(/^not admitted \(memory write rate limit\): Rate limited: /);
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE id = ? AND status = 'rejected'", id)).toBe(1);
    expect(count("SELECT COUNT(*) AS c FROM quarantine WHERE status = 'pending'")).toBe(0);
    expect(count('SELECT COUNT(*) AS c FROM memories')).toBe(memoriesBefore);

    const text = describeApproveResult(id, result!);
    expect(text).toContain(`Quarantine item ${id} was not approved: not admitted (memory write rate limit)`);
    expect(text).not.toMatch(/re-scan/);
  });

  it('a refusal from the scan itself still says re-scan', () => {
    const id = insertPending(SKILL_HELD, 'Quarantined: Skill-level threat detected: agent_manipulation (confidence: 0.9)', 'cli', 'mcp');
    const result = approveQuarantineItem(id, 'dashboard-test');
    expect(result?.status).toBe('rejected');
    expect(result?.reason).toMatch(/^still held on re-scan: /);
    expect(result?.reason).not.toMatch(/rate limit/);
  });
});
