/**
 * revoke-by-source — bulk-delete every memory written by a given source, gated
 * by the trust-hierarchy revoke ACL (own the source, or be high-trust and
 * outrank it). The remediation path for purging a poisoned agent's memories.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase } from '../database/init.js';
import { addMemory, getMemoryById } from '../memory/store.js';
import { executeForget } from '../tools/forget.js';
import { queryAuditLogs } from '../defence/audit/queries.js';
import { setRevokeBySourceEnabled } from '../cloud/config.js';
import type { DefenceSource } from '../defence/types.js';

const PROJECT = 'revoke-test';
const HIGH: DefenceSource = { type: 'cli', identifier: 'mcp' };               // ~0.9
const LOW_CALLER: DefenceSource = { type: 'agent', identifier: 'spawn>a>b' }; // ~0.25

function seed(source: string, title: string): number {
  return addMemory({ title, content: `content of ${title}`, category: 'note', project: PROJECT, source }).id;
}

const forget = (args: Record<string, unknown>) =>
  executeForget(args as Parameters<typeof executeForget>[0]);

beforeEach(() => {
  initDatabase(':memory:');
  setRevokeBySourceEnabled(true); // mechanics tests need the gate ON
});
afterEach(() => {
  setRevokeBySourceEnabled(false); // contain the flag (per-worker config sandbox)
  closeDatabase();
});

describe('revoke-by-source gate', () => {
  it('rejects fromSource when the gate is OFF (default)', async () => {
    setRevokeBySourceEnabled(false);
    seed('agent:agent-spawned', 'should survive while gate off');
    const res = await forget({ fromSource: 'agent:agent-spawned', confirm: true, source: HIGH, project: '*' });
    expect(res.success).toBe(false);
    expect(res.error ?? '').toMatch(/disabled/i);
  });
});

describe('revoke-by-source', () => {
  it('high-trust caller revokes a lower-trust source; outranked memories deleted, others preserved', async () => {
    const a1 = seed('agent:agent-spawned', 'poison-1');
    const a2 = seed('agent:agent-spawned', 'poison-2');
    const own = seed('cli:mcp', 'legit owner memory');

    const res = await forget({ fromSource: 'agent:agent-spawned', confirm: true, source: HIGH, project: '*' });

    expect(res.deleted).toBe(2);
    expect(getMemoryById(a1)).toBeNull();
    expect(getMemoryById(a2)).toBeNull();
    expect(getMemoryById(own)).not.toBeNull(); // different source — untouched

    // provenance: the revoke produced ALLOW rows tagged operation='revoke'
    const revokes = queryAuditLogs({ operation: 'revoke', limit: 50 });
    expect(revokes.filter(r => r.firewall_result === 'ALLOW').length).toBeGreaterThanOrEqual(2);
  });

  it('owner can revoke their own source', async () => {
    const id = seed('cli:mcp', 'mine to forget');
    const res = await forget({ fromSource: 'cli:mcp', confirm: true, source: HIGH, project: '*' });
    expect(res.deleted).toBe(1);
    expect(getMemoryById(id)).toBeNull();
  });

  it('a low-trust caller CANNOT revoke a higher-trust source (0 deleted, rows survive)', async () => {
    const h1 = seed('cli:mcp', 'high memory 1');
    const h2 = seed('cli:mcp', 'high memory 2');

    const res = await forget({ fromSource: 'cli:mcp', confirm: true, source: LOW_CALLER, project: '*' });

    expect(res.deleted).toBe(0);
    expect(getMemoryById(h1)).not.toBeNull();
    expect(getMemoryById(h2)).not.toBeNull();
    // denials are audited
    expect(queryAuditLogs({ firewallResult: 'BLOCK', limit: 50 }).length).toBeGreaterThan(0);
  });

  it('type-prefix revoke (agent:*) purges all agent-typed sources, leaves others', async () => {
    seed('agent:agent-spawned', 'agent A');
    seed('agent:other', 'agent B');
    const keep = seed('cli:mcp', 'cli keeper');

    const res = await forget({ fromSource: 'agent:*', confirm: true, source: HIGH, project: '*' });

    expect(res.deleted).toBe(2);
    expect(getMemoryById(keep)).not.toBeNull();
  });

  it('rejects a blanket wildcard fromSource', async () => {
    seed('cli:mcp', 'should survive');
    const res = await forget({ fromSource: '*', confirm: true, source: HIGH, project: '*' });
    expect(res.success).toBe(false);
  });

  it('dry-run previews without deleting', async () => {
    const id = seed('agent:agent-spawned', 'dry-run target');
    const res = await forget({ fromSource: 'agent:agent-spawned', dryRun: true, source: HIGH, project: '*' });
    expect(res.wouldDelete).toBe(1);
    expect(res.deleted).toBeUndefined();
    expect(getMemoryById(id)).not.toBeNull(); // untouched
  });

  it('requires confirm for a multi-row revoke', async () => {
    seed('agent:agent-spawned', 'r1');
    seed('agent:agent-spawned', 'r2');
    const res = await forget({ fromSource: 'agent:agent-spawned', source: HIGH, project: '*' }); // no confirm
    expect(res.success).toBe(false);
    expect(res.wouldDelete).toBe(2);
  });
});
