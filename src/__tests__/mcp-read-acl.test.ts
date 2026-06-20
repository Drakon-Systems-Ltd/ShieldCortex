/**
 * MCP read-path access control — integration.
 *
 * The recall-boundary shim (v4.36.0) guarded the two .mjs prompt hooks, but the
 * MCP read TOOLS still returned rows without applying the access-control engine
 * consistently: `get_memory` (direct-ID fetch — the sharpest exfil primitive),
 * `get_related`, and `get_context` had no read ACL. These tests prove a
 * low-trust / non-owner caller can no longer pull RESTRICTED or other-source
 * memories through those tools, while an authorised owner still can.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory, createMemoryLink } from '../memory/store.js';
import { executeGetMemory, executeGetRelated, executeRecall } from '../tools/recall.js';
import { executeGetContext, executeExport, executeStartSession } from '../tools/context.js';
import { scoreSource } from '../defence/trust/source-scorer.js';
import { resolveToolSource } from '../defence/trust/resolve-tool-source.js';
import type { DefenceSource } from '../defence/types.js';

const PROJECT = 'mcp-read-acl';
const OWNER: DefenceSource = { type: 'cli', identifier: 'owner-cli' }; // ~0.9, owns the rows
// Deeply-nested spawned sub-agent: trust ≈ 0.3 × 0.7² ≈ 0.147, and not the owner.
const LOW_TRUST: DefenceSource = { type: 'agent', identifier: 'agent-spawned>task-1>task-2' };

function seed(opts: { title: string; restricted?: boolean }): number {
  const m = addMemory({
    title: opts.title,
    content: `Sensitive material in "${opts.title}" — must be ACL-gated on the MCP read path.`,
    category: 'note',
    project: PROJECT,
    source: 'cli:owner-cli',
  });
  if (opts.restricted) {
    getDatabase().prepare(`UPDATE memories SET sensitivity_level = 'RESTRICTED' WHERE id = ?`).run(m.id);
  }
  return m.id;
}

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('get_memory read ACL', () => {
  it('denies a low-trust non-owner direct-fetch of a RESTRICTED memory', () => {
    const id = seed({ title: 'api creds', restricted: true });
    const res = executeGetMemory({ id, source: LOW_TRUST });
    expect(res.success).toBe(false); // surfaced as not-found, never the content
    expect(res.memory).toBeUndefined();
  });

  it('allows the authorised owner to fetch the same RESTRICTED memory', () => {
    const id = seed({ title: 'api creds', restricted: true });
    const res = executeGetMemory({ id, source: OWNER });
    expect(res.success).toBe(true);
    expect(res.memory?.id).toBe(id);
  });
});

describe('get_related read ACL', () => {
  it('omits a RESTRICTED related memory from a low-trust caller', () => {
    const anchor = seed({ title: 'anchor' });
    const secret = seed({ title: 'related secret', restricted: true });
    createMemoryLink(anchor, secret, 'related');

    const res = executeGetRelated({ id: anchor, source: LOW_TRUST });
    expect(res.success).toBe(true);
    expect((res.related ?? []).some((r) => r.memory.id === secret)).toBe(false);
  });

  it('includes the related memory for the authorised owner', () => {
    const anchor = seed({ title: 'anchor' });
    const secret = seed({ title: 'related secret', restricted: true });
    createMemoryLink(anchor, secret, 'related');

    const res = executeGetRelated({ id: anchor, source: OWNER });
    expect((res.related ?? []).some((r) => r.memory.id === secret)).toBe(true);
  });
});

describe('get_context read guard (sensitivity — shared bootstrap surface)', () => {
  it('strips RESTRICTED for ALL callers but keeps INTERNAL context for a low-trust caller (no blackout)', async () => {
    seed({ title: 'ctx restricted secret', restricted: true });
    seed({ title: 'ctx internal note' }); // INTERNAL

    const low = await executeGetContext({ project: PROJECT, format: 'raw', source: LOW_TRUST });
    expect(low.success).toBe(true);
    expect(low.context ?? '').not.toContain('ctx restricted secret'); // RESTRICTED never surfaced
    expect(low.context ?? '').toContain('ctx internal note'); // subagent keeps INTERNAL project context

    const owner = await executeGetContext({ project: PROJECT, format: 'raw', source: OWNER });
    expect(owner.context ?? '').not.toContain('ctx restricted secret'); // stripped even for the owner
  });
});

describe('start_session read guard (sensitivity)', () => {
  it('excludes RESTRICTED from the session preamble', async () => {
    seed({ title: 'ss restricted secret', restricted: true });
    seed({ title: 'ss internal note' });

    const res = await executeStartSession({ project: PROJECT });
    expect(res.success).toBe(true);
    expect(res.context ?? '').not.toContain('ss restricted secret');
  });
});

describe('recall read ACL (tool level)', () => {
  it('a low-trust caller does not recall RESTRICTED rows', async () => {
    seed({ title: 'recall secret', restricted: true });
    const res = await executeRecall({
      mode: 'recent', limit: 50, project: PROJECT, source: LOW_TRUST,
      includeGlobal: true, includeDecayed: true,
    } as Parameters<typeof executeRecall>[0]);
    expect((res.memories ?? []).some((m) => m.sensitivityLevel === 'RESTRICTED')).toBe(false);
  });

  it('the owner recalls their own rows', async () => {
    const id = seed({ title: 'recall own note' });
    const res = await executeRecall({
      mode: 'recent', limit: 50, project: PROJECT, source: OWNER,
      includeGlobal: true, includeDecayed: true,
    } as Parameters<typeof executeRecall>[0]);
    expect((res.memories ?? []).some((m) => m.id === id)).toBe(true);
  });
});

describe('read-guard invariants (regression canaries)', () => {
  it('trust assumptions the security cases rest on hold', () => {
    expect(scoreSource(LOW_TRUST).score).toBeLessThan(0.5);
    expect(scoreSource(OWNER).score).toBeGreaterThanOrEqual(0.7);
  });

  it('NO-REGRESSION: a high-trust NON-owner still reads other-source INTERNAL memories (read-all tier)', () => {
    const id = seed({ title: 'shared internal note' }); // owned by cli:owner-cli
    const highNonOwner: DefenceSource = { type: 'cli', identifier: 'other-cli' }; // 0.9, not the owner
    const res = executeGetMemory({ id, source: highNonOwner });
    expect(res.success).toBe(true);
    expect(res.memory?.id).toBe(id);
  });

  it('quarantined (trust 0) rows are invisible via get_memory even to the owner', () => {
    const id = seed({ title: 'pending review note' });
    getDatabase().prepare(`UPDATE memories SET trust_score = 0 WHERE id = ?`).run(id);
    const res = executeGetMemory({ id, source: OWNER });
    expect(res.success).toBe(false);
  });

  it('quarantined (trust 0) rows are excluded from a bulk export even for the owner', () => {
    const id = seed({ title: 'quarantined export note' });
    getDatabase().prepare(`UPDATE memories SET trust_score = 0 WHERE id = ?`).run(id);
    const res = executeExport({ project: PROJECT, source: OWNER });
    expect(res.data ?? '').not.toContain('quarantined export note');
  });
});

describe('end-to-end shipping path (resolveToolSource composed with the guard)', () => {
  afterEach(() => {
    delete process.env.CLAUDE_CODE_ENTRYPOINT;
  });

  it('a subagent (env-resolved low-trust source) is denied a RESTRICTED get_memory', () => {
    const id = seed({ title: 'e2e restricted', restricted: true });
    process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent'; // env ceiling => agent-spawned (0.3)
    const source = resolveToolSource(undefined, { toolName: 'get_memory', project: PROJECT });
    const res = executeGetMemory({ id, source });
    expect(res.success).toBe(false);
  });

  it('a spoofed declared user:direct is clamped to the env ceiling and still denied RESTRICTED', () => {
    const id = seed({ title: 'e2e spoof restricted', restricted: true });
    process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';
    // Caller lies and claims user:direct (1.0) — resolveToolSource must clamp it
    // down to the env ceiling so the escalation doesn't grant RESTRICTED access.
    const source = resolveToolSource({ type: 'user', identifier: 'direct' }, { toolName: 'get_memory', project: PROJECT });
    const res = executeGetMemory({ id, source });
    expect(res.success).toBe(false);
  });
});

describe('export_memories read ACL', () => {
  it('excludes RESTRICTED rows from a low-trust bulk export but includes them for the owner', () => {
    seed({ title: 'export secret', restricted: true });
    seed({ title: 'export normal' });

    const low = executeExport({ project: PROJECT, source: LOW_TRUST });
    expect(low.success).toBe(true);
    expect(low.data ?? '').not.toContain('export secret'); // RESTRICTED never dumped to low-trust

    const owner = executeExport({ project: PROJECT, source: OWNER });
    expect(owner.data ?? '').toContain('export secret'); // owner gets the full backup
  });
});
