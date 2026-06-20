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
import { executeGetMemory, executeGetRelated } from '../tools/recall.js';
import { executeGetContext, executeExport } from '../tools/context.js';
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

describe('get_context read ACL', () => {
  it('excludes a RESTRICTED memory from the context surfaced to a low-trust caller', async () => {
    seed({ title: 'context secret', restricted: true });
    const res = await executeGetContext({ project: PROJECT, format: 'raw', source: LOW_TRUST });
    expect(res.success).toBe(true);
    expect(res.context ?? '').not.toContain('context secret');
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
