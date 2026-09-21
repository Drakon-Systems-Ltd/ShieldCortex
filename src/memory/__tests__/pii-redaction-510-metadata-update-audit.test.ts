/**
 * #510 / #534 follow-up — the metadata path must not leak what the content
 * path redacts. Independent repro (TARS, PR #534 review at b17678ce):
 *
 *   1. a record created with a salary is stored redacted;
 *   2. a later partial update adds a raw email under metadata;
 *   3. the stored metadata must carry [REDACTED:email], not the address, and
 *   4. defence_audit must never hold SHA-256 of the raw text — only of the
 *      redacted form the row actually stores.
 *
 * All values are synthetic (example.com, round salary figure).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const user = { type: 'user' as const, identifier: 'pii-510-metadata-update-test' };

describe('#510 metadata update path: redaction and audit hash', () => {
  beforeEach(async () => {
    const { closeDatabase, initDatabase } = await import('../../database/init.js');
    closeDatabase();
    initDatabase(':memory:');
    delete process.env.SHIELDCORTEX_PII_REDACTION;
  });

  afterEach(async () => {
    const { closeDatabase } = await import('../../database/init.js');
    closeDatabase();
    delete process.env.SHIELDCORTEX_PII_REDACTION;
  });

  it('a raw email added to metadata by a later update is stored redacted and never audit-hashed raw', async () => {
    const { addMemory, updateMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { createContentHash } = await import('../../defence/audit/logger.js');

    const created = addMemory({ title: 'Staff record', content: 'salary 55000' }, undefined, user);
    expect(created.content).toBe('salary [REDACTED:salary]');

    const updated = updateMemory(created.id, { metadata: { email: 'pat@example.com' } });
    expect(updated).not.toBeNull();

    const db = getDatabase();
    const row = db
      .prepare('SELECT content, metadata, sensitivity_level FROM memories WHERE id = ?')
      .get(created.id) as { content: string; metadata: string; sensitivity_level: string };

    // (a) the redaction applied to content is applied to metadata values too
    expect(row.content).toBe('salary [REDACTED:salary]');
    expect(row.metadata).not.toContain('pat@example.com');
    expect(JSON.parse(row.metadata)).toEqual({ email: '[REDACTED:email]' });
    expect(row.sensitivity_level).toBe('CONFIDENTIAL');

    // (b) no audit row hashes the raw text; the only content hash is of the stored form
    const hashes = (db.prepare('SELECT content_hash FROM defence_audit').all() as Array<{ content_hash: string | null }>)
      .map(r => r.content_hash)
      .filter((h): h is string => typeof h === 'string');
    expect(hashes.length).toBeGreaterThan(0);
    expect(hashes).not.toContain(createContentHash('pat@example.com'));
    expect(hashes).not.toContain(createContentHash('salary 55000'));
    expect(hashes).toContain(createContentHash('salary [REDACTED:salary]'));
  });

  it('a content update that becomes a contact beside a metadata identifier is audit-hashed over the redacted text', async () => {
    const { addMemory, updateMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { createContentHash } = await import('../../defence/audit/logger.js');

    const created = addMemory({ title: 'Other staff record', content: 'Details to follow.', metadata: { salary: 55000 } }, undefined, user);
    const stored = getDatabase().prepare('SELECT metadata FROM memories WHERE id = ?').get(created.id) as { metadata: string };
    expect(JSON.parse(stored.metadata)).toEqual({ salary: '[REDACTED:salary]' });

    const raw = 'reach pat@example.com about the review';
    updateMemory(created.id, { content: raw });

    const db = getDatabase();
    const row = db.prepare('SELECT content FROM memories WHERE id = ?').get(created.id) as { content: string };
    expect(row.content).toBe('reach [REDACTED:email] about the review');

    const hashes = (db.prepare('SELECT content_hash FROM defence_audit').all() as Array<{ content_hash: string | null }>)
      .map(r => r.content_hash)
      .filter((h): h is string => typeof h === 'string');
    expect(hashes).not.toContain(createContentHash(raw));
    expect(hashes).toContain(createContentHash(row.content));
  });
});
