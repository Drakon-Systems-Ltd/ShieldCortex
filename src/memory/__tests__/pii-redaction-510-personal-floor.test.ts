/**
 * #510 floor × #718 PERSONAL tier (PR #722 review, B2).
 *
 * #510: a row that names an identifier never sits below CONFIDENTIAL.
 * #718 added PERSONAL between INTERNAL and CONFIDENTIAL; the three raise sites
 * (add stamp, update, enrich) only lifted PUBLIC/INTERNAL, so a PERSONAL row
 * that gained a UTR + salary stayed PERSONAL. One test per site.
 *
 * Identifier fixtures are the synthetic #510 ones (UTR 12345 67890,
 * salary £48,500, metadata utr 1234567890).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const user = { type: 'user' as const, identifier: 'pii-510-personal-floor' };
const PERSONAL_CONTENT = 'Surprise birthday trip for my wife in March';
const PII_510 = 'UTR 12345 67890, salary £48,500 per year.';

describe('#510 floor applies to PERSONAL rows (#722 B2)', () => {
  beforeEach(async () => {
    const { closeDatabase, initDatabase } = await import('../../database/init.js');
    closeDatabase();
    initDatabase(':memory:');
    delete process.env.SHIELDCORTEX_PII_REDACTION;
  });

  afterEach(async () => {
    const { closeDatabase } = await import('../../database/init.js');
    closeDatabase();
  });

  const levelOf = async (id: number) => {
    const { getDatabase } = await import('../../database/init.js');
    return (getDatabase().prepare('SELECT sensitivity_level FROM memories WHERE id = ?').get(id) as { sensitivity_level: string })
      .sensitivity_level;
  };

  it('fixture sanity: the personal note on its own is PERSONAL', async () => {
    const { addMemory } = await import('../store.js');
    const created = addMemory({ title: 'March plans', content: PERSONAL_CONTENT }, undefined, user);
    expect(await levelOf(created.id)).toBe('PERSONAL');
  });

  it('add: a PERSONAL-scanned row whose identifier sits only in metadata is stamped CONFIDENTIAL', async () => {
    const { addMemory } = await import('../store.js');
    const created = addMemory(
      { title: 'March plans', content: PERSONAL_CONTENT, metadata: { utr: 1234567890 } },
      undefined,
      user,
    );
    expect(await levelOf(created.id)).toBe('CONFIDENTIAL');
  });

  it('update: adding a UTR + salary to a PERSONAL row raises it to CONFIDENTIAL', async () => {
    const { addMemory, updateMemory } = await import('../store.js');
    const created = addMemory({ title: 'March plans', content: PERSONAL_CONTENT }, undefined, user);
    expect(await levelOf(created.id)).toBe('PERSONAL');
    const updated = updateMemory(created.id, { content: `${PERSONAL_CONTENT}. ${PII_510}` });
    expect(updated?.content).not.toContain('12345 67890');
    expect(await levelOf(created.id)).toBe('CONFIDENTIAL');
  });

  it('enrich: appending a UTR + salary to a PERSONAL row raises it to CONFIDENTIAL', async () => {
    const { addMemory } = await import('../store.js');
    const { enrichMemory } = await import('../lifecycle.js');
    const created = addMemory({ title: 'March plans', content: PERSONAL_CONTENT }, undefined, user);
    expect(await levelOf(created.id)).toBe('PERSONAL');
    const result = enrichMemory(created.id, `${PERSONAL_CONTENT} ${PII_510}`, 'search');
    expect(result.enriched).toBe(true);
    expect(await levelOf(created.id)).toBe('CONFIDENTIAL');
  });
});
