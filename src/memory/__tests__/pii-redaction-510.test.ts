/**
 * #510 (SC-11) — PII must be redacted on memory WRITE, not just flagged at
 * audit time. Repro from the 15 Sep 2026 adversarial run: a record holding a
 * UK National Insurance number + salary + email + phone was stored verbatim.
 *
 * All values here are synthetic (HMRC's invalid "QQ" NI prefix, the retired
 * SSA specimen SSN, Ofcom drama-reserved phone numbers, example.com).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { PII_KINDS, detectPII, hasRedactionToken, redactForPersistence, redactPII } from '../../defence/sensitivity/pii.js';
import { classifyContent } from '../../defence/sensitivity/classifier.js';

const user = { type: 'user' as const, identifier: 'pii-510-test' };

describe('#510 store funnel redacts PII on write', () => {
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

  it('SC-11 repro: NI + salary + email + phone are not stored in plaintext', async () => {
    const { addMemory, getMemoryById } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const created = addMemory({
      title: 'customer ni',
      content: 'Customer Pat Example, National Insurance QQ123456C, salary 55000, email pat@example.com phone 07700900123',
    }, undefined, user);

    const row = getDatabase()
      .prepare('SELECT title, content, sensitivity_level FROM memories WHERE id = ?')
      .get(created.id) as { title: string; content: string; sensitivity_level: string };
    for (const plaintext of ['QQ123456C', '55000', 'pat@example.com', '07700900123']) {
      expect(row.content).not.toContain(plaintext);
    }
    expect(row.content).toContain('[REDACTED:ni-number]');
    expect(row.content).toContain('[REDACTED:salary]');
    expect(row.content).toContain('[REDACTED:email]');
    expect(row.content).toContain('[REDACTED:phone]');
    // Non-PII context survives so the memory keeps its value.
    expect(row.content).toContain('Customer Pat Example');
    expect(row.sensitivity_level).toBe('CONFIDENTIAL');
    // The returned object and the FTS index carry the redacted text too.
    expect(getMemoryById(created.id)?.content).toBe(row.content);
    const fts = getDatabase()
      .prepare("SELECT COUNT(*) AS n FROM memories_fts WHERE memories_fts MATCH 'QQ123456C'")
      .get() as { n: number };
    expect(fts.n).toBe(0);
  });

  it('redacts PII carried in the title', async () => {
    const { addMemory } = await import('../store.js');
    const created = addMemory({
      title: 'Payroll note NI QQ 12 34 56 C',
      content: 'Payroll record for the new starter was filed on time.',
    }, undefined, user);
    expect(created.title).not.toContain('QQ 12 34 56 C');
    expect(created.title).toContain('[REDACTED:ni-number]');
  });

  it('redacts PII introduced by updateMemory', async () => {
    const { addMemory, updateMemory } = await import('../store.js');
    const created = addMemory({ title: 'Starter', content: 'New starter joins the finance team.' }, undefined, user);
    const updated = updateMemory(created.id, { content: 'New starter UTR 12345 67890, salary £48,500 per year.' });
    expect(updated?.content).not.toContain('12345 67890');
    expect(updated?.content).not.toContain('48,500');
  });

  it('repeat update with identical raw input does not write the raw text', async () => {
    const { addMemory, updateMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const created = addMemory({ title: 'Pay', content: 'salary 55000' }, undefined, user);
    expect(created.content).not.toContain('55000');
    updateMemory(created.id, { title: 'Pay', content: 'salary 55000' });
    const row = getDatabase()
      .prepare('SELECT title, content, content_hash FROM memories WHERE id = ?')
      .get(created.id) as { title: string; content: string; content_hash: string };
    expect(row.content).toBe('salary [REDACTED:salary]');
    const fts = getDatabase()
      .prepare("SELECT COUNT(*) AS n FROM memories_fts WHERE memories_fts MATCH '55000'")
      .get() as { n: number };
    expect(fts.n).toBe(0);
  });

  it('redacts tags and metadata strings, keeping JSON structure', async () => {
    const { addMemory, updateMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const created = addMemory({
      title: 'Starter pack',
      content: 'Onboarding paperwork was filed.',
      tags: ['hr', 'NI QQ123456C'],
      metadata: { salary: 55000, nested: { note: 'SSN 078-05-1120', keep: 'plain text' } },
    }, undefined, user);
    const read = () => getDatabase()
      .prepare('SELECT tags, metadata FROM memories WHERE id = ?')
      .get(created.id) as { tags: string; metadata: string };

    let row = read();
    expect(row.tags).not.toContain('QQ123456C');
    expect(JSON.parse(row.tags)).toEqual(['hr', 'NI [REDACTED:ni-number]']);
    expect(row.metadata).not.toContain('55000');
    expect(row.metadata).not.toContain('078-05-1120');
    expect(JSON.parse(row.metadata).nested.keep).toBe('plain text');

    updateMemory(created.id, { tags: ['hr', 'NINO QQ654321A'] });
    row = read();
    expect(row.tags).not.toContain('QQ654321A');
    expect(Array.isArray(JSON.parse(row.tags))).toBe(true);
  });

  it('content_hash of a redacted row is not the hash of the raw identifier text', async () => {
    const { addMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { createContentHash } = await import('../../defence/audit/logger.js');
    const raw = 'NI QQ123456C';
    const created = addMemory({ title: 'Hash oracle', content: raw }, undefined, user);
    const row = getDatabase()
      .prepare('SELECT content_hash FROM memories WHERE id = ?')
      .get(created.id) as { content_hash: string };
    expect(row.content_hash).not.toBe(createContentHash(raw));
  });

  it('audit content_hash is over the redacted text for PII, byte-identical otherwise', async () => {
    const { addMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { createContentHash } = await import('../../defence/audit/logger.js');
    const hashes = () => (getDatabase().prepare('SELECT content_hash FROM defence_audit').all() as Array<{ content_hash: string }>)
      .map(r => r.content_hash);

    addMemory({ title: 'Pay review', content: 'salary 55000' }, undefined, user);
    expect(hashes()).not.toContain(createContentHash('salary 55000'));
    expect(hashes()).toContain(createContentHash('salary [REDACTED:salary]'));

    const plain = 'The deploy script lives in scripts/deploy.sh';
    addMemory({ title: 'Deploy note', content: plain }, undefined, user);
    expect(hashes()).toContain(createContentHash(plain));
  });

  it('an identifier found only in metadata still raises the row to CONFIDENTIAL', async () => {
    const { addMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const created = addMemory({ title: 'Supplier record', content: 'Details are in the metadata.', metadata: { utr: 1234567890 } }, undefined, user);
    const row = getDatabase()
      .prepare('SELECT metadata, sensitivity_level FROM memories WHERE id = ?')
      .get(created.id) as { metadata: string; sensitivity_level: string };
    expect(JSON.parse(row.metadata)).toEqual({ utr: '[REDACTED:tax-id]' });
    expect(row.sensitivity_level).toBe('CONFIDENTIAL');
  });

  it('leaves a contact-only memory intact (labelled, not redacted)', async () => {
    const { addMemory } = await import('../store.js');
    const content = 'Vendor support is support@example.com, escalate by phone on 020 7946 0958.';
    const created = addMemory({ title: 'Vendor contact', content }, undefined, user);
    expect(created.content).toBe(content);
    expect(created.sensitivityLevel).toBe('CONFIDENTIAL');
  });

  it('SHIELDCORTEX_PII_REDACTION=off stores verbatim but still labels', async () => {
    process.env.SHIELDCORTEX_PII_REDACTION = 'off';
    const { addMemory } = await import('../store.js');
    const created = addMemory({
      title: 'Own record',
      content: 'My National Insurance number is QQ123456C.',
    }, undefined, user);
    expect(created.content).toContain('QQ123456C');
    expect(created.sensitivityLevel).toBe('CONFIDENTIAL');
  });
});

describe('#510 detector — formats', () => {
  const kinds = (text: string) => detectPII(text).map(f => f.kind).sort();

  it('UK National Insurance number, spaced and unspaced', () => {
    expect(kinds('NINO QQ123456C on file')).toEqual(['ni-number']);
    expect(kinds('ni: QQ 12 34 56 C')).toEqual(['ni-number']);
  });

  it('US SSN — dashed, and undashed only with context', () => {
    expect(kinds('SSN 078-05-1120')).toEqual(['ssn']);
    expect(kinds('social security number: 078051120')).toEqual(['ssn']);
    expect(kinds('build 078051120 passed')).toEqual([]);
  });

  it('tax identifiers need a label (UTR, EIN, TIN, tax id)', () => {
    expect(kinds('UTR 12345 67890')).toEqual(['tax-id']);
    expect(kinds('Unique Taxpayer Reference: 1234567890')).toEqual(['tax-id']);
    expect(kinds('EIN 12-3456789')).toEqual(['tax-id']);
    expect(kinds('tax id = 123456789')).toEqual(['tax-id']);
  });

  it('salary figures need salary context', () => {
    expect(kinds('salary 55000')).toEqual(['salary']);
    expect(kinds('Her salary is £48,500 per annum')).toEqual(['salary']);
    expect(kinds('compensation: $120k')).toEqual(['salary']);
    expect(kinds('annual wage of €39.500')).toEqual(['salary']);
  });

  it('contact details ride along only with an identifier', () => {
    expect(redactPII('email pat@example.com phone 07700900123').redacted).toBe(false);
    const r = redactPII('NI QQ123456C, email pat@example.com, tel +44 7700 900123, cell (555) 010-0199');
    expect(r.text).toBe('NI [REDACTED:ni-number], email [REDACTED:email], tel [REDACTED:phone], cell [REDACTED:phone]');
    expect(r.kinds).toEqual(['email', 'ni-number', 'phone']);
  });

  it('is idempotent', () => {
    const once = redactPII('NI QQ123456C salary 55000').text;
    expect(redactPII(once).text).toBe(once);
  });

  it('classifier raises identifier-bearing content to CONFIDENTIAL with pii labels', () => {
    const c = classifyContent('National Insurance QQ123456C, salary 55000', 'note');
    expect(c.level).toBe('CONFIDENTIAL');
    expect(c.detectedPatterns).toEqual(expect.arrayContaining(['pii:ni-number', 'pii:salary']));
  });
});

describe('#510 detector — evasions', () => {
  const evasions: Array<[string, string]> = [
    ['fullwidth digits', 'NI QQ１２３４５６C'],
    ['Arabic-Indic digits', 'salary ٥٥٠٠٠'],
    ['zero-width split', 'NI QQ12​34‍56C'],
    ['Unicode dashes', 'SSN 078‑05–1120'],
    ['dotted SSN with a label', 'ssn 078.05.1120'],
    ['double-spaced NI', 'NINO QQ  12  34  56  C'],
  ];
  it.each(evasions)('%s', (_name, text) => {
    const result = redactPII(text);
    expect(result.redacted).toBe(true);
    expect(result.text).not.toMatch(/[0-9０-９٠-٩]{2}/);
  });

  it('replaces the span in the ORIGINAL text and keeps the rest byte-for-byte', () => {
    expect(redactPII('café — NI QQ１２３４５６C — naïve').text).toBe('café — NI [REDACTED:ni-number] — naïve');
  });
});

describe('#510 redactForPersistence', () => {
  it('an identifier in any field takes contacts in every field', () => {
    const { fields, redacted, kinds } = redactForPersistence({
      title: 'Contact pat@example.com',
      content: 'Nothing sensitive here.',
      tags: ['NI QQ123456C'],
      metadata: '{"phone":"07700900123","count":3}',
    });
    expect(redacted).toBe(true);
    expect(fields.title).toBe('Contact [REDACTED:email]');
    expect(fields.tags).toEqual(['NI [REDACTED:ni-number]']);
    expect(JSON.parse(fields.metadata as string)).toEqual({ phone: '[REDACTED:phone]', count: 3 });
    expect(kinds).toEqual(['email', 'ni-number', 'phone']);
  });

  it('survives hostile metadata: deep nesting stays valid and scanned', () => {
    let deep: unknown = 'NI QQ123456C';
    for (let i = 0; i < 40; i++) deep = { child: deep };
    const out = JSON.stringify(redactForPersistence({ metadata: deep }).fields.metadata);
    expect(out).not.toContain('QQ123456C');
  });

  const nest = (levels: number, leaf: unknown): unknown => (levels === 0 ? leaf : { child: nest(levels - 1, leaf) });

  it('fails SAFE at the depth bound: the unscanned subtree is replaced, never passed through', () => {
    const result = redactForPersistence({ metadata: nest(8, { salary: 55000 }) });
    const out = JSON.stringify(result.fields.metadata);
    expect(out).not.toContain('55000');
    expect(out).toContain('"[REDACTED:unscanned]"');
    expect(JSON.parse(out)).toBeTruthy();
    expect(result.redacted).toBe(true); // callers raise a redacted row to CONFIDENTIAL
    expect(result.kinds).toEqual(['unscanned']);
    // One level shallower is scanned normally.
    expect(JSON.stringify(redactForPersistence({ metadata: nest(6, { salary: 55000 }) }).fields.metadata))
      .toContain('"salary":"[REDACTED:salary]"');
  });

  it('fails SAFE when the size budget runs out', () => {
    const metadata = { filler: Array.from({ length: 5001 }, () => ({})), late: { salary: 55000 } };
    const result = redactForPersistence({ metadata });
    expect((result.fields.metadata as { late: unknown }).late).toBe('[REDACTED:unscanned]');
    expect(JSON.stringify(result.fields.metadata)).not.toContain('55000');
    expect(result.redacted).toBe(true);
  });

  it('keeps Date, Buffer, Map and Set intact while redacting around them', () => {
    const when = new Date('2026-09-20T10:00:00.000Z');
    const blob = Buffer.from([0, 1, 2, 250]);
    const { fields } = redactForPersistence({
      metadata: { when, blob, lookup: new Map<string, unknown>([['utr', 1234567890], ['colour', 'red']]), seen: new Set(['a', 'b']), note: 'NI QQ123456C' },
    });
    const out = fields.metadata as { when: Date; blob: Buffer; lookup: Map<string, unknown>; seen: Set<string>; note: string };
    expect(out.when).toBeInstanceOf(Date);
    expect(out.when.getTime()).toBe(when.getTime());
    expect(JSON.stringify({ when: out.when })).toBe(JSON.stringify({ when }));
    expect(Buffer.isBuffer(out.blob)).toBe(true);
    expect([...out.blob]).toEqual([0, 1, 2, 250]);
    expect([...out.lookup]).toEqual([['utr', '[REDACTED:tax-id]'], ['colour', 'red']]);
    expect([...out.seen]).toEqual(['a', 'b']);
    expect(out.note).toBe('NI [REDACTED:ni-number]');
  });

  it('a key that names an identifier redacts its value whatever the type', () => {
    const { fields, kinds } = redactForPersistence({
      metadata: { utr: 1234567890, ssn: 78051120, Tax_ID: '12 of 2026', 'national-insurance': 'qq123456c', pay: 'weekly', wage: 31.5, count: 3 },
    });
    expect(fields.metadata).toEqual({
      utr: '[REDACTED:tax-id]',
      ssn: '[REDACTED:ssn]',
      Tax_ID: '[REDACTED:tax-id]',
      'national-insurance': '[REDACTED:ni-number]',
      pay: 'weekly',
      wage: '[REDACTED:salary]',
      count: 3,
    });
    expect(kinds).toEqual(['ni-number', 'salary', 'ssn', 'tax-id']);
    // Already-redacted input is left alone.
    expect(redactForPersistence({ metadata: { utr: '[REDACTED:tax-id]' } }).redacted).toBe(false);
  });

  it('a redaction token in the input does not exempt a value under an identifier key', () => {
    const { fields, redacted } = redactForPersistence({
      metadata: { utr: '[REDACTED:salary] 1234567890', nino: 'see [REDACTED:email] ref 4471' },
    });
    expect(fields.metadata).toEqual({ utr: '[REDACTED:tax-id]', nino: '[REDACTED:ni-number]' });
    expect(redacted).toBe(true);
  });

  it('binary under an identifier key is redacted whole; elsewhere it passes through', () => {
    const blob = Buffer.from('1234567890');
    const { fields } = redactForPersistence({
      metadata: { utr: Buffer.from('1234567890'), ssn: new Uint8Array([7, 8, 0, 5]), ni: new ArrayBuffer(4), blob },
    });
    const out = fields.metadata as Record<string, unknown>;
    expect(out.utr).toBe('[REDACTED:tax-id]');
    expect(out.ssn).toBe('[REDACTED:ssn]');
    expect(out.ni).toBe('[REDACTED:ni-number]');
    expect(out.blob).toBe(blob);
  });

  it('an identifier key is not inherited into descriptor children', () => {
    const { fields } = redactForPersistence({
      metadata: {
        salary: { amount: 55000, year: 2026, currency: 'GBP', Period: 12, history: [41000, { amount: 48000, updated: 2025 }] },
      },
    });
    expect(fields.metadata).toEqual({
      salary: {
        amount: '[REDACTED:salary]',
        year: 2026,
        currency: 'GBP',
        Period: 12,
        history: ['[REDACTED:salary]', { amount: '[REDACTED:salary]', updated: 2025 }],
      },
    });
  });

  it('look-alike keys are not identifier keys', () => {
    const metadata = { pay_period: 12, payload: 'v2 chunk 7', display: 1080, einstein: 1879, nino_checked: true, salary_band: 'B' };
    const result = redactForPersistence({ metadata });
    expect(result.redacted).toBe(false);
    expect(result.fields.metadata).toEqual(metadata);
  });
});

describe('#510 review round 5: identifiers held outside the field being written', () => {
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

  it('a contact added by a later update is redacted beside an already-redacted identifier', async () => {
    const { addMemory, updateMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const created = addMemory({ title: 'staff pay', content: 'Pat Example salary 55000' }, undefined, user);
    updateMemory(created.id, { metadata: { contact: 'pat@example.com' } });

    const row = getDatabase()
      .prepare('SELECT content, metadata FROM memories WHERE id = ?')
      .get(created.id) as { content: string; metadata: string };
    expect(row.content).toContain('[REDACTED:salary]');
    expect(row.metadata).not.toContain('pat@example.com');
    expect(row.metadata).toContain('[REDACTED:email]');
  });

  it('an identifier token marks the record, and still exempts nothing', () => {
    const result = redactForPersistence({ content: 'pay [REDACTED:salary], reach pat@example.com' });
    expect(result.redacted).toBe(true);
    expect(result.fields.content).toBe('pay [REDACTED:salary], reach [REDACTED:email]');
    // A contact-kind token alone is not an identifier.
    expect(redactForPersistence({ content: '[REDACTED:email] or pat@example.com' }).redacted).toBe(false);
  });

  it('the audit hash is never the raw-content hash when the identifier sits in metadata', async () => {
    const { addMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { createContentHash } = await import('../../defence/audit/logger.js');
    const content = 'reach pat@example.com about the review';
    const created = addMemory({ title: 'contact', content, metadata: { salary: 55000 } }, undefined, user);

    const db = getDatabase();
    const row = db.prepare('SELECT content FROM memories WHERE id = ?').get(created.id) as { content: string };
    expect(row.content).not.toContain('pat@example.com');
    const hashes = (db.prepare('SELECT content_hash FROM defence_audit').all() as Array<{ content_hash: string }>)
      .map(r => r.content_hash);
    expect(hashes.length).toBeGreaterThan(0);
    expect(hashes).not.toContain(createContentHash(content));
    expect(hashes).toContain(createContentHash(row.content));
  });
});

describe('#510 redaction tokens', () => {
  it('only a complete token of an emitted kind counts', () => {
    expect(PII_KINDS).toContain('unscanned');
    for (const kind of PII_KINDS) expect(hasRedactionToken(`x [REDACTED:${kind}] y`)).toBe(true);
    for (const spoof of ['[REDACTED:fake', '[REDACTED:fake]', '[REDACTED:', '[REDACTED:ssn', 'REDACTED:ssn]', '', null, undefined]) {
      expect(hasRedactionToken(spoof)).toBe(false);
    }
  });
});

describe('#510 accepted residuals (D1): unlabelled look-alikes stay, labelled ones go', () => {
  it.each([
    ['ab123456c', 'NI number ab123456c'],
    ['AB123456a', 'national insurance AB123456a'],
    ['078051120', 'SSN 078051120'],
  ])('%s', (bare, labelled) => {
    const unlabelled = `value ${bare} recorded`;
    expect(redactPII(unlabelled).text).toBe(unlabelled);
    expect(redactPII(labelled).text).not.toContain(bare);
  });
});

describe('#510 detector — false positives', () => {
  const clean = [
    'Order number 1234567890 shipped on 2026-09-15.',
    'Order #AB12345678 and invoice INV-2026-000451 were paid.',
    'commit 0d66439e9f1c2ab34de56f7890ab12cd34ef5678 on origin/main',
    'sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    'uuid 123e4567-e89b-12d3-a456-426614174000',
    'Upgraded shieldcortex@5.0.5 to v5.0.7, node v24.21.0.',
    'Ticket JIRA-123456 and issue #510 track the fix; see PROJ-20260915.',
    'Meeting on 15/09/2026 at 14:30, follow-up 2026-09-20T10:00:00Z.',
    'Pay the 3 outstanding invoices and pay attention to the 2026 budget.',
    'The pipeline paid off: latency fell from 55000 ms to 1200 ms.',
    'Part AB123456 rev C, model QX1234567.',
    'Tax year 2025-26 starts 6 April; the tax rate is 20 percent.',
    'ISBN 978-3-16-148410-0, tracking 9400111899223100012345.',
    'Order ref 123-45-6789 was refunded.',
    'Ticket number 078-05-1120 is closed.',
    'Fixture ID DF123456A loaded, slot QQ123456C free.',
    'Test vector 000-12-3456 and 666-12-3456 and 900-12-3456.',
  ];
  it.each(clean)('no identifier hit: %s', (text) => {
    expect(detectPII(text).filter(f => f.identifier)).toEqual([]);
    expect(redactPII(text).text).toBe(text);
  });
});
