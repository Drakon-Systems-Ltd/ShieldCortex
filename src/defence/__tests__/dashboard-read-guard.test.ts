/**
 * Dashboard read-guard: the HTTP visualization API (and its WS feed) is a
 * browser-rendered surface, so credential-class content must never be sent to it.
 *
 * Policy (redact, don't drop): RESTRICTED memories KEEP their row (so the owner
 * can see/manage them) but their `content` is replaced with a placeholder. Crucially
 * the secret can also live in the TITLE or METADATA (sensitivity is classified on
 * title+content together), so credential SPANS in those fields are masked too. The
 * dashboard does NOT drop low-trust rows — it is a management surface where the owner
 * triages them; only RESTRICTED *content* is withheld.
 */

import {
  redactRestrictedForDisplay,
  deepRedactRestrictedContent,
  RESTRICTED_CONTENT_PLACEHOLDER,
} from '../trust/read-guard.js';
import type { Memory } from '../../memory/types.js';

// A real GitHub-token-shaped secret (matches gh[ps]_[A-Za-z0-9_]{36,}).
const SECRET = 'ghp_' + 'A'.repeat(40);

function mem(overrides: Partial<Memory> = {}): Memory {
  return {
    id: 1,
    uuid: 'u1',
    type: 'long_term',
    category: 'note',
    title: 'A memory',
    content: 'the actual content',
    project: 'p',
    tags: [],
    salience: 0.5,
    accessCount: 0,
    lastAccessed: new Date(0),
    createdAt: new Date(0),
    updatedAt: new Date(0),
    decayedScore: 0.5,
    metadata: {},
    scope: 'project',
    transferable: false,
    status: 'active',
    pinned: false,
    reviewedAt: null,
    reviewedBy: null,
    sourceKind: 'user',
    captureMethod: 'manual',
    trustScore: 1,
    sensitivityLevel: 'INTERNAL',
    source: 'user:direct',
    cloudExcluded: false,
    memoryPurpose: 'project',
    memoryScope: 'private',
    ...overrides,
  } as Memory;
}

describe('redactRestrictedForDisplay', () => {
  it('masks the content of a RESTRICTED memory with the placeholder', () => {
    const out = redactRestrictedForDisplay([mem({ sensitivityLevel: 'RESTRICTED', content: 'AKIASECRETKEYHERE' })]);
    expect(out[0].content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
  });

  it('keeps a benign RESTRICTED title intact (manageability — title is a label, not the secret)', () => {
    const out = redactRestrictedForDisplay([
      mem({ id: 42, title: 'AWS deploy key', sensitivityLevel: 'RESTRICTED', content: 'secret' }),
    ]);
    expect(out[0].id).toBe(42);
    expect(out[0].title).toBe('AWS deploy key');
    expect(out[0].sensitivityLevel).toBe('RESTRICTED');
  });

  it('scrubs a credential SPAN in the title of a RESTRICTED memory (secret-in-title leak)', () => {
    const out = redactRestrictedForDisplay([mem({ title: `token ${SECRET}`, sensitivityLevel: 'RESTRICTED' })]);
    expect(out[0].title).not.toContain(SECRET);
    expect(out[0].title).toContain('[REDACTED]');
  });

  it('scrubs credential spans in string metadata values of a RESTRICTED memory', () => {
    const out = redactRestrictedForDisplay([
      mem({ sensitivityLevel: 'RESTRICTED', metadata: { note: `key is ${SECRET}`, count: 3 } }),
    ]);
    expect(JSON.stringify(out[0].metadata)).not.toContain(SECRET);
    expect((out[0].metadata as { count: number }).count).toBe(3);
  });

  it('leaves a benign non-RESTRICTED memory entirely untouched', () => {
    const out = redactRestrictedForDisplay([mem({ sensitivityLevel: 'INTERNAL', content: 'public-ish', title: 'a normal title' })]);
    expect(out[0].content).toBe('public-ish');
    expect(out[0].title).toBe('a normal title');
  });

  it('shows non-RESTRICTED content in full but still masks a credential span in its title (defensive)', () => {
    const out = redactRestrictedForDisplay([mem({ sensitivityLevel: 'INTERNAL', content: 'public-ish', title: `note ${SECRET}` })]);
    expect(out[0].content).toBe('public-ish');
    expect(out[0].title).not.toContain(SECRET);
    expect(out[0].title).toContain('[REDACTED]');
  });

  it('does not mutate the input memory', () => {
    const input = mem({ sensitivityLevel: 'RESTRICTED', content: 'original-secret', title: `t ${SECRET}` });
    redactRestrictedForDisplay([input]);
    expect(input.content).toBe('original-secret');
    expect(input.title).toBe(`t ${SECRET}`);
  });

  it('does NOT drop low-trust / trust-0 rows (management surface keeps them visible)', () => {
    const out = redactRestrictedForDisplay([mem({ id: 1, trustScore: 0 }), mem({ id: 2, trustScore: 0.3 })]);
    expect(out.map((m) => m.id)).toEqual([1, 2]);
  });
});

describe('deepRedactRestrictedContent (HTTP response interceptor core)', () => {
  it('redacts a RESTRICTED memory content at the top level', () => {
    const out = deepRedactRestrictedContent({ ...mem({ sensitivityLevel: 'RESTRICTED', content: 'secret' }) });
    expect((out as { content: string }).content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
  });

  it('scrubs a credential span in the title of a nested RESTRICTED object', () => {
    const out = deepRedactRestrictedContent({
      memories: [mem({ title: `prod ${SECRET}`, sensitivityLevel: 'RESTRICTED' })],
    }) as { memories: { title: string }[] };
    expect(out.memories[0].title).not.toContain(SECRET);
    expect(out.memories[0].title).toContain('[REDACTED]');
  });

  it('scrubs BARE title fields with no sensitivity label (contradictions / graph / recall surfaces)', () => {
    const out = deepRedactRestrictedContent({
      contradictions: [{ memoryAId: 1, memoryATitle: `key ${SECRET}`, memoryBTitle: 'benign label' }],
      memories: [{ id: 7, title: `entity ${SECRET}` }], // graph-style row: title only, no sensitivity/content
      data: { memoryId: 9, title: `deleted ${SECRET}` }, // memory_deleted event shape
    }) as {
      contradictions: { memoryATitle: string; memoryBTitle: string }[];
      memories: { title: string }[];
      data: { title: string };
    };
    expect(out.contradictions[0].memoryATitle).not.toContain(SECRET);
    expect(out.contradictions[0].memoryATitle).toContain('[REDACTED]');
    expect(out.contradictions[0].memoryBTitle).toBe('benign label');
    expect(out.memories[0].title).not.toContain(SECRET);
    expect(out.data.title).not.toContain(SECRET);
  });

  it('redacts memories nested in arrays (e.g. /api/memories { memories: [...] })', () => {
    const out = deepRedactRestrictedContent({
      memories: [mem({ id: 1, sensitivityLevel: 'RESTRICTED', content: 'sk_live_x' }), mem({ id: 2, content: 'fine' })],
    }) as { memories: { content: string }[] };
    expect(out.memories[0].content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
    expect(out.memories[1].content).toBe('fine');
  });

  it('redacts deeply nested memories (recall results[].memory, sessions[].memories[])', () => {
    const out = deepRedactRestrictedContent({
      results: [{ score: 1, memory: mem({ sensitivityLevel: 'RESTRICTED', content: 'token' }) }],
      sessions: [{ memories: [mem({ sensitivityLevel: 'RESTRICTED', content: 'aws-key' })] }],
    }) as { results: { memory: { content: string } }[]; sessions: { memories: { content: string }[] }[] };
    expect(out.results[0].memory.content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
    expect(out.sessions[0].memories[0].content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
  });

  it('also redacts snake_case rows (sensitivity_level)', () => {
    const out = deepRedactRestrictedContent({ rows: [{ id: 1, sensitivity_level: 'RESTRICTED', content: 'secret' }] }) as {
      rows: { content: string }[];
    };
    expect(out.rows[0].content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
  });

  it('leaves non-memory payloads untouched', () => {
    const payload = { count: 5, items: ['a', 'b'], pagination: { total: 10, hasMore: false }, nested: { ok: true } };
    expect(deepRedactRestrictedContent(payload)).toEqual(payload);
  });

  it('does not mutate the input', () => {
    const m = mem({ sensitivityLevel: 'RESTRICTED', content: 'original' });
    const payload = { memories: [m] };
    deepRedactRestrictedContent(payload);
    expect(m.content).toBe('original');
  });

  it('handles primitives, null, and strings without throwing', () => {
    expect(deepRedactRestrictedContent(null)).toBeNull();
    expect(deepRedactRestrictedContent('a string with content')).toBe('a string with content');
    expect(deepRedactRestrictedContent(42)).toBe(42);
  });

  it('is safe against circular references', () => {
    const obj: Record<string, unknown> = { sensitivityLevel: 'RESTRICTED', content: 'secret' };
    obj.self = obj;
    expect(() => deepRedactRestrictedContent(obj)).not.toThrow();
    expect((deepRedactRestrictedContent(obj) as { content: string }).content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
  });
});
