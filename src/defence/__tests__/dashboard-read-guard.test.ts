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

  it('passes Date fields through untouched instead of collapsing them to {} (dashboard-v2 step 5 regression)', () => {
    // A Date has no enumerable own properties, so the generic-object
    // rebuild (`Object.keys(obj)` -> copy) used to turn every
    // createdAt/lastAccessed/updatedAt in every JSON response into `{}` —
    // reproduced here exactly as res.json() sees it: a real Date instance,
    // not an ISO string (JSON.stringify only stringifies it at the end).
    const createdAt = new Date('2026-06-01T12:00:00.000Z');
    const out = deepRedactRestrictedContent({
      memories: [{ ...mem({ sensitivityLevel: 'INTERNAL' }), createdAt, lastAccessed: createdAt }],
    }) as { memories: Array<{ createdAt: Date; lastAccessed: Date }> };
    expect(out.memories[0].createdAt).toBeInstanceOf(Date);
    expect(out.memories[0].createdAt.toISOString()).toBe('2026-06-01T12:00:00.000Z');
    expect(out.memories[0].lastAccessed).toBeInstanceOf(Date);
  });

  // ── Review-round regressions (dashboard-v2 build review, item 7) ──

  it('redacts EVERY occurrence of an aliased RESTRICTED row, not just the first (aliasing bypass)', () => {
    const row = mem({ sensitivityLevel: 'RESTRICTED', content: 'the-secret', title: `t ${SECRET}` });
    const out = deepRedactRestrictedContent({ a: row, b: row, list: [row, row] }) as {
      a: Memory; b: Memory; list: Memory[];
    };
    for (const m of [out.a, out.b, out.list[0], out.list[1]]) {
      expect(m.content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
      expect(m.title).not.toContain(SECRET);
      expect(m).not.toBe(row); // never the original object
    }
    expect(JSON.stringify(out)).not.toContain('the-secret');
    expect(row.content).toBe('the-secret'); // input untouched
  });

  it('normalises Dates to plain timestamps: decorated / subclassed toJSON / invalid cannot carry data', () => {
    const decorated = Object.assign(new Date('2026-06-01T12:00:00.000Z'), { smuggled: SECRET });
    class LeakyDate extends Date {
      toJSON() {
        return `leak ${SECRET}`;
      }
    }
    const leaky = new LeakyDate('2026-06-01T12:00:00.000Z');
    const invalid = new Date('not a date');
    const out = deepRedactRestrictedContent({ decorated, leaky, invalid }) as {
      decorated: Date & { smuggled?: string }; leaky: Date; invalid: Date;
    };
    expect(out.decorated).toBeInstanceOf(Date);
    expect(out.decorated.toISOString()).toBe('2026-06-01T12:00:00.000Z');
    expect(out.decorated.smuggled).toBeUndefined();
    expect(out.leaky.constructor).toBe(Date); // plain Date, subclass toJSON gone
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out.invalid).toBeInstanceOf(Date);
    expect(Number.isNaN(out.invalid.getTime())).toBe(true);
  });

  it('materialises Map → object and Set → array (then redacts), and passes binary views through', () => {
    const restricted = mem({ sensitivityLevel: 'RESTRICTED', content: 'in-map' });
    const buf = Buffer.from('bytes');
    const u8 = new Uint8Array([1, 2, 3]);
    const out = deepRedactRestrictedContent({
      m: new Map<string, unknown>([['row', restricted], ['n', 1]]),
      s: new Set<unknown>([restricted, 'x']),
      buf,
      u8,
    }) as { m: Record<string, unknown>; s: unknown[]; buf: Buffer; u8: Uint8Array };
    expect((out.m.row as Memory).content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
    expect(out.m.n).toBe(1);
    expect(Array.isArray(out.s)).toBe(true);
    expect((out.s[0] as Memory).content).toBe(RESTRICTED_CONTENT_PLACEHOLDER);
    expect(out.s[1]).toBe('x');
    expect(out.buf).toBe(buf);
    expect(out.u8).toBe(u8);
    expect(JSON.stringify(out)).not.toContain('in-map');
  });

  it('shares one sanitised copy for a repeated benign object and still breaks cycles inside arrays', () => {
    const shared = { title: `k ${SECRET}` };
    const arr: unknown[] = [shared];
    arr.push(arr);
    const out = deepRedactRestrictedContent({ x: shared, y: shared, arr }) as { x: { title: string }; y: { title: string }; arr: unknown[] };
    expect(out.x).toBe(out.y);
    expect(out.x.title).not.toContain(SECRET);
    expect(out.arr[1]).toBe(out.arr);
  });
});
