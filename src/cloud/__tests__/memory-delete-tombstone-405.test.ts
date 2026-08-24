/**
 * #405 — cloud deletion must not bypass privacy or transmit content.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import type { Memory } from '../../memory/types.js';

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;

function baseMemory(over: Partial<Memory> = {}): Memory {
  const now = new Date();
  return {
    id: 42,
    uuid: '11111111-1111-4111-8111-111111111111',
    type: 'fact',
    category: 'general',
    title: 'SECRET TITLE should never leave',
    content: 'SECRET BODY should never leave',
    project: 'demo',
    tags: ['secret-tag'],
    salience: 0.9,
    accessCount: 0,
    lastAccessed: now,
    createdAt: now,
    updatedAt: now,
    decayedScore: 0.9,
    metadata: { password: 'nope' },
    scope: 'project',
    transferable: false,
    status: 'active',
    pinned: false,
    reviewedAt: null,
    reviewedBy: null,
    sourceKind: 'user',
    captureMethod: 'manual',
    trustScore: 0.8,
    sensitivityLevel: 'INTERNAL',
    source: 'test',
    cloudExcluded: false,
    memoryPurpose: 'durable_fact',
    memoryScope: 'project',
    hostId: null,
    agentId: null,
    captureLayer: null,
    ...over,
  } as Memory;
}

describe('#405 cloud delete tombstone privacy', () => {
  let tempDir: string;
  let posted: unknown[];

  beforeEach(() => {
    jest.resetModules();
    posted = [];
    tempDir = mkdtempSync(join(tmpdir(), 'sc-405-'));
    const configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    writeFileSync(
      join(configDir, 'config.json'),
      JSON.stringify({
        cloudEnabled: true,
        cloudApiKey: 'test-key-not-real',
        cloudBaseUrl: 'https://cloud.test.invalid',
        cloudSyncExcludeSensitive: true,
      }),
      'utf8',
    );
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;

    // Mock fetch before importing modules under test
    // @ts-expect-error test mock
    global.fetch = jest.fn(async (_url: string, init?: { body?: string }) => {
      if (init?.body) posted.push(JSON.parse(init.body));
      return { ok: true } as Response;
    });
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
    // @ts-expect-error cleanup
    delete global.fetch;
  });

  it('buildMemoryDeleteTombstone strips title/content/tags/metadata', async () => {
    const { buildMemoryDeleteTombstone } = await import('../memory-sync.js');
    const t = buildMemoryDeleteTombstone(baseMemory());
    expect(t.external_id).toBe('11111111-1111-4111-8111-111111111111');
    expect(t.deleted_at).toBeTruthy();
    expect(t.title).toBe('');
    expect(t.content).toBe('');
    expect(t.tags).toEqual([]);
    expect(t.metadata).toEqual({});
    expect(JSON.stringify(t)).not.toMatch(/SECRET/);
    expect(JSON.stringify(t)).not.toMatch(/password/);
  });

  it('does not post when cloud_excluded', async () => {
    const { syncMemoryDeleteToCloud } = await import('../memory-sync.js');
    syncMemoryDeleteToCloud(baseMemory({ cloudExcluded: true, content: 'SECRET BODY' }));
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toHaveLength(0);
  });

  it('does not post CONFIDENTIAL under default excludeSensitive', async () => {
    const { syncMemoryDeleteToCloud } = await import('../memory-sync.js');
    syncMemoryDeleteToCloud(baseMemory({ sensitivityLevel: 'CONFIDENTIAL' }));
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toHaveLength(0);
  });

  it('does not post RESTRICTED under default excludeSensitive', async () => {
    const { syncMemoryDeleteToCloud } = await import('../memory-sync.js');
    syncMemoryDeleteToCloud(baseMemory({ sensitivityLevel: 'RESTRICTED' }));
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toHaveLength(0);
  });

  it('posts tombstone only for allowed INTERNAL record', async () => {
    const { syncMemoryDeleteToCloud } = await import('../memory-sync.js');
    syncMemoryDeleteToCloud(baseMemory({ sensitivityLevel: 'INTERNAL' }));
    await new Promise((r) => setTimeout(r, 30));
    expect(posted).toHaveLength(1);
    const body = JSON.stringify(posted[0]);
    expect(body).not.toMatch(/SECRET/);
    expect(body).not.toMatch(/password/);
    expect(body).not.toMatch(/secret-tag/);
    const mem = (posted[0] as { memories: Array<Record<string, unknown>> }).memories[0];
    expect(mem.title).toBe('');
    expect(mem.content).toBe('');
    expect(mem.deleted_at).toBeTruthy();
    expect(mem.external_id).toBe('11111111-1111-4111-8111-111111111111');
  });

  it('fail-closed when sensitivity missing', async () => {
    const { syncMemoryDeleteToCloud } = await import('../memory-sync.js');
    const m = baseMemory();
    // @ts-expect-error intentional
    delete m.sensitivityLevel;
    syncMemoryDeleteToCloud(m);
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toHaveLength(0);
  });

  it('fail-closed on blank sensitivity string', async () => {
    const { syncMemoryDeleteToCloud } = await import('../memory-sync.js');
    syncMemoryDeleteToCloud(baseMemory({ sensitivityLevel: '   ' }));
    await new Promise((r) => setTimeout(r, 20));
    expect(posted).toHaveLength(0);
  });
});
