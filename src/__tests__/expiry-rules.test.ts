/**
 * Expiry-rule regression test (Phase 9a).
 *
 * applyExpiryRules() built its WHERE clause against `createdAt` (camelCase),
 * but the memories column is `created_at` (snake_case). Every expiry-rule query
 * therefore threw `no such column: createdAt`, and the only caller (processDecay)
 * swallowed it in a silent catch — so configured expiry rules NEVER deleted
 * anything and never surfaced an error. This test pins down the contract:
 * an old memory matching a rule is deleted; a recent one survives.
 *
 * Harness: a fresh in-memory DB per test (so rows never leak) plus a real,
 * integrity-signed config file in a temp dir (so loadExpiryRules() reads a
 * genuine rule via readRawConfig — no module mock that would break the sync
 * imports store.ts pulls from cloud/config.js).
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { createHmac } from 'crypto';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { applyExpiryRules, type ExpiryRule } from '../memory/expiry.js';

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

interface MemorySeed {
  uuid: string;
  title: string;
  createdAt: string;
  category?: string;
  type?: 'short_term' | 'long_term' | 'episodic';
  salience?: number;
  tags?: string[];
}

function insertMemory(seed: MemorySeed): number {
  const db = getDatabase();
  const r = db.prepare(`
    INSERT INTO memories (uuid, type, category, title, content, salience, tags, created_at)
    VALUES (@uuid, @type, @category, @title, @content, @salience, @tags, @created_at)
  `).run({
    uuid: seed.uuid,
    type: seed.type ?? 'long_term',
    category: seed.category ?? 'note',
    title: seed.title,
    content: `content for ${seed.title}`,
    salience: seed.salience ?? 0.5,
    tags: JSON.stringify(seed.tags ?? []),
    created_at: seed.createdAt,
  });
  return Number(r.lastInsertRowid);
}

function memoryExists(id: number): boolean {
  const db = getDatabase();
  return (db.prepare('SELECT COUNT(*) AS c FROM memories WHERE id = ?').get(id) as { c: number }).c > 0;
}

/**
 * Persist real expiry rules into an integrity-signed config the way the legacy
 * writer did: config.json with no embedded _sig plus a .config-sig signed over
 * the exact bytes with a known integrity key. This makes loadExpiryRules()
 * read a genuine rule through readRawConfig() without tripping tamper mode.
 */
function writeExpiryRules(configDir: string, rules: ExpiryRule[]): void {
  const key = 'a'.repeat(64);
  writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = JSON.stringify({ expiryRules: rules }, null, 2) + '\n';
  writeFileSync(join(configDir, 'config.json'), body);
  const sig = createHmac('sha256', key).update(body, 'utf-8').digest('hex');
  writeFileSync(join(configDir, '.config-sig'), sig, { mode: 0o600 });
}

describe('expiry rules (Phase 9a)', () => {
  let tempDir: string;
  let configDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'sc-expiry-rules-'));
    configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
    rmSync(tempDir, { recursive: true, force: true });
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
  });

  it('deletes a memory older than the rule and keeps a recent one', () => {
    const oldId = insertMemory({ uuid: 'old-1', title: 'ancient note', createdAt: daysAgo(120) });
    const recentId = insertMemory({ uuid: 'recent-1', title: 'fresh note', createdAt: daysAgo(1) });

    // Rule: expire anything older than 30 days.
    writeExpiryRules(configDir, [{ maxAgeDays: 30 }]);

    const result = applyExpiryRules();

    expect(result.deleted).toBe(1);
    expect(memoryExists(oldId)).toBe(false);
    expect(memoryExists(recentId)).toBe(true);
  });

  it('respects category-scoped rules (only matching category expires)', () => {
    const oldTodo = insertMemory({ uuid: 'old-todo', title: 'old todo', createdAt: daysAgo(90), category: 'todo' });
    const oldNote = insertMemory({ uuid: 'old-note', title: 'old note', createdAt: daysAgo(90), category: 'note' });

    writeExpiryRules(configDir, [{ maxAgeDays: 30, category: 'todo' }]);

    const result = applyExpiryRules();

    expect(result.deleted).toBe(1);
    expect(memoryExists(oldTodo)).toBe(false);
    expect(memoryExists(oldNote)).toBe(true);
  });

  it('protects high-salience memories even when they match an expiry rule', () => {
    const precious = insertMemory({ uuid: 'precious', title: 'important', createdAt: daysAgo(120), salience: 0.95 });

    writeExpiryRules(configDir, [{ maxAgeDays: 30 }]);

    const result = applyExpiryRules();

    expect(result.deleted).toBe(0);
    expect(result.protected).toBe(1);
    expect(memoryExists(precious)).toBe(true);
  });
});
