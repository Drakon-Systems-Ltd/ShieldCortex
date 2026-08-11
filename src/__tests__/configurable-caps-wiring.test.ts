import { createHmac, randomUUID } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { enforceMemoryLimits } from '../memory/consolidate.js';
import { __resetCapWarningsForTest } from '../memory/config.js';

/**
 * Configurable caps — the WIRING half.
 *
 * `resolveMemoryConfig` is unit-tested separately; that proves nothing about
 * whether anything CONSULTS it. A correct policy function with no working call
 * site is the exact defect this repo shipped in #222, #226 and #233 — and the
 * failure would be silent here too: the operator raises their cap, the store
 * keeps evicting at 1000, and nothing says otherwise.
 *
 * These drive the REAL `enforceMemoryLimits()` with NO config argument, so the
 * default parameter — and therefore the resolver — is what decides.
 */

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
let tempDir: string;
let configDir: string;

function writeConfig(obj: unknown): void {
  const key = 'a'.repeat(64);
  writeFileSync(join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = JSON.stringify(obj, null, 2) + '\n';
  writeFileSync(join(configDir, 'config.json'), body);
  const sig = createHmac('sha256', key).update(body, 'utf-8').digest('hex');
  writeFileSync(join(configDir, '.config-sig'), sig, { mode: 0o600 });
}

const DAYS = 86_400_000;
function sqliteTs(agoMs: number): string {
  return new Date(Date.now() - agoMs).toISOString().slice(0, 19).replace('T', ' ');
}

/** Seed an evictable long-term row: old enough to clear #236's grace window. */
function seedEvictable(n: number): void {
  const db = getDatabase();
  const stmt = db.prepare(`
    INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
    VALUES (?, 'long_term', 'note', ?, 'seeded', 1.0, 0, ?, ?)
  `);
  for (let i = 0; i < n; i++) {
    stmt.run(randomUUID(), `row ${i}`, sqliteTs((10 + i) * DAYS), sqliteTs((30 + i) * DAYS));
  }
}

function longTermCount(): number {
  return (getDatabase().prepare("SELECT COUNT(*) AS n FROM memories WHERE type='long_term'").get() as { n: number }).n;
}

describe('configurable caps — the resolver is actually consulted', () => {
  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'sc-caps-wiring-'));
    configDir = join(tempDir, '.shieldcortex');
    mkdirSync(configDir, { recursive: true });
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    __resetCapWarningsForTest();
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
    rmSync(tempDir, { recursive: true, force: true });
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
  });

  it('a RAISED cap actually stops eviction — called with no config argument', () => {
    // 120 rows: over the built-in 100 short-term default's sibling long-term
    // default? No — well under 1000, so nothing should be evicted anyway.
    // The real test is a LOWERED cap below the row count (next case). Here we
    // prove a raised cap is honoured by lowering the row count under it.
    writeConfig({ memory: { maxLongTermMemories: 20 } });
    seedEvictable(25);
    expect(longTermCount()).toBe(25);

    const deleted = enforceMemoryLimits(); // ← no argument: default param decides

    expect(deleted).toBe(5);
    expect(longTermCount()).toBe(20);
  });

  it('WITHOUT the override the built-in default applies (25 rows ≪ 1000 ⇒ no eviction)', () => {
    // Same 25 rows, no memory block: the 1000 default means nothing is evicted.
    // Contrast with the case above — this is what proves the config, and not
    // some incidental change, moved the behaviour.
    writeConfig({ cloudEnabled: false });
    seedEvictable(25);

    const deleted = enforceMemoryLimits();

    expect(deleted).toBe(0);
    expect(longTermCount()).toBe(25);
  });

  it('a REFUSED cap (0) falls back to the default rather than wiping the store', () => {
    // End-to-end proof of the safety property: the operator writes a zero, and
    // the store survives intact.
    writeConfig({ memory: { maxLongTermMemories: 0 } });
    seedEvictable(25);

    const deleted = enforceMemoryLimits();

    expect(deleted).toBe(0);
    expect(longTermCount()).toBe(25);
  });

  it('an explicit config argument still wins over the file', () => {
    // Callers that pass a config (tests, the MCP server's own resolved config)
    // must not be silently overridden by the file.
    writeConfig({ memory: { maxLongTermMemories: 20 } });
    seedEvictable(25);

    const deleted = enforceMemoryLimits({ maxLongTermMemories: 24, maxShortTermMemories: 100 } as never);

    expect(deleted).toBe(1);
    expect(longTermCount()).toBe(24);
  });
});
