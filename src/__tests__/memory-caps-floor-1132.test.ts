import fs from 'node:fs';
import path from 'node:path';
import { createHmac, randomUUID } from 'node:crypto';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { enforceMemoryLimits, fullCleanup } from '../memory/consolidate.js';
import { resolveMemoryConfig, __resetCapWarningsForTest } from '../memory/config.js';
import { DEFAULT_CONFIG } from '../memory/types.js';
import { runMemoryStatsCheck } from '../cli/doctor.js';
import { clearCloudConfigCache, readRawConfig, setCapacityConfig } from '../cloud/config.js';
import { LTM_CAP_MAX, STM_CAP_MAX } from '../cloud/capacity.js';

/**
 * #1132 (round 4): an unverified memory cap is clamped per key to
 * max(default, min(stored, setter maximum)).
 *
 * Every eviction here goes through the REAL `enforceMemoryLimits()` /
 * `fullCleanup()` with NO config argument, so the resolver behind the default
 * parameter decides. Seeded rows are older than #236's one-hour eviction grace
 * window, so a wrong cap shows up as real deletions rather than being masked.
 *
 * - A forged LOWER cap never resolves below the built-in default (#1125).
 * - An honest RAISED cap that is not embedded-signed (hand-written, legacy
 *   signed, or a setter-signed file whose `_sig` was stripped) is kept up to
 *   the setter maximum, so it does not evict on upgrade.
 * - An unverified raise is bounded by the setter maximum.
 * - The resolver never hands out the shared DEFAULT_CONFIG object.
 */

const originalDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const key = 'c'.repeat(64);
let root: string;
let configDir: string;

const DAYS = 86_400_000;
function sqliteTs(agoMs: number): string {
  return new Date(Date.now() - agoMs).toISOString().slice(0, 19).replace('T', ' ');
}

/** Seed rows old enough to clear the eviction grace window. */
function seedEvictable(n: number, type: 'long_term' | 'short_term' = 'long_term'): void {
  const stmt = getDatabase().prepare(`
    INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
    VALUES (?, ?, 'note', ?, 'seeded', 1.0, 0, ?, ?)
  `);
  for (let i = 0; i < n; i++) {
    stmt.run(randomUUID(), type, `${type} row ${i}`, sqliteTs((10 + i) * DAYS), sqliteTs((30 + i) * DAYS));
  }
}

function count(type: 'long_term' | 'short_term'): number {
  return (getDatabase().prepare('SELECT COUNT(*) AS n FROM memories WHERE type = ?').get(type) as { n: number }).n;
}

const configFile = () => path.join(configDir, 'config.json');
const legacySigFile = () => path.join(configDir, '.config-sig');

/** Unsigned file, no signature of any kind. */
function writeUnsigned(memory: unknown): void {
  fs.writeFileSync(configFile(), JSON.stringify({ memory }, null, 2) + '\n');
}

/** Pre-v4.32 shape: no embedded `_sig`, a `.config-sig` HMAC over the exact bytes. */
function writeLegacySigned(memory: unknown): void {
  const body = JSON.stringify({ memory }, null, 2) + '\n';
  fs.writeFileSync(path.join(configDir, '.integrity-key'), key);
  fs.writeFileSync(configFile(), body);
  fs.writeFileSync(legacySigFile(), createHmac('sha256', key).update(body).digest('hex'));
}

/** Current shape: embedded `_sig` over the canonical body. */
function writeEmbeddedSigned(memory: unknown): void {
  const data = { memory };
  const sig = createHmac('sha256', key).update(JSON.stringify(data, null, 2)).digest('hex');
  fs.writeFileSync(path.join(configDir, '.integrity-key'), key);
  fs.writeFileSync(configFile(), JSON.stringify({ ...data, _sig: sig }, null, 2) + '\n');
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(process.cwd(), '.sc-1132-'));
  configDir = path.join(root, 'config');
  fs.mkdirSync(configDir);
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  __resetCapWarningsForTest();
  clearCloudConfigCache();
  initDatabase(':memory:');
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  closeDatabase();
  jest.restoreAllMocks();
  clearCloudConfigCache();
  fs.rmSync(root, { recursive: true, force: true });
  if (originalDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = originalDir;
});

describe('#1132 unverified memory caps are clamped to [default, setter max]', () => {
  it('R1: a hand-written unsigned LTM 1200, adopted by an ordinary read, survives fullCleanup of 1100 rows', () => {
    writeUnsigned({ maxLongTermMemories: 1200 });
    readRawConfig();
    // The ordinary read adopted the file with a legacy-only signature.
    expect(fs.existsSync(legacySigFile())).toBe(true);
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(1200);
    seedEvictable(1100);

    const result = fullCleanup();

    expect(result.consolidation.evictedLongTerm).toBe(0);
    expect(count('long_term')).toBe(1100);
  });

  it('R2: a pre-v4.32 legacy-signed LTM 1200 evicts nothing', () => {
    writeLegacySigned({ maxLongTermMemories: 1200 });
    seedEvictable(1100);

    expect(enforceMemoryLimits()).toBe(0);
    expect(count('long_term')).toBe(1100);
  });

  it('R2b: a legacy-signed STM 250 evicts nothing from 200 STM rows', () => {
    writeLegacySigned({ maxShortTermMemories: 250 });
    seedEvictable(200, 'short_term');

    expect(enforceMemoryLimits()).toBe(0);
    expect(count('short_term')).toBe(200);
  });

  it('R3: a tampered lower cap (embedded-signed 1200 edited to 20) evicts only down to the default', () => {
    writeEmbeddedSigned({ maxLongTermMemories: 1200 });
    fs.writeFileSync(configFile(), fs.readFileSync(configFile(), 'utf8').replace('1200', '20'));
    seedEvictable(1100);

    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
    expect(enforceMemoryLimits()).toBe(1100 - DEFAULT_CONFIG.maxLongTermMemories);
    expect(count('long_term')).toBe(DEFAULT_CONFIG.maxLongTermMemories);
  });

  it('R3b: an unsigned lower cap (LTM 20, STM 10) evicts nothing below the defaults', () => {
    writeUnsigned({ maxLongTermMemories: 20, maxShortTermMemories: 10 });
    seedEvictable(900);
    seedEvictable(90, 'short_term');

    expect(enforceMemoryLimits()).toBe(0);
    expect(count('long_term')).toBe(900);
    expect(count('short_term')).toBe(90);
  });

  it('R4: stripping _sig from a setter-signed LTM 5000 (value unchanged) evicts nothing', () => {
    setCapacityConfig({ maxLongTermMemories: 5000 });
    const raw = JSON.parse(fs.readFileSync(configFile(), 'utf8')) as Record<string, unknown>;
    expect(typeof raw._sig).toBe('string');
    delete raw._sig;
    fs.writeFileSync(configFile(), JSON.stringify(raw, null, 2) + '\n');
    fs.rmSync(legacySigFile(), { force: true });
    clearCloudConfigCache();
    seedEvictable(1100);

    expect(resolveMemoryConfig().maxLongTermMemories).toBe(5000);
    expect(enforceMemoryLimits()).toBe(0);
    expect(count('long_term')).toBe(1100);
  });

  it('R5: an unverified raise is bounded by the setter maximum; a signed one is not', () => {
    writeUnsigned({ maxLongTermMemories: 1e9, maxShortTermMemories: 1e9 });
    const unverified = resolveMemoryConfig();
    expect([unverified.maxLongTermMemories, unverified.maxShortTermMemories]).toEqual([LTM_CAP_MAX, STM_CAP_MAX]);

    writeEmbeddedSigned({ maxLongTermMemories: 200_000 });
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(200_000);
  });

  it('R6: the resolver returns a fresh object, never the shared DEFAULT_CONFIG', () => {
    const snapshot = { ...DEFAULT_CONFIG };

    const absent = resolveMemoryConfig();
    expect(absent).not.toBe(DEFAULT_CONFIG);
    expect(absent).toEqual(DEFAULT_CONFIG);

    writeUnsigned({ maxLongTermMemories: 20 });
    const unverified = resolveMemoryConfig();
    expect(unverified).not.toBe(DEFAULT_CONFIG);

    // A caller that mutates its result (createServer sets dbPath) must not
    // write through to the shared default.
    absent.dbPath = '/nowhere/absent.db';
    unverified.dbPath = '/nowhere/unverified.db';
    expect(DEFAULT_CONFIG).toEqual(snapshot);
  });

  it('R7: Doctor reports a legacy-signed raised cap as not verified, not over its cap, and names the signing remedy', () => {
    writeLegacySigned({ maxLongTermMemories: 1200 });
    const dbPath = path.join(root, 'memories.db');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE memories (type TEXT)');
    const insert = db.prepare("INSERT INTO memories (type) VALUES ('long_term')");
    db.transaction(() => { for (let i = 0; i < 1100; i++) insert.run(); })();
    db.close();

    const row = runMemoryStatsCheck(dbPath);

    expect(row.status).toBe('warn');
    expect(row.message).toContain('stored caps not verified');
    expect(row.message).toContain('below the default');
    expect(row.message).not.toContain('over its cap');
    expect(row.fix).toContain('config --memory-cap');
  });
});
