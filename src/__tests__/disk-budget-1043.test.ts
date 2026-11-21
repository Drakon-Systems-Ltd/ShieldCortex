/**
 * #1043: configurable disk budget (storage.diskBudgetBytes) and the doctor
 * Disk / Memories rows that point at the setters.
 *
 * Field data (clawdbot1, 5.20.4): Disk FAILED at 179 MB against the fixed
 * 100 MB budget — DB 79 MB, realtime audit 92 MB. Audit evidence has no
 * retention yet (#579), so a FAIL it caused had no remedy. And LTM sat at
 * 1000/1000 with `$ shieldcortex consolidate` as the only fix, which cannot
 * change that state (#1121).
 *
 * Large sizes are sparse files (truncate), so nothing here writes 100 MB.
 * Config lives in a per-test temp SHIELDCORTEX_CONFIG_DIR.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac, randomUUID } from 'crypto';
import Database from 'better-sqlite3';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { __resetDiskBudgetWarningForTest, clearCloudConfigCache, getDiskBudget } from '../cloud/config.js';
import { checkDiskUsage, runMemoryStatsCheck } from '../cli/doctor.js';
import { extractFixCommands } from '../cli/doctor-report.js';
import { sessionPressureThresholdBytes } from '../sessions/retention.js';
import { DIRECTORY_BUDGET_BYTES, MAX_DB_FILE_BYTES, WARN_DB_FILE_BYTES } from '../limits.js';

const MiB = 1024 * 1024;
const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
let tempDir: string;
let configDir: string;
let scDir: string;

function writeSignedConfig(obj: unknown): void {
  const key = 'a'.repeat(64);
  fs.writeFileSync(path.join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = JSON.stringify(obj, null, 2) + '\n';
  fs.writeFileSync(path.join(configDir, 'config.json'), body);
  fs.writeFileSync(path.join(configDir, '.config-sig'), createHmac('sha256', key).update(body, 'utf-8').digest('hex'), { mode: 0o600 });
  clearCloudConfigCache();
}

/** A sparse file of `bytes` apparent size under the fixture data dir. */
function sparse(rel: string, bytes: number): void {
  const p = path.join(scDir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, '');
  fs.truncateSync(p, bytes);
}

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1043-disk-'));
  configDir = path.join(tempDir, 'config');
  scDir = path.join(tempDir, 'data');
  fs.mkdirSync(configDir, { recursive: true });
  fs.mkdirSync(scDir, { recursive: true });
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  clearCloudConfigCache();
  __resetDiskBudgetWarningForTest();
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

/** Every entry in the config dir: name, bytes and mtime (a no-write proof). */
function configDirSnapshot(): Array<[string, string, number]> {
  return fs.readdirSync(configDir).sort().map((name) => {
    const p = path.join(configDir, name);
    return [name, fs.readFileSync(p, 'utf-8'), fs.lstatSync(p).mtimeMs];
  });
}

afterEach(() => {
  jest.restoreAllMocks();
  clearCloudConfigCache();
  fs.rmSync(tempDir, { recursive: true, force: true });
  if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
});

describe('#1043 getDiskBudget', () => {
  it('is the 100 MiB default with no config', () => {
    expect(getDiskBudget()).toEqual({ bytes: DIRECTORY_BUDGET_BYTES, source: 'default' });
  });

  it('honours a valid signed override', () => {
    writeSignedConfig({ storage: { diskBudgetBytes: 1024 * MiB } });
    expect(getDiskBudget()).toEqual({ bytes: 1024 * MiB, source: 'config' });
  });

  it.each([
    [{ storage: { diskBudgetBytes: '1GB' } }],
    [{ storage: { diskBudgetBytes: 10 } }],
    [{ storage: { diskBudgetBytes: -5 } }],
    [{ storage: { diskBudgetBytes: 200 * MiB + 0.5 } }],
    [{ storage: { diskBudgetBytes: 60 * 1024 * 1024 * MiB } }],
    [{ storage: { diskBudgetBytes: null } }],
    [{ storage: 'big' }],
  ])('falls back to the default, never lower, for an invalid value %j', (cfg) => {
    writeSignedConfig(cfg);
    expect(getDiskBudget()).toEqual({ bytes: DIRECTORY_BUDGET_BYTES, source: 'invalid' });
  });

  it('a TAMPERED budget (signed 1 GiB, edited to 50 MiB) is ignored: default, one warning, nothing written', () => {
    writeSignedConfig({ storage: { diskBudgetBytes: 1024 * MiB } });
    const file = path.join(configDir, 'config.json');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf-8').replace(String(1024 * MiB), String(50 * MiB)));
    clearCloudConfigCache();
    const before = configDirSnapshot();
    const warn = console.warn as unknown as jest.Mock;

    expect(getDiskBudget()).toEqual({ bytes: DIRECTORY_BUDGET_BYTES, source: 'untrusted' });
    expect(getDiskBudget()).toEqual({ bytes: DIRECTORY_BUDGET_BYTES, source: 'untrusted' });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toMatch(/signature does not verify \(tampered\)/);
    expect(configDirSnapshot()).toEqual(before);
  });

  it('an UNSIGNED budget (no signature at all) is ignored and the file is not adopted', () => {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ storage: { diskBudgetBytes: 2048 * MiB } }));
    clearCloudConfigCache();
    const before = configDirSnapshot();
    expect(getDiskBudget()).toEqual({ bytes: DIRECTORY_BUDGET_BYTES, source: 'untrusted' });
    // No .integrity-key minted, no .config-sig adopted, config.json untouched.
    expect(configDirSnapshot()).toEqual(before);
    expect(before.map(([name]) => name)).toEqual(['config.json']);
  });

  it('doctor judges against the default, not a tampered budget, and says why', async () => {
    writeSignedConfig({ storage: { diskBudgetBytes: 1024 * MiB } });
    const file = path.join(configDir, 'config.json');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf-8').replace(String(1024 * MiB), String(2048 * MiB)));
    clearCloudConfigCache();
    sparse('memories.db-wal', 99 * MiB);
    const result = await checkDiskUsage(scDir);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/99\.0 MB \/ 100 MB limit/);
    expect(result.fix).toMatch(/signature does not verify, so it is ignored/);
  });

  it('the session-capture valve gate is unchanged at the default and never moves past the DB-file policy', () => {
    expect(sessionPressureThresholdBytes(DIRECTORY_BUDGET_BYTES)).toBe(WARN_DB_FILE_BYTES);
    expect(sessionPressureThresholdBytes()).toBe(WARN_DB_FILE_BYTES);
    // A raised directory budget does not move the independent 100 MB live-DB
    // block, so capture cleanup still starts at the DB-file WARN threshold.
    expect(sessionPressureThresholdBytes(1024 * MiB)).toBe(WARN_DB_FILE_BYTES);
    expect(sessionPressureThresholdBytes(50 * 1024 * MiB)).toBe(WARN_DB_FILE_BYTES);
    expect(sessionPressureThresholdBytes(1024 * MiB)).toBeLessThan(MAX_DB_FILE_BYTES);
    // A smaller budget trims earlier, at half of it.
    expect(sessionPressureThresholdBytes(60 * MiB)).toBe(30 * MiB);
  });
});

describe('#1043 doctor Disk row uses the effective budget', () => {
  it('90 MiB of data warns against the default budget and names the setter', async () => {
    sparse('memories.db-wal', 90 * MiB);
    const result = await checkDiskUsage(scDir);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/90\.0 MB \/ 100 MB limit/);
    expect(extractFixCommands(result.fix)).toContain('shieldcortex config --disk-budget <size>');
  });

  it('the same data passes under a higher signed budget, with no setter hint', async () => {
    writeSignedConfig({ storage: { diskBudgetBytes: 1024 * MiB } });
    sparse('memories.db-wal', 90 * MiB);
    const result = await checkDiskUsage(scDir);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/90\.0 MB \/ 1 GB limit/);
    expect(result.fix).toBeUndefined();
  });

  it('the absent-directory row names the effective budget', async () => {
    writeSignedConfig({ storage: { diskBudgetBytes: 250_000_000 } });
    const result = await checkDiskUsage(path.join(tempDir, 'nope'));
    expect(result).toMatchObject({ status: 'pass', message: '0 B / 238.42 MB limit (directory not yet created)' });
  });

  it('audit-only overflow is a WARN with the evidence wording, never a FAIL', async () => {
    // The field shape, scaled: little memory data, a realtime audit plane
    // alone larger than the whole budget.
    sparse('memories.db-wal', 5 * MiB);
    sparse('audit/realtime-2026-11-21.jsonl', 150 * MiB);
    const result = await checkDiskUsage(scDir);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/5\.0 MB \/ 100 MB limit \+ 150\.0 MB audit \(not counted\)/);
    expect(result.fix).toMatch(/Nothing here will delete security evidence/);
    expect(result.fix).toMatch(/#579/);
  });

  it('a symlinked audit DIRECTORY cannot hide over-budget memory data', async () => {
    // The link target is outside the data dir, so the total never counts it;
    // before round 2 the audit figure followed the link and was subtracted
    // anyway, turning this FAIL into "0 B / 100 MB … within the limit".
    sparse('memories.db-wal', 150 * MiB);
    const outside = path.join(tempDir, 'outside-evidence');
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'realtime.jsonl'), '');
    fs.truncateSync(path.join(outside, 'realtime.jsonl'), 150 * MiB);
    fs.symlinkSync(outside, path.join(scDir, 'audit'));
    const result = await checkDiskUsage(scDir);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/^150\.0 MB \/ 100 MB limit/);
  });

  it('a symlink NESTED inside audit cannot hide over-budget memory data either', async () => {
    sparse('memories.db-wal', 150 * MiB);
    sparse('audit/realtime-2026-11-21.jsonl', 1 * MiB);
    const outside = path.join(tempDir, 'outside-evidence');
    fs.mkdirSync(outside);
    fs.writeFileSync(path.join(outside, 'big.jsonl'), '');
    fs.truncateSync(path.join(outside, 'big.jsonl'), 150 * MiB);
    fs.symlinkSync(outside, path.join(scDir, 'audit', 'linked'));
    const result = await checkDiskUsage(scDir);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/^150\.0 MB \/ 100 MB limit \+ 1\.0 MB audit \(not counted\)/);
  });

  it('memory data over the budget still FAILs, with audit shown separately', async () => {
    sparse('memories.db-wal', 99 * MiB);
    sparse('audit/realtime-2026-11-21.jsonl', 50 * MiB);
    const result = await checkDiskUsage(scDir);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/99\.0 MB \/ 100 MB limit \+ 50\.0 MB audit \(not counted\)/);
  });
});

describe('#1043 doctor Memories row names the cap setter at the cap', () => {
  function memoriesDb(stm: number, ltm: number): string {
    const dbPath = path.join(tempDir, 'memories.db');
    const db = new Database(dbPath);
    db.prepare('CREATE TABLE memories (id INTEGER PRIMARY KEY, uuid TEXT, type TEXT)').run();
    const ins = db.prepare('INSERT INTO memories (uuid, type) VALUES (?, ?)');
    db.transaction(() => {
      for (let i = 0; i < stm; i++) ins.run(randomUUID(), 'short_term');
      for (let i = 0; i < ltm; i++) ins.run(randomUUID(), 'long_term');
    })();
    db.close();
    return dbPath;
  }
  const CAPS = { maxShortTermMemories: 100, maxLongTermMemories: 1000 };

  it('LTM 1000/1000, STM 100/100: the fix is the cap setter at 2x, not consolidate', () => {
    const result = runMemoryStatsCheck(memoriesDb(100, 1000), CAPS);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/1000\/1000 LTM — at its cap; at the cap, consolidation evicts the oldest/);
    expect(extractFixCommands(result.fix)).toEqual(['shieldcortex config --memory-cap ltm=2000']);
  });

  it('the suggested cap is clamped to the setter maximum (100000)', () => {
    const result = runMemoryStatsCheck(memoriesDb(0, 57_000), { maxShortTermMemories: 100, maxLongTermMemories: 60_000 });
    expect(extractFixCommands(result.fix)).toEqual(['shieldcortex config --memory-cap ltm=100000']);
  });

  it('at the setter maximum doctor says so plainly and names no command', () => {
    const result = runMemoryStatsCheck(memoriesDb(0, 95_000), { maxShortTermMemories: 100, maxLongTermMemories: 100_000 });
    expect(result.status).toBe('warn');
    expect(extractFixCommands(result.fix)).toEqual([]);
    expect(result.fix).toMatch(/already at the largest the setter accepts \(100000\), so it cannot be raised further/);
  });

  it('a hand-edited cap below the setter minimum is suggested at the minimum (100)', () => {
    const result = runMemoryStatsCheck(memoriesDb(0, 20), { maxShortTermMemories: 100, maxLongTermMemories: 20 });
    expect(extractFixCommands(result.fix)).toEqual(['shieldcortex config --memory-cap ltm=100']);
  });

  it('LTM OVER its cap (1200/1000, e.g. a lowered cap) names consolidate, never a higher cap', () => {
    const result = runMemoryStatsCheck(memoriesDb(10, 1200), CAPS);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/1200\/1000 LTM — over its cap/);
    expect(result.message).not.toMatch(/at its cap/);
    expect(result.fix).not.toMatch(/will not change this/);
    expect(result.fix).toMatch(/pinned rows are never evicted/);
    expect(extractFixCommands(result.fix)).toEqual(['shieldcortex consolidate']);
  });

  it('one row over the cap (1001/1000) is over, not at, the cap', () => {
    const over = runMemoryStatsCheck(memoriesDb(0, 1001), CAPS);
    expect(over.message).toMatch(/1001\/1000 LTM — over its cap/);
    expect(extractFixCommands(over.fix)).toEqual(['shieldcortex consolidate']);
  });

  it('STM strictly over its cap still names consolidate', () => {
    const result = runMemoryStatsCheck(memoriesDb(101, 10), CAPS);
    expect(extractFixCommands(result.fix)).toEqual(['shieldcortex consolidate']);
  });
});
