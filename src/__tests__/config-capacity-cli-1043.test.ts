/**
 * #1043: `shieldcortex config --memory-cap` / `--disk-budget` — signed
 * capacity setters.
 *
 * The owner's host sat at LTM 1000/1000 and the only way to raise the cap was
 * a hand-edit of the signed config plus `config --resign`. These pin the
 * supported path: the write goes through the signed mutation (the signed
 * loader reads it back, integrity verdict `valid`), other keys survive, and
 * every refusal (bad spec, out of bounds, malformed target block) leaves the
 * file byte-for-byte unchanged. The setter never deletes a memory.
 *
 * Isolation: a per-test temp SHIELDCORTEX_CONFIG_DIR and a temp
 * CLAUDE_MEMORY_DB, the same fixture shape as configurable-caps-wiring.test.ts.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac, randomUUID } from 'crypto';
import Database from 'better-sqlite3';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { handleCloudConfig } from '../cloud/cli.js';
import {
  clearCloudConfigCache,
  getDiskBudget,
  inspectConfigIntegrity,
  isConfigTampered,
  readRawConfig,
} from '../cloud/config.js';
import { resolveMemoryConfig, __resetCapWarningsForTest } from '../memory/config.js';
import { parseDiskBudget, parseMemoryCapSpec } from '../cloud/capacity.js';

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const originalDb = process.env.CLAUDE_MEMORY_DB;
let tempDir: string;
let configDir: string;
let logs: string[];

const configFile = (): string => path.join(configDir, 'config.json');

/** A legacy-signed config.json, as configurable-caps-wiring.test.ts writes it. */
function writeSignedConfig(obj: unknown): void {
  const key = 'a'.repeat(64);
  fs.writeFileSync(path.join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = JSON.stringify(obj, null, 2) + '\n';
  fs.writeFileSync(configFile(), body);
  fs.writeFileSync(path.join(configDir, '.config-sig'), createHmac('sha256', key).update(body, 'utf-8').digest('hex'), { mode: 0o600 });
  clearCloudConfigCache();
}

function snapshot(): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const name of ['config.json', '.config-sig', '.integrity-key']) {
    const p = path.join(configDir, name);
    out[name] = fs.existsSync(p) ? fs.readFileSync(p, 'utf-8') : null;
  }
  return out;
}

function run(args: string[]): { exitCode: number | undefined } {
  const exit = jest.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw Object.assign(new Error('exit'), { exitCode: code });
  }) as never);
  try {
    handleCloudConfig(args);
    return { exitCode: undefined };
  } catch (err) {
    const code = (err as { exitCode?: number }).exitCode;
    if (code === undefined) throw err;
    return { exitCode: code };
  } finally {
    exit.mockRestore();
    clearCloudConfigCache();
  }
}

/** The stored file must verify under the signed loader, not merely carry a `_sig`. */
function expectSignedAndValid(): Record<string, any> {
  clearCloudConfigCache();
  expect(inspectConfigIntegrity().verdict).toBe('valid');
  const raw = readRawConfig({ readOnly: true }) as Record<string, any>;
  expect(isConfigTampered()).toBe(false);
  return raw;
}

const BASE = {
  defenceMode: 'balanced',
  memory: { plane: 'sc_canonical', inject: { nativeContract: 'sc_only' } },
  autoMemory: { stopHookSamplingTurns: 3 },
  someUnrelatedKey: { nested: [1, 2, 3] },
};

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1043-cli-'));
  configDir = path.join(tempDir, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true });
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  // Never let the lowering warning read a host database.
  process.env.CLAUDE_MEMORY_DB = path.join(tempDir, 'absent.db');
  clearCloudConfigCache();
  __resetCapWarningsForTest();
  logs = [];
  jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')); });
  jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')); });
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  clearCloudConfigCache();
  fs.rmSync(tempDir, { recursive: true, force: true });
  if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
  if (originalDb === undefined) delete process.env.CLAUDE_MEMORY_DB;
  else process.env.CLAUDE_MEMORY_DB = originalDb;
});

describe('#1043 config --memory-cap / --disk-budget write signed values', () => {
  it('ltm=2000 is written signed, read back by the loader, and touches nothing else', () => {
    writeSignedConfig(BASE);
    expect(run(['--memory-cap', 'ltm=2000']).exitCode).toBeUndefined();
    const raw = expectSignedAndValid();
    expect(raw.memory.maxLongTermMemories).toBe(2000);
    expect(raw.memory.maxShortTermMemories).toBeUndefined();
    expect(raw.memory.plane).toBe('sc_canonical');
    expect(raw.memory.inject).toEqual({ nativeContract: 'sc_only' });
    expect(raw.autoMemory).toEqual({ stopHookSamplingTurns: 3 });
    expect(raw.someUnrelatedKey).toEqual({ nested: [1, 2, 3] });
    expect(raw.defenceMode).toBe('balanced');
    expect(resolveMemoryConfig(undefined, { readOnly: true })).toMatchObject({ maxLongTermMemories: 2000, maxShortTermMemories: 100 });
    expect(logs.join('\n')).toMatch(/Long-term \(LTM\) memory cap: 1000 -> 2000/);
  });

  it('ltm and stm together, and --disk-budget alongside, in one command', () => {
    writeSignedConfig(BASE);
    expect(run(['--memory-cap', 'stm=200,ltm=5000', '--disk-budget', '1GiB']).exitCode).toBeUndefined();
    const raw = expectSignedAndValid();
    expect(raw.memory).toMatchObject({ maxLongTermMemories: 5000, maxShortTermMemories: 200, plane: 'sc_canonical' });
    expect(raw.storage).toEqual({ diskBudgetBytes: 1024 ** 3 });
    expect(getDiskBudget()).toEqual({ bytes: 1024 ** 3, source: 'config' });
    expect(logs.join('\n')).toMatch(/Disk budget: 100 MB -> 1 GB/);
  });

  it('works on a fresh install with no config.json', () => {
    expect(run(['--disk-budget', '250MB']).exitCode).toBeUndefined();
    const raw = expectSignedAndValid();
    expect(raw.storage).toEqual({ diskBudgetBytes: 250_000_000 });
  });

  it('lowering below the current count warns, and the setter deletes nothing', () => {
    const dbPath = path.join(tempDir, 'memories.db');
    const db = new Database(dbPath);
    db.prepare('CREATE TABLE memories (id INTEGER PRIMARY KEY, uuid TEXT, type TEXT)').run();
    const ins = db.prepare("INSERT INTO memories (uuid, type) VALUES (?, 'long_term')");
    for (let i = 0; i < 150; i++) ins.run(randomUUID());
    db.close();
    process.env.CLAUDE_MEMORY_DB = dbPath;
    writeSignedConfig(BASE);

    expect(run(['--memory-cap', 'ltm=100']).exitCode).toBeUndefined();
    expect(expectSignedAndValid().memory.maxLongTermMemories).toBe(100);
    expect(logs.join('\n')).toMatch(/the store holds 150 Long-term \(LTM\) memories, more than the new cap/);
    expect(logs.join('\n')).toMatch(/evict the oldest unpinned memories/);
    const after = new Database(dbPath, { readonly: true });
    expect((after.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c).toBe(150);
    after.close();
  });
});

describe('#1043 refusals write nothing', () => {
  it.each([
    [['--memory-cap', 'ltm=99']],
    [['--memory-cap', 'ltm=100001']],
    [['--memory-cap', 'stm=9']],
    [['--memory-cap', 'stm=10001']],
    [['--memory-cap', 'ltm=1.5']],
    [['--memory-cap', 'ltm=2e3']],
    [['--memory-cap', 'ltm=-2000']],
    [['--memory-cap', 'ltm=2000,ltm=3000']],
    [['--memory-cap', 'ltm=2000,stm=200,ltm=1']],
    [['--memory-cap', 'max=2000']],
    [['--memory-cap', '2000']],
    [['--memory-cap']],
    [['--memory-cap', '--disk-budget', '1GB']],
    [['--disk-budget', '49MiB']],
    [['--disk-budget', '51GiB']],
    [['--disk-budget', '1.5GB']],
    [['--disk-budget', '-1GB']],
    [['--disk-budget', '1TB']],
    [['--disk-budget', '0x40000000']],
    [['--disk-budget', '1GBx']],
    [['--disk-budget']],
    // A valid flag must not half-apply when its partner is invalid.
    [['--memory-cap', 'ltm=2000', '--disk-budget', 'lots']],
    [['--disk-budget', '1GB', '--memory-cap', 'ltm=5']],
  ])('%j exits 1 and leaves the config untouched', (args) => {
    writeSignedConfig(BASE);
    const before = snapshot();
    expect(run(args).exitCode).toBe(1);
    expect(snapshot()).toEqual(before);
  });

  it.each([
    ['memory', 'not-an-object', ['--memory-cap', 'ltm=2000']],
    ['memory', [1, 2], ['--memory-cap', 'stm=50']],
    ['memory', null, ['--memory-cap', 'ltm=2000']],
    ['storage', 5, ['--disk-budget', '1GB']],
  ])('a malformed existing %s block (%j) is refused, not replaced', (key, value, args) => {
    writeSignedConfig({ ...BASE, [key]: value });
    const before = snapshot();
    expect(run(args as string[]).exitCode).toBe(1);
    expect(snapshot()).toEqual(before);
    expect(logs.join('\n')).toMatch(new RegExp(`the "${key}" entry in config.json is not an object`));
  });

  it('a tampered config is refused by the existing integrity refusal', () => {
    writeSignedConfig(BASE);
    fs.writeFileSync(configFile(), fs.readFileSync(configFile(), 'utf-8').replace('balanced', 'permissive'));
    clearCloudConfigCache();
    const before = snapshot();
    expect(run(['--memory-cap', 'ltm=2000']).exitCode).toBe(1);
    expect(snapshot()).toEqual(before);
  });
});

describe('#1043 value grammar', () => {
  it('parses the documented spellings exactly', () => {
    expect(parseMemoryCapSpec('ltm=2000')).toEqual({ ok: true, value: { maxLongTermMemories: 2000 } });
    expect(parseMemoryCapSpec('stm=10,ltm=100000')).toEqual({ ok: true, value: { maxShortTermMemories: 10, maxLongTermMemories: 100000 } });
    expect(parseDiskBudget('250MB')).toEqual({ ok: true, value: 250_000_000 });
    expect(parseDiskBudget('1GB')).toEqual({ ok: true, value: 1_000_000_000 });
    expect(parseDiskBudget('500MiB')).toEqual({ ok: true, value: 500 * 1024 * 1024 });
    expect(parseDiskBudget('1gib')).toEqual({ ok: true, value: 1024 ** 3 });
    expect(parseDiskBudget(String(50 * 1024 * 1024))).toEqual({ ok: true, value: 50 * 1024 * 1024 });
    expect(parseDiskBudget('50GiB')).toEqual({ ok: true, value: 50 * 1024 ** 3 });
  });
});
