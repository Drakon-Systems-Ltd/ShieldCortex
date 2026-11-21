import fs from 'node:fs';
import path from 'node:path';
import { createHmac } from 'node:crypto';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { resolveMemoryConfig, __resetCapWarningsForTest } from '../memory/config.js';
import { runMemoryStatsCheck } from '../cli/doctor.js';
import { DEFAULT_CONFIG } from '../memory/types.js';

const originalDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const key = 'b'.repeat(64);
let root: string;
let configDir: string;
let dbPath: string;

function writeConfig(memory: unknown, signed: boolean): void {
  const body = JSON.stringify({ memory }, null, 2) + '\n';
  fs.writeFileSync(path.join(configDir, 'config.json'), body);
  if (signed) {
    fs.writeFileSync(path.join(configDir, '.integrity-key'), key);
    fs.writeFileSync(path.join(configDir, '.config-sig'), createHmac('sha256', key).update(body).digest('hex'));
  }
}

function writeEmbeddedConfig(memory: unknown, stale = false): void {
  const data = { memory };
  const sig = createHmac('sha256', key).update(JSON.stringify(data, null, 2)).digest('hex');
  const body = JSON.stringify({ ...data, _sig: stale ? '0'.repeat(64) : sig }, null, 2) + '\n';
  fs.writeFileSync(path.join(configDir, '.integrity-key'), key);
  fs.writeFileSync(path.join(configDir, 'config.json'), body);
  if (stale) {
    fs.writeFileSync(path.join(configDir, '.config-sig'), createHmac('sha256', key).update(body).digest('hex'));
  }
}

function snapshot(): string[] {
  return fs.readdirSync(configDir).sort().map((name) => {
    const file = path.join(configDir, name);
    const stat = fs.lstatSync(file);
    return `${name}:${stat.mode}:${stat.mtimeMs}:${fs.readFileSync(file).toString('base64')}`;
  });
}

beforeEach(() => {
  root = fs.mkdtempSync(path.join(process.cwd(), '.sc-1125-'));
  configDir = path.join(root, 'config');
  fs.mkdirSync(configDir);
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  dbPath = path.join(root, 'memories.db');
  const db = new Database(dbPath);
  db.exec('CREATE TABLE memories (type TEXT)');
  db.close();
  __resetCapWarningsForTest();
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(root, { recursive: true, force: true });
  if (originalDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = originalDir;
});

describe('#1125 signed memory caps', () => {
  it('ignores a tampered lower cap, warns once, and leaves the config directory untouched', () => {
    writeConfig({ maxLongTermMemories: 5000 }, true);
    const file = path.join(configDir, 'config.json');
    fs.writeFileSync(file, fs.readFileSync(file, 'utf8').replace('5000', '10'));
    const before = snapshot();
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
    const row = runMemoryStatsCheck(dbPath);
    expect(row.message).toContain('stored caps ignored because config signature does not verify');
    expect(row.status).toBe('warn');
    expect(console.warn).toHaveBeenCalledTimes(1);
    expect(snapshot()).toEqual(before);
  });

  it('ignores an unsigned lower cap without adopting or signing it', () => {
    writeConfig({ maxShortTermMemories: 10, maxLongTermMemories: 10 }, false);
    const before = snapshot();
    const caps = resolveMemoryConfig();
    expect([caps.maxShortTermMemories, caps.maxLongTermMemories]).toEqual([
      DEFAULT_CONFIG.maxShortTermMemories, DEFAULT_CONFIG.maxLongTermMemories,
    ]);
    expect(runMemoryStatsCheck(dbPath).message).toContain('stored caps ignored because config is not signed');
    expect(snapshot()).toEqual(before);
  });

  it('accepts a legacy signature over the exact config bytes', () => {
    writeConfig({ maxShortTermMemories: 25, maxLongTermMemories: 50 }, true);
    const before = snapshot();
    const caps = resolveMemoryConfig();
    expect([caps.maxShortTermMemories, caps.maxLongTermMemories]).toEqual([25, 50]);
    expect(runMemoryStatsCheck(dbPath).message).not.toContain('stored caps ignored');
    expect(snapshot()).toEqual(before);
  });

  it('accepts a valid embedded signature and a stale embedded signature backed by exact legacy bytes', () => {
    writeEmbeddedConfig({ maxShortTermMemories: 25, maxLongTermMemories: 50 });
    let before = snapshot();
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(50);
    expect(snapshot()).toEqual(before);

    writeEmbeddedConfig({ maxShortTermMemories: 30, maxLongTermMemories: 60 }, true);
    before = snapshot();
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(60);
    expect(snapshot()).toEqual(before);
  });

  it('ordinary inputs keep defaults without an integrity warning', () => {
    expect(resolveMemoryConfig().maxLongTermMemories).toBe(DEFAULT_CONFIG.maxLongTermMemories);
    writeConfig({}, false);
    expect(resolveMemoryConfig().maxShortTermMemories).toBe(DEFAULT_CONFIG.maxShortTermMemories);
    expect(runMemoryStatsCheck(dbPath).message).not.toContain('stored caps ignored');
    expect(console.warn).not.toHaveBeenCalled();
  });
});
