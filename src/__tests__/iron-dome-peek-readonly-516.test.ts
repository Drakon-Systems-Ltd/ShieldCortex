import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { initDatabase, closeDatabase, getDatabase, peekDatabase } from '../database/init.js';
import { checkIronDomeProfile } from '../cli/doctor.js';
import { peekEffectiveIronDomeConfig } from '../defence/iron-dome/index.js';
import { DEFAULT_IRON_DOME_CONFIG } from '../defence/iron-dome/config.js';

describe('Iron Dome diagnostic peek stays read-only (#516)', () => {
  let dir: string;
  let dbPath: string;
  let previousConfigDir: string | undefined;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iron-dome-peek-readonly-516-'));
    previousConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
    process.env.SHIELDCORTEX_CONFIG_DIR = path.join(dir, 'config');
    fs.mkdirSync(process.env.SHIELDCORTEX_CONFIG_DIR);
    dbPath = path.join(dir, 'memories.db');
    initDatabase(dbPath);
  });

  afterEach(() => {
    closeDatabase();
    if (previousConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = previousConfigDir;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function storeEnabled(): void {
    const db = getDatabase();
    db.exec('CREATE TABLE iron_dome_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
    db.prepare('INSERT INTO iron_dome_config (key, value) VALUES (?, ?)')
      .run('config', JSON.stringify({ ...DEFAULT_IRON_DOME_CONFIG, enabled: true }));
  }

  it('does not reconnect, close the owner handle, or migrate a replacement file', async () => {
    const owner = getDatabase();
    // Keep WAL sidecars from the original fixture off the replacement path.
    owner.pragma('wal_checkpoint(TRUNCATE)');
    owner.pragma('journal_mode = DELETE');
    const replacement = path.join(dir, 'replacement.db');
    const minimal = new Database(replacement);
    minimal.exec('CREATE TABLE fixture (id INTEGER)');
    const before = (minimal.prepare('SELECT count(*) AS n FROM sqlite_master').get() as { n: number }).n;
    minimal.close();
    fs.renameSync(dbPath, path.join(dir, 'original.db'));
    fs.renameSync(replacement, dbPath);

    const result = await checkIronDomeProfile(dbPath);
    expect(result).toMatchObject({ status: 'info', message: 'could not read Iron Dome profile — stored config unreadable' });
    expect(peekEffectiveIronDomeConfig()).toBeNull();
    expect(peekDatabase()).toBeNull();
    expect(owner.open).toBe(true);
    expect(owner.prepare('SELECT count(*) AS n FROM sqlite_master').get()).toBeDefined();

    const inspect = new Database(dbPath, { readonly: true, fileMustExist: true });
    try {
      expect((inspect.prepare('SELECT count(*) AS n FROM sqlite_master').get() as { n: number }).n).toBe(before);
      expect(inspect.prepare("SELECT name FROM sqlite_master WHERE name = 'iron_dome_config'").get()).toBeUndefined();
    } finally { inspect.close(); }
  });

  it('reads an unsigned cold cloud cache without adopting or writing config', async () => {
    storeEnabled();
    const configDir = process.env.SHIELDCORTEX_CONFIG_DIR!;
    const configFile = path.join(configDir, 'config.json');
    const bytes = Buffer.from(JSON.stringify({
      cloudIronDome: {
        patterns: [],
        policy: { name: 'fleet', base_profile: 'school', config_overrides: { killPhrase: 'private fleet stop' } },
        patternsUpdatedAt: null,
        policyUpdatedAt: null,
        lastFetchedAt: '2020-01-01T00:00:00Z',
      },
    }));
    fs.writeFileSync(configFile, bytes);
    const before = fs.statSync(configFile);
    const filesBefore = fs.readdirSync(configDir);

    const peeked = peekEffectiveIronDomeConfig();
    const result = await checkIronDomeProfile(dbPath);
    expect(peeked?.profile).toBe('school');
    expect(result).toMatchObject({ status: 'pass', message: 'school profile' });
    expect(fs.readFileSync(configFile)).toEqual(bytes);
    const after = fs.statSync(configFile);
    expect({ mtimeMs: after.mtimeMs, size: after.size }).toEqual({ mtimeMs: before.mtimeMs, size: before.size });
    expect(fs.readdirSync(configDir)).toEqual(filesBefore);
  });
});
