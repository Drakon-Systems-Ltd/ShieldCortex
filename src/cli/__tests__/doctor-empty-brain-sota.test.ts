/**
 * Doctor empty-brain / native-contract check (Memory SOTA A-min).
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

describe('checkMemoryPlaneEmptyBrain', () => {
  let tmpHome: string;
  let scDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-eb-home-'));
    scDir = path.join(tmpHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true, mode: 0o700 });
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeConfig(cfg: Record<string, unknown>): void {
    fs.writeFileSync(path.join(scDir, 'config.json'), `${JSON.stringify(cfg, null, 2)}\n`);
  }

  function openDb(): Database.Database {
    const dbPath = path.join(scDir, 'memories.db');
    const db = new Database(dbPath);
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY,
        title TEXT, content TEXT, status TEXT, sensitivity_level TEXT
      );
      CREATE TABLE session_events (
        id INTEGER PRIMARY KEY,
        created_at TEXT
      );
      CREATE TABLE hook_invocations (
        id INTEGER PRIMARY KEY,
        invoked_at TEXT
      );
    `);
    return db;
  }

  async function runCheck() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkMemoryPlaneEmptyBrain();
  }

  it('fails when auto-memory on, activity present, zero admitted memories', async () => {
    writeConfig({ openclawAutoMemory: true, proactiveRecall: true });
    const db = openDb();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    db.close();
    const r = await runCheck();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/0 admitted/i);
  });

  it('fails when inject on without nativeContract', async () => {
    writeConfig({
      openclawAutoMemory: true,
      memory: { inject: { mode: 'start' } },
    });
    const db = openDb();
    db.prepare(
      `INSERT INTO memories (title, content, status, sensitivity_level) VALUES ('a','b','active','INTERNAL')`,
    ).run();
    db.close();
    const r = await runCheck();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/nativeContract/i);
  });

  it('passes with admitted memories and contract', async () => {
    writeConfig({
      openclawAutoMemory: true,
      memory: { inject: { mode: 'start', nativeContract: 'sc_only' } },
    });
    const db = openDb();
    db.prepare(
      `INSERT INTO memories (title, content, status, sensitivity_level) VALUES ('a','b','active','INTERNAL')`,
    ).run();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    db.close();
    const r = await runCheck();
    expect(r.status).toBe('pass');
  });
});
