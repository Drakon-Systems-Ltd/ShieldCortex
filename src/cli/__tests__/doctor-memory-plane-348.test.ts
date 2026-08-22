/**
 * Track A harden + T1 doctor checks (#348 / #393 / #394).
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

describe('checkMemoryPlaneDrift + checkMemoryHostContract', () => {
  let tmpHome: string;
  let scDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-348-home-'));
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
        title TEXT, content TEXT, status TEXT, sensitivity_level TEXT,
        created_at TEXT
      );
      CREATE TABLE session_events (
        id INTEGER PRIMARY KEY,
        created_at TEXT
      );
    `);
    return db;
  }

  async function runDrift() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkMemoryPlaneDrift();
  }

  async function runHost() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkMemoryHostContract();
  }

  it('fails illegal plane value', async () => {
    writeConfig({ memory: { plane: 'multi_master' } });
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/illegal memory\.plane/i);
    expect(r.fix).toMatch(/--memory-plane/);
  });

  it('warns dual_legacy when activity and zero durable admits', async () => {
    writeConfig({
      openclawAutoMemory: true,
      memory: { plane: 'dual_legacy', inject: { mode: 'start', nativeContract: 'sc_only' } },
    });
    const db = openDb();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    // old admitted row outside window doesn't count as 7d durable admit
    db.prepare(
      `INSERT INTO memories (title, content, status, sensitivity_level, created_at)
       VALUES ('old', 'x', 'active', 'INTERNAL', datetime('now', '-30 days'))`,
    ).run();
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/dual_legacy/i);
  });

  it('fails import_only when native touched and zero durable admits', async () => {
    writeConfig({
      memory: {
        plane: 'import_only',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 't', agentId: 'a' },
      },
    });
    const db = openDb();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    db.close();
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '# brain\n'.repeat(20));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/drift|import_only/i);
  });

  it('host contract fails when OC memorySearch still enabled under sc_only', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(ocDir, { recursive: true });
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: true } } }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/memorySearch|contract/i);
  });

  it('host contract passes when inject off', async () => {
    writeConfig({ memory: { plane: 'dual_legacy' } });
    const r = await runHost();
    expect(r.status).toBe('info');
  });

  it('host contract fails when memorySearch key absent (OC default-on)', async () => {
    writeConfig({
      openclawAutoMemory: true,
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(ocDir, { recursive: true });
    fs.writeFileSync(path.join(ocDir, 'openclaw.json'), JSON.stringify({ agents: { defaults: {} } }, null, 2));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/default-on|not proven off|Memory Search/i);
  });

  it('host contract passes only when memorySearch.enabled === false', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(ocDir, { recursive: true });
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('pass');
  });

  it('import_only fails on native touch even when SC has 7d admits', async () => {
    writeConfig({
      memory: {
        plane: 'import_only',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 't', agentId: 'a' },
      },
    });
    const db = openDb();
    db.prepare(
      `INSERT INTO memories (title, content, status, sensitivity_level, created_at)
       VALUES ('fresh', 'fact', 'active', 'INTERNAL', datetime('now'))`,
    ).run();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    db.close();
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '# still the brain\n'.repeat(10));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/native memory artifact touched|drift/i);
  });
});

