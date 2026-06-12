import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';

/**
 * Doctor's project-keys collision check knows both sides of every collision,
 * so its fix-hint must hand the user a runnable command: explicit `--map`
 * pairs (not a `<root>` placeholder zsh chokes on), quoted when a key has
 * spaces, and `--include-stm` whenever a colliding legacy key has rows the
 * repair tool's default long_term/episodic scope would silently skip —
 * the exact trap where the suggested command "fixes" nothing and the
 * warning survives the repair.
 */
describe('doctor project-keys fix hint', () => {
  let tmpHome: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doc-pk-'));
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function seedDb(rows: Array<{ project: string; type: string }>): void {
    const dir = path.join(tmpHome, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    const db = new Database(path.join(dir, 'memories.db'));
    db.exec('CREATE TABLE memories (id INTEGER PRIMARY KEY, project TEXT, type TEXT)');
    const insert = db.prepare('INSERT INTO memories (project, type) VALUES (?, ?)');
    for (const r of rows) insert.run(r.project, r.type);
    db.close();
  }

  async function check() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkProjectKeyConsistency();
  }

  it('LTM-only collision → explicit --map pair, no --include-stm, no <root> placeholder', async () => {
    seedDb([
      { project: '79', type: 'long_term' },
      { project: 'mkdelta221-79', type: 'long_term' },
    ]);
    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.fix).toContain('--map 79=mkdelta221-79');
    expect(result.fix).not.toContain('--include-stm');
    expect(result.fix).not.toContain('<root>');
  });

  it('STM-only collision → hint adds --include-stm (default repair scope would skip it)', async () => {
    seedDb([
      { project: '79', type: 'short_term' },
      { project: 'mkdelta221-79', type: 'long_term' },
    ]);
    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.fix).toContain('--map 79=mkdelta221-79');
    expect(result.fix).toContain('--include-stm');
  });

  it('legacy key with spaces → map pair is shell-quoted', async () => {
    seedDb([
      { project: 'Gods of the Cosmos', type: 'long_term' },
      { project: 'mkdelta221-Gods of the Cosmos', type: 'long_term' },
    ]);
    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.fix).toContain('--map "Gods of the Cosmos=mkdelta221-Gods of the Cosmos"');
  });

  it('no collisions → pass (regression guard)', async () => {
    seedDb([
      { project: 'mkdelta221-79', type: 'long_term' },
      { project: 'drakon-shieldcortex', type: 'long_term' },
    ]);
    const result = await check();
    expect(result.status).toBe('pass');
  });
});
