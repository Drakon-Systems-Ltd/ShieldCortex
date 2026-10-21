import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, createHmac } from 'node:crypto';
import { spawn } from 'node:child_process';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { initDatabase, closeDatabase } from '../../database/init.js';
import { checkDiskUsage, runMemoryStatsCheck, runSemanticCoverageCheck, type CheckResult } from '../doctor.js';
import { configuredChannels, maintain, type MaintainDeps } from '../maintain.js';
import { clearCloudConfigCache } from '../../cloud/config.js';

let dir: string;
let dbPath: string;
const cap = { maxShortTermMemories: 10, maxLongTermMemories: 1000 };
const fakeEmbed = async (): Promise<Float32Array> => new Float32Array(384).fill(0.1);

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-maintain-652-'));
  dbPath = path.join(dir, 'memories.db');
  initDatabase(dbPath);
  closeDatabase();
});
afterEach(() => { try { closeDatabase(); } catch { /* closed */ } fs.rmSync(dir, { recursive: true, force: true }); });
const sha = (file: string): string => createHash('sha256').update(fs.readFileSync(file)).digest('hex');

function fixture(): { deps: MaintainDeps; limit: number } {
  const db = new Database(dbPath);
  db.pragma('journal_mode = DELETE');
  const insert = db.prepare("INSERT INTO memories (uuid, title, content, type, category, salience, tags, created_at, last_accessed, embedding) VALUES (?, ?, ?, 'short_term', 'note', 0.5, '[]', datetime('now', '-2 days'), datetime('now'), NULL)");
  for (let i = 0; i < 12; i++) insert.run(`maintain-${i}`, `Title ${i}`, `Content ${i}`);
  db.exec('CREATE TABLE fixture_space (payload TEXT)');
  const bulk = db.prepare('INSERT INTO fixture_space VALUES (?)');
  for (let i = 0; i < 400; i++) bulk.run(`${i}-${'x'.repeat(2000)}`);
  db.exec('DELETE FROM fixture_space');
  expect((db.pragma('freelist_count', { simple: true }) as number) / (db.pragma('page_count', { simple: true }) as number)).toBeGreaterThanOrEqual(0.2);
  db.close();
  const limit = Math.ceil(fs.statSync(dbPath).size / 0.96);
  return { limit, deps: { dataDir: dir, dbPath, diskLimit: limit, consolidateConfig: { ...cap } as MaintainDeps['consolidateConfig'], embed: fakeEmbed, channels: [] } };
}

describe('maintain #652 slice A', () => {
  it('clears a real free-page, STM, and missing-vector fixture; second run is a no-op', async () => {
    const { deps } = fixture();
    const before = await checkDiskUsage(dir, deps.diskLimit);
    expect(before.status).toBe('fail');
    const first = await maintain({}, deps);
    expect(first.exitCode).toBe(0);
    expect(first.steps.consolidate.status).toBe('ran');
    expect(first.steps.embed.status).toBe('ran');
    expect(first.steps.vacuum.status).toBe('ran');
    expect(first.steps.doctor.results.filter(r => r.status === 'fail')).toHaveLength(0);
    expect(runMemoryStatsCheck(dbPath, cap).status).toBe('pass');
    expect(runSemanticCoverageCheck(dbPath).status).toBe('pass');
    expect((await checkDiskUsage(dir, deps.diskLimit)).status).toBe('pass');
    const second = await maintain({}, deps);
    expect(second.exitCode).toBe(0);
    expect(second.steps.consolidate.status).toBe('skipped');
    expect(second.steps.embed.missing).toBe(0);
    expect(second.steps.embed.embedded).toBe(0);
    expect(second.steps.vacuum.status).toBe('skipped');
    expect(second.steps.notify.status).toBe('noop');
    expect(second.steps.doctor.results).toEqual(first.steps.doctor.results);
  });

  it('keeps a non-clearable disk FAIL and throttles the same notification for 24 hours', async () => {
    const { deps, limit } = fixture();
    fs.writeFileSync(path.join(dir, 'other.bin'), Buffer.alloc(limit));
    let now = new Date('2026-10-14T00:00:00Z');
    const sent: CheckResult[][] = [];
    deps.now = () => now;
    deps.notifier = async checks => { sent.push(checks); return true; };
    const first = await maintain({}, deps);
    expect(first.exitCode).toBe(1);
    expect(first.steps.doctor.results.some(r => r.label === 'Disk' && r.status === 'fail')).toBe(true);
    expect(sent).toHaveLength(1);
    expect((await maintain({}, deps)).steps.notify.reason).toBe('throttled');
    expect(sent).toHaveLength(1);
    now = new Date(now.getTime() + 86_400_000);
    expect((await maintain({}, deps)).steps.notify.status).toBe('ran');
    expect(sent).toHaveLength(2);
    deps.doctor = async () => [{ label: 'Different failure', status: 'fail', message: 'still broken' }];
    expect((await maintain({}, deps)).steps.notify.status).toBe('ran');
    expect(sent).toHaveLength(3);
    expect(sent[0][0].message).not.toContain('other.bin');
  });

  it('dry run leaves DB bytes, mtime, state and notifier untouched', async () => {
    const { deps } = fixture();
    const before = fs.readFileSync(dbPath);
    const mtime = fs.statSync(dbPath).mtimeMs;
    const notifier = jest.fn<() => Promise<boolean>>().mockResolvedValue(true);
    deps.notifier = notifier;
    const report = await maintain({ dryRun: true }, deps);
    expect(report.steps.vacuum.status).toBe('skipped');
    expect(fs.readFileSync(dbPath)).toEqual(before);
    expect(fs.statSync(dbPath).mtimeMs).toBe(mtime);
    expect(fs.existsSync(path.join(dir, 'state', 'maintain-notify.json'))).toBe(false);
    expect(notifier).not.toHaveBeenCalled();
  });

  it('skips consolidate and vacuum under a live lock without failing them, and doctor still runs', async () => {
    const { deps } = fixture();
    fs.writeFileSync(`${dbPath}.lock`, JSON.stringify({ pid: process.pid }));
    const consolidate = jest.fn(() => { throw new Error('must not run under a live lock'); });
    deps.consolidate = consolidate as unknown as MaintainDeps['consolidate'];
    const report = await maintain({}, deps);
    expect(consolidate).not.toHaveBeenCalled();
    expect(report.steps.consolidate.status).toBe('skipped');
    expect(report.steps.consolidate.reason).toBe('locked');
    expect(report.steps.embed.status).toBe('skipped');
    expect(report.steps.embed.reason).toBe('locked');
    const db = new Database(dbPath, { readonly: true });
    expect((db.prepare('SELECT COUNT(*) AS n FROM memories WHERE embedding IS NOT NULL').get() as { n: number }).n).toBe(0);
    db.close();
    expect(report.steps.vacuum.reason).toBe('locked');
    expect(report.steps.doctor.status).toBe('ran');
    expect(report.steps.doctor.results.some(r => r.label.startsWith('Maintenance'))).toBe(false);
    expect(report.steps.notify.reason).toBe('not-configured');
  });

  it('skips every write when another process takes the lock after the precheck', async () => {
    const { deps } = fixture();
    initDatabase(dbPath);
    closeDatabase();
    const altered = new Database(dbPath);
    altered.exec('DROP TABLE mcp_tool_hashes');
    altered.pragma('journal_mode = DELETE');
    altered.close();
    const snapshot = () => {
      const db = new Database(dbPath, { readonly: true });
      try {
        return {
          rows: (db.prepare('SELECT COUNT(*) AS n FROM memories').get() as { n: number }).n,
          missing: (db.prepare('SELECT COUNT(*) AS n FROM memories WHERE embedding IS NULL').get() as { n: number }).n,
          pages: db.pragma('page_count', { simple: true }) as number,
          free: db.pragma('freelist_count', { simple: true }) as number,
        };
      } finally { db.close(); }
    };
    const before = snapshot();
    expect(before.rows).toBeGreaterThan(cap.maxShortTermMemories);
    expect(before.missing).toBeGreaterThan(0);
    expect(before.free / before.pages).toBeGreaterThanOrEqual(0.2);
    const beforeHash = sha(dbPath);
    const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1e6)'], { stdio: 'ignore' });
    try {
      if (!child.pid) throw new Error('could not spawn lock owner');
      const otherPid = child.pid;
      const consolidate = jest.fn(() => { throw new Error('consolidate must not run'); });
      const embed = jest.fn(fakeEmbed);
      const vacuum = jest.fn((_db: Database.Database) => { throw new Error('vacuum must not run'); });
      deps.consolidate = consolidate as unknown as MaintainDeps['consolidate'];
      deps.embed = embed;
      deps.vacuum = vacuum;
      deps.doctor = async () => [{ label: 'stub', status: 'pass', message: 'stub' }];
      const lockBody = JSON.stringify({ pid: otherPid, entryPath: 'other-shieldcortex' });
      let filesAtLock: string[] = [];
      deps.afterLockCheck = () => {
        fs.writeFileSync(`${dbPath}.lock`, lockBody);
        filesAtLock = fs.readdirSync(dir).sort();
      };
      const report = await maintain({}, deps);
      expect(report.exitCode).toBe(0);
      expect(report.steps.consolidate).toMatchObject({ status: 'skipped', reason: 'locked' });
      expect(report.steps.embed).toMatchObject({ status: 'skipped', reason: 'locked', missing: 0, embedded: 0 });
      expect(report.steps.vacuum).toMatchObject({ status: 'skipped', reason: 'locked' });
      expect(report.steps.doctor.status).toBe('ran');
      expect(report.steps.doctor.results).toEqual([{ label: 'stub', status: 'pass', message: 'stub' }]);
      expect(consolidate).not.toHaveBeenCalled();
      expect(embed).not.toHaveBeenCalled();
      expect(vacuum).not.toHaveBeenCalled();
      expect(snapshot()).toEqual(before);
      expect(sha(dbPath)).toBe(beforeHash);
      expect(fs.readdirSync(dir).sort()).toEqual(filesAtLock);
      const readOnly = new Database(dbPath, { readonly: true, fileMustExist: true });
      try {
        expect(readOnly.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'mcp_tool_hashes'").get()).toBeUndefined();
      } finally { readOnly.close(); }
      expect(fs.readFileSync(`${dbPath}.lock`, 'utf8')).toBe(lockBody);
      expect(JSON.parse(fs.readFileSync(`${dbPath}.lock`, 'utf8')).pid).toBe(otherPid);
    } finally { child.kill(); }
  });

  it('skips uncached embedding without a write or embed failure', async () => {
    const { deps } = fixture();
    delete deps.embed;
    deps.modelCacheReady = async () => false;
    deps.consolidateConfig = { ...cap, maxShortTermMemories: 100 } as MaintainDeps['consolidateConfig'];
    deps.vacuum = () => { /* keep the fixture unchanged */ };
    const report = await maintain({}, deps);
    expect(report.steps.embed).toMatchObject({ status: 'skipped', reason: 'embedding model not cached', embedded: 0 });
    expect(report.steps.embed.missing).toBeGreaterThan(0);
    expect(report.steps.doctor.results.some(r => r.label === 'Maintenance embed')).toBe(false);
    const db = new Database(dbPath, { readonly: true });
    expect((db.prepare('SELECT COUNT(*) AS n FROM memories WHERE embedding IS NOT NULL').get() as { n: number }).n).toBe(0);
    db.close();
  });

  it('reports a throwing step as failed and still runs every later step', async () => {
    const { deps } = fixture();
    deps.consolidate = () => { throw new Error('consolidate exploded'); };
    const report = await maintain({}, deps);
    expect(report.steps.consolidate.status).toBe('failed');
    expect(report.steps.embed.status).toBe('ran');
    expect(report.steps.vacuum.status).toBe('ran');
    expect(report.steps.doctor.status).toBe('ran');
    expect(report.steps.doctor.results.some(r => r.label === 'Maintenance consolidate' && r.status === 'fail')).toBe(true);
    expect(report.exitCode).toBe(1);
    expect(report.steps.notify.reason).toBe('not-configured');
  });

  it('turns a throwing doctor into a reported FAIL with exit 1', async () => {
    const { deps } = fixture();
    deps.doctor = async () => { throw new Error('doctor exploded'); };
    const report = await maintain({}, deps);
    expect(report.steps.doctor.status).toBe('failed');
    expect(report.failures).toBe(1);
    expect(report.exitCode).toBe(1);
  });

  it('throttles each FAIL set across an A/B/A sequence and expires it after 24 hours', async () => {
    const { deps } = fixture();
    let label = 'A';
    let now = new Date('2026-10-14T00:00:00Z');
    const sent: string[] = [];
    deps.doctor = async () => [{ label, status: 'fail', message: 'local value' }];
    deps.now = () => now;
    deps.notifier = async checks => { sent.push(checks[0].label); return true; };
    expect((await maintain({}, deps)).steps.notify.status).toBe('ran');
    label = 'B';
    expect((await maintain({}, deps)).steps.notify.status).toBe('ran');
    label = 'A';
    expect((await maintain({}, deps)).steps.notify.reason).toBe('throttled');
    expect(sent).toEqual(['A', 'B']);
    now = new Date(now.getTime() + 86_400_000);
    expect((await maintain({}, deps)).steps.notify.status).toBe('ran');
    expect(sent).toEqual(['A', 'B', 'A']);
    expect(JSON.parse(fs.readFileSync(path.join(dir, 'state', 'maintain-notify.json'), 'utf8')).sent).toEqual({ A: now.getTime() });
  });

  it('reads the legacy single-entry throttle state', async () => {
    const { deps } = fixture();
    const now = new Date('2026-10-14T00:00:00Z');
    const state = path.join(dir, 'state', 'maintain-notify.json');
    fs.mkdirSync(path.dirname(state), { recursive: true });
    fs.writeFileSync(state, JSON.stringify({ fingerprint: 'A', sentAt: now.getTime() }));
    deps.now = () => now;
    deps.doctor = async () => [{ label: 'A', status: 'fail', message: 'local only' }];
    const notify = jest.fn<() => Promise<boolean>>().mockResolvedValue(true);
    deps.notifier = notify;
    expect((await maintain({}, deps)).steps.notify.reason).toBe('throttled');
    expect(notify).not.toHaveBeenCalled();
  });

  it.each(['null', '[]', '42'])('treats a %s notification state root as no earlier delivery', async stored => {
    const { deps } = fixture();
    const state = path.join(dir, 'state', 'maintain-notify.json');
    fs.mkdirSync(path.dirname(state), { recursive: true });
    fs.writeFileSync(state, stored);
    deps.doctor = async () => [{ label: 'A', status: 'fail', message: 'local only' }];
    const notify = jest.fn<() => Promise<boolean>>().mockResolvedValue(true);
    deps.notifier = notify;
    const report = await maintain({}, deps);
    expect(report.steps.notify).toMatchObject({ status: 'ran', reason: 'sent' });
    expect(notify).toHaveBeenCalledTimes(1);
    expect(JSON.parse(fs.readFileSync(state, 'utf8')).sent.A).toEqual(expect.any(Number));
  });

  it('passes the normalised notification timeout to delivery', async () => {
    const old = process.env.SHIELDCORTEX_CONFIG_DIR;
    process.env.SHIELDCORTEX_CONFIG_DIR = dir;
    clearCloudConfigCache();
    try {
      fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard: { notify: { timeoutMs: 1234 } } }));
      const { deps } = fixture();
      deps.doctor = async () => [{ label: 'A', status: 'fail', message: 'local only' }];
      const send = jest.fn<NonNullable<MaintainDeps['channels']>[number]['send']>().mockResolvedValue({ delivered: true });
      deps.channels = [{ name: 'test', send }];
      const report = await maintain({}, deps);
      expect(report.steps.notify).toMatchObject({ status: 'ran', reason: 'sent' });
      expect(send).toHaveBeenCalledWith(expect.anything(), { timeoutMs: 1234 });
    } finally {
      if (old === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
      else process.env.SHIELDCORTEX_CONFIG_DIR = old;
      clearCloudConfigCache();
    }
  });

  it('keeps an open failure on consolidate instead of replacing it with database unavailable', async () => {
    const { deps } = fixture();
    deps.dbPath = path.join(dir, 'missing', 'cannot-open.db');
    deps.doctor = async () => [];
    const report = await maintain({ dryRun: true }, deps);
    // A missing dry-run DB is unavailable but not an open failure. A directory
    // at the DB path makes the read-only open itself throw (a garbage file
    // would open lazily and fail later, inside the consolidate query).
    expect(report.steps.consolidate.reason).toBe('database unavailable');
    fs.mkdirSync(deps.dbPath = path.join(dir, 'dir-not-db.db'));
    const failed = await maintain({ dryRun: true }, deps);
    expect(failed.steps.consolidate.status).toBe('failed');
    expect(failed.steps.consolidate.reason).not.toBe('database unavailable');
  });

  it('uses the selected DB for the disk free-page note and leaves the default DB unopened', async () => {
    const { deps } = fixture();
    const selected = path.join(dir, 'other.db');
    fs.renameSync(dbPath, selected);
    deps.dbPath = selected;
    const defaultDb = new Database(dbPath);
    defaultDb.pragma('journal_mode = WAL');
    defaultDb.exec('CREATE TABLE marker (x INTEGER)');
    defaultDb.close();
    for (const suffix of ['-wal', '-shm']) fs.rmSync(dbPath + suffix, { force: true });
    const before = { sha: sha(dbPath), mtime: fs.statSync(dbPath).mtimeMs };
    const report = await maintain({ dryRun: true }, deps);
    const disk = report.steps.doctor.results.find(r => r.label === 'Disk');
    expect(disk?.message).toMatch(/\([1-9][\d.]* [KMGT]?B free\)/);
    expect(sha(dbPath)).toBe(before.sha);
    expect(fs.statSync(dbPath).mtimeMs).toBe(before.mtime);
    expect(fs.existsSync(dbPath + '-wal')).toBe(false);
    expect(fs.existsSync(dbPath + '-shm')).toBe(false);
  });

  it('builds a signed webhook channel from the integrity-checked runtime notify block', async () => {
    const old = process.env.SHIELDCORTEX_CONFIG_DIR;
    process.env.SHIELDCORTEX_CONFIG_DIR = dir;
    clearCloudConfigCache();
    try {
      fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard: { notify: { enabled: true, webhookUrl: 'https://ops.example.test/hook', webhookSecret: 's3cret' } } }));
      const requests: Array<{ body: string; headers: Record<string, string> }> = [];
      const fetchImpl = (async (_url: string, init: RequestInit) => {
        requests.push({ body: String(init.body), headers: init.headers as Record<string, string> });
        return { ok: true, status: 200 } as Response;
      }) as typeof fetch;
      const channels = await configuredChannels(fetchImpl);
      expect(channels).toHaveLength(1);
      await channels[0].send({ event: 'maintenance_fail', checks: [] } as Parameters<typeof channels[0]['send']>[0], { timeoutMs: 1000 });
      expect(requests).toHaveLength(1);
      expect(requests[0].headers['X-ShieldCortex-Signature']).toBe(createHmac('sha256', 's3cret').update(requests[0].body).digest('hex'));
    } finally {
      if (old === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
      else process.env.SHIELDCORTEX_CONFIG_DIR = old;
      clearCloudConfigCache();
    }
  });

  it('dry-runs an unsigned memory config without changing any HOME file', async () => {
    const home = path.join(dir, 'home');
    const configDir = path.join(home, '.shieldcortex');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ memory: { maxShortTermMemories: 20 } }));
    const snapshot = (): Record<string, { size: number; sha256: string; mtimeMs: number }> => {
      const found: Record<string, { size: number; sha256: string; mtimeMs: number }> = {};
      const walk = (folder: string): void => {
        for (const item of fs.readdirSync(folder, { withFileTypes: true })) {
          const file = path.join(folder, item.name);
          if (item.isDirectory()) walk(file);
          else { const stat = fs.statSync(file); found[path.relative(home, file)] = { size: stat.size, sha256: sha(file), mtimeMs: stat.mtimeMs }; }
        }
      };
      walk(home);
      return found;
    };
    const oldHome = process.env.HOME;
    const oldConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
    process.env.HOME = home;
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    clearCloudConfigCache();
    try {
      const before = snapshot();
      const report = await maintain({ dryRun: true }, { dbPath, doctor: async () => [] });
      expect(report.steps.consolidate.status).toBe('skipped');
      expect(snapshot()).toEqual(before);
      expect(fs.existsSync(path.join(configDir, '.integrity-key'))).toBe(false);
      expect(fs.readFileSync(path.join(configDir, 'config.json'), 'utf8')).not.toContain('_sig');
    } finally {
      if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome;
      if (oldConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR; else process.env.SHIELDCORTEX_CONFIG_DIR = oldConfigDir;
      clearCloudConfigCache();
    }
  });

});
