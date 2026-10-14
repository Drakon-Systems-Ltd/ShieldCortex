import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { initDatabase, closeDatabase } from '../../database/init.js';
import { checkDiskUsage, runMemoryStatsCheck, runSemanticCoverageCheck, type CheckResult } from '../doctor.js';
import { maintain, type MaintainDeps } from '../maintain.js';

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
    expect(report.steps.embed.status).toBe('ran');
    expect(report.steps.vacuum.reason).toBe('locked');
    expect(report.steps.doctor.status).toBe('ran');
    expect(report.steps.doctor.results.some(r => r.label.startsWith('Maintenance'))).toBe(false);
    expect(report.steps.notify.reason).toBe('not-configured');
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

});
