/**
 * Failing-first spec for #148 — a maintenance backup must not consume the
 * operator's entire disk budget.
 *
 * Live on a fleet box, 31 Jul 2026: `doctor` warned about a project-key
 * collision and recommended `--fix-project-keys`. That repair copied the whole
 * 48 MB database as a backup with no headroom check, taking the host from
 * 51.7 MB to 98.8 MB against its own 100 MB limit — so the very next `doctor`
 * reported a disk FAILURE caused by the fix it had just told the operator to
 * run. Clearing it did not help: the next repair recreated it. Not winnable
 * by hand.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  planBackup,
  pruneOldBackups,
  BACKUP_SUFFIX_RE,
} from '../backup-budget.js';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'sc-backup-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

/** Create a file of an exact size. */
function file(name: string, bytes: number): string {
  const p = join(dir, name);
  writeFileSync(p, Buffer.alloc(bytes));
  return p;
}

const MB = 1024 * 1024;

describe('#148 — the backup is planned against the disk budget', () => {
  it('proceeds when there is comfortable headroom', () => {
    const db = file('memories.db', 10 * MB);
    const plan = planBackup({ dbPath: db, dir, limitBytes: 100 * MB });
    expect(plan.action).toBe('backup');
  });

  it('prunes an older backup rather than refusing, when pruning creates room', () => {
    const db = file('memories.db', 48 * MB);
    file('memories.db.bak.2026-07-31T15-27-33-553Z', 48 * MB); // the live incident
    const plan = planBackup({ dbPath: db, dir, limitBytes: 100 * MB });
    expect(plan.action).toBe('backup');
    expect(plan.prune.length).toBe(1);
    expect(plan.prune[0]).toContain('.bak.');
  });

  it('REFUSES rather than filling the budget when even pruning cannot make room', () => {
    // A 60 MB DB cannot be backed up inside a 100 MB budget: 60 live + 60 copy.
    const db = file('memories.db', 60 * MB);
    const plan = planBackup({ dbPath: db, dir, limitBytes: 100 * MB });
    expect(plan.action).toBe('refuse');
    expect(plan.reason).toMatch(/headroom|budget|limit/i);
  });

  it('the refusal names a way forward rather than just saying no', () => {
    const db = file('memories.db', 60 * MB);
    const plan = planBackup({ dbPath: db, dir, limitBytes: 100 * MB });
    expect(plan.action).toBe('refuse');
    expect(plan.reason.length).toBeGreaterThan(20);
  });

  it('the exact live case: 48MB DB in a 100MB budget with one old backup — proceeds after pruning', () => {
    const db = file('memories.db', 48 * MB);
    file('memories.db.bak.2026-07-31T15-27-33-553Z', 48 * MB);
    const plan = planBackup({ dbPath: db, dir, limitBytes: 100 * MB });
    expect(plan.action).toBe('backup');
    // 48 live + 48 new copy = 96 < 100, but ONLY once the old one goes.
    expect(plan.prune.length).toBeGreaterThan(0);
  });

  it('counts every file in the directory toward the budget, not just the DB', () => {
    const db = file('memories.db', 30 * MB);
    file('audit.log', 45 * MB);
    const plan = planBackup({ dbPath: db, dir, limitBytes: 100 * MB });
    // 30 live + 45 other + 30 copy = 105 > 100, and there is no backup to prune.
    expect(plan.action).toBe('refuse');
  });
});

describe('#148 — old backups are pruned, which doctor already claimed happened', () => {
  it('keeps the newest and removes the rest', () => {
    file('memories.db', 1 * MB);
    file('memories.db.bak.2026-07-29T10-00-00-000Z', MB);
    file('memories.db.bak.2026-07-30T10-00-00-000Z', MB);
    file('memories.db.bak.2026-07-31T10-00-00-000Z', MB);
    const removed = pruneOldBackups(dir, 'memories.db', 1);
    expect(removed.length).toBe(2);
    const left = readdirSync(dir).filter(f => BACKUP_SUFFIX_RE.test(f));
    expect(left).toEqual(['memories.db.bak.2026-07-31T10-00-00-000Z']);
  });

  it('keep=0 removes them all', () => {
    file('memories.db', 1 * MB);
    file('memories.db.bak.2026-07-30T10-00-00-000Z', MB);
    expect(pruneOldBackups(dir, 'memories.db', 0).length).toBe(1);
  });

  it('never touches the live database', () => {
    const db = file('memories.db', 1 * MB);
    file('memories.db.bak.2026-07-30T10-00-00-000Z', MB);
    pruneOldBackups(dir, 'memories.db', 0);
    expect(statSync(db).size).toBe(1 * MB);
  });

  it('never touches WAL, shm or lock siblings', () => {
    file('memories.db', MB);
    file('memories.db-wal', MB);
    file('memories.db-shm', MB);
    file('memories.db.lock', 100);
    pruneOldBackups(dir, 'memories.db', 0);
    const left = readdirSync(dir).sort();
    expect(left).toEqual(['memories.db', 'memories.db-shm', 'memories.db-wal', 'memories.db.lock']);
  });

  it('is safe on a directory with no backups at all', () => {
    file('memories.db', MB);
    expect(pruneOldBackups(dir, 'memories.db', 1)).toEqual([]);
  });

  it('only matches OUR backup shape', () => {
    expect(BACKUP_SUFFIX_RE.test('memories.db.bak.2026-07-31T10-00-00-000Z')).toBe(true);
    expect(BACKUP_SUFFIX_RE.test('memories.db')).toBe(false);
    expect(BACKUP_SUFFIX_RE.test('memories.db-wal')).toBe(false);
    expect(BACKUP_SUFFIX_RE.test('somebody-elses.backup')).toBe(false);
  });
});
