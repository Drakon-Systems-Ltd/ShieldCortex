/**
 * Failing-first spec for #163 — permissions on our own state.
 *
 * Measured on a live production box, default install, nothing hand-modified:
 * `~/.shieldcortex` 775, `memories.db` 644, `audit/` 775, config backups 664.
 * No code set a mode on any of them.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  secureStatePermissions,
  auditStatePermissions,
  SECURE_DIR_MODE,
  SECURE_FILE_MODE,
} from '../state-permissions.js';

let dir: string;
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-perms-')); });
afterEach(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ } });

const modeOf = (p: string) => fs.statSync(p).mode & 0o777;

/** Recreate the exact state measured on the live box. */
function buildLooseState(): void {
  fs.chmodSync(dir, 0o775);
  fs.writeFileSync(path.join(dir, 'memories.db'), 'db');
  fs.chmodSync(path.join(dir, 'memories.db'), 0o644);
  fs.mkdirSync(path.join(dir, 'audit'));
  fs.chmodSync(path.join(dir, 'audit'), 0o775);
  fs.mkdirSync(path.join(dir, 'approvals'));
  fs.chmodSync(path.join(dir, 'approvals'), 0o775);
  fs.writeFileSync(path.join(dir, 'config.json.bak-20260506'), '{}');
  fs.chmodSync(path.join(dir, 'config.json.bak-20260506'), 0o664);
}

describe('#163 — the state directory is brought to owner-only', () => {
  it('hardens the exact live state: dir 775, db 644, audit 775, backup 664', () => {
    buildLooseState();
    const findings = secureStatePermissions(dir);

    expect(modeOf(dir)).toBe(SECURE_DIR_MODE);
    expect(modeOf(path.join(dir, 'memories.db'))).toBe(SECURE_FILE_MODE);
    expect(modeOf(path.join(dir, 'audit'))).toBe(SECURE_DIR_MODE);
    expect(modeOf(path.join(dir, 'approvals'))).toBe(SECURE_DIR_MODE);
    expect(modeOf(path.join(dir, 'config.json.bak-20260506'))).toBe(SECURE_FILE_MODE);

    // Every correction is REPORTED, not silently applied.
    const paths = findings.map(f => path.basename(f.path)).sort();
    expect(paths).toContain('memories.db');
    expect(paths).toContain('audit');
    expect(paths).toContain('config.json.bak-20260506');
    expect(findings.every(f => f.fixed)).toBe(true);
  });

  it('covers WAL/shm siblings and every backup, not just the live database', () => {
    // A protection the backup path does not inherit is a protection with a
    // scheduled expiry.
    for (const name of ['memories.db', 'memories.db-wal', 'memories.db-shm', 'memories.db.bak.2026-08-01T00-00-00-000Z']) {
      fs.writeFileSync(path.join(dir, name), 'x');
      fs.chmodSync(path.join(dir, name), 0o644);
    }
    secureStatePermissions(dir);
    for (const name of ['memories.db', 'memories.db-wal', 'memories.db-shm', 'memories.db.bak.2026-08-01T00-00-00-000Z']) {
      expect(modeOf(path.join(dir, name))).toBe(SECURE_FILE_MODE);
    }
  });

  it('is idempotent and reports nothing on an already-hardened tree', () => {
    buildLooseState();
    secureStatePermissions(dir);
    expect(secureStatePermissions(dir)).toEqual([]);
  });

  it('never loosens a directory or file that is already tighter than required', () => {
    fs.chmodSync(dir, 0o700);
    fs.writeFileSync(path.join(dir, 'memories.db'), 'db');
    fs.chmodSync(path.join(dir, 'memories.db'), 0o400);   // read-only, tighter
    secureStatePermissions(dir);
    expect(modeOf(path.join(dir, 'memories.db'))).toBe(0o400);
  });

  it('does nothing at all when the state directory does not exist', () => {
    const absent = path.join(dir, 'nope');
    expect(secureStatePermissions(absent)).toEqual([]);
  });

  it('ignores files that are not ours', () => {
    fs.writeFileSync(path.join(dir, 'unrelated.txt'), 'x');
    fs.chmodSync(path.join(dir, 'unrelated.txt'), 0o644);
    secureStatePermissions(dir);
    expect(modeOf(path.join(dir, 'unrelated.txt'))).toBe(0o644);
  });
});

describe('#163 — doctor measures without mutating', () => {
  it('reports the too-open paths and changes nothing', () => {
    buildLooseState();
    const before = modeOf(path.join(dir, 'memories.db'));
    const findings = auditStatePermissions(dir);

    expect(findings.length).toBeGreaterThan(0);
    const db = findings.find(f => f.path.endsWith('memories.db'));
    expect(db).toBeDefined();
    expect(db?.found).toBe('644');
    expect(db?.required).toBe('600');
    // Measured, not assumed — and not corrected behind the operator's back.
    expect(modeOf(path.join(dir, 'memories.db'))).toBe(before);
  });

  it('reports nothing once the tree is hardened', () => {
    buildLooseState();
    secureStatePermissions(dir);
    expect(auditStatePermissions(dir)).toEqual([]);
  });
});
