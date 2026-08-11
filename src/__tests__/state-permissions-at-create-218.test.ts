import { mkdtempSync, rmSync, mkdirSync, statSync, openSync, closeSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import {
  mkdirSecure,
  SECURE_OPEN_MODE,
  SECURE_DIR_MODE,
  secureStatePermissions,
} from '../setup/state-permissions.js';

/**
 * #218 — create state-tree paths owner-only at CREATION, so a runtime that
 * recreates a lock file or a log dir after the install-time hardening pass no
 * longer lands loose and fails doctor after every gateway restart.
 *
 * The reported loop: closeDatabase() unlinks memories.db.lock on every clean
 * shutdown; initDatabase() recreates it via openSync('wx'). With no mode that
 * is 0666 & ~umask (644/664), which auditStatePermissions flags and doctor
 * turns into a hard fail — green, one restart, red, forever.
 *
 * These assert the two create primitives, and that secureStatePermissions
 * still retro-tightens an already-loose path (the create-mode cannot, so the
 * install/update/repair pass is still load-bearing).
 *
 * mode & 0o777 masks the file-type bits; skipped on Windows where POSIX modes
 * are not meaningful.
 */
const isWindows = process.platform === 'win32';
const d = isWindows ? describe.skip : describe;

function modeOf(p: string): number {
  return statSync(p).mode & 0o777;
}

d('#218 — owner-only at creation', () => {
  let root: string;
  beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'sc-perms-218-')); });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); });

  it('mkdirSecure creates a directory at 0700', () => {
    const dir = join(root, 'audit');
    mkdirSecure(dir);
    expect(modeOf(dir)).toBe(SECURE_DIR_MODE);
    expect(modeOf(dir)).toBe(0o700);
  });

  it('mkdirSecure applies the mode to every parent it creates', () => {
    // recursive mkdir sets the mode on each level it makes — the whole new
    // subtree is owner-only, not just the leaf.
    const nested = join(root, 'a', 'b', 'c');
    mkdirSecure(nested);
    expect(modeOf(join(root, 'a'))).toBe(0o700);
    expect(modeOf(join(root, 'a', 'b'))).toBe(0o700);
    expect(modeOf(nested)).toBe(0o700);
  });

  it('a file opened with SECURE_OPEN_MODE lands at 0600 — the lock-file fix', () => {
    // Mirrors init.ts acquireStartupLock: openSync(path, 'wx', SECURE_OPEN_MODE).
    const lock = join(root, 'memories.db.lock');
    const fd = openSync(lock, 'wx', SECURE_OPEN_MODE);
    closeSync(fd);
    expect(modeOf(lock)).toBe(0o600);
  });

  it('reproduces the reported regression: a mode-LESS open lands loose', () => {
    // The bug, pinned so a future edit that drops the mode arg is caught here.
    const lock = join(root, 'loose.lock');
    const fd = openSync(lock, 'wx');   // no mode — 0666 & ~umask
    closeSync(fd);
    expect(modeOf(lock) & 0o077).not.toBe(0);   // group/other bits present
  });
});

d('#218 — the create-mode does NOT retro-tighten, so the pass is still needed', () => {
  let root: string;
  beforeEach(() => { root = mkdtempSync(join(tmpdir(), 'sc-perms-218b-')); });
  afterEach(() => { rmSync(root, { recursive: true, force: true }); });

  it('mkdirSecure is a no-op on a directory that already exists loose', () => {
    // This is WHY secureStatePermissions must keep running on install/update/
    // repair: a box hardened loose once cannot self-correct via create-mode.
    const dir = join(root, 'audit');
    mkdirSync(dir, { mode: 0o777 });
    const before = modeOf(dir);
    mkdirSecure(dir);
    expect(modeOf(dir)).toBe(before);   // unchanged — mkdir mode ignored for existing
    expect(modeOf(dir) & 0o077).not.toBe(0);
  });

  it('secureStatePermissions retro-tightens the loose dir', () => {
    // The repair/install/update leg: given the loose dir above, the pass fixes it.
    mkdirSync(join(root, 'audit'), { mode: 0o777 });
    const findings = secureStatePermissions(root);
    expect(findings.some(f => f.path.endsWith('audit') && f.fixed)).toBe(true);
    expect(modeOf(join(root, 'audit')) & 0o077).toBe(0);
  });
});
