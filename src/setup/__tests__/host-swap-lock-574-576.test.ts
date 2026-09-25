import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { acquireUpdateLock, updateLockPath } from '../host-swap.js';

/**
 * #574 / #576 round 4 — the one write lock, after review took apart the two
 * things round 3 let it do.
 *
 * Blocker 2: it RECLAIMED a lock whose pid was dead and whose stamp was over
 * ten minutes old, by reading the file and then unlinking the pathname. Two
 * contenders can both pass the read, and the second one's `unlink` then
 * deletes the first one's brand-new LIVE lock. An unlink by pathname after a
 * read cannot establish ownership of whatever is at that pathname now.
 *
 * Nit 1: `release()` identified ownership by pid alone, so acquire A, release
 * A, acquire B, release A again deleted B's lock inside one process.
 *
 * Blocker 4: the symlink preflight ran after the lock was created, so a
 * symlinked `~/.openclaw` was followed, the lock found there was deleted and
 * ours was written in its place — and only then was the symlink refused.
 */
let root: string;
const FROZEN = new Date('2026-09-24T12:34:56.789Z');

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-lock-'));
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

describe('acquireUpdateLock — mutual exclusion (#574/#576 r3 blocker 2)', () => {
  it('refuses a second acquisition while the first is held', () => {
    const first = acquireUpdateLock(root, { now: FROZEN });
    expect('lock' in first).toBe(true);

    const second = acquireUpdateLock(root, { now: FROZEN });

    expect('busy' in second).toBe(true);
    expect((second as { busy: string }).busy).toMatch(/another ShieldCortex update\/install is running/);
  });

  it('never removes an existing lock, however stale it looks', () => {
    // Dead pid (2^22 is above every Linux default `pid_max`), stamp an hour
    // old, and a token from nowhere. Round 3 deleted exactly this file.
    const lock = updateLockPath(root);
    const body = `shieldcortex-update 4194304 2026-09-24T11:00:00.000Z abc\n`;
    fs.writeFileSync(lock, body);

    const result = acquireUpdateLock(root, { now: FROZEN });

    expect('busy' in result).toBe(true);
    expect(fs.readFileSync(lock, 'utf-8')).toBe(body);
  });

  it('reports the recorded pid and time, and promises no expiry', () => {
    fs.writeFileSync(updateLockPath(root), 'shieldcortex-update 4194304 2026-09-24T11:00:00.000Z abc\n');

    const { busy } = acquireUpdateLock(root, { now: FROZEN }) as { busy: string };

    expect(busy).toContain(updateLockPath(root));
    expect(busy).toMatch(/recorded pid 4194304/);
    expect(busy).toMatch(/taken 2026-09-24T11:00:00\.000Z/);
    expect(busy).toMatch(/nothing removes it for you/);
    expect(busy).not.toMatch(/ten minutes/);
  });

  it('refuses an unparseable lock too, and says there is no run to identify', () => {
    // The SIGKILL-between-create-and-write state: a file no age check clears.
    fs.writeFileSync(updateLockPath(root), '');

    const { busy } = acquireUpdateLock(root, { now: FROZEN }) as { busy: string };

    expect(busy).toMatch(/not a lock record/);
    expect(fs.readFileSync(updateLockPath(root), 'utf-8')).toBe('');
  });

  it('refuses a symlink at the lock path rather than following or replacing it', () => {
    const victim = path.join(root, 'victim.txt');
    fs.writeFileSync(victim, 'important\n');
    fs.symlinkSync(victim, updateLockPath(root));

    const result = acquireUpdateLock(root, { now: FROZEN });

    expect('busy' in result).toBe(true);
    expect(fs.readFileSync(victim, 'utf-8')).toBe('important\n');
    expect(fs.lstatSync(updateLockPath(root)).isSymbolicLink()).toBe(true);
  });
});

describe('UpdateLock.release — only ever the file it created (#574/#576 r3 nit 1)', () => {
  it('releasing a stale handle does not delete the lock that replaced it', () => {
    const a = acquireUpdateLock(root, { now: FROZEN });
    expect('lock' in a).toBe(true);
    (a as { lock: { release(): void } }).lock.release();
    expect(fs.existsSync(updateLockPath(root))).toBe(false);

    const b = acquireUpdateLock(root, { now: FROZEN });
    expect('lock' in b).toBe(true);
    const bBody = fs.readFileSync(updateLockPath(root), 'utf-8');

    // The same process, the same pid, a second release of the FIRST handle.
    (a as { lock: { release(): void } }).lock.release();

    expect(fs.existsSync(updateLockPath(root))).toBe(true);
    expect(fs.readFileSync(updateLockPath(root), 'utf-8')).toBe(bBody);
    // And B can still give its own lock back.
    (b as { lock: { release(): void } }).lock.release();
    expect(fs.existsSync(updateLockPath(root))).toBe(false);
  });

  it('does not delete a lock somebody else wrote at the same path', () => {
    const a = acquireUpdateLock(root, { now: FROZEN }) as { lock: { release(): void } };
    const other = 'shieldcortex-update 4194304 2026-09-24T11:00:00.000Z somebody-else\n';
    fs.writeFileSync(updateLockPath(root), other);

    a.lock.release();

    expect(fs.readFileSync(updateLockPath(root), 'utf-8')).toBe(other);
  });
});

describe('the integration root is validated before the lock exists (#574/#576 r3 blocker 4)', () => {
  it('refuses a symlinked root, writing nothing — not even a lock', () => {
    const real = path.join(root, 'real');
    const linked = path.join(root, 'linked');
    fs.mkdirSync(real);
    // Somebody else's lock, inside the tree the link points at. Round 3
    // followed the link, DELETED this file and wrote its own there.
    const foreign = 'shieldcortex-update 4194304 2026-09-24T11:00:00.000Z foreign\n';
    fs.writeFileSync(updateLockPath(real), foreign);
    fs.symlinkSync(real, linked);

    const result = acquireUpdateLock(linked, { now: FROZEN, bound: root });

    expect('busy' in result).toBe(true);
    expect((result as { busy: string }).busy).toMatch(/is a symlink; nothing written/);
    expect(fs.readFileSync(updateLockPath(real), 'utf-8')).toBe(foreign);
    expect(fs.readdirSync(real)).toEqual(['.shieldcortex-update.lock']);
  });

  it('refuses a symlinked component between the bound and the root', () => {
    // `<root>/profiles` -> elsewhere, with the profile root underneath it:
    // the Hermes profile shape, where the root itself is a real directory.
    const elsewhere = path.join(root, 'elsewhere');
    fs.mkdirSync(path.join(elsewhere, 'work'), { recursive: true });
    fs.symlinkSync(elsewhere, path.join(root, 'profiles'));

    const result = acquireUpdateLock(path.join(root, 'profiles', 'work'), { now: FROZEN, bound: root });

    expect('busy' in result).toBe(true);
    expect(fs.readdirSync(path.join(elsewhere, 'work'))).toEqual([]);
  });

  it('refuses a symlinked root before creating it, when createRoot is asked for', () => {
    const real = path.join(root, 'real');
    const linked = path.join(root, '.hermes');
    fs.mkdirSync(real);
    fs.symlinkSync(real, linked);

    const result = acquireUpdateLock(linked, { now: FROZEN, createRoot: true });

    expect('busy' in result).toBe(true);
    expect(fs.readdirSync(real)).toEqual([]);
  });

  it('still creates a root that is simply absent', () => {
    const fresh = path.join(root, '.hermes');

    const result = acquireUpdateLock(fresh, { now: FROZEN, createRoot: true });

    expect('lock' in result).toBe(true);
    expect(fs.lstatSync(fresh).isDirectory()).toBe(true);
  });
});
