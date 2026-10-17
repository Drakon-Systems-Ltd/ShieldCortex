/**
 * #763 — the startup lock is ownership-safe across publication, stale
 * takeover and release.
 *
 * Interleavings are made deterministic without any production seam: `fs` is
 * replaced by the real module with `linkSync` / `renameSync` / `openSync`
 * wrapped, so a test can run "another process" at the exact point between two
 * syscalls of acquireStartupLock — after the record is written but before it
 * is published, and after a stale record is read but before it is removed.
 * `writeFileSync` / `openSync` can also fail or stall the no-hard-link
 * fallback's write and the read of a record moved aside. Every other call
 * falls through to the real filesystem.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import * as realFs from 'fs';
import os from 'node:os';
import path from 'node:path';

type Hook = (src: string, dest: string) => void;
const hooks: {
  beforeLockLink?: Hook;
  beforeLockRename?: Hook;
  /** Runs before the record moved aside is linked back to the lock path. */
  beforeAsideLink?: Hook;
  /** One-shot link error on the lock path. */
  linkError?: string;
  /** Every link to the lock path fails with this code (a filesystem without hard links). */
  linkErrorAlways?: string;
  failTempOpen?: boolean;
  /** One-shot EIO from the exclusive create of the lock path. */
  failLockCreate?: boolean;
  /** One-shot EACCES opening a record moved aside. */
  failAsideRead?: boolean;
  /** Runs before the no-hard-link fallback writes its record. */
  beforeLockWrite?: Hook;
  /** One-shot error from the no-hard-link fallback's write. */
  lockWriteError?: string;
  /** Runs before every read-only open of the lock path. */
  beforeLockRead?: () => void;
  /** Runs after every read-only open of the lock path returns its descriptor. */
  afterLockRead?: () => void;
} = {};

const isLock = (p: unknown): boolean => String(p).endsWith('.lock');
const isAside = (p: unknown): boolean => String(p).endsWith('.aside');
const fail = (code: string, what: string): never => {
  throw Object.assign(new Error(`${code}: ${what}`), { code });
};
const take = <K extends 'beforeLockLink' | 'beforeLockRename' | 'beforeAsideLink' | 'beforeLockWrite'>(key: K): Hook | undefined => {
  const hook = hooks[key];
  hooks[key] = undefined;
  return hook;
};

const linkSync = ((src: realFs.PathLike, dest: realFs.PathLike) => {
  if (isLock(dest)) {
    if (isAside(src)) take('beforeAsideLink')?.(String(src), String(dest));
    else take('beforeLockLink')?.(String(src), String(dest));
    if (hooks.linkErrorAlways) fail(hooks.linkErrorAlways, `link '${String(src)}'`);
    if (hooks.linkError) {
      const code = hooks.linkError;
      hooks.linkError = undefined;
      fail(code, `link '${String(src)}'`);
    }
  }
  return realFs.linkSync(src, dest);
}) as typeof realFs.linkSync;

const renameSync = ((src: realFs.PathLike, dest: realFs.PathLike) => {
  if (isLock(src)) take('beforeLockRename')?.(String(src), String(dest));
  return realFs.renameSync(src, dest);
}) as typeof realFs.renameSync;

/** Descriptors the no-hard-link fallback opened on the lock path. */
const lockCreateFds = new Set<number>();
const openSync = ((p: realFs.PathLike, ...rest: unknown[]) => {
  if (hooks.failTempOpen && String(p).endsWith('.tmp')) {
    hooks.failTempOpen = false;
    fail('EACCES', `open '${String(p)}'`);
  }
  if (isLock(p) && rest[0] === 'wx' && hooks.failLockCreate) {
    hooks.failLockCreate = false;
    fail('EIO', `open '${String(p)}'`);
  }
  if (isAside(p) && hooks.failAsideRead) {
    hooks.failAsideRead = false;
    fail('EACCES', `open '${String(p)}'`);
  }
  if (isLock(p) && rest[0] === 'r') hooks.beforeLockRead?.();
  const fd = (realFs.openSync as (...args: unknown[]) => number)(p, ...rest);
  if (isLock(p) && rest[0] === 'r') hooks.afterLockRead?.();
  if (isLock(p) && rest[0] === 'wx') lockCreateFds.add(fd);
  return fd;
}) as typeof realFs.openSync;

const writeFileSync = ((file: unknown, ...rest: unknown[]) => {
  if (typeof file === 'number' && lockCreateFds.has(file)) {
    lockCreateFds.delete(file);
    take('beforeLockWrite')?.(String(file), lockPath);
    if (hooks.lockWriteError) {
      const code = hooks.lockWriteError;
      hooks.lockWriteError = undefined;
      fail(code, 'write');
    }
  }
  return (realFs.writeFileSync as (...args: unknown[]) => void)(file, ...rest);
}) as typeof realFs.writeFileSync;

const mocked = { ...realFs, linkSync, renameSync, openSync, writeFileSync };
jest.unstable_mockModule('fs', () => ({ ...mocked, default: mocked }));

const { initDatabase, closeDatabase, holdsStartupLock, isDatabaseInitialized, StartupLockHeldError, __databaseTestUtils } = await import('../init.js');
const { maintain } = await import('../../cli/maintain.js');

const DEAD_PID = 2_000_000_001;
const EPERM_PID = 2_000_000_002;

let dir: string;
let dbPath: string;
let lockPath: string;
let errorSpy: ReturnType<typeof jest.spyOn>;
let killSpy: ReturnType<typeof jest.spyOn>;

const record = (pid: number, entryPath = '/tmp/other-shieldcortex.js'): string =>
  JSON.stringify({ pid, startedAt: new Date().toISOString(), entryPath, nonce: `foreign-${pid}-${Math.random()}` }, null, 2);
/** Publish a lock record the way an unrelated process would. */
const writeForeign = (body: string): void => {
  realFs.rmSync(lockPath, { force: true });
  realFs.writeFileSync(lockPath, body);
};
const age = (seconds: number): void => {
  const then = new Date(Date.now() - seconds * 1000);
  realFs.utimesSync(lockPath, then, then);
};
/** Lock temp / aside files left behind (anything derived from the lock name). */
const strays = (): string[] => realFs.readdirSync(dir).filter(name => name.startsWith('memories.db.lock.'));
/** Contents of every record left at an aside name. */
const asides = (): string[] => strays().filter(isAside).map(name => realFs.readFileSync(path.join(dir, name), 'utf8'));
const continuedAnyway = (): boolean =>
  errorSpy.mock.calls.some((call: unknown[]) => String(call[0]).includes('continuing anyway (SQLite WAL handles concurrency)'));
const acquire = (refuseIfLocked?: boolean): void => __databaseTestUtils.acquireStartupLock(dbPath, refuseIfLocked);

beforeEach(() => {
  dir = realFs.mkdtempSync(path.join(os.tmpdir(), 'sc-lock-763-'));
  dbPath = path.join(dir, 'memories.db');
  lockPath = `${dbPath}.lock`;
  errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  const realKill = process.kill.bind(process);
  killSpy = jest.spyOn(process, 'kill').mockImplementation(((pid: number, signal?: string | number) => {
    if (pid === DEAD_PID) throw Object.assign(new Error('kill ESRCH'), { code: 'ESRCH' });
    if (pid === EPERM_PID) throw Object.assign(new Error('kill EPERM'), { code: 'EPERM' });
    return realKill(pid, signal);
  }) as typeof process.kill);
});

afterEach(() => {
  for (const key of Object.keys(hooks) as (keyof typeof hooks)[]) hooks[key] = undefined;
  lockCreateFds.clear();
  closeDatabase();
  errorSpy.mockRestore();
  killSpy.mockRestore();
  realFs.rmSync(dir, { recursive: true, force: true });
});

describe('#763 lock publication', () => {
  it('publishes a complete record atomically and releases only that record', () => {
    let seenInWindow: { lockExists: boolean; temp: string } | null = null;
    hooks.beforeLockLink = (src) => {
      seenInWindow = { lockExists: realFs.existsSync(lockPath), temp: realFs.readFileSync(src, 'utf8') };
    };
    acquire();
    expect(holdsStartupLock()).toBe(true);
    const published = realFs.readFileSync(lockPath, 'utf8');
    // Before the link, the lock path did not exist and the temp file already
    // held the full record — a reader can never observe a partial lock.
    expect(seenInWindow).toEqual({ lockExists: false, temp: published });
    const parsed = JSON.parse(published) as { pid: number; nonce: string; startedAt: string };
    expect(parsed.pid).toBe(process.pid);
    expect(typeof parsed.nonce).toBe('string');
    expect(strays()).toEqual([]);
    closeDatabase();
    expect(realFs.existsSync(lockPath)).toBe(false);
    expect(strays()).toEqual([]);
  });

  it('does not take over a lock another process publishes inside the temp-then-link window', () => {
    const foreign = record(process.pid);
    hooks.beforeLockLink = () => writeForeign(foreign);
    acquire();
    expect(holdsStartupLock()).toBe(false);
    expect(continuedAnyway()).toBe(true);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
    expect(strays()).toEqual([]);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
  });

  it('treats a fresh empty or partial lock (publisher still writing) as held, not stale', () => {
    writeForeign('');
    acquire();
    expect(holdsStartupLock()).toBe(false);
    expect(continuedAnyway()).toBe(true);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe('');

    writeForeign('{"pid": 12');
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe('{"pid": 12');
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe('{"pid": 12');
    expect(strays()).toEqual([]);
  });

  it('still takes over an old malformed lock', () => {
    writeForeign('not json');
    age(60);
    acquire(true);
    expect(holdsStartupLock()).toBe(true);
    expect(JSON.parse(realFs.readFileSync(lockPath, 'utf8')).pid).toBe(process.pid);
    expect(strays()).toEqual([]);
  });

  it('falls back to exclusive create when the filesystem has no hard links', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    acquire();
    expect(holdsStartupLock()).toBe(true);
    expect(JSON.parse(realFs.readFileSync(lockPath, 'utf8')).pid).toBe(process.pid);
    expect(strays()).toEqual([]);
    closeDatabase();
    expect(realFs.existsSync(lockPath)).toBe(false);
  });
});

describe('#763 no-hard-link fallback publication', () => {
  it('does not claim a record whose path was replaced before its write finished', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    const live = record(process.pid);
    // Stalled past the grace: another process took the empty record over.
    hooks.beforeLockWrite = () => writeForeign(live);
    acquire();
    expect(holdsStartupLock()).toBe(false);
    expect(continuedAnyway()).toBe(true);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
  });

  it('a write failure after the path was replaced leaves the replacement in place', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    const live = record(process.pid);
    hooks.beforeLockWrite = () => writeForeign(live);
    hooks.lockWriteError = 'EIO';
    expect(() => acquire()).toThrow(/EIO/);
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
  });

  it('a write failure never removes another record found at the inode it created', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    const live = record(EPERM_PID);
    // Rewritten in place, the path keeps the device and inode this call
    // created — what cleanup would see if that inode were reused by another
    // process's record — but holds bytes this call never wrote.
    hooks.beforeLockWrite = () => realFs.writeFileSync(lockPath, live);
    hooks.lockWriteError = 'EIO';
    expect(() => acquire(true)).toThrow(/EIO/);
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
  });

  it('treats a partial record with a future mtime as held, not stale', () => {
    writeForeign('{"pid": 12');
    const later = new Date(Date.now() + 60_000);
    realFs.utimesSync(lockPath, later, later);
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    acquire();
    expect(continuedAnyway()).toBe(true);
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe('{"pid": 12');
    expect(strays()).toEqual([]);
  });
});

describe('#763 a displaced record is never deleted', () => {
  it('without hard links, a live record that replaced the stale one is put back by copy', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    const live = record(EPERM_PID);
    hooks.beforeLockRename = () => writeForeign(live);
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
  });

  it('without hard links, a live record that cannot be put back is left aside and the loser does not publish', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    const live = record(EPERM_PID);
    hooks.beforeLockRename = () => { writeForeign(live); hooks.failLockCreate = true; };
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(asides()).toEqual([live]);
    expect(realFs.existsSync(lockPath)).toBe(false);
  });

  it('a same-process retry after the put-back failed does not publish while that owner is live', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    const live = record(EPERM_PID);
    hooks.beforeLockRename = () => { writeForeign(live); hooks.failLockCreate = true; };
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(asides()).toEqual([live]);

    // The put-back still fails: the vacant lock path is not taken.
    hooks.failLockCreate = true;
    expect(() => initDatabase(dbPath, { refuseIfLocked: true })).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(isDatabaseInitialized()).toBe(false);
    expect(realFs.existsSync(dbPath)).toBe(false);
    expect(realFs.existsSync(lockPath)).toBe(false);
    expect(asides()).toEqual([live]);
  });

  it('a same-process retry once the transient error clears puts the record back and does not take the lock', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    const live = record(EPERM_PID);
    hooks.beforeLockRename = () => { writeForeign(live); hooks.failLockCreate = true; };
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(asides()).toEqual([live]);

    expect(() => initDatabase(dbPath, { refuseIfLocked: true })).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(isDatabaseInitialized()).toBe(false);
    expect(realFs.existsSync(dbPath)).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
  });

  it('a displaced record whose owner has exited no longer blocks a retry', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    const gone = record(DEAD_PID);
    hooks.beforeLockRename = () => { writeForeign(gone); hooks.failLockCreate = true; };
    acquire();
    expect(holdsStartupLock()).toBe(false);
    expect(asides()).toEqual([gone]);

    hooks.failLockCreate = true;
    acquire(true);
    expect(holdsStartupLock()).toBe(true);
    expect(JSON.parse(realFs.readFileSync(lockPath, 'utf8')).pid).toBe(process.pid);
    expect(asides()).toEqual([gone]);
  });

  it('a third publisher taking the path (EEXIST) leaves both live records on disk', () => {
    writeForeign(record(DEAD_PID));
    const second = record(EPERM_PID);
    const third = record(process.pid);
    hooks.beforeLockRename = () => writeForeign(second);
    hooks.beforeAsideLink = () => writeForeign(third);
    acquire();
    expect(holdsStartupLock()).toBe(false);
    expect(continuedAnyway()).toBe(true);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(third);
    expect(asides()).toEqual([second]);
  });

  it('a record that cannot be read or put back is left aside, not deleted', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    const live = record(EPERM_PID);
    hooks.beforeLockRename = () => { writeForeign(live); hooks.failAsideRead = true; };
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(asides()).toEqual([live]);
  });

  it('release whose restore fails leaves the foreign record aside', () => {
    acquire();
    expect(holdsStartupLock()).toBe(true);
    const foreign = record(process.pid);
    // Replaced between close's ownership check and the removal.
    hooks.beforeLockRename = () => {
      writeForeign(foreign);
      hooks.linkErrorAlways = 'ENOTSUP';
      hooks.failLockCreate = true;
    };
    closeDatabase();
    expect(holdsStartupLock()).toBe(false);
    expect(asides()).toEqual([foreign]);
  });
});

describe('#763 stale takeover', () => {
  it('leaves a live record that replaced the stale one between read and takeover', () => {
    writeForeign(record(DEAD_PID));
    const live = record(process.pid);
    hooks.beforeLockRename = () => writeForeign(live);
    acquire();
    expect(holdsStartupLock()).toBe(false);
    expect(continuedAnyway()).toBe(true);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
  });

  it('refuses when a live record replaced the stale one under refuseIfLocked', () => {
    writeForeign(record(DEAD_PID));
    const live = record(EPERM_PID);
    hooks.beforeLockRename = () => writeForeign(live);
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
  });

  it('refuseIfLocked takes over a dead (ESRCH) owner and becomes owner', () => {
    writeForeign(record(DEAD_PID));
    const opened = initDatabase(dbPath, { refuseIfLocked: true });
    expect(opened.open).toBe(true);
    expect(holdsStartupLock()).toBe(true);
    expect(JSON.parse(realFs.readFileSync(lockPath, 'utf8')).pid).toBe(process.pid);
    expect(strays()).toEqual([]);
    closeDatabase();
    expect(realFs.existsSync(lockPath)).toBe(false);
  });

  it('refuseIfLocked throws for an EPERM-probed owner before opening SQLite', () => {
    const live = record(EPERM_PID);
    writeForeign(live);
    expect(() => initDatabase(dbPath, { refuseIfLocked: true })).toThrow(StartupLockHeldError);
    expect(holdsStartupLock()).toBe(false);
    expect(isDatabaseInitialized()).toBe(false);
    expect(realFs.existsSync(dbPath)).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(live);
    expect(strays()).toEqual([]);
  });

  it('a takeover whose re-publish fails leaves no lock state, so release cannot remove a foreign lock', () => {
    writeForeign(record(DEAD_PID));
    // Stale record removed, then the re-publish fails on its temp file.
    hooks.beforeLockRename = () => { hooks.failTempOpen = true; };
    expect(() => acquire()).toThrow(/EACCES/);
    expect(holdsStartupLock()).toBe(false);
    const foreign = record(process.pid);
    writeForeign(foreign);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
    expect(strays()).toEqual([]);
  });
});

describe('#813 displaced startup-lock holder', () => {
  it('stops reporting ownership after a stale reaper moves its record aside and a third starter publishes', () => {
    writeForeign(record(DEAD_PID));
    let aRecord = '';
    let bRecord = '';
    // R has already judged S stale. A removes S and acquires through the
    // real publication path while R is paused immediately before rename.
    hooks.beforeLockRename = () => {
      realFs.unlinkSync(lockPath);
      acquire(true);
      expect(holdsStartupLock()).toBe(true);
      aRecord = realFs.readFileSync(lockPath, 'utf8');
      // R will move A aside. B publishes into the vacancy before R restores.
      hooks.beforeAsideLink = () => {
        bRecord = record(process.ppid);
        const temp = `${lockPath}.third.tmp`;
        realFs.writeFileSync(temp, bRecord);
        try { realFs.linkSync(temp, lockPath); }
        finally { realFs.unlinkSync(temp); }
      };
    };

    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(bRecord);
    expect(asides()).toEqual([aRecord]);
    // A's descriptor is still open in this module, but B is now at the
    // canonical path. A must revoke its own ownership on this check.
    expect(holdsStartupLock()).toBe(false);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(bRecord);
  });

  it('reports no ownership while its record is aside, and owns it again once the stale reaper links it back', () => {
    writeForeign(record(DEAD_PID));
    let aRecord = '';
    let duringVacancy: boolean | undefined;
    hooks.beforeLockRename = () => {
      realFs.unlinkSync(lockPath);
      acquire(true);
      aRecord = realFs.readFileSync(lockPath, 'utf8');
      // R has moved A aside and is about to link it back; nobody else publishes.
      hooks.beforeAsideLink = () => {
        duringVacancy = holdsStartupLock();
      };
    };

    // R restores A's record (same inode), then judges it live and refuses.
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(duringVacancy).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(aRecord);
    expect(asides()).toEqual([]);
    expect(holdsStartupLock()).toBe(true);
    // Ownership survived the vacancy, so shutdown still releases A's record.
    closeDatabase();
    expect(realFs.existsSync(lockPath)).toBe(false);
  });
});

describe('#817 holder whose record is put back by copy (no hard links)', () => {
  it('retains ownership after no-hard-link restore of its exact record', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    let ownBytes = '';
    let ownInode = 0;
    hooks.beforeLockRename = () => {
      realFs.unlinkSync(lockPath);
      acquire(true);
      expect(holdsStartupLock()).toBe(true);
      ownBytes = realFs.readFileSync(lockPath, 'utf8');
      ownInode = realFs.statSync(lockPath).ino;
    };
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(ownBytes);
    expect(realFs.statSync(lockPath).ino).not.toBe(ownInode);
    expect(asides()).toEqual([]);
    expect(holdsStartupLock()).toBe(true);
  });

  it('shutdown removes the copy-restored own record and leaves nothing aside', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    writeForeign(record(DEAD_PID));
    let ownInode = 0;
    hooks.beforeLockRename = () => {
      realFs.unlinkSync(lockPath);
      acquire(true);
      ownInode = realFs.statSync(lockPath).ino;
    };
    expect(() => acquire(true)).toThrow(StartupLockHeldError);
    expect(realFs.statSync(lockPath).ino).not.toBe(ownInode);
    closeDatabase();
    expect(realFs.existsSync(lockPath)).toBe(false);
    expect(strays()).toEqual([]);
    expect(holdsStartupLock()).toBe(false);
  });

  it('a different record on a new inode still revokes ownership, and shutdown leaves it', () => {
    hooks.linkErrorAlways = 'ENOTSUP';
    acquire(true);
    expect(holdsStartupLock()).toBe(true);
    const own = realFs.readFileSync(lockPath, 'utf8');
    // Same PID and layout, another nonce: a different process's record.
    const nonce = (JSON.parse(own) as { nonce: string }).nonce;
    const foreign = own.replace(nonce, `${nonce}-other`);
    expect(foreign).not.toBe(own);
    writeForeign(foreign);
    expect(holdsStartupLock()).toBe(false);
    // Revoked for good: putting the exact own bytes back later does not restore it.
    writeForeign(own);
    expect(holdsStartupLock()).toBe(false);
    writeForeign(foreign);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
    expect(strays()).toEqual([]);
  });

  // #818 r2: the second read-open is re-adoption's own open of the candidate.
  // Another record taking the lock path just before it, or just after it
  // returns (before the candidate is verified and adopted), must not report
  // ownership.
  it.each(['before', 'after'] as const)('#818 r2: fails closed when the lock path changes %s the re-adoption open', (when) => {
    acquire(true);
    const own = realFs.readFileSync(lockPath, 'utf8');
    writeForeign(own); // A completed byte-identical copy on a new inode.
    const foreign = record(EPERM_PID);
    let opens = 0;
    const swap = (): void => {
      if (++opens === 2) writeForeign(foreign);
    };
    if (when === 'before') hooks.beforeLockRead = swap;
    else hooks.afterLockRead = swap;
    const observed = holdsStartupLock();
    hooks.beforeLockRead = undefined;
    hooks.afterLockRead = undefined;
    expect(opens).toBe(2);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
    expect(holdsStartupLock()).toBe(false);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
    expect(observed).toBe(false);
  });
});

describe('#763 release', () => {
  it('continue-anyway never removes the foreign lock on close', () => {
    const foreign = record(process.pid);
    writeForeign(foreign);
    const opened = initDatabase(dbPath);
    expect(opened.open).toBe(true);
    expect(holdsStartupLock()).toBe(false);
    closeDatabase();
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
    expect(strays()).toEqual([]);
  });

  it('leaves a record another process put in place of ours', () => {
    acquire();
    expect(holdsStartupLock()).toBe(true);
    const foreign = record(process.pid);
    writeForeign(foreign);
    closeDatabase();
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
    expect(strays()).toEqual([]);
  });
});

describe('#763 maintain with a borrowed handle', () => {
  it('does not close a module handle another caller opened', async () => {
    const opened = initDatabase(dbPath);
    // The lock is gone (e.g. removed by hand), so maintain's pre-check sees no
    // live owner and initDatabase hands back the existing module handle.
    realFs.rmSync(lockPath, { force: true });
    const report = await maintain({}, {
      dataDir: dir,
      dbPath,
      diskLimit: Number.MAX_SAFE_INTEGER,
      consolidateConfig: { maxShortTermMemories: 10, maxLongTermMemories: 1000 } as never,
      embed: async () => new Float32Array(384).fill(0.1),
      doctor: async () => [],
      channels: [],
    });
    expect(report.steps.consolidate.status).not.toBe('failed');
    expect(opened.open).toBe(true);
    expect(isDatabaseInitialized()).toBe(true);
    expect((opened.prepare('SELECT COUNT(*) AS n FROM memories').get() as { n: number }).n).toBe(0);
  });
});

describe('#813 maintain after its lock record is replaced mid-run', () => {
  it('skips embed and vacuum as locked and leaves the new holder in place', async () => {
    let foreign = '';
    let vacuumCalls = 0;
    const report = await maintain({}, {
      dataDir: dir,
      dbPath,
      diskLimit: Number.MAX_SAFE_INTEGER,
      consolidateConfig: { maxShortTermMemories: 1000, maxLongTermMemories: 1000 } as never,
      // Runs after maintain took the lock and before the embed step's check:
      // another starter's record replaces this process's record.
      modelCacheReady: async () => {
        expect(holdsStartupLock()).toBe(true);
        foreign = record(process.ppid);
        writeForeign(foreign);
        return true;
      },
      vacuum: () => { vacuumCalls++; },
      doctor: async () => [],
      channels: [],
    });
    expect(vacuumCalls).toBe(0);
    expect(report.steps.embed.status).toBe('skipped');
    expect(report.steps.embed.reason).toBe('locked');
    expect(report.steps.vacuum.reason).toBe('locked');
    expect(holdsStartupLock()).toBe(false);
    expect(realFs.readFileSync(lockPath, 'utf8')).toBe(foreign);
  });
});
