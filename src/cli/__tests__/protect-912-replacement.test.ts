/** #912: exercise the privileged command against an entirely synthetic filesystem. */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { Stats } from 'fs';
import type { LockedPolicy } from '../../defence/iron-dome/policy-lock.js';

const ROOT = '/synthetic/protected';
const LOCK = `${ROOT}/policy.json`;
const CONFIG = '/synthetic/config.json';
const OLD_PIN = { path: '/synthetic/old-review.sh', sha256: 'a'.repeat(64) };
const oldPolicy: LockedPolicy = {
  version: 1,
  actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [OLD_PIN] },
  defenceMode: 'balanced',
};
const fsReal = jest.requireActual<typeof import('fs')>('fs');
let lockBytes = '';
let lockUid = 1001;
let inode = 7;
let pending: string | null = null;
let renamed = 0;
let raceOnWrite = false;
let unsafeRoot = false;
let identityReadFails = false;

function fakeStat(file: boolean, uid = 0, ino = 1): Stats {
  return {
    uid, gid: 0, dev: 1, ino, ctimeMs: 1, mtimeMs: 1,
    mode: file ? 0o100644 : 0o40755,
    isFile: () => file, isDirectory: () => !file, isSymbolicLink: () => false,
  } as Stats;
}
const synthetic = (p: unknown): p is string => typeof p === 'string' && (p === '/synthetic' || p.startsWith('/synthetic/'));
const tmpPath = (p: unknown): p is string => typeof p === 'string' && p.startsWith(`${LOCK}.tmp-`);
const fsMock = {
  ...fsReal,
  lstatSync: ((p: string, ...args: unknown[]) => p === '/' || p === '/etc' ? fakeStat(false) : synthetic(p)
    ? p === LOCK ? fakeStat(true, lockUid, inode) : p === CONFIG ? fakeStat(true, 1001)
      : p === ROOT && unsafeRoot ? { ...fakeStat(false, 1001), mode: 0o40777 } as Stats : fakeStat(false)
    : p === '/etc/shieldcortex' || p === '/etc/shieldcortex/policy.json' || p === '/etc/shieldcortex.conf'
      ? (() => { throw new Error('absent'); })()
      : fsReal.lstatSync(p, ...(args as []))),
  statSync: ((p: string, ...args: unknown[]) => p === '/' || p === '/etc' ? fakeStat(false) : synthetic(p)
    ? p === LOCK ? fakeStat(true, lockUid, inode) : fakeStat(false)
    : fsReal.statSync(p, ...(args as []))),
  openSync: ((p: string, flags: number | string) => p === LOCK
    ? identityReadFails ? (() => { throw new Error('cannot establish identity'); })() : 912
    : fsReal.openSync(p, flags)),
  fstatSync: ((fd: number, ...args: unknown[]) => fd === 912 ? fakeStat(true, lockUid, inode) : fsReal.fstatSync(fd, ...(args as []))),
  closeSync: ((fd: number) => fd === 912 ? undefined : fsReal.closeSync(fd)),
  readFileSync: ((p: string | number) => p === LOCK || p === 912
    ? lockBytes : p === CONFIG
      ? JSON.stringify({ ...oldPolicy, actionGuard: { ...oldPolicy.actionGuard, reviewedScripts: [] } })
      : fsReal.readFileSync(p, 'utf8')),
  existsSync: ((p: string) => synthetic(p) ? p === ROOT || p === LOCK || (tmpPath(p) && pending !== null) : fsReal.existsSync(p)),
  chmodSync: ((p: string, mode: number) => synthetic(p) ? undefined : fsReal.chmodSync(p, mode)),
  writeFileSync: ((p: string, body: string, ...args: unknown[]) => {
    if (tmpPath(p)) {
      pending = body;
      if (raceOnWrite) inode++;
      return;
    }
    return fsReal.writeFileSync(p, body, ...(args as []));
  }),
  renameSync: ((from: string, to: string) => {
    if (tmpPath(from) && to === LOCK) { lockBytes = pending ?? ''; lockUid = 0; inode++; pending = null; renamed++; return; }
    return fsReal.renameSync(from, to);
  }),
  rmSync: ((p: string, ...args: unknown[]) => { if (tmpPath(p)) { pending = null; return; } return fsReal.rmSync(p, ...(args as [])); }),
};

jest.unstable_mockModule('fs', () => ({ ...fsMock, default: fsMock }));
const { runProtect } = await import('../protect.js');
const { readPolicyLock } = await import('../../defence/iron-dome/policy-lock.js');
const { defaultProtectedFsSeam, verifyProtectedDirectoryChain } = await import('../../defence/iron-dome/protected-root.js');
const agentSeam = () => ({ ...defaultProtectedFsSeam(), geteuid: () => 1001 });

describe('#912 privileged replacement of an unverifiable lock', () => {
  let priorRoot: string | undefined;
  beforeEach(() => {
    priorRoot = process.env.SHIELDCORTEX_PROTECTED_ROOT;
    process.env.SHIELDCORTEX_PROTECTED_ROOT = ROOT;
    lockBytes = JSON.stringify(oldPolicy);
    lockUid = 1001;
    inode = 7;
    pending = null;
    renamed = 0;
    raceOnWrite = false;
    unsafeRoot = false;
    identityReadFails = false;
    jest.spyOn(process, 'geteuid').mockReturnValue(0);
  });
  afterEach(() => {
    jest.restoreAllMocks();
    if (priorRoot === undefined) delete process.env.SHIELDCORTEX_PROTECTED_ROOT;
    else process.env.SHIELDCORTEX_PROTECTED_ROOT = priorRoot;
  });

  it('dry-run offers a successful fresh candidate without adopting old pins or writing', () => {
    expect(readPolicyLock({ seam: agentSeam(), audit: false, warn: false }).status).toBe('unverifiable');
    expect(verifyProtectedDirectoryChain(ROOT, 1001, agentSeam()).ok).toBe(true);
    const result = runProtect(['--dry-run', '--agent-uid', '1001']);
    expect(result.code).toBe(0);
    expect(result.lines.join('\n')).toContain(`Would write ${LOCK}`);
    expect(result.lines.join('\n')).toContain('"reviewedScripts": []');
    expect(result.lines.join('\n')).not.toContain(OLD_PIN.path);
    expect(renamed).toBe(0);
  });

  it('atomically replaces the present unverifiable lock and leaves a verifiable lock with no old pins', () => {
    expect(readPolicyLock({ seam: agentSeam(), audit: false, warn: false }).status).toBe('unverifiable');
    const result = runProtect(['--agent-uid', '1001']);
    expect(result.code).toBe(0);
    expect(renamed).toBe(1);
    expect(pending).toBeNull();
    expect(readPolicyLock({ seam: agentSeam(), audit: false, warn: false }).status).toBe('locked');
    expect(JSON.parse(lockBytes).actionGuard.reviewedScripts).toEqual([]);
  });

  it.each([
    ['unparseable', '{not JSON'],
    ['schema-invalid', JSON.stringify({ ...oldPolicy, version: 2 })],
  ])('replaces root-owned %s bytes only after establishing their identity', (_kind, bytes) => {
    lockUid = 0;
    lockBytes = bytes;
    expect(readPolicyLock({ seam: agentSeam(), audit: false, warn: false }).status).toBe('unverifiable');
    const preview = runProtect(['--dry-run', '--agent-uid', '1001']);
    expect(preview.code).toBe(0);
    expect(preview.lines.join('\n')).toContain('"reviewedScripts": []');
    expect(preview.lines.join('\n')).not.toContain(OLD_PIN.path);
    expect(renamed).toBe(0);
    const result = runProtect(['--agent-uid', '1001']);
    expect(result.code).toBe(0);
    expect(renamed).toBe(1);
    expect(readPolicyLock({ seam: agentSeam(), audit: false, warn: false }).status).toBe('locked');
  });

  it('refuses an unsafe destination before writing a temporary file', () => {
    unsafeRoot = true;
    const result = runProtect(['--agent-uid', '1001']);
    expect(result.code).toBe(1);
    expect(result.lines.join('\n')).toMatch(/REFUSED destination/);
    expect(pending).toBeNull();
    expect(renamed).toBe(0);
  });

  it('refuses when an unverifiable destination has no descriptor identity', () => {
    identityReadFails = true;
    const result = runProtect(['--agent-uid', '1001']);
    expect(result.code).toBe(1);
    expect(result.lines.join('\n')).toMatch(/identity could not be established/);
    expect(pending).toBeNull();
    expect(renamed).toBe(0);
  });

  it('refuses stale identity of unverifiable old bytes before rename', () => {
    raceOnWrite = true;
    const result = runProtect(['--agent-uid', '1001']);
    expect(result.code).toBe(1);
    expect(result.lines.join('\n')).toMatch(/changed before replace/);
    expect(pending).toBeNull();
    expect(renamed).toBe(0);
  });

  it('still refuses pin loss from a verified lock', () => {
    lockUid = 0;
    const result = runProtect(['--from-config', '--config', CONFIG, '--agent-uid', '1001']);
    expect(result.code).toBe(1);
    expect(result.lines.join('\n')).toMatch(/existing trusted pin would be lost/);
    expect(renamed).toBe(0);
  });

  it('refuses an identity change before rename', () => {
    lockUid = 0;
    raceOnWrite = true;
    const result = runProtect(['--agent-uid', '1001']);
    expect(result.code).toBe(1);
    expect(result.lines.join('\n')).toMatch(/changed before replace/);
    expect(renamed).toBe(0);
    expect(pending).toBeNull();
  });
});
