import { describe, expect, it } from '@jest/globals';
import {
  lockSnapshotUnchanged,
  replacementCandidate,
  replacementRefusals,
  snapshotExistingLock,
} from '../protect.js';
import type { LockedPolicy } from '../../defence/iron-dome/policy-lock.js';
import { PROTECTED_ROOT_ENV, type ProtectedFsSeam, type ProtectedStat } from '../../defence/iron-dome/protected-root.js';

const pin = { path: '/opt/reviewed.sh', sha256: 'a'.repeat(64), note: 'reviewed by operator' };
const old: LockedPolicy = {
  version: 1,
  actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [pin] },
  defenceMode: 'strict',
};
const defaultOptions = { dryRun: true, fromConfig: false };
const fromConfigOptions = { dryRun: true, fromConfig: true };

describe('#912 replacement comparison', () => {
  it('preserves verified pins without opening or rehashing the script, and rejects strict to balanced', () => {
    const candidate = replacementCandidate({}, defaultOptions, old);
    expect(candidate.actionGuard?.reviewedScripts).toEqual([pin]);
    expect(replacementRefusals(old, candidate)).toEqual([expect.stringContaining('defenceMode')]);
  });

  it('refuses --from-config off, omitted covered keys, and pin loss', () => {
    const off = replacementCandidate({ actionGuard: { enabled: false } }, fromConfigOptions, old);
    expect(replacementRefusals(old, off)).toEqual(expect.arrayContaining([
      expect.stringContaining('actionGuard.enabled'),
      expect.stringContaining('actionGuard.reviewedScripts'),
      expect.stringContaining('defenceMode'),
    ]));
    const omitted = replacementCandidate({}, fromConfigOptions, { version: 1, memory: { inject: { mode: 'off' } } });
    expect(replacementRefusals({ version: 1, memory: { inject: { mode: 'off' } } }, omitted))
      .toEqual([expect.stringContaining('memory.inject.mode')]);
    const lostPin = { ...old, actionGuard: { ...old.actionGuard, reviewedScripts: [] } };
    expect(replacementRefusals(old, lostPin)).toEqual([expect.stringContaining('existing trusted pin would be lost')]);
  });

  it('accepts an unchanged policy, and forbids adding a pin during replacement', () => {
    expect(replacementRefusals(old, structuredClone(old))).toEqual([]);
    expect(replacementRefusals({ ...old, defenceMode: 'balanced', actionGuard: { ...old.actionGuard, autoApprove: ['ls'] } }, old)).toEqual([]);
    const newPin = { path: '/opt/new.sh', sha256: 'b'.repeat(64) };
    const added = { ...old, actionGuard: { ...old.actionGuard, reviewedScripts: [pin, newPin] } };
    expect(replacementRefusals(old, added)).toEqual([expect.stringContaining('candidate adds a new pin')]);
  });
});

describe('#912 verified snapshot and race check', () => {
  const lockPath = '/fixture/policy.json';
  const root: ProtectedStat = { uid: 0, gid: 0, mode: 0o40755, isFile: false, isDirectory: true, isSymbolicLink: false };
  const file: ProtectedStat = { uid: 0, gid: 0, mode: 0o100644, isFile: true, isDirectory: false, isSymbolicLink: false, dev: 1, ino: 2, ctimeMs: 3, mtimeMs: 4 };
  function fixture() {
    let stat: ProtectedStat | null = file;
    let bytes = JSON.stringify(old);
    let readIdentity: (() => { contents: string; before: ProtectedStat; after: ProtectedStat } | null) | null = null;
    const seam: ProtectedFsSeam = {
      lstat: (p) => p === lockPath ? stat : p === '/etc/shieldcortex' || p === '/etc/shieldcortex/policy.json' || p === '/etc/shieldcortex.conf' ? null : root,
      stat: (p) => p === lockPath ? stat : root,
      readlink: () => null,
      readFile: (p) => p === lockPath ? bytes : null,
      readFileWithIdentity: (p) => p === lockPath
        ? (readIdentity ? readIdentity() : stat ? { contents: bytes, before: stat, after: stat } : null)
        : null,
      geteuid: () => 1001,
      platform: 'linux',
      env: (name) => name === PROTECTED_ROOT_ENV ? '/fixture' : undefined,
    };
    return {
      seam,
      setStat: (next: ProtectedStat | null) => { stat = next; },
      setBytes: (next: string) => { bytes = next; },
      setReadIdentity: (next: typeof readIdentity) => { readIdentity = next; },
    };
  }

  it('reads only a verified old lock as trusted and refuses failed verification', () => {
    const f = fixture();
    const verified = snapshotExistingLock(lockPath, f.seam);
    expect(verified.ok).toBe(true);
    if (verified.ok) expect(verified.snapshot).toMatchObject({ status: 'locked', policy: old });
    f.setStat({ ...file, uid: 1001 });
    expect(snapshotExistingLock(lockPath, f.seam)).toMatchObject({ ok: false });
  });

  it('detects concurrent byte, identity, and absence changes before replace', () => {
    const f = fixture();
    const first = snapshotExistingLock(lockPath, f.seam);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(lockSnapshotUnchanged(lockPath, f.seam, first.snapshot)).toBe(true);
    f.setBytes(JSON.stringify({ ...old, defenceMode: 'balanced' }));
    expect(lockSnapshotUnchanged(lockPath, f.seam, first.snapshot)).toBe(false);
    f.setBytes(JSON.stringify(old));
    f.setStat({ ...file, ino: 3 });
    expect(lockSnapshotUnchanged(lockPath, f.seam, first.snapshot)).toBe(false);
    f.setStat(null);
    expect(lockSnapshotUnchanged(lockPath, f.seam, first.snapshot)).toBe(false);
  });

  it('detects a lock appearing after an absent snapshot', () => {
    const f = fixture();
    f.setStat(null);
    const first = snapshotExistingLock(lockPath, f.seam);
    expect(first).toMatchObject({ ok: true, snapshot: { status: 'absent' } });
    if (!first.ok) return;
    f.setStat(file);
    expect(lockSnapshotUnchanged(lockPath, f.seam, first.snapshot)).toBe(false);
  });

  it.each([
    ['top level', { futureConstraint: { required: true } }, 'futureConstraint'],
    ['action guard', { actionGuard: { ...old.actionGuard, futureConstraint: true } }, 'actionGuard.futureConstraint'],
    ['broker', { actionGuard: { ...old.actionGuard, broker: { enabled: false, futureConstraint: true } } }, 'actionGuard.broker.futureConstraint'],
    ['memory', { memory: { futureConstraint: true } }, 'memory.futureConstraint'],
    ['memory child', { memory: { inject: { mode: 'off', futureConstraint: true } } }, 'memory.inject.futureConstraint'],
    ['reviewed script', { actionGuard: { ...old.actionGuard, reviewedScripts: [{ ...pin, futureConstraint: true }] } }, 'actionGuard.reviewedScripts[0].futureConstraint'],
  ])('refuses replacement of a verified lock with unknown %s fields', (_label, extra, field) => {
    const f = fixture();
    f.setBytes(JSON.stringify({ ...old, ...extra }));
    expect(snapshotExistingLock(lockPath, f.seam)).toEqual({
      ok: false,
      detail: expect.stringContaining(`unrecognized fields (${field})`),
    });
  });

  it('refuses when descriptor identity is missing or changes during a read', () => {
    const f = fixture();
    f.setReadIdentity(() => null);
    expect(snapshotExistingLock(lockPath, f.seam)).toEqual({
      ok: false,
      detail: expect.stringContaining('identity could not be established'),
    });
    f.setReadIdentity(() => ({ contents: JSON.stringify(old), before: file, after: { ...file, ino: 3 } }));
    expect(snapshotExistingLock(lockPath, f.seam)).toMatchObject({ ok: false });
    f.setReadIdentity(() => ({ contents: JSON.stringify(old), before: { ...file, ino: 3 }, after: { ...file, ino: 3 } }));
    expect(snapshotExistingLock(lockPath, f.seam)).toMatchObject({ ok: false });
    f.setReadIdentity(() => ({ contents: JSON.stringify(old), before: { ...file, dev: undefined }, after: file }));
    expect(snapshotExistingLock(lockPath, f.seam)).toMatchObject({ ok: false });
    f.setReadIdentity(() => {
      f.setStat({ ...file, ino: 4 });
      return { contents: JSON.stringify(old), before: file, after: file };
    });
    expect(snapshotExistingLock(lockPath, f.seam)).toMatchObject({ ok: false });
  });
});
