/**
 * #339 — fixed temp-root confinement, proven through a virtual fs view.
 *
 * The guard trusts a FIXED set of temp roots (`/tmp/`, `/var/tmp/`,
 * `/var/folders/`), and resolves a delete target through `lstatSync` /
 * `realpathSync` before judging it. The live-filesystem cases in
 * guard-tmp-confine-339.test.ts can only build fixtures under the runtime's
 * scratch root, which a sandboxed runner puts under $HOME — outside every fixed
 * root — so they cannot show a positive fixed-root verdict on every machine.
 *
 * This file can, without writing a byte: `node:fs` is replaced by a view in
 * which a few paths under `/tmp` (and under one made-up arbitrary scratch root)
 * are answered from a table, and every other path falls through to the real
 * filesystem — so a link out to /etc resolves against the real /etc. The guard
 * code is the production module, imported after the mock; nothing in it is
 * stubbed but those two fs calls.
 */
import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import * as realFs from 'node:fs';

const RMRF = ['rm', '-rf'].join(' ');
const ETC = ['/', 'etc'].join('');

const SEAM = '/tmp/sc339-seam';
/** Stands in for a TMPDIR under $HOME: real-looking, but not a fixed root. */
const ARBITRARY = '/sc339-scratch-home/.cache/scratch';

type Entry = { kind: 'dir' } | { kind: 'link'; target: string };

/** The virtual view. Anything under a VIRTUAL_ROOTS entry not listed here is ENOENT. */
const VIEW = new Map<string, Entry>([
  ['/tmp', { kind: 'dir' }],
  [SEAM, { kind: 'dir' }],
  [`${SEAM}/real-dir`, { kind: 'dir' }],
  [`${SEAM}/escape-link`, { kind: 'link', target: ETC }],
  [`${SEAM}/inner-link`, { kind: 'link', target: `${SEAM}/real-dir` }],
  [`${SEAM}/into-arbitrary`, { kind: 'link', target: `${ARBITRARY}/real-dir` }],
  ['/sc339-scratch-home', { kind: 'dir' }],
  ['/sc339-scratch-home/.cache', { kind: 'dir' }],
  [ARBITRARY, { kind: 'dir' }],
  [`${ARBITRARY}/real-dir`, { kind: 'dir' }],
  [`${ARBITRARY}/into-tmp`, { kind: 'link', target: `${SEAM}/real-dir` }],
]);
const VIRTUAL_ROOTS = ['/tmp', '/sc339-scratch-home'];

const virtualCalls: string[] = [];

function isVirtual(p: string): boolean {
  return VIRTUAL_ROOTS.some(root => p === root || p.startsWith(`${root}/`));
}

function enoent(p: string): NodeJS.ErrnoException {
  const err = new Error(`ENOENT: no such file or directory, lstat '${p}'`) as NodeJS.ErrnoException;
  err.code = 'ENOENT';
  return err;
}

function fakeStats(entry: Entry) {
  return {
    isSymbolicLink: () => entry.kind === 'link',
    isDirectory: () => entry.kind === 'dir',
    isFile: () => false,
  };
}

function virtualRealpath(p: string, hops = 0): string {
  if (hops > 8) throw Object.assign(new Error('ELOOP'), { code: 'ELOOP' });
  const entry = VIEW.get(p);
  if (!entry) throw enoent(p);
  if (entry.kind === 'dir') return p;
  return isVirtual(entry.target)
    ? virtualRealpath(entry.target, hops + 1)
    : realFs.realpathSync(entry.target);
}

const lstatSync = ((p: realFs.PathLike, ...rest: unknown[]) => {
  const s = String(p);
  if (!isVirtual(s)) return (realFs.lstatSync as (...a: unknown[]) => unknown)(p, ...rest);
  virtualCalls.push(s);
  const entry = VIEW.get(s);
  if (!entry) throw enoent(s);
  return fakeStats(entry);
}) as typeof realFs.lstatSync;

const realpathSync = Object.assign(
  (p: realFs.PathLike, ...rest: unknown[]) => {
    const s = String(p);
    if (!isVirtual(s)) return (realFs.realpathSync as (...a: unknown[]) => unknown)(p, ...rest);
    virtualCalls.push(s);
    return virtualRealpath(s);
  },
  { native: realFs.realpathSync.native },
) as typeof realFs.realpathSync;

jest.unstable_mockModule('node:fs', () => ({
  ...realFs,
  default: { ...realFs, lstatSync, realpathSync },
  lstatSync,
  realpathSync,
}));

const { evaluateToolCall } = await import('../tool-action-guard.js');

function verdict(command: string) {
  return evaluateToolCall('Bash', { command });
}

beforeEach(() => {
  virtualCalls.length = 0;
});

describe('#339 fixed-root seam — the view is the one the guard reads', () => {
  it('the guard consults the virtual view for a fixed-root target', () => {
    verdict(`${RMRF} ${SEAM}/real-dir`);
    expect(virtualCalls).toContain(`${SEAM}/real-dir`);
  });

  it('nothing under the seam exists on the real disk', () => {
    expect(realFs.existsSync(SEAM)).toBe(false);
    expect(realFs.existsSync('/sc339-scratch-home')).toBe(false);
  });
});

describe('#339 fixed-root seam — positive confinement under a fixed temp root', () => {
  it('a real directory under the temp root stays confined (#170 relief holds)', () => {
    expect(verdict(`${RMRF} ${SEAM}/real-dir`).decision).toBe('allow');
  });

  it('a path that does not exist at all is judged lexically and stays confined', () => {
    expect(verdict(`${RMRF} ${SEAM}/never-created`).decision).toBe('allow');
    expect(virtualCalls).toContain(`${SEAM}/never-created`);
  });

  it('a link that stays inside the temp root stays confined', () => {
    expect(verdict(`${RMRF} ${SEAM}/inner-link`).decision).toBe('allow');
    expect(verdict(`${RMRF} ${SEAM}/inner-link/child`).decision).toBe('allow');
  });

  it('an arbitrary-root link INTO the temp root is confined by where it resolves', () => {
    expect(verdict(`${RMRF} ${ARBITRARY}/into-tmp`).decision).toBe('allow');
  });
});

describe('#339 fixed-root seam — escape refusal under a fixed temp root', () => {
  // Each of these is under /tmp as WRITTEN, so a lexical reading would allow
  // it. Only resolution through the view can block it.
  it('a temp-root path that is a symlink OUT of the tree is not confined', () => {
    expect(verdict(`${RMRF} ${SEAM}/escape-link`).decision).toBe('block');
  });

  it('a path THROUGH a symlinked parent is not confined even when it does not exist', () => {
    expect(verdict(`${RMRF} ${SEAM}/escape-link/child`).decision).toBe('block');
  });

  it('one escaping target costs the exemption for the whole line', () => {
    expect(verdict(`${RMRF} ${SEAM}/real-dir ${SEAM}/escape-link`).decision).toBe('block');
  });

  it('a temp-root link into an arbitrary scratch root is not confined', () => {
    expect(verdict(`${RMRF} ${SEAM}/into-arbitrary`).decision).toBe('block');
  });
});

describe('#339 fixed-root seam — an arbitrary TMPDIR is not a trusted root', () => {
  it('a real directory under an arbitrary scratch root is not confined', () => {
    expect(verdict(`${RMRF} ${ARBITRARY}/real-dir`).decision).toBe('block');
  });

  it('a missing path under an arbitrary scratch root is not confined', () => {
    expect(verdict(`${RMRF} ${ARBITRARY}/never-created`).decision).toBe('block');
  });
});
