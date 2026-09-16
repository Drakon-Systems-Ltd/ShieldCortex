/**
 * #501 — the OS ownership boundary.
 *
 * Every rule here is about a case that is otherwise only reachable with real
 * root: a root-owned file in a root-owned directory. The injected seam is the
 * point — it lets the POSITIVE case be asserted in an ordinary unit test,
 * where the negative cases (agent-owned, writable dir, symlink) already live.
 */
import { describe, expect, it } from '@jest/globals';
import {
  DEFAULT_PROTECTED_ROOT,
  POLICY_LOCK_FILENAME,
  PROTECTED_ROOT_ENV,
  PROTECTED_ROOT_POINTER,
  describeProtectedFailure,
  resolveProtectedRoot,
  verifyProtectedFile,
  type ProtectedFsSeam,
  type ProtectedStat,
} from '../protected-root.js';

const AGENT_UID = 1001;
const ROOT_UID = 0;

type Entry = { uid?: number; gid?: number; mode?: number; kind?: 'file' | 'dir' | 'symlink'; target?: string };

/**
 * A seam over a literal path → entry table. Anything not named is absent, so a
 * test states exactly the host it means and nothing leaks in from the machine
 * the suite happens to run on.
 */
function seamOf(
  entries: Record<string, Entry>,
  opts: { platform?: NodeJS.Platform; euid?: number | null; files?: Record<string, string>; env?: Record<string, string> } = {},
): ProtectedFsSeam {
  const stat = (path: string, follow: boolean): ProtectedStat | null => {
    const e = entries[path];
    if (!e) return null;
    const kind = e.kind ?? 'file';
    if (kind === 'symlink' && follow) {
      return e.target ? stat(e.target, true) : null;
    }
    return {
      uid: e.uid ?? ROOT_UID,
      gid: e.gid ?? ROOT_UID,
      mode: e.mode ?? (kind === 'dir' ? 0o40755 : 0o100644),
      isFile: kind === 'file',
      isDirectory: kind === 'dir',
      isSymbolicLink: kind === 'symlink',
    };
  };
  return {
    lstat: (p) => stat(p, false),
    stat: (p) => stat(p, true),
    readFile: (p) => opts.files?.[p] ?? null,
    geteuid: () => (opts.euid === undefined ? AGENT_UID : opts.euid),
    platform: opts.platform ?? 'linux',
    env: (n) => opts.env?.[n],
  };
}

/** A host with a genuinely root-owned /etc/shieldcortex/policy.json. */
function rootOwnedHost(extra: Record<string, Entry> = {}): Record<string, Entry> {
  return {
    '/': { kind: 'dir', mode: 0o40755 },
    '/etc': { kind: 'dir', mode: 0o40755 },
    '/etc/shieldcortex': { kind: 'dir', mode: 0o40755 },
    '/etc/shieldcortex/policy.json': { kind: 'file', mode: 0o100644 },
    ...extra,
  };
}

const LOCK_PATH = `${DEFAULT_PROTECTED_ROOT}/${POLICY_LOCK_FILENAME}`;

describe('#501 verifyProtectedFile — the positive case', () => {
  it('accepts a root-owned 0644 file in a root-owned 0755 chain', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost()));
    expect(v).toEqual({ ok: true, reason: null, detail: expect.any(String) });
  });

  it('accepts an owner-writable file — the owner is not the agent', () => {
    // 0600 root:root is unreadable in practice but the OWNERSHIP rule must not
    // conflate "owner can write" with "agent can write".
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex/policy.json': { kind: 'file', mode: 0o100600 },
    })));
    expect(v.ok).toBe(true);
  });

  it('accepts a root-owned symlinked ancestor (macOS /etc -> /private/etc)', () => {
    const v = verifyProtectedFile('/etc/shieldcortex/policy.json', seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/private': { kind: 'dir', mode: 0o40755 },
      '/private/etc': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'symlink', target: '/private/etc', uid: ROOT_UID },
      '/etc/shieldcortex': { kind: 'dir', mode: 0o40755 },
      '/etc/shieldcortex/policy.json': { kind: 'file', mode: 0o100644 },
    }));
    expect(v.ok).toBe(true);
  });
});

describe('#501 verifyProtectedFile — every way it must fail closed', () => {
  it('refuses a file owned by the agent uid', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex/policy.json': { kind: 'file', uid: AGENT_UID },
    })));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('owned-by-agent');
  });

  it('refuses a root-owned but group-writable file', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex/policy.json': { kind: 'file', mode: 0o100664 },
    })));
    expect(v.reason).toBe('group-or-other-writable');
  });

  it('refuses a root-owned but world-writable file', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex/policy.json': { kind: 'file', mode: 0o100646 },
    })));
    expect(v.reason).toBe('group-or-other-writable');
  });

  it('refuses a symlink, even one pointing at a genuinely root-owned file', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex/real.json': { kind: 'file', mode: 0o100644 },
      '/etc/shieldcortex/policy.json': { kind: 'symlink', uid: ROOT_UID, target: '/etc/shieldcortex/real.json' },
    })));
    expect(v.reason).toBe('symlink');
  });

  it('refuses a directory in place of the file', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex/policy.json': { kind: 'dir', mode: 0o40755 },
    })));
    expect(v.reason).toBe('not-regular-file');
  });

  it('refuses an absent file', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf({ '/': { kind: 'dir' }, '/etc': { kind: 'dir' } }));
    expect(v.reason).toBe('missing');
  });

  it('refuses a root-owned file in an AGENT-OWNED directory (unlink + recreate)', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex': { kind: 'dir', uid: AGENT_UID, mode: 0o40755 },
    })));
    expect(v.reason).toBe('parent-owned-by-agent');
  });

  it('refuses a root-owned file in a world-writable directory', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc/shieldcortex': { kind: 'dir', mode: 0o40777 },
    })));
    expect(v.reason).toBe('parent-group-or-other-writable');
  });

  it('refuses when a GRANDparent is agent-writable, not just the parent', () => {
    // The immediate parent is impeccable; /etc is not. An agent that can write
    // /etc renames /etc/shieldcortex aside and puts its own there.
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost({
      '/etc': { kind: 'dir', mode: 0o40777 },
    })));
    expect(v.reason).toBe('parent-group-or-other-writable');
  });

  it('refuses an agent-owned symlink in the directory chain', () => {
    const v = verifyProtectedFile('/etc/shieldcortex/policy.json', seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'symlink', uid: AGENT_UID, target: '/tmp/fake-etc' },
      '/tmp/fake-etc': { kind: 'dir', mode: 0o40755 },
      '/etc/shieldcortex': { kind: 'dir', mode: 0o40755 },
      '/etc/shieldcortex/policy.json': { kind: 'file', mode: 0o100644 },
    }));
    expect(v.reason).toBe('parent-owned-by-agent');
  });

  it('refuses everything on win32 — there is no boundary to check', () => {
    const v = verifyProtectedFile('C:\\ProgramData\\shieldcortex\\policy.json', seamOf(rootOwnedHost(), { platform: 'win32' }));
    expect(v.reason).toBe('unsupported-platform');
  });

  it('refuses when the agent itself is root — nothing can constrain it', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost(), { euid: 0 }));
    expect(v.reason).toBe('running-as-root');
  });

  it('refuses when the runtime exposes no euid', () => {
    const v = verifyProtectedFile(LOCK_PATH, seamOf(rootOwnedHost(), { euid: null }));
    expect(v.reason).toBe('euid-unavailable');
  });

  it('every failure reason has a plain-language description', () => {
    const reasons = [
      'unsupported-platform', 'euid-unavailable', 'running-as-root', 'missing', 'symlink',
      'not-regular-file', 'owned-by-agent', 'group-or-other-writable', 'parent-missing',
      'parent-not-directory', 'parent-owned-by-agent', 'parent-group-or-other-writable',
    ] as const;
    for (const r of reasons) {
      expect(describeProtectedFailure(r)).toEqual(expect.stringMatching(/\S/));
    }
  });
});

describe('#501 resolveProtectedRoot', () => {
  it('is /etc/shieldcortex by default', () => {
    const r = resolveProtectedRoot(seamOf({ '/': { kind: 'dir' } }));
    expect(r).toEqual({ supported: true, root: DEFAULT_PROTECTED_ROOT, source: 'default' });
  });

  it('reports win32 as unsupported, plainly', () => {
    const r = resolveProtectedRoot(seamOf({}, { platform: 'win32' }));
    expect(r.supported).toBe(false);
    expect(r.supported === false && r.reason).toBe('win32');
    expect(r.supported === false && r.detail).toMatch(/Windows/);
  });

  it('reports a root agent as unsupported, plainly', () => {
    const r = resolveProtectedRoot(seamOf({}, { euid: 0 }));
    expect(r.supported === false && r.reason).toBe('running-as-root');
    expect(r.supported === false && r.detail).toMatch(/root/i);
  });

  it('follows a root-owned pointer file to another root', () => {
    const r = resolveProtectedRoot(seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'dir', mode: 0o40755 },
      [PROTECTED_ROOT_POINTER]: { kind: 'file', mode: 0o100644 },
    }, { files: { [PROTECTED_ROOT_POINTER]: '# distro layout\nroot=/usr/local/etc/shieldcortex\n' } }));
    expect(r).toEqual({ supported: true, root: '/usr/local/etc/shieldcortex', source: 'pointer' });
  });

  it('IGNORES a pointer file the agent owns', () => {
    const r = resolveProtectedRoot(seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'dir', mode: 0o40755 },
      [PROTECTED_ROOT_POINTER]: { kind: 'file', uid: AGENT_UID, mode: 0o100644 },
    }, { files: { [PROTECTED_ROOT_POINTER]: 'root=/tmp/agent-owned\n' } }));
    expect(r).toEqual({ supported: true, root: DEFAULT_PROTECTED_ROOT, source: 'default' });
  });

  it('ignores a relative path in an otherwise valid pointer', () => {
    const r = resolveProtectedRoot(seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'dir', mode: 0o40755 },
      [PROTECTED_ROOT_POINTER]: { kind: 'file', mode: 0o100644 },
    }, { files: { [PROTECTED_ROOT_POINTER]: 'root=../relative\n' } }));
    expect(r.root).toBe(DEFAULT_PROTECTED_ROOT);
  });
});

describe(`#501 ${PROTECTED_ROOT_ENV} can only tighten, never loosen`, () => {
  it('is honoured on a host with no canonical protected root', () => {
    const r = resolveProtectedRoot(seamOf({ '/': { kind: 'dir' } }, { env: { [PROTECTED_ROOT_ENV]: '/tmp/sc-test-root' } }));
    expect(r).toEqual({ supported: true, root: '/tmp/sc-test-root', source: 'test-override' });
  });

  it('is IGNORED when a real lock file exists at the canonical root', () => {
    // The bypass this rule exists to kill: an agent setting the variable at an
    // empty directory to make a real, root-owned lock read as absent.
    const r = resolveProtectedRoot(seamOf(rootOwnedHost(), { env: { [PROTECTED_ROOT_ENV]: '/tmp/empty' } }));
    expect(r).toEqual({ supported: true, root: DEFAULT_PROTECTED_ROOT, source: 'default' });
  });

  it('is IGNORED when the canonical root DIRECTORY exists but is empty', () => {
    // An operator mid-`protect`, or a lock that was deleted: the directory
    // alone is enough to say "this host is managed", so the variable stays off.
    const r = resolveProtectedRoot(seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'dir', mode: 0o40755 },
      '/etc/shieldcortex': { kind: 'dir', mode: 0o40755 },
    }, { env: { [PROTECTED_ROOT_ENV]: '/tmp/empty' } }));
    expect(r.root).toBe(DEFAULT_PROTECTED_ROOT);
  });

  it('ignores a relative override', () => {
    const r = resolveProtectedRoot(seamOf({ '/': { kind: 'dir' } }, { env: { [PROTECTED_ROOT_ENV]: 'relative/path' } }));
    expect(r.root).toBe(DEFAULT_PROTECTED_ROOT);
  });
});
