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
  verifyProtectedDirectoryChain,
  verifyProtectedFile,
  type ProtectedFsSeam,
  type ProtectedStat,
} from '../protected-root.js';
import { readPolicyLock } from '../policy-lock.js';

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
  opts: {
    platform?: NodeJS.Platform;
    euid?: number | null;
    files?: Record<string, string>;
    env?: Record<string, string>;
    /** Every path the verifier asked about, in order — so a test can prove a path was examined. */
    touched?: string[];
  } = {},
): ProtectedFsSeam {
  const stat = (path: string, follow: boolean): ProtectedStat | null => {
    opts.touched?.push(path);
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
    readlink: (p) => {
      const e = entries[p];
      return e?.kind === 'symlink' && e.target ? e.target : null;
    },
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

  /** macOS layout: /etc is a root-owned symlink into /private. */
  function macHost(extra: Record<string, Entry> = {}): Record<string, Entry> {
    return {
      '/': { kind: 'dir', mode: 0o40755 },
      '/private': { kind: 'dir', mode: 0o40755 },
      '/private/etc': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'symlink', target: '/private/etc', uid: ROOT_UID },
      '/etc/shieldcortex': { kind: 'dir', mode: 0o40755 },
      '/etc/shieldcortex/policy.json': { kind: 'file', mode: 0o100644 },
      ...extra,
    };
  }

  it('accepts a root-owned symlinked ancestor (macOS /etc -> /private/etc) — and PROVES it examined the target chain', () => {
    // Review of #522: the previous form of this test named `/private` in the
    // table but nothing asserted the verifier ever looked at it, so it was
    // green by construction. The verdict alone is not the property; the
    // target ancestry being examined is.
    const touched: string[] = [];
    const v = verifyProtectedFile('/etc/shieldcortex/policy.json', seamOf(macHost(), { touched }));
    expect(v.ok).toBe(true);
    expect(touched).toEqual(expect.arrayContaining(['/private/etc', '/private']));
  });

  it('negative control for the above: an agent-owned /private fails the SAME layout', () => {
    const v = verifyProtectedFile('/etc/shieldcortex/policy.json', seamOf(macHost({
      '/private': { kind: 'dir', uid: AGENT_UID, mode: 0o40755 },
    })));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('parent-owned-by-agent');
    expect(v.detail).toContain('/etc -> /private/etc');
    expect(v.detail).toContain('/private is owned by this agent');
  });
});

describe('#522 review blocker — a root-owned symlink whose TARGET ancestry is agent-writable', () => {
  // `/protected -> /agent-parent/safe`, symlink root-owned, `safe` root-owned
  // 0755, but `/agent-parent` is the agent's. The agent renames `safe` aside,
  // re-creates it, and writes its own policy.json. The old walk `stat`ed the
  // symlink (reporting the root-owned `safe`), then continued from `/` — it
  // never asked about `/agent-parent` at all.
  function symlinkedHost(agentParent: Entry): Record<string, Entry> {
    return {
      '/': { kind: 'dir', mode: 0o40755 },
      '/agent-parent': agentParent,
      '/agent-parent/safe': { kind: 'dir', mode: 0o40755 },
      '/protected': { kind: 'symlink', target: '/agent-parent/safe', uid: ROOT_UID },
      '/protected/policy.json': { kind: 'file', mode: 0o100644 },
    };
  }

  it('refuses when the symlink target\'s parent is agent-OWNED (the exact review probe)', () => {
    const touched: string[] = [];
    const v = verifyProtectedDirectoryChain('/protected', AGENT_UID, seamOf(
      symlinkedHost({ kind: 'dir', uid: AGENT_UID, mode: 0o40755 }),
      { touched },
    ));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('parent-owned-by-agent');
    expect(v.detail).toContain('/protected -> /agent-parent/safe');
    expect(touched).toContain('/agent-parent');
  });

  it('refuses the same through verifyProtectedFile on the lock file itself', () => {
    const v = verifyProtectedFile('/protected/policy.json', seamOf(
      symlinkedHost({ kind: 'dir', uid: AGENT_UID, mode: 0o40755 }),
    ));
    expect(v.reason).toBe('parent-owned-by-agent');
  });

  it('refuses when the symlink target\'s parent is root-owned but world-WRITABLE', () => {
    const v = verifyProtectedDirectoryChain('/protected', AGENT_UID, seamOf(
      symlinkedHost({ kind: 'dir', mode: 0o40777 }),
    ));
    expect(v.reason).toBe('parent-group-or-other-writable');
    expect(v.detail).toContain('/agent-parent');
  });

  it('positive control: the identical layout with a root-owned 0755 parent is accepted', () => {
    const v = verifyProtectedDirectoryChain('/protected', AGENT_UID, seamOf(
      symlinkedHost({ kind: 'dir', mode: 0o40755 }),
    ));
    expect(v).toEqual({ ok: true, reason: null, detail: expect.any(String) });
  });

  it('resolves a RELATIVE symlink target against the symlink\'s own directory', () => {
    // /opt/protected -> ../agent-parent/safe, i.e. /agent-parent/safe.
    const v = verifyProtectedDirectoryChain('/opt/protected', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/opt': { kind: 'dir', mode: 0o40755 },
      '/opt/protected': { kind: 'symlink', target: '../agent-parent/safe', uid: ROOT_UID },
      '/agent-parent': { kind: 'dir', uid: AGENT_UID, mode: 0o40755 },
      '/agent-parent/safe': { kind: 'dir', mode: 0o40755 },
    }));
    expect(v.reason).toBe('parent-owned-by-agent');
    expect(v.detail).toContain('/opt/protected -> /agent-parent/safe');
  });

  it('still walks the LEXICAL chain above a symlink whose target is impeccable', () => {
    // /agent-dir/link -> /safe; /safe chain is fine, but /agent-dir CONTAINS
    // the symlink, so the agent can re-point it. The target check must not
    // replace the lexical check — both chains.
    const v = verifyProtectedDirectoryChain('/agent-dir/link', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/safe': { kind: 'dir', mode: 0o40755 },
      '/agent-dir': { kind: 'dir', uid: AGENT_UID, mode: 0o40755 },
      '/agent-dir/link': { kind: 'symlink', target: '/safe', uid: ROOT_UID },
    }));
    expect(v.reason).toBe('parent-owned-by-agent');
    expect(v.detail).toContain('/agent-dir is owned by this agent');
  });

  it('follows a symlink whose target is itself under another symlink (chained)', () => {
    // /a -> /b/x, /b -> /agent-parent/c. The agent-owned parent is two hops away.
    const v = verifyProtectedDirectoryChain('/a', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/a': { kind: 'symlink', target: '/b/x', uid: ROOT_UID },
      '/b': { kind: 'symlink', target: '/agent-parent/c', uid: ROOT_UID },
      '/b/x': { kind: 'dir', mode: 0o40755 },
      '/agent-parent': { kind: 'dir', uid: AGENT_UID, mode: 0o40755 },
      '/agent-parent/c': { kind: 'dir', mode: 0o40755 },
    }));
    expect(v.reason).toBe('parent-owned-by-agent');
    expect(v.detail).toContain('/agent-parent');
  });

  it('fails closed on a symlink whose target cannot be read', () => {
    const seam = seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/protected': { kind: 'symlink', uid: ROOT_UID }, // no target: readlink -> null
    });
    const v = verifyProtectedDirectoryChain('/protected', AGENT_UID, seam);
    expect(v.reason).toBe('parent-symlink-unresolvable');
  });

  it('fails closed on a symlink whose readlink returns an EMPTY string (review round 5, FIND-1)', () => {
    // `null` (target unresolvable) and `''` (target resolved to nothing) are
    // distinct seam answers; `seamOf`'s falsy check collapses them, so this
    // case builds a bare seam that returns '' specifically, to prove the
    // guard checks the value and not just truthiness.
    const seam: ProtectedFsSeam = {
      lstat: (p) => (p === '/protected' ? {
        uid: ROOT_UID, gid: 0, mode: 0o120777, isFile: false, isDirectory: false, isSymbolicLink: true,
      } : p === '/' ? { uid: ROOT_UID, gid: 0, mode: 0o40755, isFile: false, isDirectory: true, isSymbolicLink: false } : null),
      stat: () => null,
      readlink: (p) => (p === '/protected' ? '' : null),
      readFile: () => null,
      geteuid: () => AGENT_UID,
      platform: 'linux',
      env: () => undefined,
    };
    const v = verifyProtectedDirectoryChain('/protected', AGENT_UID, seam);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('parent-symlink-unresolvable');
  });

  it('fails closed on a symlink LOOP instead of recursing forever', () => {
    const v = verifyProtectedDirectoryChain('/a', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/a': { kind: 'symlink', target: '/b', uid: ROOT_UID },
      '/b': { kind: 'symlink', target: '/a', uid: ROOT_UID },
    }));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('parent-symlink-cycle');
  });

  // #522 r2 P1. `path.resolve` (and `fs.realpathSync`) collapse `..` LEXICALLY.
  // The kernel does not: it follows each intermediate symlink FIRST and applies
  // `..` to the directory that link really lands in. So a root-owned link whose
  // target puts a `..` behind a symlink was verified against a path no reader
  // ever opens, while the path a reader DOES open sat under an agent-owned
  // directory.
  it('applies a `..` inside a symlink target to the REAL parent, not the lexical one', () => {
    // /protected -> safe/jump/../policy-dir, resolved from `/`.
    //   lexical : /safe/policy-dir            (root-owned, impeccable — the decoy)
    //   kernel  : /safe/jump -> /agent-parent/hop, `..` -> /agent-parent,
    //             then policy-dir -> /agent-parent/policy-dir
    const v = verifyProtectedDirectoryChain('/protected', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/protected': { kind: 'symlink', target: 'safe/jump/../policy-dir', uid: ROOT_UID },
      '/safe': { kind: 'dir', mode: 0o40755 },
      '/safe/policy-dir': { kind: 'dir', mode: 0o40755 },
      '/safe/jump': { kind: 'symlink', target: '/agent-parent/hop', uid: ROOT_UID },
      '/agent-parent': { kind: 'dir', uid: AGENT_UID, mode: 0o40755 },
      '/agent-parent/hop': { kind: 'dir', mode: 0o40755 },
      '/agent-parent/policy-dir': { kind: 'dir', mode: 0o40755 },
    }));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('parent-owned-by-agent');
    expect(v.detail).toContain('/agent-parent');
    // The decoy really was impeccable — otherwise this would pass for the
    // wrong reason and the lexical bug would still be invisible.
    expect(verifyProtectedDirectoryChain('/safe/policy-dir', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/safe': { kind: 'dir', mode: 0o40755 },
      '/safe/policy-dir': { kind: 'dir', mode: 0o40755 },
    })).ok).toBe(true);
  });

  it('a plain `..` with NO intermediate symlink still resolves lexically and passes', () => {
    // /protected -> safe/sub/../policy-dir. `sub` is an ordinary directory, so
    // lexical and kernel agree on /safe/policy-dir and the chain is clean. The
    // fix must not start refusing an ordinary relative target.
    const v = verifyProtectedDirectoryChain('/protected', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/protected': { kind: 'symlink', target: 'safe/sub/../policy-dir', uid: ROOT_UID },
      '/safe': { kind: 'dir', mode: 0o40755 },
      '/safe/sub': { kind: 'dir', mode: 0o40755 },
      '/safe/policy-dir': { kind: 'dir', mode: 0o40755 },
    }));
    expect(v.ok).toBe(true);
  });

  it('a `..` that escapes the containing directory into an agent-owned parent fails', () => {
    // No symlink trickery at all — lexical and kernel agree — but the target
    // climbs out of /safe into /agent-parent, which the agent owns.
    const v = verifyProtectedDirectoryChain('/safe/protected', AGENT_UID, seamOf({
      '/': { kind: 'dir', mode: 0o40755 },
      '/safe': { kind: 'dir', mode: 0o40755 },
      '/safe/protected': { kind: 'symlink', target: '../agent-parent/policy-dir', uid: ROOT_UID },
      '/agent-parent': { kind: 'dir', uid: AGENT_UID, mode: 0o40755 },
      '/agent-parent/policy-dir': { kind: 'dir', mode: 0o40755 },
    }));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('parent-owned-by-agent');
    expect(v.detail).toContain('/agent-parent');
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
      'parent-symlink-unresolvable', 'parent-symlink-cycle',
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

  // ── The #501 review's BLOCK-2 ──────────────────────────────────────────────
  //
  // Everything above gates the variable on the CANONICAL root, which is sound
  // only on a host that uses `/etc/shieldcortex`. A POINTER host by definition
  // keeps policy somewhere else, so `/etc/shieldcortex` does not exist there —
  // and as first built, one variable walked the resolver straight past a
  // genuinely root-owned, verified pointer. That is not a stricter outcome:
  // it is `locked` -> `absent`, i.e. unlocked.

  /** A host whose policy lives at /opt/scpolicy, via the documented pointer. */
  function pointerHost(): Record<string, Entry> {
    return {
      '/': { kind: 'dir', mode: 0o40755 },
      '/etc': { kind: 'dir', mode: 0o40755 },
      '/opt': { kind: 'dir', mode: 0o40755 },
      '/opt/scpolicy': { kind: 'dir', mode: 0o40755 },
      '/opt/scpolicy/policy.json': { kind: 'file', mode: 0o100644 },
      [PROTECTED_ROOT_POINTER]: { kind: 'file', mode: 0o100644 },
    };
  }

  const POINTER_FILES = { [PROTECTED_ROOT_POINTER]: 'root=/opt/scpolicy\n' };

  it('is IGNORED on a pointer host — a verified pointer out-ranks the variable', () => {
    const hostile = resolveProtectedRoot(seamOf(pointerHost(), {
      files: POINTER_FILES,
      env: { [PROTECTED_ROOT_ENV]: '/tmp/nowhere' },
    }));
    expect(hostile).toEqual({ supported: true, root: '/opt/scpolicy', source: 'pointer' });
    // And it is the SAME answer the host gives with no variable set at all —
    // which is the property, not merely "not /tmp/nowhere".
    expect(hostile).toEqual(resolveProtectedRoot(seamOf(pointerHost(), { files: POINTER_FILES })));
  });

  it('the pointer\'s LOCKED policy survives a hostile override, end to end', () => {
    // Stated through the reader, because that is where the loosening would have
    // shown up: before the fix this read `{ status: 'absent' }` at the attacker's
    // empty directory, which is the unlocked posture on a locked host.
    const seam = seamOf(pointerHost(), {
      files: {
        ...POINTER_FILES,
        '/opt/scpolicy/policy.json': JSON.stringify({
          version: 1,
          actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false } },
          defenceMode: 'strict',
        }),
      },
      env: { [PROTECTED_ROOT_ENV]: '/tmp/nowhere' },
    });
    const state = readPolicyLock({ seam, audit: false, warn: false });
    expect(state.status).toBe('locked');
    expect(state.path).toBe('/opt/scpolicy/policy.json');
    expect(state.status === 'locked' && state.policy.actionGuard?.enforce).toBe(true);
  });

  it('an UNVERIFIABLE pointer does not block the variable — it was never a root', () => {
    // The other half of the gate. An agent-owned pointer yields no production
    // root at all, so the host is unlocked and the test seam stays usable;
    // gating on the mere EXISTENCE of the pointer file would have let an agent
    // disable the seam by touching a file it owns.
    const host = pointerHost();
    host[PROTECTED_ROOT_POINTER] = { kind: 'file', uid: AGENT_UID, mode: 0o100644 };
    delete host['/opt/scpolicy'];
    delete host['/opt/scpolicy/policy.json'];
    const r = resolveProtectedRoot(seamOf(host, {
      files: POINTER_FILES,
      env: { [PROTECTED_ROOT_ENV]: '/tmp/sc-test-root' },
    }));
    expect(r).toEqual({ supported: true, root: '/tmp/sc-test-root', source: 'test-override' });
  });
});
