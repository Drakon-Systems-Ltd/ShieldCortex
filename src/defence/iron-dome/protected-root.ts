/**
 * Protected root — the OS ownership boundary (#501).
 *
 * ShieldCortex's config integrity HMAC (`.integrity-key` + `_sig`) is a
 * corruption detector, not a tamper control: the key sits beside the file it
 * signs, owned by the same UID as the agent, so anything that can edit the
 * config can re-sign it. The only signing authority a same-UID process cannot
 * forge on this host is the operating system's own ownership boundary.
 *
 * This module is that boundary, and nothing else. It answers two questions:
 *
 *   1. `resolveProtectedRoot()` — where do protected artefacts live?
 *   2. `verifyProtectedFile(path)` — is this file one the agent could not have
 *      written?
 *
 * Both are deliberately free of cryptography, of ShieldCortex config, and of
 * the database: they are imported by the Claude Code hook's dist path and by
 * the OpenClaw plugin, where a heavyweight import is a startup cost paid on
 * every tool call.
 *
 * #500 (self-protection of hook wiring, expected hashes, install-root pin) is
 * expected to build on the same two functions.
 */
import { lstatSync, readFileSync, statSync } from 'fs';
import { dirname, isAbsolute, resolve as resolvePath } from 'path';

// ── Audit vocabulary ──────────────────────────────────

/**
 * The outcome vocabulary for "a protected thing could not be verified".
 *
 * `policy_unverifiable` is the load-bearing one: a protected artefact EXISTS
 * but does not pass the ownership test, so we cannot tell an operator-owned
 * policy from one the agent wrote for itself. That is never silently ignored —
 * it forces the fail-closed posture (see policy-lock.ts).
 */
export const PROTECTED_AUDIT_OUTCOMES = [
  /** A protected artefact exists but failed verification. Fail closed. */
  'policy_unverifiable',
  /** A verified, root-owned protected artefact is in force. */
  'policy_locked',
  /** No protected artefact exists; the host is running unlocked. */
  'policy_unlocked',
  /** A write was refused because a verified lock covers the key. */
  'policy_refused',
] as const;

export type ProtectedAuditOutcome = (typeof PROTECTED_AUDIT_OUTCOMES)[number];

/** The `action` field every protected-root audit row carries. */
export const PROTECTED_AUDIT_ACTION = 'policy-lock';

export interface ProtectedAuditEvent {
  outcome: ProtectedAuditOutcome;
  /** The protected path this concerns, when there is one. */
  path?: string | null;
  /** Machine reason (a {@link ProtectedFileFailure} or a policy-lock reason). */
  reason?: string | null;
  /** Free-text detail for the audit row. Never content, never secrets. */
  detail?: string;
}

/**
 * Emit a protected-root audit row, best-effort.
 *
 * Deliberately a LAZY dynamic import of the iron-dome audit logger, not a
 * static one: a static import would drag the SQLite audit logger into every
 * consumer of this module, including the PreToolUse hook's dist import, where
 * it is both a startup cost on every tool call and a new way for the guard to
 * fail. Fire-and-forget with a swallowed rejection, exactly like
 * `logIronDomeAudit` itself — an audit row is evidence, never a gate.
 */
export function emitProtectedAudit(event: ProtectedAuditEvent): void {
  const allowed = event.outcome === 'policy_locked' || event.outcome === 'policy_unlocked';
  const reason =
    `${event.outcome}` +
    (event.path ? ` path=${event.path}` : '') +
    (event.reason ? ` reason=${event.reason}` : '') +
    (event.detail ? ` — ${event.detail}` : '');
  void import('./audit.js')
    .then(({ logIronDomeAudit }) => {
      logIronDomeAudit({ action: PROTECTED_AUDIT_ACTION, allowed, reason });
    })
    .catch(() => { /* best-effort: evidence, never a gate */ });
}

// ── The filesystem seam ───────────────────────────────

/** The subset of `fs.Stats` the ownership test actually reads. */
export interface ProtectedStat {
  uid: number;
  gid: number;
  /** Raw mode bits, as `fs.Stats.mode`. */
  mode: number;
  isFile: boolean;
  isDirectory: boolean;
  isSymbolicLink: boolean;
}

/**
 * The injectable seam. Everything this module learns about the host comes
 * through here, so the ownership rules can be tested exhaustively — including
 * the root-owned cases that are otherwise only reachable with real sudo.
 */
export interface ProtectedFsSeam {
  /** lstat, NOT following symlinks. null when absent or unstattable. */
  lstat(path: string): ProtectedStat | null;
  /** stat, following symlinks. null when absent or unstattable. */
  stat(path: string): ProtectedStat | null;
  /** File contents as utf-8, or null when unreadable. */
  readFile(path: string): string | null;
  /** Effective uid, or null where the platform has no such concept. */
  geteuid(): number | null;
  platform: NodeJS.Platform;
  /** Environment lookup — see {@link PROTECTED_ROOT_ENV} for the ONLY use. */
  env(name: string): string | undefined;
}

function toProtectedStat(s: {
  uid: number; gid: number; mode: number;
  isFile(): boolean; isDirectory(): boolean; isSymbolicLink(): boolean;
}): ProtectedStat {
  return {
    uid: s.uid,
    gid: s.gid,
    mode: s.mode,
    isFile: s.isFile(),
    isDirectory: s.isDirectory(),
    isSymbolicLink: s.isSymbolicLink(),
  };
}

/** The real host seam. */
export function defaultProtectedFsSeam(): ProtectedFsSeam {
  return {
    lstat(path) {
      try { return toProtectedStat(lstatSync(path)); } catch { return null; }
    },
    stat(path) {
      try { return toProtectedStat(statSync(path)); } catch { return null; }
    },
    readFile(path) {
      try { return readFileSync(path, 'utf-8'); } catch { return null; }
    },
    geteuid() {
      return typeof process.geteuid === 'function' ? process.geteuid() : null;
    },
    platform: process.platform,
    env(name) { return process.env[name]; },
  };
}

// ── Where the protected root lives ────────────────────

/** POSIX default. Root-owned `0755`, holding root-owned `0644` artefacts. */
export const DEFAULT_PROTECTED_ROOT = '/etc/shieldcortex';

/**
 * The ONLY production override: a root-owned pointer file that must itself
 * pass {@link verifyProtectedFile}. A distro or an operator who keeps policy
 * somewhere other than `/etc/shieldcortex` writes the absolute path here.
 * An unverifiable pointer is ignored — it can never move the root somewhere
 * the agent controls.
 *
 * Format: a single `key=value` line, `root=/absolute/path` (blank lines and
 * `#` comments ignored).
 */
export const PROTECTED_ROOT_POINTER = '/etc/shieldcortex.conf';

/**
 * A TEST seam, and a deliberately non-loosening one.
 *
 * The design rule is "override only via a root-owned file, never env", and this
 * does not break it: the canonical root is probed FIRST, and if a policy
 * artefact exists there the variable is ignored outright. So an agent that sets
 * it can never hide a real lock — the only thing it can do on a host with no
 * lock is introduce one, and a lock it can write is by definition same-UID and
 * therefore unverifiable, which is STRICTER than unlocked, not looser.
 *
 * It exists because the regression proof for #501 has to drive the built dist
 * and the built hook as separate processes (see the design doc §6); an
 * in-process seam cannot reach them, and the test may not write to `/etc`.
 */
export const PROTECTED_ROOT_ENV = 'SHIELDCORTEX_PROTECTED_ROOT';

/** The artefact name the policy lock uses inside the protected root. */
export const POLICY_LOCK_FILENAME = 'policy.json';

export type ProtectedRootUnsupportedReason = 'win32' | 'running-as-root' | 'euid-unavailable';

export type ProtectedRootResolution =
  | {
      supported: true;
      root: string;
      /** Which rule chose this root. */
      source: 'default' | 'pointer' | 'test-override';
    }
  | {
      supported: false;
      root: null;
      reason: ProtectedRootUnsupportedReason;
      /** Plain-language statement for doctor / CLI. */
      detail: string;
    };

function parsePointerRoot(contents: string): string | null {
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    if (line.slice(0, eq).trim() !== 'root') continue;
    const value = line.slice(eq + 1).trim();
    if (!value || !isAbsolute(value)) return null;
    return resolvePath(value);
  }
  return null;
}

/**
 * The one canonical protected path.
 *
 * Unsupported is not a failure to hide: a Windows host has no comparable
 * same-host ownership boundary, and an agent already running as root can write
 * anything root can write, so no local file can constrain it. Both are reported
 * plainly rather than papered over with a boundary that does not exist.
 */
export function resolveProtectedRoot(seam: ProtectedFsSeam = defaultProtectedFsSeam()): ProtectedRootResolution {
  if (seam.platform === 'win32') {
    return {
      supported: false,
      root: null,
      reason: 'win32',
      detail:
        'Windows has no same-host POSIX ownership boundary ShieldCortex can stand on, so a policy lock ' +
        'cannot exist here. A remote policy authority is the answer for this platform, not a local file ' +
        'the agent could rewrite.',
    };
  }
  const euid = seam.geteuid();
  if (euid === null) {
    return {
      supported: false,
      root: null,
      reason: 'euid-unavailable',
      detail: 'This runtime does not expose an effective uid, so file ownership cannot be compared. No policy lock is possible.',
    };
  }
  if (euid === 0) {
    return {
      supported: false,
      root: null,
      reason: 'running-as-root',
      detail:
        'The agent is running as root (euid 0). Anything root can read, root can rewrite, so no file on this ' +
        'host can constrain it. Run the agent as an unprivileged user for the policy lock to mean anything.',
    };
  }

  // Canonical root first, always — see PROTECTED_ROOT_ENV for why order matters.
  const canonicalLock = `${DEFAULT_PROTECTED_ROOT}/${POLICY_LOCK_FILENAME}`;
  const canonicalOccupied = seam.lstat(canonicalLock) !== null || seam.lstat(DEFAULT_PROTECTED_ROOT) !== null;

  if (!canonicalOccupied) {
    const override = seam.env(PROTECTED_ROOT_ENV)?.trim();
    if (override && isAbsolute(override)) {
      return { supported: true, root: resolvePath(override), source: 'test-override' };
    }
  }

  const pointer = verifyProtectedFile(PROTECTED_ROOT_POINTER, seam);
  if (pointer.ok) {
    const contents = seam.readFile(PROTECTED_ROOT_POINTER);
    const pointed = contents === null ? null : parsePointerRoot(contents);
    if (pointed) return { supported: true, root: pointed, source: 'pointer' };
  }

  return { supported: true, root: DEFAULT_PROTECTED_ROOT, source: 'default' };
}

// ── Is this file one the agent could not have written? ─

export type ProtectedFileFailure =
  | 'unsupported-platform'
  | 'euid-unavailable'
  | 'running-as-root'
  | 'missing'
  | 'symlink'
  | 'not-regular-file'
  | 'owned-by-agent'
  | 'group-or-other-writable'
  | 'parent-missing'
  | 'parent-not-directory'
  | 'parent-owned-by-agent'
  | 'parent-group-or-other-writable';

export interface ProtectedFileVerdict {
  ok: boolean;
  /** null exactly when `ok` is true. */
  reason: ProtectedFileFailure | null;
  /** Plain-language sentence, safe to print to an operator. Always set. */
  detail: string;
}

/** Group-write or other-write. Owner-write is fine: the owner is not the agent. */
const GROUP_OR_OTHER_WRITE = 0o022;

function fail(reason: ProtectedFileFailure, detail: string): ProtectedFileVerdict {
  return { ok: false, reason, detail };
}

/**
 * Verify that `path` is a file the agent's own UID could not have created,
 * replaced or rewritten.
 *
 * The rules, and why each one is load-bearing:
 *
 *   - **regular file, and `lstat` not `stat`** — a symlink the agent owns can
 *     point at a root-owned file today and at the agent's own file tomorrow;
 *     following it would verify the wrong inode.
 *   - **`uid !== euid`** — the whole boundary. A file the agent owns is a file
 *     the agent rewrites.
 *   - **no group/other write** — root-owned and world-writable is root-owned in
 *     name only.
 *   - **every ancestor directory, same rules** — a root-owned file inside a
 *     directory the agent can write is removable and re-creatable by the agent
 *     (`unlink` + create is governed by the DIRECTORY's permissions, not the
 *     file's). The walk continues to the filesystem root because the same
 *     argument applies one level further up: an agent-writable `/etc` makes an
 *     agent-writable `/etc/shieldcortex` regardless of that directory's own
 *     mode.
 *
 * Directories are checked with `stat` for ownership and mode, plus an `lstat`
 * symlink-owner check. `/etc` is a symlink to `/private/etc` on macOS, so an
 * lstat-only directory rule would refuse every Mac; an agent-owned SYMLINK in
 * the chain is still refused, which is the case the lstat rule was there for.
 */
export function verifyProtectedFile(
  path: string,
  seam: ProtectedFsSeam = defaultProtectedFsSeam(),
): ProtectedFileVerdict {
  if (seam.platform === 'win32') {
    return fail('unsupported-platform', 'Windows: no POSIX ownership boundary to verify against.');
  }
  const euid = seam.geteuid();
  if (euid === null) {
    return fail('euid-unavailable', 'This runtime exposes no effective uid, so ownership cannot be compared.');
  }
  if (euid === 0) {
    return fail(
      'running-as-root',
      'The agent is running as root, so no file ownership can constrain it. A protected file is meaningless here.',
    );
  }

  const st = seam.lstat(path);
  if (st === null) return fail('missing', `${path} does not exist.`);
  if (st.isSymbolicLink) {
    return fail('symlink', `${path} is a symlink; a protected artefact must be a regular file, not a redirect the agent can re-point.`);
  }
  if (!st.isFile) return fail('not-regular-file', `${path} is not a regular file.`);
  if (st.uid === euid) {
    return fail('owned-by-agent', `${path} is owned by this agent's own uid (${euid}); it can rewrite it at will.`);
  }
  if ((st.mode & GROUP_OR_OTHER_WRITE) !== 0) {
    return fail(
      'group-or-other-writable',
      `${path} is group- or other-writable (mode ${(st.mode & 0o7777).toString(8)}); owned by another uid but writable by this one.`,
    );
  }

  return verifyProtectedDirectoryChain(dirname(path), euid, seam);
}

/**
 * Walk a directory and every ancestor, applying the ownership rules. Exported
 * because #500's artefacts (an install-root pin, an expected-hashes file) need
 * to ask the same question about a directory on its own.
 */
export function verifyProtectedDirectoryChain(
  startDir: string,
  euid: number,
  seam: ProtectedFsSeam = defaultProtectedFsSeam(),
): ProtectedFileVerdict {
  let dir = resolvePath(startDir);
  // Bounded: dirname('/') === '/', so the loop terminates at the filesystem
  // root. The cap is belt-and-braces against a pathological seam.
  for (let depth = 0; depth < 64; depth += 1) {
    const link = seam.lstat(dir);
    if (link === null) return fail('parent-missing', `${dir} does not exist.`);
    if (link.isSymbolicLink && link.uid === euid) {
      return fail(
        'parent-owned-by-agent',
        `${dir} is a symlink owned by this agent's uid (${euid}); it can re-point the whole directory.`,
      );
    }
    const st = seam.stat(dir);
    if (st === null) return fail('parent-missing', `${dir} could not be stat'd.`);
    if (!st.isDirectory) return fail('parent-not-directory', `${dir} is not a directory.`);
    if (st.uid === euid) {
      return fail(
        'parent-owned-by-agent',
        `${dir} is owned by this agent's own uid (${euid}); it can unlink and re-create anything inside it, ` +
        'whoever owns the file.',
      );
    }
    if ((st.mode & GROUP_OR_OTHER_WRITE) !== 0) {
      return fail(
        'parent-group-or-other-writable',
        `${dir} is group- or other-writable (mode ${(st.mode & 0o7777).toString(8)}); this agent can unlink and ` +
        're-create the files inside it.',
      );
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { ok: true, reason: null, detail: 'verified: owned by another uid, in a directory chain this agent cannot write.' };
}

/** A one-line, operator-facing sentence for a failure reason. */
export function describeProtectedFailure(reason: ProtectedFileFailure): string {
  switch (reason) {
    case 'unsupported-platform': return 'platform has no POSIX ownership boundary';
    case 'euid-unavailable': return 'effective uid unavailable';
    case 'running-as-root': return 'agent runs as root';
    case 'missing': return 'file absent';
    case 'symlink': return 'path is a symlink';
    case 'not-regular-file': return 'path is not a regular file';
    case 'owned-by-agent': return 'file owned by the agent uid';
    case 'group-or-other-writable': return 'file is group/other writable';
    case 'parent-missing': return 'parent directory absent';
    case 'parent-not-directory': return 'parent path is not a directory';
    case 'parent-owned-by-agent': return 'parent directory owned by the agent uid';
    case 'parent-group-or-other-writable': return 'parent directory is group/other writable';
  }
}
