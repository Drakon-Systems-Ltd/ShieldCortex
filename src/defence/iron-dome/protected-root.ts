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
import { lstatSync, readFileSync, readlinkSync, statSync } from 'fs';
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
  /**
   * The raw target of a symlink, exactly as `fs.readlink` returns it (may be
   * relative to the symlink's own directory). null when not a symlink or
   * unreadable. The directory-chain walk needs this to verify a symlinked
   * ancestor's REAL ancestry, not just the lexical path that named it.
   */
  readlink(path: string): string | null;
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
    readlink(path) {
      try { return readlinkSync(path, 'utf-8'); } catch { return null; }
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
 * does not break it: BOTH production rules — the canonical root and the
 * root-owned pointer file — are resolved FIRST, and if either answers, the
 * variable is ignored outright. So an agent that sets it can never hide a real
 * lock — the only thing it can do on a host with no lock is introduce one, and
 * a lock it can write is by definition same-UID and therefore unverifiable,
 * which is STRICTER than unlocked, not looser.
 *
 * The pointer half of that sentence is the #501 review's BLOCK-2: gating on
 * the canonical root alone left a pointer host wide open, because a pointer
 * host is precisely a host with no `/etc/shieldcortex`.
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

  // Both PRODUCTION roots are resolved before the env seam is even read, and
  // that ordering is the fix for the #501 review's BLOCK-2. The original code
  // gated the variable on the CANONICAL root alone, which is sound only on a
  // host that uses `/etc/shieldcortex`. A pointer host by definition keeps
  // policy elsewhere, so `/etc/shieldcortex` does not exist there — and the
  // agent could set one variable and walk the resolver away from a genuinely
  // root-owned, verified pointer root. That is `locked` → `absent`: straight to
  // unlocked, the one outcome this seam was argued to be incapable of.
  const canonicalLock = `${DEFAULT_PROTECTED_ROOT}/${POLICY_LOCK_FILENAME}`;
  const canonicalOccupied = seam.lstat(canonicalLock) !== null || seam.lstat(DEFAULT_PROTECTED_ROOT) !== null;
  const pointed = resolvePointerRoot(seam);

  // "Occupied" therefore means "a production root is resolvable HERE", by
  // either rule — not merely "`/etc/shieldcortex` exists". The env seam is
  // consulted last and only on a host where neither production rule answers,
  // which is exactly the unlocked host where the worst it can do is introduce
  // a same-UID lock: unverifiable, i.e. STRICTER than unlocked.
  if (!canonicalOccupied && pointed === null) {
    const override = seam.env(PROTECTED_ROOT_ENV)?.trim();
    if (override && isAbsolute(override)) {
      return { supported: true, root: resolvePath(override), source: 'test-override' };
    }
  }

  if (pointed !== null) return { supported: true, root: pointed, source: 'pointer' };

  return { supported: true, root: DEFAULT_PROTECTED_ROOT, source: 'default' };
}

/**
 * The pointed-to root, or null when there is no pointer this host can trust.
 *
 * An unverifiable pointer is ignored outright — the file has to pass the same
 * ownership rules as the lock itself, so it can never move the root somewhere
 * the agent controls.
 */
function resolvePointerRoot(seam: ProtectedFsSeam): string | null {
  if (!verifyProtectedFile(PROTECTED_ROOT_POINTER, seam).ok) return null;
  const contents = seam.readFile(PROTECTED_ROOT_POINTER);
  return contents === null ? null : parsePointerRoot(contents);
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
  | 'parent-group-or-other-writable'
  | 'parent-symlink-unresolvable'
  | 'parent-symlink-cycle';

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
 * Directories are checked with `lstat`. A symlinked ancestor is allowed only
 * when the SYMLINK is not agent-owned AND its resolved target's whole
 * directory chain passes the same rules. `/etc` is a symlink to
 * `/private/etc` on macOS, so refusing symlinked ancestors outright would
 * refuse every Mac; but a root-owned `/x -> /agent-owned/safe` is exactly as
 * agent-replaceable as `/agent-owned/safe` itself (the agent renames `safe`
 * aside and re-creates it). The lexical chain above the symlink is walked
 * too: an agent-writable directory that CONTAINS the symlink can replace the
 * symlink. Both chains must pass.
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
 *
 * Two chains are walked, and both must pass:
 *
 *   - the LEXICAL chain: `startDir`, its `dirname`, and so on up to `/`.
 *   - for every symlink met on the way, the RESOLVED chain: the link's target
 *     and every ancestor of the target, recursively (the target may itself
 *     pass through further symlinks).
 *
 * The lexical chain alone was the PR #522 review blocker: a root-owned
 * `/protected -> /agent-parent/safe` passed, because `stat` reported the
 * root-owned `safe` and the walk then continued from `/`, never examining
 * `/agent-parent`. A symlink's `stat` says what the target IS, not who can
 * replace it.
 *
 * The target is resolved LEXICALLY (`path.resolve`), which matches the
 * kernel except when a `..` segment in the target traverses a FURTHER
 * symlink — component-at-a-time resolution would be needed to close that,
 * and it is deliberately out of scope here: every symlink on such a path
 * must already be non-agent-owned to reach the divergence, so it is not
 * agent-reachable (round-5 review, FIND-2).
 */
export function verifyProtectedDirectoryChain(
  startDir: string,
  euid: number,
  seam: ProtectedFsSeam = defaultProtectedFsSeam(),
): ProtectedFileVerdict {
  return walkDirectoryChain(resolvePath(startDir), euid, seam, {
    active: [],
    verified: new Set(),
    budget: MAX_CHAIN_STEPS,
  });
}

/**
 * Belt-and-braces bound on the total number of directories examined across
 * both chains. `active` catches genuine symlink loops exactly; the budget
 * exists for a pathological seam that never reaches `/`.
 */
const MAX_CHAIN_STEPS = 256;

interface ChainWalk {
  /** Directories whose verification is in progress (a stack) — re-entry is a loop. */
  active: string[];
  /** Directories already verified on another path; no need to walk twice. */
  verified: Set<string>;
  budget: number;
}

function walkDirectoryChain(
  startDir: string,
  euid: number,
  seam: ProtectedFsSeam,
  walk: ChainWalk,
): ProtectedFileVerdict {
  let dir = startDir;
  // Bounded: dirname('/') === '/', so the lexical loop terminates at the
  // filesystem root; `active` terminates the symlink recursion.
  for (;;) {
    if (walk.budget <= 0) {
      return fail(
        'parent-symlink-cycle',
        `${dir}: the directory chain did not terminate within ${MAX_CHAIN_STEPS} steps.`,
      );
    }
    walk.budget -= 1;

    if (walk.active.includes(dir)) {
      return fail('parent-symlink-cycle', `${dir} is reached again through its own symlink chain; a loop cannot be verified.`);
    }
    if (!walk.verified.has(dir)) {
      walk.active.push(dir);
      const verdict = verifyOneDirectory(dir, euid, seam, walk);
      walk.active.pop();
      if (!verdict.ok) return verdict;
      walk.verified.add(dir);
    }

    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { ok: true, reason: null, detail: 'verified: owned by another uid, in a directory chain this agent cannot write.' };
}

/**
 * Resolve a symlink target the way the kernel does: component by component,
 * following any intermediate symlink BEFORE the next component is applied, so
 * that a `..` is applied to the REAL parent rather than to the lexical one.
 *
 * Deliberately NOT `path.resolve` and NOT `fs.realpathSync`: both collapse
 * `..` lexically, so both answer `safe/policy-dir` for `safe/jump/../policy-dir`
 * while the kernel answers `<target of jump>/../policy-dir`. And deliberately
 * not `fs.realpathSync.native` either, which is correct but bypasses
 * {@link ProtectedFsSeam} — every filesystem read on this path goes through
 * the seam so the tests can drive ownership and link layouts that cannot be
 * built without root.
 *
 * `base` is the directory the (relative) target is resolved against. Returns
 * the resolved absolute path, or null when the walk exhausts `walk.budget` —
 * a symlink loop inside the target, which the caller reports as unresolvable.
 * A component that does not exist cannot be a symlink, so it is appended
 * literally and the caller's chain walk reports it as missing.
 */
function resolveLinkTarget(
  base: string,
  target: string,
  seam: ProtectedFsSeam,
  walk: ChainWalk,
): string | null {
  let current = isAbsolute(target) ? '/' : base;
  // A stack, so an intermediate symlink's own target is spliced in AHEAD of
  // the components still to come — exactly the kernel's order.
  const pending = target.split('/').reverse();
  while (pending.length > 0) {
    if (walk.budget <= 0) return null;
    walk.budget -= 1;

    const component = pending.pop() as string;
    if (component === '' || component === '.') continue;
    if (component === '..') {
      // `current` has already had every symlink in it followed, so this is the
      // REAL parent — the whole point of resolving one component at a time.
      current = dirname(current);
      continue;
    }

    const next = resolvePath(current, component);
    const stat = seam.lstat(next);
    if (stat === null || !stat.isSymbolicLink) {
      current = next;
      continue;
    }
    const inner = seam.readlink(next);
    if (inner === null || inner === '') {
      // Unreadable target: the caller's chain walk on `next` reports it.
      current = next;
      continue;
    }
    if (isAbsolute(inner)) current = '/';
    for (const part of inner.split('/').reverse()) pending.push(part);
  }
  return current;
}

/** The rules for ONE directory in the chain, recursing into a symlink's target chain. */
function verifyOneDirectory(
  dir: string,
  euid: number,
  seam: ProtectedFsSeam,
  walk: ChainWalk,
): ProtectedFileVerdict {
  const link = seam.lstat(dir);
  if (link === null) return fail('parent-missing', `${dir} does not exist.`);

  if (link.isSymbolicLink) {
    if (link.uid === euid) {
      return fail(
        'parent-owned-by-agent',
        `${dir} is a symlink owned by this agent's uid (${euid}); it can re-point the whole directory.`,
      );
    }
    const target = seam.readlink(dir);
    if (target === null || target === '') {
      return fail('parent-symlink-unresolvable', `${dir} is a symlink whose target could not be read.`);
    }
    // A symlink target is relative to the directory that CONTAINS the link.
    const resolved = resolvePath(dirname(dir), target);
    const targetVerdict = walkDirectoryChain(resolved, euid, seam, walk);
    if (!targetVerdict.ok) {
      return fail(targetVerdict.reason ?? 'parent-symlink-unresolvable', `${dir} -> ${resolved}: ${targetVerdict.detail}`);
    }

    // …and `resolvePath` is not enough on its own, because it collapses `..`
    // LEXICALLY while the kernel follows each intermediate symlink FIRST and
    // then applies `..` to the real parent. For `safe/jump/../policy-dir` the
    // lexical answer is `safe/policy-dir` — a path nothing ever opens — while
    // a reader that follows `jump` lands in the directory that holds whatever
    // `jump` points at. An agent who owns THAT directory owned the file, and
    // this walk vouched for somewhere else entirely (#522 r2 P1). `..` behind
    // a symlink is the only way the two answers differ, so the real path is
    // resolved component-by-component and verified as well when it does. This
    // is purely additive: the lexical chain still has to pass, so nothing that
    // is refused today starts being accepted.
    const realTarget = resolveLinkTarget(dirname(dir), target, seam, walk);
    if (realTarget === null) {
      return fail(
        'parent-symlink-unresolvable',
        `${dir} -> ${target}: the target's own symlink chain did not terminate within ${MAX_CHAIN_STEPS} steps.`,
      );
    }
    if (realTarget !== resolved) {
      const realVerdict = walkDirectoryChain(realTarget, euid, seam, walk);
      if (!realVerdict.ok) {
        return fail(
          realVerdict.reason ?? 'parent-symlink-unresolvable',
          `${dir} -> ${realTarget} (the path a reader actually opens; \`${target}\` collapses lexically to ` +
          `${resolved}, which is not where the kernel lands): ${realVerdict.detail}`,
        );
      }
    }
    // The target chain vouches for what the link points at today; the lexical
    // walk continuing above `dir` vouches for who can re-point it tomorrow.
    return { ok: true, reason: null, detail: `${dir} -> ${resolved}: target chain verified.` };
  }

  if (!link.isDirectory) return fail('parent-not-directory', `${dir} is not a directory.`);
  if (link.uid === euid) {
    return fail(
      'parent-owned-by-agent',
      `${dir} is owned by this agent's own uid (${euid}); it can replace anything inside it, whoever owns the file.`,
    );
  }
  if ((link.mode & GROUP_OR_OTHER_WRITE) !== 0) {
    return fail(
      'parent-group-or-other-writable',
      `${dir} is group- or other-writable (mode ${(link.mode & 0o7777).toString(8)}); this agent can replace ` +
      'the files inside it.',
    );
  }
  return { ok: true, reason: null, detail: `${dir}: verified.` };
}

/**
 * A one-line, operator-facing sentence for a failure reason.
 *
 * Takes a plain `string`, not just {@link ProtectedFileFailure}: callers layer
 * their own reasons on top of these (policy-lock adds `parse-failed`,
 * `schema-failed`), and an unrecognised reason must render as ITSELF rather
 * than as `undefined` in an operator's doctor output.
 */
export function describeProtectedFailure(reason: ProtectedFileFailure | string): string {
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
    case 'parent-symlink-unresolvable': return 'a symlinked parent directory could not be resolved';
    case 'parent-symlink-cycle': return 'the parent directory chain loops or does not terminate';
    default: return reason;
  }
}
