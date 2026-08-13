/**
 * ShieldCortex — permissions on our own state (#163).
 *
 * Hardening audit, 1 Aug 2026, measured on a live production box with a default
 * install and nothing hand-modified:
 *
 *   ~/.shieldcortex        775   everything below
 *   memories.db            644   every captured memory — the product's asset
 *   audit/                 775   the enforcement audit trail
 *   config.json.bak-*      664   copies of a file deliberately written 0600
 *
 * Nothing in the codebase set a mode on any of them; they inherited the process
 * umask. The 0600 discipline existed for `config.json` and the approval store
 * file, so the intent was there — it had simply never been applied to the
 * largest and most sensitive artifacts.
 *
 * Two of these are more than tidiness:
 *
 *   - A world-readable `memories.db` is the entire data asset of a
 *     memory-SECURITY product readable by any local user.
 *   - A group-writable `audit/` means a non-owner can delete or forge records.
 *     That trail is what proves enforcement fired — it is what the live canary
 *     checks and what every incident this week was reconstructed from. An audit
 *     log that others can edit is not an audit log.
 *
 * And a 0600 file inside a 775 directory is not protected at all: unlink +
 * recreate needs only directory write permission. That is the same shape as the
 * original #127 finding — mechanism guarded, state container not.
 *
 * ZEROTH LAW: best-effort, never fatal. A chmod that fails on an exotic
 * filesystem (a network mount, a container overlay) must never break the host
 * or the agent. But it is REPORTED rather than swallowed — a silent failure to
 * harden is the false-green pattern wearing yet another hat.
 */
import fs from 'fs';
import path from 'path';

/** Directories: owner-only. Group/world have no business traversing our state. */
export const SECURE_DIR_MODE = 0o700;
/** Files: owner read/write only. */
export const SECURE_FILE_MODE = 0o600;

/** Subdirectories of the state dir that must be owner-only. */
export const SECURE_SUBDIRS = ['audit', 'approvals', 'logs', 'quarantine', 'recall-log', 'precompact-log'];

/** Files that must be owner-only, by exact name or by prefix. */
const SECURE_FILE_PREFIXES = ['memories.db', 'config.json', 'worker.json', 'integrity'];

/**
 * #218 — create state-tree paths already owner-only, at CREATION.
 *
 * The audited set (this dir + SECURE_SUBDIRS + SECURE_FILE_PREFIXES) is
 * hardened at install/update by `secureStatePermissions`. But `mkdir`'s mode
 * binds only when the directory is CREATED and is IGNORED for one that already
 * exists, and `open(2)` without a mode uses `0666 & ~umask` (644, or 664 under
 * umask 002) — so ANY path a runtime recreates after the install-time pass
 * (the lock file every gateway bounce, the log/audit dirs every hook run) lands
 * loose again, and doctor fails on it after every restart.
 *
 * The fix is to stop relying on a later pass: create it secure the first time.
 * `secureStatePermissions` still runs on install/update to retro-tighten the
 * fleet's already-loose paths, because a create-mode cannot do that.
 *
 * These are the single source of truth for the two create modes; no state-tree
 * creator should pass a bare `{ recursive: true }` or a mode-less `open`.
 */
export function mkdirSecure(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: SECURE_DIR_MODE });
}

/** Mode for openSync/writeFileSync of any file inside the state tree. */
export const SECURE_OPEN_MODE = SECURE_FILE_MODE;   // 0o600

export interface PermissionFinding {
  path: string;
  /** The mode we found, as an octal string (e.g. "644"). */
  found: string;
  /** The mode required. */
  required: string;
  /** True when we successfully corrected it. */
  fixed: boolean;
  /** Present when the correction failed — never fatal, always reported. */
  error?: string;
}

function modeOf(target: string): number | null {
  try {
    return fs.statSync(target).mode & 0o777;
  } catch {
    return null;
  }
}

/** Anything readable or writable by group or other. */
function isTooOpen(mode: number, required: number): boolean {
  return (mode & ~required) !== 0;
}

function secure(target: string, required: number, findings: PermissionFinding[]): void {
  const mode = modeOf(target);
  if (mode === null) return;                       // absent — nothing to harden
  if (!isTooOpen(mode, required)) return;          // already at or tighter than required
  const finding: PermissionFinding = {
    path: target,
    found: mode.toString(8).padStart(3, '0'),
    required: required.toString(8).padStart(3, '0'),
    fixed: false,
  };
  try {
    fs.chmodSync(target, required);
    finding.fixed = true;
  } catch (err) {
    finding.error = err instanceof Error ? err.message : String(err);
  }
  findings.push(finding);
}

/**
 * Bring `~/.shieldcortex` and everything security-relevant inside it to
 * owner-only. Returns every path that WAS too open, whether or not the
 * correction succeeded — callers report, they do not assume.
 *
 * Idempotent and safe to run on every install, upgrade and doctor pass. It must
 * run on upgrade too, not only on fresh installs: every existing box is in the
 * measured state above, and fixing only the installer would leave the whole
 * fleet exactly as it is (the #146 lesson).
 */
export function secureStatePermissions(stateDir: string): PermissionFinding[] {
  const findings: PermissionFinding[] = [];
  if (modeOf(stateDir) === null) return findings;   // not created yet

  secure(stateDir, SECURE_DIR_MODE, findings);
  for (const sub of SECURE_SUBDIRS) secure(path.join(stateDir, sub), SECURE_DIR_MODE, findings);

  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(stateDir, { withFileTypes: true });
  } catch {
    return findings;
  }
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    // Backups and WAL/shm siblings included by prefix: a protection the backup
    // path does not inherit is a protection with a scheduled expiry.
    if (!SECURE_FILE_PREFIXES.some(p => entry.name.startsWith(p))) continue;
    secure(path.join(stateDir, entry.name), SECURE_FILE_MODE, findings);
  }
  return findings;
}

/**
 * Measure without changing anything — for `doctor`, which reports rather than
 * mutates. Returns the paths that are currently too open.
 */
export function auditStatePermissions(stateDir: string): Array<{ path: string; found: string; required: string }> {
  const out: Array<{ path: string; found: string; required: string }> = [];
  const check = (target: string, required: number): void => {
    const mode = modeOf(target);
    if (mode === null || !isTooOpen(mode, required)) return;
    out.push({
      path: target,
      found: mode.toString(8).padStart(3, '0'),
      required: required.toString(8).padStart(3, '0'),
    });
  };

  if (modeOf(stateDir) === null) return out;
  check(stateDir, SECURE_DIR_MODE);
  for (const sub of SECURE_SUBDIRS) check(path.join(stateDir, sub), SECURE_DIR_MODE);
  try {
    for (const entry of fs.readdirSync(stateDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      if (!SECURE_FILE_PREFIXES.some(p => entry.name.startsWith(p))) continue;
      check(path.join(stateDir, entry.name), SECURE_FILE_MODE);
    }
  } catch {
    // unreadable state dir — the Database/Disk checks already report that
  }
  return out;
}
