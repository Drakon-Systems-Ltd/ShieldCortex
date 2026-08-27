/**
 * ShieldCortex — resolvable hook commands (#146).
 *
 * Fleet evidence, 31 Jul 2026: three of four boxes could not resolve a bare
 * `shieldcortex` from the non-interactive shell a harness spawns hooks in. Two
 * were running zero Claude Code enforcement — installed, configured, and
 * reported healthy by `doctor` the whole time.
 *
 * The cause was writing a bare command name. That makes enforcement depend on
 * the operator's shell configuration, which we neither control nor inspect: a
 * user-level npm prefix (the standard sudo-free setup) plus a distro `.bashrc`
 * that extends PATH *below* its own non-interactive early-return is enough for
 * every hook to die silently. The operator's own terminal resolves it fine, so
 * nothing looks wrong.
 *
 * Three halves to the fix, all here so they cannot drift apart:
 *
 *   1. `buildHookCommand` — the installer writes an ABSOLUTE path.
 *   2. `hookCommandResolves` — doctor verifies by RUNNING, not by reading.
 *   3. `needsAbsolutePathRepair` / `repairHookCommand` — upgrade fixes installs
 *      that are already wrong. Fixing the installer alone would leave every
 *      existing broken box broken forever, which is the quiet half of this bug.
 */
import { accessSync, constants, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

/** The bare name we historically wrote, and still fall back to. */
const BARE = 'shieldcortex';

/**
 * A leading run of `VAR=value` assignments, which sh treats as environment for
 * the command that follows. Our own installer emits this form
 * (`SHIELDCORTEX_RECALL_ENFORCE=1 shieldcortex hook prompt-recall`), and a
 * fixer that only matches commands *starting with* `shieldcortex` silently
 * skips them — which is exactly what happened during the live fleet repair.
 */
const ENV_PREFIX = /^((?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*)/;

function isExecutable(p: string): boolean {
  try {
    accessSync(p, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export interface ResolveHookBinaryOptions {
  /** `<npm prefix>/bin`, when the caller already knows it. */
  npmPrefixBin?: string;
  /** Extra directories to try, in order. */
  candidates?: string[];
}

/**
 * Locate the shieldcortex binary as an absolute path, or null.
 *
 * Null is a legitimate answer and callers must handle it: writing a path that
 * does not exist would be worse than the bare name we already write, because
 * it would fail on every host rather than merely on most.
 */
export function resolveHookBinary(opts: ResolveHookBinaryOptions = {}): string | null {
  const tried: string[] = [];
  if (opts.npmPrefixBin) tried.push(join(opts.npmPrefixBin, BARE));
  for (const c of opts.candidates ?? []) tried.push(c.endsWith(BARE) ? c : join(c, BARE));

  // `npm prefix -g` is the authoritative answer for a global install and is
  // where every affected fleet box had it. Consulted only if the caller did
  // not already supply one, since spawning npm is slow.
  if (!opts.npmPrefixBin) {
    try {
      const prefix = execFileSync('npm', ['config', 'get', 'prefix'], {
        encoding: 'utf-8',
        timeout: 5_000,
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (prefix && prefix !== 'undefined') tried.push(join(prefix, 'bin', BARE));
    } catch {
      // npm absent or slow — fall through to the remaining candidates.
    }
  }

  for (const p of tried) if (isExecutable(p)) return p;
  return null;
}

/** Quote a path for `sh -c` only when it needs it. */
function shellQuote(p: string): string {
  return /[\s"'\\$`]/.test(p) ? `"${p.replace(/(["\\$`])/g, '\\$1')}"` : p;
}

/**
 * The command string the installer writes.
 *
 * With no binary this returns the historical bare form — degrading to today's
 * behaviour, which is at least correct on hosts where PATH happens to work.
 */
export function buildHookCommand(binary: string | null, subcommand: string): string {
  if (!binary) return `${BARE} hook ${subcommand}`;
  return `${shellQuote(binary)} hook ${subcommand}`;
}

/** Strip a leading env-assignment run and return the executable token. */
function executableToken(command: string): string | null {
  const trimmed = String(command ?? '').trim();
  if (!trimmed) return null;
  const withoutEnv = trimmed.replace(ENV_PREFIX, '');
  const m = withoutEnv.match(/^("([^"]+)"|'([^']+)'|\S+)/);
  if (!m) return null;
  return m[2] ?? m[3] ?? m[1];
}

/**
 * Does this command actually resolve to something runnable?
 *
 * This is the check that would have caught the live fleet breakage. It asks the
 * question a harness asks — resolve this token the way a non-interactive shell
 * would — rather than the question we used to ask, which was merely "is a hook
 * entry present in settings.json".
 */
export function hookCommandResolves(command: string): boolean {
  const exe = executableToken(command);
  if (!exe) return false;

  // Absolute or relative path: check it directly.
  if (exe.includes('/')) return isExecutable(exe);

  // Bare name: resolve it the way the hook's own subprocess will. `command -v`
  // inside `sh -c` is precisely the lookup that failed on three fleet boxes.
  try {
    execFileSync('sh', ['-c', `command -v ${exe}`], {
      timeout: 5_000,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Where a shape-valid command actually lands (#393 SOL r2 B3).
 *
 * The shape check alone still trusted two things it never verified: that the
 * token RESOLVES to something runnable (a missing bare binary "owned"
 * session-start while every hook died silently — the #146 fleet failure worn
 * as a PASS), and that what it resolves to is plausibly OUR binary (any
 * executable named `/tmp/shieldcortex` qualified). Doctor cannot attest binary
 * identity, so a hit under a world-writable staging root is capped at
 * `suspicious` — never proof.
 */
export type HookCommandTrust = 'resolves' | 'unresolvable' | 'suspicious';

/** World-writable staging roots where anyone can plant an executable. On
 * macOS `/tmp` and `/var/tmp` are symlinks into `/private`, and the platform
 * temp dir (`os.tmpdir()`) lives under `/var/folders/...` — all of them are
 * attacker-stageable, so the realpath'd platform tmpdir joins the fixed
 * roots. */
const WORLD_WRITABLE_ROOTS: string[] = (() => {
  const roots = ['/tmp', '/var/tmp', '/dev/shm', '/private/tmp', '/private/var/tmp'];
  for (const t of [tmpdir()]) {
    try {
      const real = realpathSync(t);
      for (const r of [t, real]) if (r && r !== '/' && !roots.includes(r)) roots.push(r);
    } catch {
      if (t && t !== '/' && !roots.includes(t)) roots.push(t);
    }
  }
  return roots;
})();

function underWorldWritableRoot(p: string): boolean {
  const hit = (q: string): boolean =>
    WORLD_WRITABLE_ROOTS.some((root) => q === root || q.startsWith(`${root}/`));
  if (hit(p)) return true;
  // A symlink out of a "clean" prefix into /tmp is the same plant, one hop
  // removed. Unresolvable links fall through to the direct check above.
  try {
    return hit(realpathSync(p));
  } catch {
    return false;
  }
}

/**
 * Classify where a hook command's executable lands. Bare names are resolved
 * the way the hook's own `sh -c` subprocess would, and the RESOLVED path is
 * classified — a bare name whose PATH hit lands in /tmp is just as planted as
 * a literal `/tmp/shieldcortex`.
 *
 * `searchPath` overrides the subprocess PATH for the bare-name lookup. Tests
 * need it because jest's `process.env` is a sandboxed copy that never reaches
 * a spawned child (same quirk documented on `openClawConfigPath`).
 */
export function hookCommandTrust(command: string, opts: { searchPath?: string } = {}): HookCommandTrust {
  const exe = executableToken(command);
  if (!exe) return 'unresolvable';
  if (exe.includes('/')) {
    if (!isExecutable(exe)) return 'unresolvable';
    return underWorldWritableRoot(exe) ? 'suspicious' : 'resolves';
  }
  // Only interpolate tokens that cannot smuggle shell syntax; anything odder
  // than a plain program name is not a shape we ever write.
  if (!/^[A-Za-z0-9._-]+$/.test(exe)) return 'unresolvable';
  try {
    // Absolute /bin/sh: with a PATH override in force, a bare `sh` would be
    // looked up in that same override and never be found.
    const resolved = execFileSync('/bin/sh', ['-c', `command -v ${exe}`], {
      encoding: 'utf-8',
      timeout: 5_000,
      stdio: ['ignore', 'pipe', 'ignore'],
      ...(opts.searchPath !== undefined ? { env: { ...process.env, PATH: opts.searchPath } } : {}),
    }).trim();
    if (!resolved) return 'unresolvable';
    return underWorldWritableRoot(resolved) ? 'suspicious' : 'resolves';
  } catch {
    return 'unresolvable';
  }
}

/**
 * Strict shape check for a ShieldCortex hook command (#393 SOL H3).
 *
 * `command.includes('shieldcortex')` proves ownership of nothing: `echo
 * shieldcortex`, a stale wrapper, or `shieldcortex-evil hook session-start`
 * all match it. A command counts as ours only when the executable token itself
 * is the shieldcortex binary — bare, or any path whose basename is exactly
 * `shieldcortex` (a `.cmd`/`.exe`/`.bat` wrapper of that name on Windows) —
 * and the arguments are exactly `hook <subcommand>`: the one shape
 * `buildHookCommand` writes and the hook dispatcher supports. Env-assignment
 * prefixes are allowed because our own installer emits them.
 */
export function isShieldCortexHookCommand(command: unknown, subcommand: string): boolean {
  if (typeof command !== 'string') return false;
  const withoutEnv = command.trim().replace(ENV_PREFIX, '');
  const m = withoutEnv.match(/^("([^"]+)"|'([^']+)'|\S+)([\s\S]*)$/);
  if (!m) return false;
  const exe = m[2] ?? m[3] ?? m[1];
  const base = exe.replace(/\\/g, '/').split('/').pop() ?? '';
  if (base !== BARE && base.replace(/\.(cmd|exe|bat)$/i, '') !== BARE) return false;
  return (m[4] ?? '').trim().replace(/\s+/g, ' ') === `hook ${subcommand}`;
}

/** Is this one of OUR commands, written in the fragile bare form? */
export function needsAbsolutePathRepair(command: string): boolean {
  const exe = executableToken(command);
  if (!exe) return false;
  return exe === BARE;
}

/**
 * Rewrite a bare command to an absolute one, preserving any env-var prefix and
 * every trailing argument. Idempotent: an already-absolute command is returned
 * unchanged, so upgrade can run this on every box every time.
 */
export function repairHookCommand(command: string, binary: string | null): string {
  if (!binary || !needsAbsolutePathRepair(command)) return command;
  const trimmed = command.trim();
  const envMatch = trimmed.match(ENV_PREFIX);
  const prefix = envMatch ? envMatch[1] : '';
  const rest = trimmed.slice(prefix.length);
  return prefix + rest.replace(BARE, shellQuote(binary));
}
