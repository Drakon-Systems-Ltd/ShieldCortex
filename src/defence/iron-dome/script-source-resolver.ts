/**
 * ShieldCortex — the invoked-script source resolver, defined once (#160).
 *
 * `evaluateToolCall` folds an invoked script's CONTENTS into the scan only when
 * the caller supplies a resolver. Without one the call yields
 * `opaque-script-invocation` and allows — which is the correct default for a
 * pure function that must not do I/O, but it means the write-then-exec fix
 * shipped in v4.47.17 is only as wired as its callers.
 *
 * It was wired on one of two enforcement surfaces. The OpenClaw realtime plugin
 * passed a resolver; the Claude Code PreToolUse hook — the surface that gates
 * every Bash call in a Claude Code session — called the guard with two
 * arguments and no resolver. A payload written in one call and executed by path
 * in the next was folded and blocked on one surface and allowed on the other,
 * with a green suite either side because each surface was tested against its
 * own wiring.
 *
 * That is the third instance of this family (#146 was the same shape: a fix on
 * one call site, the sibling left as it was). The recurring root cause in this
 * codebase is not bad logic — it is a fix landing on one of two call sites. So
 * the resolver lives here, once, and both surfaces import it.
 *
 * Safety rails are deliberately identical to what the plugin used, because a
 * resolver is a file-read primitive reached from untrusted tool input:
 *   - never read pseudo-filesystems (/proc, /sys, /dev) — reads there can block
 *     or have side effects,
 *   - never read anything but a regular file,
 *   - cap the size, so a huge file cannot be used to stall the guard,
 *   - swallow every error and return null, so an unreadable path degrades to
 *     `opaque-script-invocation` rather than crashing the interceptor. A guard
 *     that throws is a guard that fails open.
 */
import { readFileSync, statSync } from 'fs';
import { homedir } from 'os';
import { isAbsolute, join, resolve as resolvePath } from 'path';

/** 256 KB — matches the guard core's fold cap. */
export const MAX_SCRIPT_SOURCE_BYTES = 262_144;

/** Pseudo-filesystems: reading these can block or have side effects. */
export const UNREADABLE_PATH_PREFIX = /^\/(?:proc|sys|dev)\//;

/**
 * Build a resolver that reads an invoked script's source, relative to `cwd`.
 * Returns null for anything it cannot safely read — the caller reads null as
 * "opaque", never as "safe".
 */
export function createScriptSourceResolver(cwd?: string): (scriptPath: string) => string | null {
  const base = cwd && typeof cwd === 'string' ? cwd : process.cwd();
  return (scriptPath: string): string | null => {
    try {
      if (!scriptPath || typeof scriptPath !== 'string') return null;
      const expanded = scriptPath.startsWith('~/') ? join(homedir(), scriptPath.slice(2)) : scriptPath;
      const full = isAbsolute(expanded) ? expanded : resolvePath(base, expanded);
      if (UNREADABLE_PATH_PREFIX.test(full)) return null;
      const st = statSync(full);
      if (!st.isFile() || st.size > MAX_SCRIPT_SOURCE_BYTES) return null;
      return readFileSync(full, 'utf8');
    } catch {
      return null;                          // missing, unreadable, anything — stay silent, stay alive
    }
  };
}
