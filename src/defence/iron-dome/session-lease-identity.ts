/**
 * #854 — the ONE lease identity both enforcement planes act as.
 *
 * The Claude Code PreToolUse hook has always leased as
 * `sessionKeyFor(session_id)` (`sc-` + HMAC). The OpenClaw interceptor leased
 * as the RAW sessionId, which can never equal an `sc-…` holder — so whichever
 * plane acquired first, the other plane of the same session was refused as
 * "held by another session". Both planes now derive the holder here, from the
 * same formula and the same salt the hooks use.
 *
 * Identity comes only from the session id the launcher hands each plane, with
 * surrounding whitespace trimmed. Distinct canonical ids are distinct sessions;
 * nothing here guesses a relationship between them.
 */
import { sessionKeyFor, type SessionGuardOptions } from './session-guard.js';

/**
 * The lease holder for a raw session id:
 *  - the session key, for a nonblank id;
 *  - '' for a blank, whitespace-only or missing id. `evaluateToolCallLease`
 *    maps '' to its per-process `anon-pid-<pid>` fallback, unchanged — so
 *    blank callers inside ONE process share that holder and re-enter each
 *    other, while a blank on the hook plane (`ppid:<pid>`) never matches it;
 *  - null when the id is nonblank but its key cannot be derived (ill-formed
 *    Unicode or no usable salt). That is NOT a blank: falling back to '' would
 *    put every named session of this process on one shared holder. A caller
 *    must refuse the scoped lease call instead.
 */
export function leaseIdentityFor(
  rawSessionId: string | null | undefined,
  opts: Pick<SessionGuardOptions, 'home' | 'salt'> = {},
): string | null {
  if (typeof rawSessionId !== 'string' || !rawSessionId.trim()) return '';
  return sessionKeyFor(rawSessionId, opts);
}
