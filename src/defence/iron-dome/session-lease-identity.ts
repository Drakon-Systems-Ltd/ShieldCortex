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
 * Identity comes only from the session id the launcher hands each plane. Two
 * different raw ids are two sessions; nothing here guesses otherwise.
 */
import { sessionKeyFor, type SessionGuardOptions } from './session-guard.js';

/**
 * The lease holder for a raw session id: the session key, or '' when the id is
 * blank or no salt is available. '' is deliberate — `evaluateToolCallLease`
 * gives a blank self its per-process fallback, and a blank never re-enters.
 */
export function leaseIdentityFor(
  rawSessionId: string | null | undefined,
  opts: Pick<SessionGuardOptions, 'home' | 'salt'> = {},
): string {
  return sessionKeyFor(typeof rawSessionId === 'string' ? rawSessionId : undefined, opts) ?? '';
}
