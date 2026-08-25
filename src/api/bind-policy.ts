/**
 * #411 — API bind policy.
 *
 * Loopback (127.0.0.1 / ::1 / localhost) may start with the default
 * per-session token bootstrap. Non-loopback binds are fail-closed unless
 * the operator explicitly opts in AND a strong API token is configured.
 *
 * Never trust proxy headers (X-Forwarded-For) for loopback decisions.
 */

import { isIP } from 'net';

export const NON_LOOPBACK_ALLOW_ENV = 'SHIELDCORTEX_ALLOW_NON_LOOPBACK';
export const API_TOKEN_ENV = 'SHIELDCORTEX_API_TOKEN';

/** True for addresses that are only reachable from the local machine. */
export function isLoopbackHost(host: string | undefined | null): boolean {
  if (!host) return false;
  const h = host.trim().toLowerCase();
  if (h === 'localhost') return true;
  // Strip IPv6 brackets: [::1]
  const bare = h.startsWith('[') && h.endsWith(']') ? h.slice(1, -1) : h;
  // Zone id e.g. fe80::1%lo0
  const noZone = bare.split('%')[0]!;
  if (noZone === '::1') return true;
  if (noZone === '127.0.0.1') return true;
  const ver = isIP(noZone);
  if (ver === 4) {
    return noZone.startsWith('127.');
  }
  if (ver === 6) {
    // IPv4-mapped IPv6 loopback ::ffff:127.0.0.1
    const mapped = noZone.match(/^:ffff:(.+)$/i) || noZone.match(/^::ffff:(.+)$/i);
    if (mapped) {
      return isLoopbackHost(mapped[1]);
    }
    return noZone === '0:0:0:0:0:0:0:1' || noZone === '::1';
  }
  // Some stacks hand us the bare mapped form without isIP===6 classifying it.
  const mappedLoose = noZone.match(/^::ffff:(.+)$/i);
  if (mappedLoose) {
    return isLoopbackHost(mappedLoose[1]);
  }
  return false;
}

export interface BindPolicyInput {
  host: string;
  /** Explicit operator opt-in for non-loopback (env). */
  allowNonLoopback: boolean;
  /**
   * Strong token available before listen:
   * - env SHIELDCORTEX_API_TOKEN, or
   * - successfully generated/readable session token (≥32 chars)
   */
  apiToken: string | null | undefined;
}

export type BindPolicyResult =
  | { ok: true; mode: 'loopback' | 'non-loopback-authenticated' }
  | { ok: false; reason: string; code: 'NON_LOOPBACK_DENIED' | 'AUTH_REQUIRED' | 'AUTH_WEAK' };

/**
 * Decide whether the API may bind to `host`.
 * Fail-closed on non-loopback without opt-in + strong token.
 */
export function evaluateBindPolicy(input: BindPolicyInput): BindPolicyResult {
  if (isLoopbackHost(input.host)) {
    return { ok: true, mode: 'loopback' };
  }

  if (!input.allowNonLoopback) {
    return {
      ok: false,
      code: 'NON_LOOPBACK_DENIED',
      reason:
        `Refusing to bind API on non-loopback host "${input.host}". ` +
        `Default is loopback-only (127.0.0.1). To expose the API on a network interface you must set ` +
        `${NON_LOOPBACK_ALLOW_ENV}=1 and configure a strong ${API_TOKEN_ENV} (≥32 chars).`,
    };
  }

  const token = (input.apiToken ?? '').trim();
  if (!token) {
    return {
      ok: false,
      code: 'AUTH_REQUIRED',
      reason:
        `Non-loopback bind requires a strong API token. Set ${API_TOKEN_ENV} to a secret ≥32 characters ` +
        `(or ensure the session token file is readable).`,
    };
  }
  if (token.length < 32) {
    return {
      ok: false,
      code: 'AUTH_WEAK',
      reason: `${API_TOKEN_ENV} is too short (need ≥32 characters). Refusing non-loopback bind.`,
    };
  }

  return { ok: true, mode: 'non-loopback-authenticated' };
}

/** Human startup lines (never include the token value). */
export function formatBindPolicyDiagnostic(host: string, result: BindPolicyResult): string[] {
  if (result.ok) {
    if (result.mode === 'loopback') {
      return [`[ShieldCortex] API bind ${host} (loopback) — local trust model`];
    }
    return [
      `[ShieldCortex] API bind ${host} (non-loopback) — authenticated mode`,
      `[ShieldCortex] Public /api/auth/session-token is DISABLED on non-loopback binds`,
    ];
  }
  return [
    `[ShieldCortex] API bind blocked: ${result.code}`,
    result.reason,
  ];
}
