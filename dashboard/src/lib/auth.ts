/**
 * Dashboard Auth Utility
 *
 * Fetches the per-session API token on first use (one-time handshake)
 * and wraps fetch() to include the Authorization header on mutating requests.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

let cachedToken: string | null = null;
let tokenPromise: Promise<string> | null = null;

/**
 * Fetch the session token from the server (one-time).
 * Caches the result — subsequent calls return the cached token.
 */
export async function getApiToken(): Promise<string> {
  if (cachedToken) return cachedToken;

  // Deduplicate concurrent calls
  if (tokenPromise) return tokenPromise;

  tokenPromise = (async () => {
    const res = await fetch(`${API_BASE}/api/auth/session-token`);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || 'Failed to fetch session token');
    }
    const { token } = await res.json();
    cachedToken = token;
    return token;
  })();

  try {
    return await tokenPromise;
  } finally {
    tokenPromise = null;
  }
}

/**
 * Auth-aware fetch wrapper.
 * Adds Authorization header on all requests (server requires auth on all non-public endpoints).
 */
export async function authFetch(url: string, options?: RequestInit): Promise<Response> {
  const token = await getApiToken();
  const headers = new Headers(options?.headers);
  headers.set('Authorization', `Bearer ${token}`);

  return fetch(url, { ...options, headers });
}

/**
 * Best-effort error extraction for API responses.
 * Keeps operator-facing errors specific instead of collapsing everything into
 * generic "failed" messages when the backend already explained the problem.
 */
export async function readApiError(response: Response, fallback: string): Promise<string> {
  const contentType = response.headers.get('content-type') ?? '';

  if (contentType.includes('application/json')) {
    const body = await response.json().catch(() => null) as
      | { error?: unknown; message?: unknown; code?: unknown }
      | null;

    if (typeof body?.error === 'string' && body.error.trim()) {
      return body.error;
    }

    if (typeof body?.message === 'string' && body.message.trim()) {
      return body.message;
    }

    if (typeof body?.code === 'string' && body.code.trim()) {
      return `${fallback} (${body.code})`;
    }
  }

  const text = await response.text().catch(() => '');
  return text.trim() || fallback;
}

// ── Feature gating helpers ────────────────────────────────

/**
 * Error thrown when accessing a Pro/Team feature without the required licence.
 * Used by gatedFetch and checked in React Query retry logic.
 */
export class FeatureLockedError extends Error {
  feature: string;
  requiredTier: string;

  constructor(feature: string, requiredTier: string) {
    super(`Feature locked: ${feature}`);
    this.name = 'FeatureLockedError';
    this.feature = feature;
    this.requiredTier = requiredTier;
  }
}

/**
 * Auth-aware fetch that detects structured 403 (FEATURE_GATED) responses
 * and throws FeatureLockedError instead of returning the response.
 *
 * Use in hooks for Pro-gated endpoints — React Query can then short-circuit
 * retries and components can check `isLocked` instead of showing error UI.
 */
export async function gatedFetch(url: string, options?: RequestInit): Promise<Response> {
  const response = await authFetch(url, options);
  if (response.status === 403) {
    const body = await response.json().catch(() => ({}));
    if (body.code === 'FEATURE_GATED') {
      throw new FeatureLockedError(body.feature, body.requiredTier);
    }
  }
  return response;
}
