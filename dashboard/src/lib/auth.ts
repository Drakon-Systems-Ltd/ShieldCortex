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
