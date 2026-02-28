/**
 * Periodic online licence validation — catches revocations.
 *
 * Fire-and-forget, never blocks. Same pattern as syncToCloud() in cloud/sync.ts.
 * If offline, the licence stays valid until its exp date.
 */

import { getLicenseFile, updateValidationStatus } from './store.js';
import { parseLicensePayload } from './verify.js';
import { ONLINE_VALIDATION_INTERVAL_MS } from './keys.js';
import { getCloudConfig } from '../cloud/config.js';

type ValidationStatus = 'valid' | 'revoked' | 'expired';

let lastValidationAttempt = 0;

/**
 * Run online validation if enough time has passed since the last check.
 * Non-blocking — errors are silently ignored.
 */
export function scheduleOnlineValidation(): void {
  const now = Date.now();
  if (now - lastValidationAttempt < ONLINE_VALIDATION_INTERVAL_MS) return;
  lastValidationAttempt = now;

  // Fire-and-forget
  validateOnline().catch(() => {});
}

// ── Shared HTTP helper ──────────────────────────────────

/**
 * Fetch the validation status from the SaaS API.
 * Returns null on network error, timeout, or server error.
 */
async function fetchValidationStatus(sid: string): Promise<ValidationStatus | null> {
  const config = getCloudConfig();
  const baseUrl = config.cloudBaseUrl || 'https://api.shieldcortex.ai';

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const res = await fetch(
      `${baseUrl}/v1/license/validate?sid=${encodeURIComponent(sid)}`,
      { signal: controller.signal },
    );

    if (!res.ok) return null;

    const data = await res.json() as { status: 'active' | 'revoked' | 'expired' | 'unknown' };
    if (data.status === 'unknown') return null; // Subscription not found — treat as network error
    return data.status === 'active' ? 'valid' : data.status;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

// ── Public API ──────────────────────────────────────────

/**
 * Validate the stored licence key against the SaaS API.
 * Called periodically (every 24h) and once on activation.
 */
export async function validateOnline(): Promise<void> {
  const file = getLicenseFile();
  if (!file?.key) return;

  const payload = parseLicensePayload(file.key);
  if (!payload?.sid) return;

  const status = await fetchValidationStatus(payload.sid);
  if (status) {
    updateValidationStatus(status);
  }
  // If null (network error), leave status unchanged — licence stays valid
}

/**
 * Run a one-time validation immediately (used during activation).
 * Returns the validation status, or 'unvalidated' if the check fails.
 */
export async function validateOnceNow(): Promise<ValidationStatus | 'unvalidated'> {
  const file = getLicenseFile();
  if (!file?.key) return 'unvalidated';

  const payload = parseLicensePayload(file.key);
  if (!payload?.sid) return 'unvalidated';

  const status = await fetchValidationStatus(payload.sid);
  if (status) {
    updateValidationStatus(status);
    return status;
  }
  return 'unvalidated';
}
