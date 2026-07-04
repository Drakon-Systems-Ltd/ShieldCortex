/**
 * Trial machinery — RETIRED (Free + Enterprise pricing model).
 *
 * The auto 14-day Pro trial used to start on first install and unlock the
 * Pro-gated local features. Those features are all Free now, so:
 *   - no new trials ever start (no trial.json is created)
 *   - existing trial.json files are ignored (left on disk, never read into
 *     licence-tier decisions) — in-flight trials degrade to the same
 *     Free-with-everything state
 *   - no trial welcome banners or expiry nags render anywhere
 *
 * The exports are kept as inert stubs because they are part of the public
 * API surface (re-exported via src/license/index.ts) and older callers may
 * still import them. Licence-key machinery (activation, Ed25519 validation,
 * revocation polling) lives elsewhere and is untouched.
 */

// ── Types (kept for API compatibility) ───────────────────

export interface TrialFile {
  startedAt: string;       // ISO timestamp
  durationDays: number;
  acknowledged: boolean;
}

export interface TrialStatus {
  active: boolean;
  daysRemaining: number;
  startedAt: string;
  expiresAt: string;
  justCreated: boolean;
}

// ── Public API (inert) ────────────────────────────────────

/** Clear the in-memory trial cache — retained as a no-op for callers/tests. */
export function clearTrialCache(): void {
  // No cache — trials are retired.
}

/**
 * Trials are retired: never creates trial.json, never reports an active
 * trial. Always returns null. The `_licenseFileExists` parameter is kept so
 * existing call sites compile unchanged.
 */
export function getTrialStatus(_licenseFileExists: boolean): TrialStatus | null {
  return null;
}

/** Always false — no trial can be active. */
export function isTrialActive(_licenseFileExists: boolean): boolean {
  return false;
}

/** Always 0 — no trial exists to count down. */
export function getTrialDaysRemaining(_licenseFileExists: boolean): number {
  return 0;
}

/** No-op — there is no trial welcome to acknowledge, and nothing is written. */
export function acknowledgeTrialWelcome(): void {
  // Intentionally does nothing.
}
