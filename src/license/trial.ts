/**
 * 14-day Pro trial — auto-granted on first install, no signup required.
 *
 * Trial state is stored in ~/.shieldcortex/trial.json.
 * It is NEVER reset on reinstall (file persists across npm updates).
 * An active paid license always takes priority over the trial.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CONFIG_DIR = join(homedir(), '.shieldcortex');
const TRIAL_FILE = join(CONFIG_DIR, 'trial.json');
const TRIAL_DURATION_DAYS = 14;

// ── Types ────────────────────────────────────────────────

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
  justCreated: boolean;    // true only on the very first run that created the file
}

// ── Cache ────────────────────────────────────────────────

let cachedTrial: TrialStatus | null | undefined = undefined; // undefined = not loaded yet

/** Clear the in-memory trial cache (useful for testing). */
export function clearTrialCache(): void {
  cachedTrial = undefined;
}

// ── Helpers ──────────────────────────────────────────────

function computeStatus(data: TrialFile, justCreated = false): TrialStatus {
  const startMs = new Date(data.startedAt).getTime();
  const expiryMs = startMs + data.durationDays * 24 * 60 * 60 * 1000;
  const nowMs = Date.now();
  const msRemaining = expiryMs - nowMs;
  const daysRemaining = Math.max(0, Math.ceil(msRemaining / (24 * 60 * 60 * 1000)));

  return {
    active: nowMs < expiryMs,
    daysRemaining,
    startedAt: data.startedAt,
    expiresAt: new Date(expiryMs).toISOString(),
    justCreated,
  };
}

// ── Public API ────────────────────────────────────────────

/**
 * Read (and lazily create) the trial state.
 *
 * - If `trial.json` already exists: read and return its status.
 * - If `trial.json` does NOT exist AND `license.json` does NOT exist: create it now (first install).
 * - If `trial.json` does NOT exist AND `license.json` DOES exist: don't create — user already has a paid license.
 * - Returns null if no trial applies.
 *
 * Pass `licenseFileExists` to avoid a second disk read inside store.ts.
 */
export function getTrialStatus(licenseFileExists: boolean): TrialStatus | null {
  // Skip trial if env var set (useful for tests and CI)
  if (process.env.SHIELDCORTEX_SKIP_TRIAL === '1') return null;

  if (cachedTrial !== undefined) return cachedTrial;

  try {
    if (existsSync(TRIAL_FILE)) {
      const data: TrialFile = JSON.parse(readFileSync(TRIAL_FILE, 'utf-8'));
      // Return full status whether active or expired — callers use status.active to distinguish.
      // Only return null when no trial file exists at all.
      const status = computeStatus(data, false);
      cachedTrial = status;
      return cachedTrial;
    }

    // No trial file — only create on first install (no license either)
    if (licenseFileExists) {
      cachedTrial = null;
      return null;
    }

    // First run — create the trial file
    mkdirSync(CONFIG_DIR, { recursive: true });
    const now = new Date().toISOString();
    const trialData: TrialFile = {
      startedAt: now,
      durationDays: TRIAL_DURATION_DAYS,
      acknowledged: false,
    };
    writeFileSync(TRIAL_FILE, JSON.stringify(trialData, null, 2) + '\n', { mode: 0o600 });

    const status = computeStatus(trialData, true);
    cachedTrial = status; // always active on creation
    return cachedTrial;
  } catch {
    cachedTrial = null;
    return null;
  }
}

/**
 * Whether a trial is currently active (Pro features unlocked by trial).
 * Only returns true when no paid license is in effect — callers should
 * check the license first and only fall back to this.
 */
export function isTrialActive(licenseFileExists: boolean): boolean {
  return getTrialStatus(licenseFileExists)?.active === true;
}

/**
 * Days remaining in the trial (0 if expired or no trial).
 */
export function getTrialDaysRemaining(licenseFileExists: boolean): number {
  return getTrialStatus(licenseFileExists)?.daysRemaining ?? 0;
}

/**
 * Mark the welcome message as acknowledged (suppress on subsequent runs).
 */
export function acknowledgeTrialWelcome(): void {
  try {
    if (!existsSync(TRIAL_FILE)) return;
    const data: TrialFile = JSON.parse(readFileSync(TRIAL_FILE, 'utf-8'));
    if (!data.acknowledged) {
      data.acknowledged = true;
      writeFileSync(TRIAL_FILE, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
    }
    // Update cache
    if (cachedTrial) {
      cachedTrial = { ...cachedTrial, justCreated: false };
    }
  } catch {
    // Best effort
  }
}

/** Exposed for tests — returns the full trial file path */
export function getTrialFilePath(): string {
  return TRIAL_FILE;
}
