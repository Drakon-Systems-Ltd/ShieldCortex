/**
 * License file I/O — reads/writes ~/.shieldcortex/license.json
 *
 * The Ed25519 signature on the key itself provides integrity for the tier
 * and expiry. The validationStatus field is advisory — a tampered value
 * only persists until the next online validation (≤24h). HMAC is not
 * needed here because the hard security boundary is the signed key, not
 * the JSON file.
 *
 * License is cached in memory after first read.
 */

import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { verifyLicenseKey } from './verify.js';
import type { LicenseTier, LicenseInfo, LicenseFile } from './keys.js';
import {
  getTrialStatus,
  isTrialActive,
  getTrialDaysRemaining,
  clearTrialCache,
} from './trial.js';

export { isTrialActive, getTrialDaysRemaining, getTrialStatus };

function getConfigDir(): string {
  return process.env.SHIELDCORTEX_CONFIG_DIR || join(homedir(), '.shieldcortex');
}

function getLicenseFilePath(): string {
  return join(getConfigDir(), 'license.json');
}

// ── Cache ────────────────────────────────────────────────
//
// In-memory cache of the parsed/verified licence. Refreshed automatically
// when the on-disk file mtime changes (v4.27.2). This lets long-running
// workers pick up `shieldcortex license activate <key>` without a process
// restart — previously the worker held the old tier cached for its
// lifetime and any cloud_sync / heartbeat feature gate stayed stuck on
// the value at startup. The mtime check is a single stat() per call
// (microseconds); cheap enough to run on every gate hit.

let cachedLicense: LicenseInfo | null = null;
let cachedLicenseFileMtimeMs: number | null = null;

/**
 * Read the licence file's current mtime (ms). Returns null if the file
 * doesn't exist — that's a valid cached state too (= FREE).
 */
function readLicenseFileMtimeMs(): number | null {
  try {
    return statSync(getLicenseFilePath()).mtimeMs;
  } catch {
    return null;
  }
}

/** Clear the in-memory cache (useful for testing or after activation). */
export function clearLicenseCache(): void {
  cachedLicense = null;
  cachedLicenseFileMtimeMs = null;
  clearTrialCache();
}

// ── Read ─────────────────────────────────────────────────

/**
 * Read and verify the stored license.
 * Returns a LicenseInfo with tier='free' if no license exists or verification fails.
 */
export function getLicense(): LicenseInfo {
  // Hot-reload: if the licence file's mtime has changed since the value
  // was cached (or the file appeared/disappeared), drop the cache so the
  // new tier takes effect immediately. This is what makes long-running
  // workers see `shieldcortex license activate <key>` without a restart.
  const currentMtimeMs = readLicenseFileMtimeMs();
  if (cachedLicense !== null && cachedLicenseFileMtimeMs !== currentMtimeMs) {
    cachedLicense = null;
    clearTrialCache();
  }

  if (cachedLicense) return cachedLicense;

  const FREE: LicenseInfo = {
    valid: false,
    tier: 'free',
    email: null,
    expiresAt: null,
    daysUntilExpiry: null,
    teamId: null,
    subscriptionId: null,
  };

  try {
    const licenseFile = getLicenseFilePath();
    if (!existsSync(licenseFile)) {
      cachedLicense = FREE;
      cachedLicenseFileMtimeMs = null;
      return FREE;
    }

    const raw: LicenseFile = JSON.parse(readFileSync(licenseFile, 'utf-8'));
    if (!raw.key) {
      cachedLicense = FREE;
      cachedLicenseFileMtimeMs = currentMtimeMs;
      return FREE;
    }

    // Check if previously marked as revoked or expired by online validation.
    // Revoked = subscription cancelled (hard block).
    // Expired = advisory; verifyLicenseKey() applies the 7-day grace period
    // so we only hard-block on revoked here.
    if (raw.validationStatus === 'revoked') {
      cachedLicense = FREE;
      cachedLicenseFileMtimeMs = currentMtimeMs;
      return FREE;
    }

    // Verify the key cryptographically (checks exp + grace period)
    const info = verifyLicenseKey(raw.key);
    cachedLicense = info;
    cachedLicenseFileMtimeMs = currentMtimeMs;
    return info;
  } catch {
    cachedLicense = FREE;
    cachedLicenseFileMtimeMs = currentMtimeMs;
    return FREE;
  }
}

/**
 * Quick accessor for the current licence tier.
 * Returns 'pro' during an active trial (if no paid license is active).
 * Returns 'free' otherwise.
 */
export function getLicenseTier(): LicenseTier {
  const license = getLicense();

  // Paid license takes priority — trial is irrelevant
  if (license.valid) return license.tier;

  // No paid license: check if trial is active
  const licenseFileExists = existsSync(getLicenseFilePath());
  if (isTrialActive(licenseFileExists)) return 'pro';

  return license.tier; // 'free'
}

/**
 * Read the raw license file data (for status display).
 * Returns null if no license file exists.
 */
export function getLicenseFile(): LicenseFile | null {
  try {
    const licenseFile = getLicenseFilePath();
    if (!existsSync(licenseFile)) return null;
    return JSON.parse(readFileSync(licenseFile, 'utf-8'));
  } catch {
    return null;
  }
}

// ── Write ────────────────────────────────────────────────

/**
 * Activate a license key — verify it, then store in license.json.
 * Returns the verified LicenseInfo.
 * Throws if the key is invalid.
 */
export function activateLicense(key: string): LicenseInfo {
  const info = verifyLicenseKey(key);
  if (!info.valid) {
    throw new Error('Invalid or expired licence key. Check the key and try again.');
  }

  const file: LicenseFile = {
    key,
    activatedAt: new Date().toISOString(),
    lastValidatedAt: null,
    validationStatus: 'unvalidated',
  };

  const configDir = getConfigDir();
  const licenseFile = getLicenseFilePath();
  mkdirSync(configDir, { recursive: true });
  writeFileSync(licenseFile, JSON.stringify(file, null, 2) + '\n', { mode: 0o600 });

  // Refresh cache + mtime so the next getLicense() call in this process
  // doesn't trigger a re-read for no reason.
  cachedLicense = info;
  cachedLicenseFileMtimeMs = readLicenseFileMtimeMs();
  return info;
}

/**
 * Remove the license file (deactivate).
 */
export function deactivateLicense(): void {
  try {
    const licenseFile = getLicenseFilePath();
    if (existsSync(licenseFile)) {
      unlinkSync(licenseFile);
    }
  } catch {
    // Best effort
  }
  cachedLicense = null;
  cachedLicenseFileMtimeMs = null;
  clearTrialCache();
}

/**
 * Update the validation status and timestamp in the license file.
 * Called by the online validation module.
 */
export function updateValidationStatus(status: LicenseFile['validationStatus']): void {
  try {
    const licenseFile = getLicenseFilePath();
    if (!existsSync(licenseFile)) return;
    const raw: LicenseFile = JSON.parse(readFileSync(licenseFile, 'utf-8'));
    raw.validationStatus = status;
    raw.lastValidatedAt = new Date().toISOString();
    writeFileSync(licenseFile, JSON.stringify(raw, null, 2) + '\n', { mode: 0o600 });

    // If revoked or expired, invalidate cache so next getLicense() re-verifies
    if (status === 'revoked' || status === 'expired') {
      cachedLicense = null;
      cachedLicenseFileMtimeMs = null;
    }
  } catch {
    // Best effort
  }
}
