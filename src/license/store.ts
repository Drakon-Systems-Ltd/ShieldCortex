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

import { readFileSync, writeFileSync, existsSync, unlinkSync, mkdirSync } from 'fs';
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

const CONFIG_DIR = join(homedir(), '.shieldcortex');
const LICENSE_FILE = join(CONFIG_DIR, 'license.json');

// ── Cache ────────────────────────────────────────────────

let cachedLicense: LicenseInfo | null = null;

/** Clear the in-memory cache (useful for testing or after activation). */
export function clearLicenseCache(): void {
  cachedLicense = null;
  clearTrialCache();
}

// ── Read ─────────────────────────────────────────────────

/**
 * Read and verify the stored license.
 * Returns a LicenseInfo with tier='free' if no license exists or verification fails.
 */
export function getLicense(): LicenseInfo {
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
    if (!existsSync(LICENSE_FILE)) {
      cachedLicense = FREE;
      return FREE;
    }

    const raw: LicenseFile = JSON.parse(readFileSync(LICENSE_FILE, 'utf-8'));
    if (!raw.key) {
      cachedLicense = FREE;
      return FREE;
    }

    // Check if previously marked as revoked or expired by online validation.
    // Revoked = subscription cancelled (hard block).
    // Expired = advisory; verifyLicenseKey() applies the 7-day grace period
    // so we only hard-block on revoked here.
    if (raw.validationStatus === 'revoked') {
      cachedLicense = FREE;
      return FREE;
    }

    // Verify the key cryptographically (checks exp + grace period)
    const info = verifyLicenseKey(raw.key);
    cachedLicense = info;
    return info;
  } catch {
    cachedLicense = FREE;
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
  const licenseFileExists = existsSync(LICENSE_FILE);
  if (isTrialActive(licenseFileExists)) return 'pro';

  return license.tier; // 'free'
}

/**
 * Read the raw license file data (for status display).
 * Returns null if no license file exists.
 */
export function getLicenseFile(): LicenseFile | null {
  try {
    if (!existsSync(LICENSE_FILE)) return null;
    return JSON.parse(readFileSync(LICENSE_FILE, 'utf-8'));
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

  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(LICENSE_FILE, JSON.stringify(file, null, 2) + '\n', { mode: 0o600 });

  // Invalidate cache
  cachedLicense = info;
  return info;
}

/**
 * Remove the license file (deactivate).
 */
export function deactivateLicense(): void {
  try {
    if (existsSync(LICENSE_FILE)) {
      unlinkSync(LICENSE_FILE);
    }
  } catch {
    // Best effort
  }
  cachedLicense = null;
  clearTrialCache();
}

/**
 * Update the validation status and timestamp in the license file.
 * Called by the online validation module.
 */
export function updateValidationStatus(status: LicenseFile['validationStatus']): void {
  try {
    if (!existsSync(LICENSE_FILE)) return;
    const raw: LicenseFile = JSON.parse(readFileSync(LICENSE_FILE, 'utf-8'));
    raw.validationStatus = status;
    raw.lastValidatedAt = new Date().toISOString();
    writeFileSync(LICENSE_FILE, JSON.stringify(raw, null, 2) + '\n', { mode: 0o600 });

    // If revoked or expired, invalidate cache so next getLicense() re-verifies
    if (status === 'revoked' || status === 'expired') {
      cachedLicense = null;
    }
  } catch {
    // Best effort
  }
}
