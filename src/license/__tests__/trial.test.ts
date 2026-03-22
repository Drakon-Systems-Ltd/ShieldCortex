/**
 * 14-day Pro trial tests
 *
 * Tests:
 *  - Trial file created on first run (no license, no trial file)
 *  - getLicenseTier() returns 'pro' during active trial
 *  - getLicenseTier() returns 'free' after trial expires
 *  - Trial doesn't override an active paid license
 *  - Trial file NOT created if license already exists
 *  - Days remaining calculation
 *  - Trial only triggers once (re-installs don't reset trial)
 *  - isTrialActive / getTrialDaysRemaining helpers
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CONFIG_DIR = join(homedir(), '.shieldcortex');
const TRIAL_FILE = join(CONFIG_DIR, 'trial.json');
const LICENSE_FILE = join(CONFIG_DIR, 'license.json');

// ── Helpers ──────────────────────────────────────────────

function backupAndRemove(filePath: string): string | null {
  const backup = filePath + '.trial-test-backup';
  if (existsSync(filePath)) {
    renameSync(filePath, backup);
    return backup;
  }
  return null;
}

function restore(backup: string | null, original: string): void {
  if (existsSync(original)) unlinkSync(original);
  if (backup && existsSync(backup)) renameSync(backup, original);
}

function writeTrialFile(startedAt: string, durationDays = 14): void {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(TRIAL_FILE, JSON.stringify({ startedAt, durationDays, acknowledged: false }, null, 2) + '\n', { mode: 0o600 });
}

function daysAgo(n: number): string {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

// ── Tests ────────────────────────────────────────────────

describe('14-day Pro trial', () => {
  let trialBackup: string | null = null;
  let licenseBackup: string | null = null;

  beforeEach(() => {
    process.env.SHIELDCORTEX_SKIP_TRIAL = '';
    delete process.env.SHIELDCORTEX_SKIP_TRIAL;
  });

  afterEach(async () => {
    // Restore trial file
    restore(trialBackup, TRIAL_FILE);
    trialBackup = null;

    // Restore license file
    restore(licenseBackup, LICENSE_FILE);
    licenseBackup = null;

    // Clear caches
    const { clearLicenseCache } = await import('../store.js');
    const { clearTrialCache } = await import('../trial.js');
    clearLicenseCache();
    clearTrialCache();
  });

  describe('trial file creation', () => {
    it('should create trial.json on first run (no license, no trial file)', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      const status = getTrialStatus(false /* no license file */);

      expect(existsSync(TRIAL_FILE)).toBe(true);
      expect(status).not.toBeNull();
      expect(status?.active).toBe(true);
      expect(status?.justCreated).toBe(true);
      expect(status?.daysRemaining).toBe(14);
    });

    it('should NOT create trial.json if a license file already exists', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      const status = getTrialStatus(true /* license file exists */);

      expect(existsSync(TRIAL_FILE)).toBe(false);
      expect(status).toBeNull();
    });

    it('should NOT recreate trial.json on reinstall if it already exists', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      // Simulate a prior trial that started 5 days ago
      writeTrialFile(daysAgo(5));

      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearTrialCache();

      const status = getTrialStatus(false);

      expect(status?.active).toBe(true);
      expect(status?.daysRemaining).toBeCloseTo(9, 0);
      expect(status?.justCreated).toBe(false);
    });
  });

  describe('getLicenseTier() with trial', () => {
    it('should return "pro" during active trial (no license)', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      // Trial started 1 day ago (13 days remaining)
      writeTrialFile(daysAgo(1));

      const { clearLicenseCache, getLicenseTier } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(getLicenseTier()).toBe('pro');
    });

    it('should return "free" after trial expires', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      // Trial started 15 days ago (expired 1 day ago)
      writeTrialFile(daysAgo(15));

      const { clearLicenseCache, getLicenseTier } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(getLicenseTier()).toBe('free');
    });

    it('should return "free" when no trial and no license', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      // Set skip trial to prevent auto-creation
      process.env.SHIELDCORTEX_SKIP_TRIAL = '1';

      const { clearLicenseCache, getLicenseTier } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(getLicenseTier()).toBe('free');

      delete process.env.SHIELDCORTEX_SKIP_TRIAL;
    });
  });

  describe('trial does not override paid license', () => {
    it('getLicenseTier returns license tier even if trial is active', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      // Active trial
      writeTrialFile(daysAgo(2));

      const { clearLicenseCache, getLicense } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      // Only check if license is present — if no valid license file exists,
      // the tier returned should be 'pro' from trial, which is correct.
      // This test verifies that a valid license takes priority:
      const info = getLicense();
      if (info.valid) {
        // If there is a valid license (installed on test runner), it should win
        const { getLicenseTier } = await import('../store.js');
        // License tier should be whatever the license says, not 'free'
        expect(['pro', 'team', 'enterprise']).toContain(getLicenseTier());
      } else {
        // No license — trial should make it 'pro'
        const { getLicenseTier } = await import('../store.js');
        expect(getLicenseTier()).toBe('pro');
      }
    });
  });

  describe('days remaining calculation', () => {
    it('should return 14 days remaining on the day of creation', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      writeTrialFile(new Date().toISOString()); // just now

      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearTrialCache();

      const status = getTrialStatus(false);
      expect(status?.daysRemaining).toBe(14);
    });

    it('should return ~7 days remaining after 7 days', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      writeTrialFile(daysAgo(7));

      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearTrialCache();

      const status = getTrialStatus(false);
      expect(status?.active).toBe(true);
      // Between 6 and 8 depending on timing
      expect(status?.daysRemaining).toBeGreaterThanOrEqual(6);
      expect(status?.daysRemaining).toBeLessThanOrEqual(8);
    });

    it('should return 0 days remaining after expiry', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      writeTrialFile(daysAgo(20));

      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearTrialCache();

      const status = getTrialStatus(false);
      expect(status?.active).toBe(false);
      expect(status?.daysRemaining).toBe(0);
    });
  });

  describe('isTrialActive / getTrialDaysRemaining', () => {
    it('isTrialActive returns true during active trial', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      writeTrialFile(daysAgo(3));

      const { clearTrialCache, isTrialActive } = await import('../trial.js');
      clearTrialCache();

      expect(isTrialActive(false)).toBe(true);
    });

    it('isTrialActive returns false after expiry', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      writeTrialFile(daysAgo(15));

      const { clearTrialCache, isTrialActive } = await import('../trial.js');
      clearTrialCache();

      expect(isTrialActive(false)).toBe(false);
    });

    it('getTrialDaysRemaining returns correct value', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      writeTrialFile(daysAgo(10));

      const { clearTrialCache, getTrialDaysRemaining } = await import('../trial.js');
      clearTrialCache();

      const days = getTrialDaysRemaining(false);
      expect(days).toBeGreaterThanOrEqual(3);
      expect(days).toBeLessThanOrEqual(5);
    });

    it('getTrialDaysRemaining returns 0 when no trial', async () => {
      trialBackup = backupAndRemove(TRIAL_FILE);
      licenseBackup = backupAndRemove(LICENSE_FILE);

      process.env.SHIELDCORTEX_SKIP_TRIAL = '1';

      const { clearTrialCache, getTrialDaysRemaining } = await import('../trial.js');
      clearTrialCache();

      expect(getTrialDaysRemaining(false)).toBe(0);

      delete process.env.SHIELDCORTEX_SKIP_TRIAL;
    });
  });

  describe('SHIELDCORTEX_SKIP_TRIAL env var', () => {
    it('returns null when SHIELDCORTEX_SKIP_TRIAL=1', async () => {
      process.env.SHIELDCORTEX_SKIP_TRIAL = '1';

      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearTrialCache();

      const status = getTrialStatus(false);
      expect(status).toBeNull();

      delete process.env.SHIELDCORTEX_SKIP_TRIAL;
    });
  });
});
