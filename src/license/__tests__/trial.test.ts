/**
 * Trial retirement tests (Free + Enterprise pricing model).
 *
 * The auto 14-day Pro trial was removed when self-serve tiers were retired:
 * every local feature is Free, so there is nothing left to trial. These tests
 * pin the retirement behaviour:
 *  - No trial file is ever created on first run
 *  - An existing (in-flight) trial file grants nothing — tier stays 'free'
 *  - An expired trial file degrades to the same Free state, no nag surface
 *  - isTrialActive / getTrialDaysRemaining report inactive/zero always
 *  - acknowledgeTrialWelcome never writes anything
 *  - A licence file still takes the normal (paid) path — key machinery intact
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

let configDir = '';
let trialFile = '';
let licenseFile = '';

// ── Helpers ──────────────────────────────────────────────

function writeTrialFile(startedAt: string, durationDays = 14): void {
  mkdirSync(configDir, { recursive: true });
  writeFileSync(trialFile, JSON.stringify({ startedAt, durationDays, acknowledged: false }, null, 2) + '\n', { mode: 0o600 });
}

function daysAgo(n: number): string {
  return new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();
}

// ── Tests ────────────────────────────────────────────────

describe('trial retirement (no trials start, existing trials degrade to Free)', () => {
  beforeEach(() => {
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-trial-test-'));
    trialFile = join(configDir, 'trial.json');
    licenseFile = join(configDir, 'license.json');
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  });

  afterEach(async () => {
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    rmSync(configDir, { recursive: true, force: true });

    const { clearLicenseCache } = await import('../store.js');
    const { clearTrialCache } = await import('../trial.js');
    clearLicenseCache();
    clearTrialCache();
  });

  describe('no new trials start', () => {
    it('does NOT create trial.json on first run (no licence, no trial file)', async () => {
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      const status = getTrialStatus(false /* no license file */);

      expect(existsSync(trialFile)).toBe(false);
      expect(status).toBeNull();
    });

    it('does NOT create trial.json when a licence file exists either', async () => {
      writeFileSync(licenseFile, JSON.stringify({ key: 'placeholder', activatedAt: new Date().toISOString(), lastValidatedAt: null, validationStatus: 'unvalidated' }, null, 2));

      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      const status = getTrialStatus(true /* license file exists */);

      expect(existsSync(trialFile)).toBe(false);
      expect(status).toBeNull();
    });
  });

  describe('in-flight trials degrade gracefully to Free', () => {
    it('an active trial file grants nothing — getTrialStatus returns null', async () => {
      // Trial started 5 days ago — would have been active under the old model
      writeTrialFile(daysAgo(5));

      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearTrialCache();

      expect(getTrialStatus(false)).toBeNull();
      // The file itself is left alone (no destructive cleanup)
      expect(existsSync(trialFile)).toBe(true);
    });

    it('getLicenseTier() returns "free" even with an active trial file', async () => {
      writeTrialFile(daysAgo(1));

      const { clearLicenseCache, getLicenseTier } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(getLicenseTier()).toBe('free');
    });

    it('getLicenseTier() returns "free" for an expired trial file', async () => {
      writeTrialFile(daysAgo(15));

      const { clearLicenseCache, getLicenseTier } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(getLicenseTier()).toBe('free');
    });

    it('getLicenseTier() returns "free" with no trial and no licence', async () => {
      const { clearLicenseCache, getLicenseTier } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(getLicenseTier()).toBe('free');
      expect(existsSync(trialFile)).toBe(false);
    });
  });

  describe('licence key machinery is untouched by retirement', () => {
    it('a revoked licence file resolves to free (not trial-pro)', async () => {
      writeTrialFile(daysAgo(2));
      writeFileSync(licenseFile, JSON.stringify({
        key: 'not-a-valid-license',
        activatedAt: new Date().toISOString(),
        lastValidatedAt: null,
        validationStatus: 'revoked',
      }, null, 2));

      const { clearLicenseCache, getLicense, getLicenseTier } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      const info = getLicense();
      expect(info.valid).toBe(false);
      expect(getLicenseTier()).toBe('free');
    });
  });

  describe('helpers report inactive always', () => {
    it('isTrialActive returns false even for a would-be-active trial file', async () => {
      writeTrialFile(daysAgo(3));

      const { clearTrialCache, isTrialActive } = await import('../trial.js');
      clearTrialCache();

      expect(isTrialActive(false)).toBe(false);
    });

    it('getTrialDaysRemaining returns 0 always', async () => {
      writeTrialFile(daysAgo(10));

      const { clearTrialCache, getTrialDaysRemaining } = await import('../trial.js');
      clearTrialCache();

      expect(getTrialDaysRemaining(false)).toBe(0);
    });

    it('acknowledgeTrialWelcome is a no-op and never writes', async () => {
      const { acknowledgeTrialWelcome } = await import('../trial.js');

      expect(() => acknowledgeTrialWelcome()).not.toThrow();
      expect(existsSync(trialFile)).toBe(false);

      // Existing file content untouched too
      writeTrialFile(daysAgo(1));
      const before = readFileSync(trialFile, 'utf-8');
      acknowledgeTrialWelcome();
      expect(readFileSync(trialFile, 'utf-8')).toBe(before);
    });
  });

  describe('SHIELDCORTEX_SKIP_TRIAL env var (legacy)', () => {
    it('still returns null when SHIELDCORTEX_SKIP_TRIAL=1', async () => {
      process.env.SHIELDCORTEX_SKIP_TRIAL = '1';

      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearTrialCache();

      expect(getTrialStatus(false)).toBeNull();

      delete process.env.SHIELDCORTEX_SKIP_TRIAL;
    });
  });
});
