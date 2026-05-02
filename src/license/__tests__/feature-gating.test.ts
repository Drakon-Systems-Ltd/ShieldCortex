/**
 * Feature Gating Tests
 *
 * Verifies tier-based feature access:
 *  - Free tier: isFeatureEnabled returns false, requireFeature throws FeatureGatedError
 *  - Pro tier: all Pro features enabled, requireFeature doesn't throw
 *  - FeatureGatedResponse contract matches frontend expectations
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('Feature Gating', () => {
  let originalEnv: string | undefined;
  let configDir: string;

  beforeEach(() => {
    originalEnv = process.env.SHIELDCORTEX_LICENSE_TIER;
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-gate-test-'));
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  });

  afterEach(async () => {
    if (originalEnv !== undefined) {
      process.env.SHIELDCORTEX_LICENSE_TIER = originalEnv;
    } else {
      delete process.env.SHIELDCORTEX_LICENSE_TIER;
    }
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    delete process.env.SHIELDCORTEX_SKIP_TRIAL;
    rmSync(configDir, { recursive: true, force: true });
    const { clearLicenseCache } = await import('../store.js');
    const { clearTrialCache } = await import('../trial.js');
    clearLicenseCache();
    clearTrialCache();
  });

  describe('FeatureGatedError', () => {
    it('should include feature name and required tier', async () => {
      const { FeatureGatedError } = await import('../gate.js');
      const err = new FeatureGatedError('custom_firewall_rules', 'pro');
      expect(err.feature).toBe('custom_firewall_rules');
      expect(err.requiredTier).toBe('pro');
      expect(err.name).toBe('FeatureGatedError');
      expect(err.message).toContain('Pro');
    });

    it('should include upgrade URL in message', async () => {
      const { FeatureGatedError } = await import('../gate.js');
      const err = new FeatureGatedError('audit_export', 'pro');
      expect(err.message).toContain('shieldcortex.ai/pricing');
    });

    it('should include activate command hint', async () => {
      const { FeatureGatedError } = await import('../gate.js');
      const err = new FeatureGatedError('skill_scanner_deep', 'pro');
      expect(err.message).toContain('license activate');
    });
  });

  describe('isFeatureEnabled', () => {
    it('should return false for Pro features on free tier', async () => {
      const { isFeatureEnabled } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      // Suppress trial creation so we get a true free-tier environment
      process.env.SHIELDCORTEX_SKIP_TRIAL = '1';
      clearLicenseCache();
      clearTrialCache();

      const proFeatures = [
        'custom_injection_patterns',
        'custom_iron_dome_policies',
        'custom_firewall_rules',
        'audit_export',
        'skill_scanner_deep',
        'memory_file_scan',
      ] as const;

      for (const feature of proFeatures) {
        expect(isFeatureEnabled(feature)).toBe(false);
      }
    });
  });

  describe('requireFeature', () => {
    it('should throw FeatureGatedError for Pro features on free tier', async () => {
      const { requireFeature, FeatureGatedError } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      // Suppress trial creation so we get a true free-tier environment
      process.env.SHIELDCORTEX_SKIP_TRIAL = '1';
      clearLicenseCache();
      clearTrialCache();

      expect(() => requireFeature('custom_firewall_rules')).toThrow(FeatureGatedError);
      expect(() => requireFeature('audit_export')).toThrow(FeatureGatedError);
      expect(() => requireFeature('skill_scanner_deep')).toThrow(FeatureGatedError);
      expect(() => requireFeature('memory_file_scan')).toThrow(FeatureGatedError);
      expect(() => requireFeature('custom_injection_patterns')).toThrow(FeatureGatedError);
      expect(() => requireFeature('custom_iron_dome_policies')).toThrow(FeatureGatedError);
    });

    it('should not throw for Pro features when Pro tier is active', async () => {
      const { requireFeature } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache, getTrialStatus } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      // With no paid licence file present, the first run trial should unlock Pro features.
      const trial = getTrialStatus(false);
      expect(trial?.active).toBe(true);

      expect(() => requireFeature('custom_firewall_rules')).not.toThrow();
      expect(() => requireFeature('audit_export')).not.toThrow();
      expect(() => requireFeature('skill_scanner_deep')).not.toThrow();
      expect(() => requireFeature('memory_file_scan')).not.toThrow();
    });
  });

  describe('getRequiredTier', () => {
    it('should return pro for Pro features', async () => {
      const { getRequiredTier } = await import('../gate.js');
      expect(getRequiredTier('custom_injection_patterns')).toBe('pro');
      expect(getRequiredTier('custom_iron_dome_policies')).toBe('pro');
      expect(getRequiredTier('custom_firewall_rules')).toBe('pro');
      expect(getRequiredTier('audit_export')).toBe('pro');
      expect(getRequiredTier('skill_scanner_deep')).toBe('pro');
      expect(getRequiredTier('memory_file_scan')).toBe('pro');
    });

    it('should return team for team features', async () => {
      const { getRequiredTier } = await import('../gate.js');
      expect(getRequiredTier('cloud_sync')).toBe('team');
      expect(getRequiredTier('team_management')).toBe('team');
    });
  });

  describe('listFeatures', () => {
    it('should list all features with tier, availability, and description', async () => {
      const { listFeatures } = await import('../gate.js');
      const features = listFeatures();
      expect(features.length).toBeGreaterThanOrEqual(8);
      for (const f of features) {
        expect(f).toHaveProperty('feature');
        expect(f).toHaveProperty('requiredTier');
        expect(f).toHaveProperty('enabled');
        expect(f).toHaveProperty('description');
        expect(typeof f.description).toBe('string');
        expect(f.description.length).toBeGreaterThan(0);
      }
    });
  });

  describe('FeatureGatedResponse contract', () => {
    it('should match the shared type shape used by frontend gatedFetch', async () => {
      const { FeatureGatedError } = await import('../gate.js');
      const err = new FeatureGatedError('custom_firewall_rules', 'pro');

      // Simulate what requireProFeature middleware builds
      const body = {
        error: 'Feature requires upgrade',
        code: 'FEATURE_GATED' as const,
        feature: err.feature,
        requiredTier: err.requiredTier,
        upgradeUrl: 'https://shieldcortex.ai/pricing',
      };

      // Frontend gatedFetch checks: response.status === 403 && body.code === 'FEATURE_GATED'
      expect(body.code).toBe('FEATURE_GATED');
      expect(body.feature).toBe('custom_firewall_rules');
      expect(body.requiredTier).toBe('pro');
      expect(body.upgradeUrl).toContain('shieldcortex.ai');
      expect(body.error).toBeTruthy();
    });
  });
});
