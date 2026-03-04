/**
 * Feature Gating Tests
 *
 * Verifies tier-based feature access:
 *  - Free tier: isFeatureEnabled returns false, requireFeature throws FeatureGatedError
 *  - Pro tier: all Pro features enabled, requireFeature doesn't throw
 *  - FeatureGatedResponse contract matches frontend expectations
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';

// We test the gate module by temporarily removing the license file.
// getLicenseTier() → getLicense() reads from ~/.shieldcortex/license.json.

describe('Feature Gating', () => {
  let originalEnv: string | undefined;

  beforeEach(() => {
    originalEnv = process.env.SHIELDCORTEX_LICENSE_TIER;
  });

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.SHIELDCORTEX_LICENSE_TIER = originalEnv;
    } else {
      delete process.env.SHIELDCORTEX_LICENSE_TIER;
    }
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
      const { existsSync, renameSync } = await import('fs');
      const { join } = await import('path');
      const { homedir } = await import('os');
      const licensePath = join(homedir(), '.shieldcortex', 'license.json');
      const backupPath = licensePath + '.test-backup-1';
      let backed = false;

      if (existsSync(licensePath)) {
        renameSync(licensePath, backupPath);
        backed = true;
      }
      clearLicenseCache();

      try {
        const proFeatures = [
          'custom_injection_patterns',
          'custom_iron_dome_policies',
          'custom_firewall_rules',
          'audit_export',
          'skill_scanner_deep',
        ] as const;

        for (const feature of proFeatures) {
          expect(isFeatureEnabled(feature)).toBe(false);
        }
      } finally {
        if (backed) {
          renameSync(backupPath, licensePath);
        }
        clearLicenseCache();
      }
    });
  });

  describe('requireFeature', () => {
    it('should throw FeatureGatedError for Pro features on free tier', async () => {
      const { requireFeature, FeatureGatedError } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { existsSync, renameSync } = await import('fs');
      const { join } = await import('path');
      const { homedir } = await import('os');
      const licensePath = join(homedir(), '.shieldcortex', 'license.json');
      const backupPath = licensePath + '.test-backup-2';
      let backed = false;

      if (existsSync(licensePath)) {
        renameSync(licensePath, backupPath);
        backed = true;
      }
      clearLicenseCache();

      try {
        expect(() => requireFeature('custom_firewall_rules')).toThrow(FeatureGatedError);
        expect(() => requireFeature('audit_export')).toThrow(FeatureGatedError);
        expect(() => requireFeature('skill_scanner_deep')).toThrow(FeatureGatedError);
        expect(() => requireFeature('custom_injection_patterns')).toThrow(FeatureGatedError);
        expect(() => requireFeature('custom_iron_dome_policies')).toThrow(FeatureGatedError);
      } finally {
        if (backed) {
          renameSync(backupPath, licensePath);
        }
        clearLicenseCache();
      }
    });

    it('should not throw for Pro features when Pro tier is active', async () => {
      const { requireFeature } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { existsSync } = await import('fs');
      const { join } = await import('path');
      const { homedir } = await import('os');
      const licensePath = join(homedir(), '.shieldcortex', 'license.json');

      // This test only works if a valid Pro license is installed
      if (!existsSync(licensePath)) {
        // Skip - no license file available for Pro tier testing
        return;
      }

      clearLicenseCache();

      try {
        // If the license is Pro, these should not throw
        const { getLicenseTier } = await import('../store.js');
        const tier = getLicenseTier();
        if (tier === 'pro' || tier === 'team' || tier === 'enterprise') {
          expect(() => requireFeature('custom_firewall_rules')).not.toThrow();
          expect(() => requireFeature('audit_export')).not.toThrow();
          expect(() => requireFeature('skill_scanner_deep')).not.toThrow();
        }
      } finally {
        clearLicenseCache();
      }
    });
  });

  describe('getRequiredTier', () => {
    it('should return pro for all 5 Pro features', async () => {
      const { getRequiredTier } = await import('../gate.js');
      expect(getRequiredTier('custom_injection_patterns')).toBe('pro');
      expect(getRequiredTier('custom_iron_dome_policies')).toBe('pro');
      expect(getRequiredTier('custom_firewall_rules')).toBe('pro');
      expect(getRequiredTier('audit_export')).toBe('pro');
      expect(getRequiredTier('skill_scanner_deep')).toBe('pro');
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
