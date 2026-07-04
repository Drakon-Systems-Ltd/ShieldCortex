/**
 * Feature Gating Tests (Free + Enterprise pricing model)
 *
 * Verifies tier-based feature access:
 *  - Free tier includes EVERY local feature (former Pro gates removed)
 *  - Genuinely cloud/org-side features stay gated (team-rank: cloud_sync,
 *    team_management, shared_patterns, memory_scopes) — unlocked by
 *    Enterprise and grandfathered Team keys
 *  - FeatureGatedError points at Enterprise contact, never a purchase page
 *  - FeatureGatedResponse contract matches frontend expectations
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

/** Every local feature — all Free under the Free + Enterprise model. */
const LOCAL_FEATURES = [
  'custom_injection_patterns',
  'custom_iron_dome_policies',
  'custom_firewall_rules',
  'audit_export',
  'skill_scanner_deep',
  'cortex_learning',
  'deps_quarantine',
  'deps_clean',
  'deps_auto_protect',
  'deps_global_scan',
  'memory_types',
  'dream_mode',
  'llm_reranking',
  'positive_feedback',
  'local_ai_explainer',
  'memory_file_scan',
  'review_copilot',
  'xray_deep',
  'cloud_audit_sync',
] as const;

/** Cloud/org-side features that stay licence-gated. */
const GATED_FEATURES = [
  'cloud_sync',
  'team_management',
  'shared_patterns',
  'memory_scopes',
] as const;

describe('Feature Gating', () => {
  let configDir: string;

  beforeEach(() => {
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-gate-test-'));
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

  describe('FeatureGatedError', () => {
    it('should include feature name and required tier', async () => {
      const { FeatureGatedError } = await import('../gate.js');
      const err = new FeatureGatedError('cloud_sync', 'team');
      expect(err.feature).toBe('cloud_sync');
      expect(err.requiredTier).toBe('team');
      expect(err.name).toBe('FeatureGatedError');
      expect(err.message).toContain('Enterprise');
    });

    it('should point at Enterprise contact, not a purchase page', async () => {
      const { FeatureGatedError } = await import('../gate.js');
      const err = new FeatureGatedError('team_management', 'team');
      expect(err.message).toContain('sales@drakonsystems.com');
      expect(err.message).not.toContain('shieldcortex.ai/pricing');
      expect(err.message).not.toContain('Upgrade');
    });

    it('should include activate command hint for existing key holders', async () => {
      const { FeatureGatedError } = await import('../gate.js');
      const err = new FeatureGatedError('shared_patterns', 'team');
      expect(err.message).toContain('license activate');
    });
  });

  describe('isFeatureEnabled — Free tier includes every local feature', () => {
    it.each(LOCAL_FEATURES)('%s is enabled on a bare Free install', async (feature) => {
      const { isFeatureEnabled } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(isFeatureEnabled(feature)).toBe(true);
    });

    it.each(GATED_FEATURES)('%s stays locked on the Free tier', async (feature) => {
      const { isFeatureEnabled } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      expect(isFeatureEnabled(feature)).toBe(false);
    });
  });

  describe('requireFeature', () => {
    it('never throws for local features on a bare Free install', async () => {
      const { requireFeature } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      for (const feature of LOCAL_FEATURES) {
        expect(() => requireFeature(feature)).not.toThrow();
      }
    });

    it('throws FeatureGatedError for cloud/org features on the Free tier', async () => {
      const { requireFeature, FeatureGatedError } = await import('../gate.js');
      const { clearLicenseCache } = await import('../store.js');
      const { clearTrialCache } = await import('../trial.js');
      clearLicenseCache();
      clearTrialCache();

      for (const feature of GATED_FEATURES) {
        expect(() => requireFeature(feature)).toThrow(FeatureGatedError);
      }
    });
  });

  describe('getRequiredTier', () => {
    it('returns free for all local features', async () => {
      const { getRequiredTier } = await import('../gate.js');
      for (const feature of LOCAL_FEATURES) {
        expect(getRequiredTier(feature)).toBe('free');
      }
    });

    it('returns team-rank for the cloud/org features (Enterprise + grandfathered Team keys unlock)', async () => {
      const { getRequiredTier } = await import('../gate.js');
      for (const feature of GATED_FEATURES) {
        expect(getRequiredTier(feature)).toBe('team');
      }
    });

    it('cloud_audit_sync is a Free-tier feature (audit metadata only)', async () => {
      // Regression: v4.24.0 and earlier gated audit-ingest behind `cloud_sync` (Team),
      // so every Free-tier install silently dropped data despite a valid cloud API key.
      // The cloud free tier is "500 scans/month + 7-day audit retention" — that
      // requires the audit-ingest path to work on Free. cloud_audit_sync covers
      // metadata-only ingest; cloud_sync stays licence-gated for full memory +
      // quarantine content.
      const { getRequiredTier, isFeatureEnabled } = await import('../gate.js');
      expect(getRequiredTier('cloud_audit_sync')).toBe('free');
      expect(getRequiredTier('cloud_sync')).toBe('team');
      // Free tier: audit ingest enabled, full sync gated.
      expect(isFeatureEnabled('cloud_audit_sync')).toBe(true);
      expect(isFeatureEnabled('cloud_sync')).toBe(false);
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
      const err = new FeatureGatedError('cloud_sync', 'team');

      // Simulate what requireProFeature middleware builds
      const body = {
        error: 'Feature requires an Enterprise licence',
        code: 'FEATURE_GATED' as const,
        feature: err.feature,
        requiredTier: err.requiredTier,
        upgradeUrl: 'mailto:sales@drakonsystems.com',
      };

      // Frontend gatedFetch checks: response.status === 403 && body.code === 'FEATURE_GATED'
      expect(body.code).toBe('FEATURE_GATED');
      expect(body.feature).toBe('cloud_sync');
      expect(body.requiredTier).toBe('team');
      expect(body.upgradeUrl).toContain('sales@drakonsystems.com');
      expect(body.error).toBeTruthy();
    });
  });
});
