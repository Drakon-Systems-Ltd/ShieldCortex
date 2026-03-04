/**
 * Shared types for the license feature gating system.
 * Used by both the backend (visualization-server) and frontend (dashboard).
 */

/**
 * Structured 403 response returned when a gated feature is accessed
 * without the required licence tier.
 */
export interface FeatureGatedResponse {
  error: string;
  code: 'FEATURE_GATED';
  feature: string;
  requiredTier: string;
  upgradeUrl: string;
}
