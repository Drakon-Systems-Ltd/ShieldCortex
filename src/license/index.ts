/**
 * License module — re-exports for public API and internal use.
 */

// ── Public API (exported from lib.ts) ────────────────────
export { getLicense, getLicenseTier, getLicenseFile, clearLicenseCache } from './store.js';
export { verifyLicenseKey, parseLicensePayload } from './verify.js';
export {
  isFeatureEnabled,
  requireFeature,
  getRequiredTier,
  listFeatures,
  FeatureGatedError,
} from './gate.js';
export { scheduleOnlineValidation } from './validate.js';

// ── Types ────────────────────────────────────────────────
export type { LicenseTier, LicenseInfo, LicensePayload, LicenseFile } from './keys.js';
export type { GatedFeature } from './gate.js';
export type { FeatureGatedResponse } from './types.js';
export { TIER_RANK, KEY_PREFIXES, EXPIRY_GRACE_DAYS } from './keys.js';

// ── CLI (imported lazily from src/index.ts) ──────────────
export { handleLicenseCommand } from './cli.js';
