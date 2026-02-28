/**
 * License key types, constants, and the Ed25519 public key used to verify licence keys offline.
 *
 * The private key lives ONLY in the SaaS API (Fly.io secrets).
 * This public key can verify signatures but cannot create them.
 */

/**
 * Ed25519 public key in DER (SPKI) hex format.
 * Generated once; the matching private key is stored in Fly.io as LICENSE_SIGNING_KEY.
 */
export const LICENSE_PUBLIC_KEY_HEX =
  '302a300506032b657003210053e006dc81bf14eda2b2481868f7bbad49b614b3dafe24f950202c4f712f955d';

// ── Types ────────────────────────────────────────────────

export type LicenseTier = 'free' | 'pro' | 'team' | 'enterprise';

/** The signed payload embedded inside a license key. */
export interface LicensePayload {
  tier: Exclude<LicenseTier, 'free'>;
  teamId: number;
  email: string;
  /** Expiry — Unix seconds */
  exp: number;
  /** Issued-at — Unix seconds */
  iat: number;
  /** Stripe subscription ID — used for online revocation checks */
  sid: string;
}

/** The result of verifying a license key. */
export interface LicenseInfo {
  valid: boolean;
  tier: LicenseTier;
  email: string | null;
  expiresAt: Date | null;
  daysUntilExpiry: number | null;
  teamId: number | null;
  subscriptionId: string | null;
}

/** Stored in ~/.shieldcortex/license.json */
export interface LicenseFile {
  key: string;
  activatedAt: string;
  lastValidatedAt: string | null;
  validationStatus: 'valid' | 'expired' | 'revoked' | 'unvalidated';
}

// ── Constants ────────────────────────────────────────────

/** Key prefix convention: sc_{tier}_ */
export const KEY_PREFIXES: Record<Exclude<LicenseTier, 'free'>, string> = {
  pro: 'sc_pro_',
  team: 'sc_team_',
  enterprise: 'sc_ent_',
};

/** Tier rank for comparison (higher = more permissive) */
export const TIER_RANK: Record<LicenseTier, number> = {
  free: 0,
  pro: 1,
  team: 2,
  enterprise: 3,
};

/** Grace period after expiry (days) — covers Stripe dunning retries */
export const EXPIRY_GRACE_DAYS = 7;

/** How often to run online validation (ms) */
export const ONLINE_VALIDATION_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
