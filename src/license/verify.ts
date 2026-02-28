/**
 * Offline Ed25519 licence key verification.
 *
 * Uses Node.js built-in crypto (available since Node 18).
 * Zero external dependencies.
 */

import { verify, createPublicKey } from 'crypto';
import {
  LICENSE_PUBLIC_KEY_HEX,
  KEY_PREFIXES,
  EXPIRY_GRACE_DAYS,
  type LicenseTier,
  type LicensePayload,
  type LicenseInfo,
} from './keys.js';

// ── Base64url helpers ────────────────────────────────────

function base64urlDecode(str: string): Buffer {
  // Restore padding and convert base64url → base64
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

// ── Public key (parsed once, cached) ─────────────────────

let cachedPublicKey: ReturnType<typeof createPublicKey> | null = null;

function getPublicKey() {
  if (cachedPublicKey) return cachedPublicKey;
  const derBuffer = Buffer.from(LICENSE_PUBLIC_KEY_HEX, 'hex');
  cachedPublicKey = createPublicKey({ key: derBuffer, format: 'der', type: 'spki' });
  return cachedPublicKey;
}

// ── Key parsing ──────────────────────────────────────────

/**
 * Strip the sc_{tier}_ prefix and split into payload + signature.
 * Returns null if the key format is invalid.
 */
function splitKey(key: string): { payloadB64: string; signatureB64: string; prefixTier: string } | null {
  // Find which prefix matches
  for (const [tier, prefix] of Object.entries(KEY_PREFIXES)) {
    if (key.startsWith(prefix)) {
      const rest = key.slice(prefix.length);
      const dotIndex = rest.lastIndexOf('.');
      if (dotIndex === -1) return null;
      return {
        payloadB64: rest.slice(0, dotIndex),
        signatureB64: rest.slice(dotIndex + 1),
        prefixTier: tier,
      };
    }
  }
  return null;
}

/**
 * Parse the payload JSON from a license key without verifying the signature.
 * Returns null if parsing fails.
 */
export function parseLicensePayload(key: string): LicensePayload | null {
  const parts = splitKey(key);
  if (!parts) return null;

  try {
    const json = base64urlDecode(parts.payloadB64).toString('utf-8');
    const payload = JSON.parse(json) as LicensePayload;

    // Basic shape validation
    if (!payload.tier || !payload.teamId || !payload.exp || !payload.sid) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

// ── Signature verification ───────────────────────────────

/**
 * Verify a license key's Ed25519 signature and check expiry.
 * This is completely offline — no network calls.
 */
export function verifyLicenseKey(key: string): LicenseInfo {
  const FREE: LicenseInfo = {
    valid: false,
    tier: 'free',
    email: null,
    expiresAt: null,
    daysUntilExpiry: null,
    teamId: null,
    subscriptionId: null,
  };

  const parts = splitKey(key);
  if (!parts) return FREE;

  // Decode payload and signature
  let payload: LicensePayload;
  let signatureBuffer: Buffer;
  try {
    const json = base64urlDecode(parts.payloadB64).toString('utf-8');
    payload = JSON.parse(json);
    signatureBuffer = base64urlDecode(parts.signatureB64);
  } catch {
    return FREE;
  }

  // Verify Ed25519 signature over the raw payload bytes
  const payloadBuffer = base64urlDecode(parts.payloadB64);
  try {
    const isValid = verify(null, payloadBuffer, getPublicKey(), signatureBuffer);
    if (!isValid) return FREE;
  } catch {
    return FREE;
  }

  // Check that the prefix tier matches the payload tier
  if (parts.prefixTier !== payload.tier) return FREE;

  // Check expiry (with grace period)
  const nowSec = Math.floor(Date.now() / 1000);
  const graceSeconds = EXPIRY_GRACE_DAYS * 24 * 60 * 60;
  const effectiveExpiry = payload.exp + graceSeconds;
  const expired = nowSec > effectiveExpiry;

  const expiresAt = new Date(payload.exp * 1000);
  const daysUntilExpiry = Math.ceil((payload.exp - nowSec) / (24 * 60 * 60));

  return {
    valid: !expired,
    tier: expired ? 'free' : payload.tier as LicenseTier,
    email: payload.email,
    expiresAt,
    daysUntilExpiry,
    teamId: payload.teamId,
    subscriptionId: payload.sid,
  };
}
