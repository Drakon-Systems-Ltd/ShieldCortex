import { describe, it, expect } from '@jest/globals';
import { scanForCredentials } from '../credential-leak/index.js';

/**
 * Phase 17 A5 — credential detection must not false-positive on the well-known
 * non-secret shapes git SHAs and UUIDs.
 *
 * Surfaced in Phase 4: a 40-hex commit SHA trips the generic 32-hex "Azure"
 * pattern (a 32-hex substring lives inside it) and a canonical UUID trips the
 * Heroku/Heroku-style UUID pattern. Both are public identifiers, not secrets.
 *
 * The allowlist must be CONSERVATIVE: only these exact shapes are excluded.
 * Real high-entropy secrets (sk_live_..., random base64) must STILL be flagged.
 */
describe('credential leak: git SHA / UUID allowlist', () => {
  it('does NOT flag a 40-hex git commit SHA', () => {
    const sha = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b'; // sha256("test")[:40]-shaped 40-hex
    const result = scanForCredentials(`Deployed at commit ${sha} to production.`);
    expect(result.leaked).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it('does NOT flag a 7-hex short SHA', () => {
    const result = scanForCredentials('Fixed in 9f86d08, see the PR.');
    expect(result.leaked).toBe(false);
  });

  it('does NOT flag a canonical UUID', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    const result = scanForCredentials(`Request id: ${uuid}`);
    expect(result.leaked).toBe(false);
    expect(result.findings).toHaveLength(0);
  });

  it('STILL flags a real Stripe live secret key', () => {
    const key = 'sk_live_' + '51ABCDEFGHIJKLMNOPQRSTUVwx';
    const result = scanForCredentials(`token ${key}`);
    expect(result.leaked).toBe(true);
    expect(result.findings.some((f) => f.provider === 'stripe')).toBe(true);
  });

  it('STILL flags a random 32+ char base64 high-entropy secret', () => {
    // Base64-style token (contains / and +), high entropy, not a SHA/UUID shape.
    const secret = 'Kp9Wm2Qx7Lr4Nt8/Vy1Zb5Fh6Jd0+Sa3Gc4Pe8Ru2';
    const result = scanForCredentials(`token=${secret}`);
    expect(result.leaked).toBe(true);
  });
});
