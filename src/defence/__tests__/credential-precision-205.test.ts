/**
 * #205 — credential pattern precision: word boundaries + placeholder denylist.
 *
 * Defects measured on main before this fix:
 * - Azure bare 32-hex fired inside SHA-256 (twice) and on empty-file MD5
 * - Firebase AAAA… matched base64 zero-runs at 0.90 (credential class dead)
 * - ENV_SECRET matched documentation placeholders
 *
 * Gate: stop-count moves only in the directions the change explains.
 */
import { describe, it, expect } from '@jest/globals';
import { scanForCredentials, isDocumentationPlaceholder } from '../credential-leak/index.js';
import { isWellKnownNonSecret } from '../credential-leak/entropy.js';

// Fabricated — not a real secret.
const STANDALONE_32_HEX = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const MD5_EMPTY = 'd41d8cd98f00b204e9800998ecf8427e';
const SHA256_TEST = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

describe('#205 credential pattern precision', () => {
  describe('Azure 32-hex boundaries', () => {
    it('does NOT fire Azure inside a SHA-256 digest (no nested 32-hex hits)', () => {
      const result = scanForCredentials(`checksum ${SHA256_EMPTY}`);
      const azure = result.findings.filter((f) => f.provider === 'azure');
      expect(azure).toHaveLength(0);
    });

    it('does NOT fire Azure twice inside a non-empty SHA-256', () => {
      const result = scanForCredentials(`sha256:${SHA256_TEST}`);
      const azure = result.findings.filter((f) => f.provider === 'azure');
      expect(azure).toHaveLength(0);
    });

    it('does NOT flag the well-known empty-file MD5', () => {
      const result = scanForCredentials(`md5 ${MD5_EMPTY}`);
      const azure = result.findings.filter((f) => f.provider === 'azure');
      expect(azure).toHaveLength(0);
      expect(isWellKnownNonSecret(MD5_EMPTY)).toBe(true);
    });

    it('STILL matches a standalone 32-hex token (bounded, not nested)', () => {
      const result = scanForCredentials(`Ocp-Apim-Subscription-Key: ${STANDALONE_32_HEX}`);
      // Low confidence (0.35) medium — may be warned not blocked; presence is the contract.
      expect(result.findings.some((f) => f.provider === 'azure')).toBe(true);
    });

    it('does not match 32-hex as a substring of 33+ hex', () => {
      const longer = STANDALONE_32_HEX + 'ab';
      const result = scanForCredentials(`token ${longer}`);
      expect(result.findings.some((f) => f.provider === 'azure')).toBe(false);
    });
  });

  describe('Firebase AAAA removal', () => {
    it('does not flag AAAA+base64-looking runs as firebase', () => {
      const key = 'AAAA' + 'A'.repeat(40);
      const result = scanForCredentials(`FCM=${key}`);
      expect(result.findings.some((f) => f.provider === 'firebase')).toBe(false);
    });
  });

  describe('documentation placeholder denylist', () => {
    it.each([
      ['API_KEY=your-api-key-here'],
      ['TOKEN: replace-with-your-token'],
      ['DB_PASSWORD=changeme_in_production'],
      ['SECRET=changeme'],
      ['API_TOKEN=<your-token>'],
      ['PASSWORD=password'],
    ])('does not flag placeholder assignment: %s', (line) => {
      const result = scanForCredentials(line);
      const env = result.findings.filter((f) => f.type === 'env_secret');
      expect(env).toHaveLength(0);
    });

    it('STILL flags a real-looking env secret assignment', () => {
      // High-entropy-ish value, not placeholder language.
      const result = scanForCredentials('API_KEY=Kp9Wm2Qx7Lr4Nt8Vy1Zb5Fh6Jd');
      expect(result.findings.some((f) => f.type === 'env_secret')).toBe(true);
    });

    it('isDocumentationPlaceholder covers the named issue examples', () => {
      expect(isDocumentationPlaceholder('your-api-key-here')).toBe(true);
      expect(isDocumentationPlaceholder('replace-with-your-token')).toBe(true);
      expect(isDocumentationPlaceholder('changeme_in_production')).toBe(true);
      expect(isDocumentationPlaceholder('Kp9Wm2Qx7Lr4Nt8Vy1Zb5Fh6Jd')).toBe(false);
    });
  });

  describe('Mailgun token boundaries', () => {
    it('does not match key-32alnum inside a longer identifier', () => {
      const embedded = 'prefixkey-' + 'a'.repeat(32) + 'suffix';
      const result = scanForCredentials(embedded);
      expect(result.findings.some((f) => f.provider === 'mailgun')).toBe(false);
    });

    it('still matches a bare key- + 32 alnum token', () => {
      const key = 'key-' + 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
      const result = scanForCredentials(`mailgun ${key}`);
      expect(result.findings.some((f) => f.provider === 'mailgun')).toBe(true);
    });
  });
});
