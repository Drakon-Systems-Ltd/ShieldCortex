/**
 * #411 — non-loopback API bind requires explicit opt-in + strong auth.
 */
import { describe, expect, it } from '@jest/globals';
import {
  evaluateBindPolicy,
  formatBindPolicyDiagnostic,
  isLoopbackHost,
} from '../bind-policy.js';

describe('#411 bind policy', () => {
  describe('isLoopbackHost', () => {
    it('accepts loopback forms', () => {
      expect(isLoopbackHost('127.0.0.1')).toBe(true);
      expect(isLoopbackHost('127.0.0.2')).toBe(true);
      expect(isLoopbackHost('::1')).toBe(true);
      expect(isLoopbackHost('[::1]')).toBe(true);
      expect(isLoopbackHost('localhost')).toBe(true);
      expect(isLoopbackHost('::ffff:127.0.0.1')).toBe(true);
    });

    it('rejects non-loopback and empty', () => {
      expect(isLoopbackHost('0.0.0.0')).toBe(false);
      expect(isLoopbackHost('192.168.1.10')).toBe(false);
      expect(isLoopbackHost('10.0.0.5')).toBe(false);
      expect(isLoopbackHost('example.com')).toBe(false);
      expect(isLoopbackHost('')).toBe(false);
      expect(isLoopbackHost(null)).toBe(false);
    });

    it('does not treat proxy-looking strings as loopback', () => {
      expect(isLoopbackHost('127.0.0.1, 10.0.0.1')).toBe(false);
      expect(isLoopbackHost('x-forwarded-for:127.0.0.1')).toBe(false);
    });
  });

  describe('evaluateBindPolicy', () => {
    it('allows loopback without opt-in token', () => {
      const r = evaluateBindPolicy({
        host: '127.0.0.1',
        allowNonLoopback: false,
        apiToken: null,
      });
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.mode).toBe('loopback');
    });

    it('refuses non-loopback without opt-in', () => {
      const r = evaluateBindPolicy({
        host: '0.0.0.0',
        allowNonLoopback: false,
        apiToken: 'a'.repeat(40),
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('NON_LOOPBACK_DENIED');
    });

    it('refuses non-loopback opt-in without token', () => {
      const r = evaluateBindPolicy({
        host: '0.0.0.0',
        allowNonLoopback: true,
        apiToken: null,
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('AUTH_REQUIRED');
    });

    it('refuses non-loopback with weak token', () => {
      const r = evaluateBindPolicy({
        host: '192.168.1.5',
        allowNonLoopback: true,
        apiToken: 'short',
      });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('AUTH_WEAK');
    });

    it('allows non-loopback with opt-in + strong token', () => {
      const r = evaluateBindPolicy({
        host: '0.0.0.0',
        allowNonLoopback: true,
        apiToken: 'a'.repeat(32),
      });
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.mode).toBe('non-loopback-authenticated');
    });
  });

  describe('diagnostics', () => {
    it('never includes token material', () => {
      const secret = 'super-secret-token-value-0123456789abcd';
      const denied = evaluateBindPolicy({
        host: '0.0.0.0',
        allowNonLoopback: true,
        apiToken: secret,
      });
      // allowed path
      const linesOk = formatBindPolicyDiagnostic('0.0.0.0', denied);
      expect(linesOk.join('\n')).not.toContain(secret);

      const blocked = evaluateBindPolicy({
        host: '0.0.0.0',
        allowNonLoopback: false,
        apiToken: secret,
      });
      const lines = formatBindPolicyDiagnostic('0.0.0.0', blocked);
      expect(lines.join('\n')).not.toContain(secret);
    });
  });
});
