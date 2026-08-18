import { describe, expect, it } from '@jest/globals';
import {
  isTaintingScanSummary,
  severityFromScanSummary,
} from '../scan-taint-policy.js';

/**
 * #361 — unknown / uncertain scan results must not taint sessions.
 * Production: benign support thread → reason "unknown" → tainted → AG escalate
 * → broker unavailable → fail-closed deny on action_lease.py.
 */
describe('#361 isTaintingScanSummary', () => {
  it('rejects bare unknown / none / empty', () => {
    expect(isTaintingScanSummary('unknown')).toBe(false);
    expect(isTaintingScanSummary('UNKNOWN')).toBe(false);
    expect(isTaintingScanSummary('none')).toBe(false);
    expect(isTaintingScanSummary('')).toBe(false);
    expect(isTaintingScanSummary(null)).toBe(false);
    expect(isTaintingScanSummary(undefined)).toBe(false);
  });

  it('rejects scanner-unavailable shapes', () => {
    expect(isTaintingScanSummary('scan unavailable')).toBe(false);
    expect(isTaintingScanSummary('conversation scan unavailable (timeout) — turn allowed UNSCANNED')).toBe(false);
  });

  it('accepts concrete injection summaries', () => {
    expect(isTaintingScanSummary('HIGH (2 detections)')).toBe(true);
    expect(isTaintingScanSummary('CRITICAL (1 detections)')).toBe(true);
    expect(isTaintingScanSummary('MEDIUM (1 detections)')).toBe(true);
  });

  it('accepts multi-layer THREAT summaries (non-injection dirty)', () => {
    expect(
      isTaintingScanSummary('THREAT in "openclaw-realtime" response: encoding: base64 (12ms)'),
    ).toBe(true);
  });
});

describe('#361 severityFromScanSummary', () => {
  it('maps risk words', () => {
    expect(severityFromScanSummary('CRITICAL (1 detections)')).toBe('critical');
    expect(severityFromScanSummary('HIGH (2 detections)')).toBe('high');
    expect(severityFromScanSummary('MEDIUM (1 detections)')).toBe('medium');
  });

  it('defaults concrete threat without level to medium', () => {
    expect(severityFromScanSummary('THREAT in "x" response: encoding: base64')).toBe('medium');
  });
});
