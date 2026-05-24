import { describe, expect, it } from '@jest/globals';
import { scanForInjection } from '../defence/iron-dome/injection-scanner.js';

/**
 * Regression guard for the v4.22.0 defence canary. The doctor's `Defence canary`
 * check depends on this pattern firing reliably; if it gets deleted, renamed,
 * or the marker is changed, the doctor would silently start reporting FAIL.
 * These tests pin the pattern's existence and shape directly.
 *
 * Field context (edith, jarvis 2026-05-24): the defence layer was reported as
 * "unprovable from inside the session" because no positive-attestation surface
 * existed. The canary closes that gap — but only if the pattern stays wired up.
 */
describe('injection-scanner — defence canary pattern', () => {
  const CANARY_MARKER = '__SHIELDCORTEX_CANARY_PROBE_v1__';

  it('fires the defence_canary_test pattern on the canonical marker', () => {
    const result = scanForInjection(CANARY_MARKER);
    const canaryHits = result.detections.filter((d) => d.pattern === 'defence_canary_test');
    expect(canaryHits.length).toBeGreaterThan(0);
    expect(canaryHits[0].severity).toBe('critical');
    expect(canaryHits[0].category).toBe('canary');
  });

  it('fires the canary pattern when embedded in benign context (doctor calls it with surrounding text)', () => {
    const text = `benign-context-prefix ${CANARY_MARKER} benign-context-suffix`;
    const result = scanForInjection(text);
    expect(result.detections.some((d) => d.pattern === 'defence_canary_test')).toBe(true);
    expect(result.clean).toBe(false);
    expect(result.riskLevel).toBe('CRITICAL');
  });

  it('does NOT fire on lookalikes (no double-underscore, no version tag, wrong name)', () => {
    const decoys = [
      'SHIELDCORTEX_CANARY_PROBE_v1',
      '_SHIELDCORTEX_CANARY_PROBE_v1_',
      '__SHIELDCORTEX_CANARY_PROBE__',
      '__SHIELDCORTEX_CANARY_PROBE_v2__',
      'looking at __shieldcortex_canary_probe_v1__ in lowercase',
      'normal sentence about canaries and probes',
    ];
    for (const decoy of decoys) {
      const result = scanForInjection(decoy);
      const canaryHits = result.detections.filter((d) => d.pattern === 'defence_canary_test');
      expect(canaryHits.length).toBe(0);
    }
  });
});
