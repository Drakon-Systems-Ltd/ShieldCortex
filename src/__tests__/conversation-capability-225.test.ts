import { describe, expect, it } from '@jest/globals';
import {
  evaluateEnforcementSupport,
  describeEnforcementSupport,
  CONVERSATION_ENFORCEMENT_MIN_OPENCLAW,
} from '../integrations/openclaw-conversation-capability.js';

/**
 * #225 phase 2 — capability detection.
 *
 * `before_agent_run` is the only conversation hook that can block, and it first
 * shipped in OpenClaw 2026.5.12 (dist-verified: 0 occurrences in 2026.4.23 /
 * 5.5 / 5.6 / 5.7, 54 in 5.12). Our manifest still declares `>= 2026.3.22`.
 *
 * The trap: OpenClaw does not reject an unknown typed hook — it warns and
 * returns. So registering it on an older host looks successful and enforces
 * nothing. These tests pin that we can tell the difference BEFORE claiming
 * enforcement, and that an unreadable version is never reported as either.
 */

describe('#225 phase 2 — which hosts can enforce at all', () => {
  it('the floor is the release that actually contains the hook', () => {
    expect(CONVERSATION_ENFORCEMENT_MIN_OPENCLAW).toBe('2026.5.12');
  });

  it('rejects every version in the silently-ignoring range', () => {
    // Each of these declares support in our manifest today and would register
    // the hook to no effect.
    for (const v of ['2026.3.22', '2026.4.23', '2026.5.5', '2026.5.6', '2026.5.7']) {
      expect(evaluateEnforcementSupport(v).support).toBe('unsupported');
    }
  });

  it('accepts the first release containing it, and later ones', () => {
    for (const v of ['2026.5.12', '2026.5.19', '2026.6.1', '2026.7.1']) {
      expect(evaluateEnforcementSupport(v).support).toBe('supported');
    }
  });

  it('treats a prerelease of a supported version as supported', () => {
    // 2026.7.2-beta.7 and 2026.8.1-beta.1 are already published upstream. A raw
    // semver compare ranks a prerelease BELOW its release, which would report
    // a newer host as incapable.
    expect(evaluateEnforcementSupport('2026.7.2-beta.7').support).toBe('supported');
    expect(evaluateEnforcementSupport('2026.8.1-beta.1').support).toBe('supported');
  });

  it('reports UNKNOWN rather than guessing when the version cannot be read', () => {
    // Unknown must never collapse into either answer — claiming "unsupported"
    // would hide a capable host, claiming "supported" would promise
    // enforcement we cannot deliver.
    for (const v of [null, '', 'not-a-version', 'latest']) {
      expect(evaluateEnforcementSupport(v as string | null).support).toBe('unknown');
    }
  });

  it('carries the host and minimum versions for the operator', () => {
    const cap = evaluateEnforcementSupport('2026.4.23');
    expect(cap.hostVersion).toBe('2026.4.23');
    expect(cap.minVersion).toBe('2026.5.12');
  });
});

describe('#225 phase 2 — the message never over-promises', () => {
  it('an unsupported host is told detections can only ever be advisory', () => {
    const msg = describeEnforcementSupport(evaluateEnforcementSupport('2026.4.23'));
    expect(msg).toMatch(/UNAVAILABLE/);
    expect(msg).toContain('2026.5.12');
    expect(msg.toLowerCase()).toMatch(/advisory/);
  });

  it('a SUPPORTED host is not told it is enforcing', () => {
    // Capability is not activation. Phase 2 detects; nothing enforces yet.
    const msg = describeEnforcementSupport(evaluateEnforcementSupport('2026.7.1'));
    expect(msg).toMatch(/AVAILABLE/);
    expect(msg.toLowerCase()).toMatch(/not yet enabled|observation-only/);
  });

  it('an unknown host says unknown', () => {
    expect(describeEnforcementSupport(evaluateEnforcementSupport(null)).toLowerCase()).toMatch(/unknown/);
  });
});
