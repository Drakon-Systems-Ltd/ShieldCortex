import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { DefencePipelineResult, DefenceSource } from '../../defence/types.js';

/**
 * Regression test for Fix #4: `submitVerification` shipped the title field
 * to the cloud verbatim while only redacting `content`. A credential pattern
 * in the title (e.g. `sk_live_...`) would leak. Both fields must be redacted
 * before the payload leaves the device, matching the precedent set by
 * quarantine-sync.ts (which redacts both `original_content` and
 * `original_title`).
 */
async function loadVerify() {
  jest.unstable_mockModule('../config.js', () => ({
    getCloudConfig: () => ({
      cloudEnabled: true,
      cloudApiKey: 'sc_test_key',
      cloudBaseUrl: 'https://api.shieldcortex.test',
    }),
    getVerifyConfig: () => ({
      verifyEnabled: true,
      verifyMode: 'enforce',
      verifyTriggers: ['QUARANTINE'],
      verifyTimeoutMs: 5000,
    }),
    getDeviceId: () => 'device-test',
    getDeviceName: () => 'unit-host',
  }));
  return import('../verify.js');
}

function makePipelineResult(): DefencePipelineResult {
  return {
    allowed: false,
    firewall: {
      result: 'QUARANTINE',
      reason: 'test',
      threatIndicators: [],
      anomalyScore: 0.6,
      blockedPatterns: [],
    },
    fragmentation: null,
    sensitivity: {
      level: 'INTERNAL',
      confidence: 0.8,
      detectedPatterns: [],
      redactionRequired: false,
    },
    trust: {
      score: 0.5,
      source: { type: 'agent', identifier: 'test' },
      hierarchy: ['test'],
    },
    auditId: 1,
  };
}

describe('submitVerification credential redaction', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  it('redacts credential patterns in the title before sending to cloud', async () => {
    const { submitVerification } = await loadVerify();

    const capturedBodies: string[] = [];
    const fetchMock = jest.fn(async (_url: string, init?: { body?: string }) => {
      if (init?.body) capturedBodies.push(init.body);
      return {
        ok: true,
        json: async () => ({ id: 42, status: 'completed' }),
      };
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).fetch = fetchMock;

    // String-split avoids tripping GitHub's secret-scanner on the source while
    // still producing a runtime value that matches the credential-leak regex.
    const titleWithSecret = 'Leaked Stripe key sk_' + 'live_' + 'abcdefghijklmnopqrstuvwx in title';
    const source: DefenceSource = { type: 'agent', identifier: 'test-agent' };

    await submitVerification('benign body', titleWithSecret, makePipelineResult(), source);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(capturedBodies).toHaveLength(1);

    const body = JSON.parse(capturedBodies[0]);
    expect(typeof body.title).toBe('string');
    expect(body.title).not.toContain('sk_' + 'live_' + 'abcdefghijklmnopqrstuvwx');
    expect(body.title).toContain('[REDACTED-');
  });
});
