/**
 * LLM Verification Client
 *
 * Sends content to the ShieldCortex cloud for LLM-based second-opinion verification.
 * Two modes:
 *   - Advisory: fire-and-forget (never blocks the pipeline)
 *   - Enforce: await result, may upgrade QUARANTINE → BLOCK
 *
 * Fail-OPEN: if the cloud is unreachable or times out, the original verdict stands.
 */

import { getCloudConfig, getVerifyConfig, getDeviceId, getDeviceName } from './config.js';
import { redactCredentials } from '../defence/credential-leak/index.js';
import type { DefencePipelineResult, DefenceSource, VerifyResult } from '../defence/types.js';

/**
 * Submit content for LLM verification.
 *
 * In advisory mode: fires the request without awaiting the response.
 * In enforce mode: awaits the response up to verifyTimeoutMs.
 */
export async function submitVerification(
  content: string,
  title: string,
  pipelineResult: DefencePipelineResult,
  source: DefenceSource,
): Promise<VerifyResult | null> {
  const cloudConfig = getCloudConfig();
  const verifyConfig = getVerifyConfig();

  if (!cloudConfig.cloudEnabled || !cloudConfig.cloudApiKey || !verifyConfig.verifyEnabled) {
    return null;
  }

  if (!verifyConfig.verifyTriggers.includes(pipelineResult.firewall.result)) {
    return null;
  }

  // Redact credentials before sending to cloud
  const cleanContent = redactCredentials(content);
  const cleanTitle = redactCredentials(title);

  const payload = {
    content: cleanContent,
    title: cleanTitle,
    source_type: source.type,
    source_identifier: source.identifier,
    anomaly_score: pipelineResult.firewall.anomalyScore,
    trust_score: pipelineResult.trust.score,
    threat_indicators: pipelineResult.firewall.threatIndicators,
    pipeline_result: pipelineResult.firewall.result,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    mode: 'sync',
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), verifyConfig.verifyTimeoutMs);

  if (verifyConfig.verifyMode === 'advisory') {
    // Fire-and-forget — don't await the response
    fetch(`${cloudConfig.cloudBaseUrl}/v1/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${cloudConfig.cloudApiKey}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    })
      .then(() => { clearTimeout(timeoutId); })
      .catch(() => { clearTimeout(timeoutId); });

    return { id: 0, status: 'pending' };
  }

  // Enforce mode — await result
  try {
    const res = await fetch(`${cloudConfig.cloudBaseUrl}/v1/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${cloudConfig.cloudApiKey}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) {
      return { id: 0, status: 'failed' };
    }

    const data = await res.json() as VerifyResult;
    return data;
  } catch {
    // Timeout or network error — fail open
    clearTimeout(timeoutId);
    return { id: 0, status: 'failed' };
  }
}

/**
 * Poll for verification result by ID.
 */
export async function pollVerification(id: number): Promise<VerifyResult | null> {
  const cloudConfig = getCloudConfig();

  if (!cloudConfig.cloudEnabled || !cloudConfig.cloudApiKey) {
    return null;
  }

  const verifyConfig = getVerifyConfig();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), verifyConfig.verifyTimeoutMs);

  try {
    const res = await fetch(`${cloudConfig.cloudBaseUrl}/v1/verify/${id}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${cloudConfig.cloudApiKey}`,
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!res.ok) return null;
    return await res.json() as VerifyResult;
  } catch {
    clearTimeout(timeoutId);
    return null;
  }
}
