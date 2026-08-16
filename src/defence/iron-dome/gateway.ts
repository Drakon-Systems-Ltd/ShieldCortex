/**
 * Iron Dome — Instruction Gateway
 *
 * Validates whether an instruction channel is trusted before
 * allowing commands through. Builds on existing trust scoring concepts.
 */

import type { IronDomeConfig } from './config.js';
import type { DefenceSource } from '../types.js';
import { logIronDomeAudit } from './audit.js';

export interface GatewayResult {
  allowed: boolean;
  channel: string;
  reason: string;
  trustLevel: 'trusted' | 'untrusted' | 'blocked';
}

/**
 * Check if a channel is trusted according to Iron Dome configuration.
 */
export function isChannelTrusted(
  channel: string,
  config: IronDomeConfig,
): boolean {
  if (!config.enabled) return true;
  const normalized = channel.toLowerCase();
  if (normalized === 'dashboard') return true;
  return config.trustedChannels.includes(normalized);
}

/**
 * Validate an instruction through the gateway.
 * Returns whether the instruction should be processed.
 */
export function validateGateway(
  channel: string,
  instruction: string,
  config: IronDomeConfig,
  source?: DefenceSource,
  /**
   * Resolver-derived attestation for `source`; omit ⇒ NULL (fail-safe).
   *
   * WARNING — do NOT wire MCP-caller attestation into the advisory-check
   * paths (iron_dome_check): policy denials (requires_approval /
   * untrusted-channel probes) log as BLOCK, and the threat-graph projector
   * weighs every attested BLOCK at 1.0 with no policy/threat distinction —
   * compliant pre-flight checks would saturate the caller's shared key at
   * the daily risk cap (verified by repro, PR #315 review). Attest only
   * genuinely threat-shaped rows, after the projector can weight policy
   * rows separately.
   */
  attested?: boolean,
): GatewayResult {
  if (!config.enabled) {
    return {
      allowed: true,
      channel,
      reason: 'Iron Dome is not active',
      trustLevel: 'trusted',
    };
  }

  const normChannel = channel.toLowerCase();
  const trusted = normChannel === 'dashboard' || config.trustedChannels.includes(normChannel);

  const result: GatewayResult = {
    allowed: trusted,
    channel: normChannel,
    reason: trusted
      ? `Channel "${normChannel}" is trusted`
      : `Channel "${normChannel}" is not in trusted channels list`,
    trustLevel: trusted ? 'trusted' : 'untrusted',
  };

  // Log the gateway check
  logIronDomeAudit({
    action: 'gateway_check',
    channel: normChannel,
    allowed: result.allowed,
    reason: result.reason,
    source,
    attested,
  });

  return result;
}
