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
  });

  return result;
}
