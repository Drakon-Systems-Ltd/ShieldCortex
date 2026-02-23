/**
 * Iron Dome — Confirmation Gate
 *
 * 3-tier Destructive Action Confirmation Protocol (RED/AMBER/GREEN).
 * Gates destructive actions by classifying them into tiers that determine
 * whether explicit user confirmation, announcement, or silent execution is appropriate.
 */

import type { IronDomeConfig, IronDomeConfirmationProtocol, ConfirmationOverrides } from './config.js';
import { logIronDomeAudit } from './audit.js';

export type ConfirmationTier = 'red' | 'amber' | 'green';

export interface ConfirmationResult {
  tier: ConfirmationTier;
  action: string;
  description: string;
  reversible: boolean;
}

/**
 * Merge user overrides into a base confirmation protocol.
 *
 * Each overridden action is removed from its original tier and placed
 * into the user-specified tier. New actions (not in any default tier)
 * are simply added to the specified tier.
 */
export function mergeConfirmationProtocol(
  base: IronDomeConfirmationProtocol,
  overrides?: ConfirmationOverrides,
): IronDomeConfirmationProtocol {
  if (!overrides) return base;

  // Collect all overridden action → tier mappings
  const overrideMap = new Map<string, ConfirmationTier>();
  for (const action of overrides.red ?? []) overrideMap.set(action.toLowerCase(), 'red');
  for (const action of overrides.amber ?? []) overrideMap.set(action.toLowerCase(), 'amber');
  for (const action of overrides.green ?? []) overrideMap.set(action.toLowerCase(), 'green');

  if (overrideMap.size === 0) return base;

  // Start with base tiers, remove any actions that the user is overriding
  const red = base.red.filter(a => !overrideMap.has(a.toLowerCase()));
  const amber = base.amber.filter(a => !overrideMap.has(a.toLowerCase()));
  const green = base.green.filter(a => !overrideMap.has(a.toLowerCase()));

  // Add overridden actions to their new tiers
  for (const [action, tier] of overrideMap) {
    if (tier === 'red') red.push(action);
    else if (tier === 'amber') amber.push(action);
    else green.push(action);
  }

  return { red, amber, green };
}

/**
 * Classify an action into a confirmation tier based on the Iron Dome configuration.
 *
 * - RED: Destructive actions that ALWAYS require explicit user confirmation.
 * - AMBER: Actions that should be announced before proceeding.
 * - GREEN: Safe actions that can execute silently.
 * - Unknown actions default to AMBER (safe default).
 *
 * User overrides from `config.confirmationOverrides` are merged with profile
 * defaults, with user choices taking precedence.
 */
export function classifyAction(
  action: string,
  config: IronDomeConfig,
): ConfirmationResult {
  if (!config.enabled) {
    return {
      tier: 'green',
      action,
      description: 'Iron Dome is not active',
      reversible: true,
    };
  }

  const normAction = action.toLowerCase();
  const base = config.confirmationProtocol ?? { red: [], amber: [], green: [] };
  const protocol = mergeConfirmationProtocol(base, config.confirmationOverrides);

  // Check RED tier first (most restrictive)
  const isRed = protocol.red.some(r => normAction.includes(r.toLowerCase()));
  if (isRed) {
    const result: ConfirmationResult = {
      tier: 'red',
      action: normAction,
      description: `Action "${normAction}" requires explicit user confirmation (destructive)`,
      reversible: false,
    };

    logIronDomeAudit({
      action: 'confirmation_gate',
      actionType: normAction,
      allowed: false,
      reason: result.description,
    });

    return result;
  }

  // Check GREEN tier (most permissive)
  const isGreen = protocol.green.some(g => normAction.includes(g.toLowerCase()));
  if (isGreen) {
    return {
      tier: 'green',
      action: normAction,
      description: `Action "${normAction}" is safe to execute silently`,
      reversible: true,
    };
  }

  // Check AMBER tier explicitly
  const isAmber = protocol.amber.some(a => normAction.includes(a.toLowerCase()));
  if (isAmber) {
    return {
      tier: 'amber',
      action: normAction,
      description: `Action "${normAction}" should be announced before proceeding`,
      reversible: true,
    };
  }

  // Unknown actions default to AMBER (safe default)
  return {
    tier: 'amber',
    action: normAction,
    description: `Action "${normAction}" is not classified — defaulting to announcement required`,
    reversible: true,
  };
}

/**
 * Returns true if the action requires explicit user confirmation (RED tier).
 */
export function requiresConfirmation(
  action: string,
  config: IronDomeConfig,
): boolean {
  return classifyAction(action, config).tier === 'red';
}

/**
 * Returns true if the action requires at least an announcement (RED or AMBER tier).
 */
export function requiresAnnouncement(
  action: string,
  config: IronDomeConfig,
): boolean {
  const tier = classifyAction(action, config).tier;
  return tier === 'red' || tier === 'amber';
}
