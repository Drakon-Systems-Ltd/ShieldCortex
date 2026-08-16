/**
 * Iron Dome — Action Gate
 *
 * Controls whether external actions (send email, delete file, API call, etc.)
 * are allowed, require approval, or are blocked.
 */

import type { IronDomeConfig } from './config.js';
import type { DefenceSource } from '../types.js';
import { logIronDomeAudit } from './audit.js';

export type ActionDecision = 'approved' | 'requires_approval' | 'blocked';

export interface ActionGateResult {
  decision: ActionDecision;
  action: string;
  reason: string;
}

/**
 * Check if an action is allowed under the current Iron Dome configuration.
 */
export function isActionAllowed(
  action: string,
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
): ActionGateResult {
  if (!config.enabled) {
    return {
      decision: 'approved',
      action,
      reason: 'Iron Dome is not active',
    };
  }

  const normAction = action.toLowerCase();
  let result: ActionGateResult;

  // Check sub-agent restrictions first
  if (source?.type === 'agent') {
    const blocked = config.subAgentRestrictions.blockedOperations
      .some(op => normAction.includes(op.toLowerCase()));
    if (blocked) {
      result = {
        decision: 'blocked',
        action: normAction,
        reason: `Action "${normAction}" is blocked for sub-agents`,
      };
      logIronDomeAudit({
        action: 'action_gate',
        actionType: normAction,
        allowed: false,
        reason: result.reason,
        source,
        attested,
      });
      return result;
    }
  }

  // Check auto-approve list
  const autoApproved = config.autoApprove
    .some(a => normAction.includes(a.toLowerCase()));
  if (autoApproved) {
    result = {
      decision: 'approved',
      action: normAction,
      reason: `Action "${normAction}" is auto-approved`,
    };
    logIronDomeAudit({
      action: 'action_gate',
      actionType: normAction,
      allowed: true,
      reason: result.reason,
      source,
      attested,
    });
    return result;
  }

  // Check require-approval list
  const needsApproval = config.requireApproval
    .some(a => normAction.includes(a.toLowerCase()));
  if (needsApproval) {
    result = {
      decision: 'requires_approval',
      action: normAction,
      reason: `Action "${normAction}" requires explicit approval`,
    };
    logIronDomeAudit({
      action: 'action_gate',
      actionType: normAction,
      allowed: false,
      reason: result.reason,
      source,
      attested,
    });
    return result;
  }

  // Default: allow actions not in either list
  result = {
    decision: 'approved',
    action: normAction,
    reason: `Action "${normAction}" is not restricted`,
  };
  logIronDomeAudit({
    action: 'action_gate',
    actionType: normAction,
    allowed: true,
    reason: result.reason,
    source,
    attested,
  });
  return result;
}
