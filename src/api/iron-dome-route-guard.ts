import type { Request, Response } from 'express';
import { classifyAction, getEffectiveIronDomeConfig, getIronDomeStatus, isActionAllowed, validateGateway } from '../defence/iron-dome/index.js';
import type { DefenceSource } from '../defence/types.js';

type Next = (err?: unknown) => void;
export type Middleware = (_req: Request, res: Response, next: Next) => void;

export interface IronDomeRouteGuardOptions {
  action: string | ((req: Request) => string);
  channel: string;
  sourceIdentifier?: string | ((req: Request) => string);
  enforceAmber?: boolean;
}

function resolveValue<T>(value: T | ((req: Request) => T), req: Request): T {
  return typeof value === 'function' ? (value as (req: Request) => T)(req) : value;
}

export function createIronDomeRouteGuard(options: IronDomeRouteGuardOptions): Middleware {
  return (req: Request, res: Response, next: Next) => {
    const status = getIronDomeStatus();
    if (!status.enabled) return next();

    const config = getEffectiveIronDomeConfig();
    const action = resolveValue(options.action, req);
    const sourceIdentifier = options.sourceIdentifier
      ? resolveValue(options.sourceIdentifier, req)
      : `rest:${req.method}:${req.path}`;
    const source: DefenceSource = {
      type: 'api',
      identifier: sourceIdentifier,
    };

    const gateway = validateGateway(options.channel, action, config, source);
    if (!gateway.allowed) {
      return res.status(403).json({
        error: 'Blocked by Iron Dome gateway',
        code: 'IRON_DOME_GATEWAY_BLOCKED',
        action,
        channel: options.channel,
        reason: gateway.reason,
        trustLevel: gateway.trustLevel,
      });
    }

    const gate = isActionAllowed(action, config, source);
    if (gate.decision === 'blocked') {
      return res.status(403).json({
        error: 'Blocked by Iron Dome action gate',
        code: 'IRON_DOME_ACTION_BLOCKED',
        action,
        channel: options.channel,
        reason: gate.reason,
      });
    }

    if (gate.decision === 'requires_approval') {
      return res.status(409).json({
        error: 'Action requires explicit approval',
        code: 'IRON_DOME_APPROVAL_REQUIRED',
        action,
        channel: options.channel,
        reason: gate.reason,
      });
    }

    const confirmation = classifyAction(action, config);
    const requiresConfirmation = confirmation.tier === 'red';
    const dashboardAnnouncementSatisfied = options.channel === 'dashboard';
    const requestAnnouncementSatisfied = typeof req.get === 'function'
      && req.get('x-iron-dome-announced') === '1';
    const requiresAnnouncement = confirmation.tier === 'amber'
      && options.enforceAmber
      && !dashboardAnnouncementSatisfied
      && !requestAnnouncementSatisfied;

    if (requiresConfirmation || requiresAnnouncement) {
      return res.status(409).json({
        error: requiresConfirmation ? 'Action requires explicit confirmation' : 'Action requires announcement before execution',
        code: requiresConfirmation ? 'IRON_DOME_CONFIRMATION_REQUIRED' : 'IRON_DOME_ANNOUNCEMENT_REQUIRED',
        action,
        channel: options.channel,
        tier: confirmation.tier,
        reason: confirmation.description,
        reversible: confirmation.reversible,
      });
    }

    return next();
  };
}
