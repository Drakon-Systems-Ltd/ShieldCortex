import type { Request, Response } from 'express';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { createIronDomeRouteGuard } from '../iron-dome-route-guard.js';
import { activateIronDome, deactivateIronDome } from '../../defence/iron-dome/index.js';

function createResponseMock() {
  const json = jest.fn();
  const status = jest.fn(() => ({ json }));
  return {
    res: { status } as unknown as Response,
    status,
    json,
  };
}

describe('Iron Dome REST route guard', () => {
  afterEach(() => {
    deactivateIronDome();
    jest.restoreAllMocks();
  });

  it('allows trusted dashboard read-style actions through', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    activateIronDome('enterprise');

    const guard = createIronDomeRouteGuard({
      action: 'run_report',
      channel: 'dashboard',
      sourceIdentifier: 'dashboard:test',
    });

    const next = jest.fn();
    const { res, status, json } = createResponseMock();

    guard({ method: 'POST', path: '/api/cloud/config', body: {} } as Request, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('requires announcement for trusted dashboard amber actions', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    activateIronDome('enterprise');

    const guard = createIronDomeRouteGuard({
      action: 'modify_config',
      channel: 'dashboard',
      sourceIdentifier: 'dashboard:test',
      enforceAmber: true,
    });

    const next = jest.fn();
    const { res, status, json } = createResponseMock();

    guard({ method: 'POST', path: '/api/cloud/config', body: {} } as Request, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({
      code: 'IRON_DOME_ANNOUNCEMENT_REQUIRED',
      channel: 'dashboard',
      action: 'modify_config',
      tier: 'amber',
    }));
  });

  it('requires confirmation for destructive trusted-channel actions', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    activateIronDome('enterprise');

    const guard = createIronDomeRouteGuard({
      action: 'delete',
      channel: 'cli',
      sourceIdentifier: 'cli:test',
    });

    const next = jest.fn();
    const { res, status, json } = createResponseMock();

    guard({ method: 'DELETE', path: '/api/example', body: {} } as Request, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({
      code: 'IRON_DOME_CONFIRMATION_REQUIRED',
      channel: 'cli',
      action: 'delete',
      tier: 'red',
    }));
  });
});
