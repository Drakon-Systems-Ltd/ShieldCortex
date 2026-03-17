import type { Request, Response } from 'express';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { createIronDomeRouteGuard } from '../iron-dome-route-guard.js';
import { activateIronDome, deactivateIronDome } from '../../defence/iron-dome/index.js';
import { closeDatabase, getDatabase, initDatabase } from '../../database/init.js';

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
    closeDatabase();
    jest.restoreAllMocks();
  });

  it('allows trusted dashboard read-style actions through', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    initDatabase(':memory:');
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

  it('allows trusted dashboard amber actions because the UI click is the announcement', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    initDatabase(':memory:');
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

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('still treats dashboard as trusted when persisted channels omit it', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    initDatabase(':memory:');
    activateIronDome('enterprise');

    const db = getDatabase();
    db.prepare(`
      UPDATE iron_dome_config
         SET value = json_set(value, '$.trustedChannels', json('["terminal","cli","telegram"]'))
       WHERE key = 'config'
    `).run();

    const guard = createIronDomeRouteGuard({
      action: 'modify_config',
      channel: 'dashboard',
      sourceIdentifier: 'dashboard:test',
      enforceAmber: true,
    });

    const next = jest.fn();
    const { res, status, json } = createResponseMock();

    guard({ method: 'POST', path: '/api/cloud/config', body: {} } as Request, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('still requires announcement for non-dashboard amber actions without an acknowledgement header', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    initDatabase(':memory:');
    activateIronDome('enterprise');

    const guard = createIronDomeRouteGuard({
      action: 'modify_config',
      channel: 'cli',
      sourceIdentifier: 'cli:test',
      enforceAmber: true,
    });

    const next = jest.fn();
    const { res, status, json } = createResponseMock();

    guard({ method: 'POST', path: '/api/cloud/config', body: {}, get: () => undefined } as unknown as Request, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith(expect.objectContaining({
      code: 'IRON_DOME_ANNOUNCEMENT_REQUIRED',
      channel: 'cli',
      action: 'modify_config',
      tier: 'amber',
    }));
  });

  it('allows non-dashboard amber actions when the caller explicitly marks them announced', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    initDatabase(':memory:');
    activateIronDome('enterprise');

    const guard = createIronDomeRouteGuard({
      action: 'modify_config',
      channel: 'cli',
      sourceIdentifier: 'cli:test',
      enforceAmber: true,
    });

    const next = jest.fn();
    const { res, status, json } = createResponseMock();

    guard({ method: 'POST', path: '/api/cloud/config', body: {}, get: (key: string) => key === 'x-iron-dome-announced' ? '1' : undefined } as unknown as Request, res, next);

    expect(next).toHaveBeenCalled();
    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
  });

  it('requires confirmation for destructive trusted-channel actions', () => {
    jest.spyOn(console, 'error').mockImplementation(() => {});
    initDatabase(':memory:');
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
