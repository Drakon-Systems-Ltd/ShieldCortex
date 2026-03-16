import { afterEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../../../database/init.js';
import {
  activateIronDome,
  deactivateIronDome,
  getEffectiveIronDomeConfig,
  getIronDomeStatus,
} from '../index.js';

describe('Iron Dome config normalization', () => {
  afterEach(() => {
    deactivateIronDome();
    closeDatabase();
  });

  it('restores dashboard to persisted trusted channels when loading status', () => {
    initDatabase(':memory:');
    activateIronDome('personal');

    const db = getDatabase();
    db.prepare(`
      UPDATE iron_dome_config
      SET value = json_set(value, '$.trustedChannels', json('["terminal","cli","telegram","email"]'))
      WHERE key = 'config'
    `).run();

    const status = getIronDomeStatus();
    expect(status.config.trustedChannels).toContain('dashboard');
  });

  it('restores dashboard to effective config when persisted channels omit it', () => {
    initDatabase(':memory:');
    activateIronDome('personal');

    const db = getDatabase();
    db.prepare(`
      UPDATE iron_dome_config
      SET value = json_set(value, '$.trustedChannels', json('["terminal","cli","telegram","email"]'))
      WHERE key = 'config'
    `).run();

    const config = getEffectiveIronDomeConfig();
    expect(config.trustedChannels).toContain('dashboard');
  });
});
